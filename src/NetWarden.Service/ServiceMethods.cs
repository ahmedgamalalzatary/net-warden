using System.Diagnostics;
using System.Net;
using System.Security.Principal;
using Microsoft.Extensions.Hosting.WindowsServices;
using NetWarden.Core;
using NetWarden.Core.Apps;
using NetWarden.Core.Ipc;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Packets;
using NetWarden.Core.Rules;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;

namespace NetWarden.Service;

/// <summary>Registers every IPC method the service answers.</summary>
public static class ServiceMethods
{
    public static IpcDispatcher Create(IServiceProvider sp)
    {
        var resolver = sp.GetRequiredService<AppIdentityResolver>();
        var settings = sp.GetRequiredService<SettingsService>();
        var monitor = sp.GetRequiredService<TrafficMonitor>();
        var hostNames = sp.GetRequiredService<HostNameCache>();
        var rules = sp.GetRequiredService<RuleRepository>();
        var flows = sp.GetRequiredService<FlowContextFactory>();
        var time = sp.GetRequiredService<TimeProvider>();
        var info = CreateServiceInfo();

        var dispatcher = new IpcDispatcher()
            .Register(Methods.ServiceInfo, _ => Task.FromResult(info))
            .Register(Methods.SettingsGet, _ => Task.FromResult(settings.Current))
            .Register<ServiceSettings, ServiceSettings>(Methods.SettingsUpdate, (request, _) =>
                Task.FromResult(settings.Update(request ?? throw new ArgumentException("Settings required."))))
            .Register<ResolveAppRequest, AppInfo?>(Methods.AppsResolve, (request, _) =>
                Task.FromResult(request is null ? null : resolver.Resolve(request.ProcessId)));

        RegisterActivity(dispatcher, monitor, hostNames);
        RegisterRules(dispatcher, rules, flows, settings, time);

        // Resolved lazily: PacketFilterService depends on the IPC server, which depends on this dispatcher.
        PacketFilterService Filter() => sp.GetRequiredService<PacketFilterService>();
        var blocker = sp.GetRequiredService<Blocker>();
        dispatcher
            .Register(Methods.FilterStatus, _ => Task.FromResult(Filter().Status))
            .Register(Methods.BlockerPending, _ => Task.FromResult(blocker.Pending))
            .Register<BlockerAnswer, bool>(Methods.BlockerAnswer, (a, _) =>
                Task.FromResult(Filter().Answer(a ?? throw new ArgumentException("Answer required."))));

        var stats = sp.GetRequiredService<StatsService>();
        dispatcher
            .Register<StatsQuery, StatsResult>(Methods.StatsQuery, (q, _) => Task.Run(() => stats.Query(Require(q))))
            .Register(Methods.StatsInfo, _ => Task.Run(stats.Info))
            .Register<StatsDeleteRequest, long>(Methods.StatsDelete, (r, _) => Task.Run(() => stats.Delete(Require(r))))
            .Register(Methods.StatsCompact, _ => Task.Run(stats.Compact));
        return dispatcher;
    }

    private static void RegisterActivity(IpcDispatcher dispatcher, TrafficMonitor monitor, HostNameCache hostNames)
    {
        dispatcher
            .Register(Methods.ActivityGet, _ => Task.FromResult(monitor.Latest ?? monitor.Tick()))
            .Register(Methods.ActivityResetTotals, _ =>
            {
                monitor.ResetTotals();
                return Task.FromResult(true);
            })
            .Register<KillConnectionRequest, bool>(Methods.ConnectionsKill, (request, _) =>
            {
                ArgumentNullException.ThrowIfNull(request);
                if (request.Protocol != TransportProtocol.Tcp)
                    throw new NotSupportedException("Only TCP connections can be killed.");
                uint rc = ConnectionKiller.KillTcp(
                    IPAddress.Parse(request.LocalAddress), request.LocalPort,
                    IPAddress.Parse(request.RemoteAddress), request.RemotePort);
                if (rc != 0)
                    throw new InvalidOperationException($"Windows refused to kill the connection (error {rc}).");
                return Task.FromResult(true);
            })
            .Register<ReverseDnsRequest, string?>(Methods.DnsReverse, (request, _) =>
                IPAddress.TryParse(request?.Address, out var address)
                    ? hostNames.GetAsync(address)
                    : throw new ArgumentException("Invalid IP address."));
    }

    private static void RegisterRules(IpcDispatcher dispatcher, RuleRepository rules, FlowContextFactory flows,
        SettingsService settings, TimeProvider time)
    {
        dispatcher
            .Register(Methods.RulesGet, _ => Task.FromResult(rules.Snapshot()))
            .Register<FilterDefinition, FilterDefinition>(Methods.FiltersSave, (f, _) =>
                Task.FromResult(rules.SaveFilter(f ?? throw new ArgumentException("Filter required."))))
            .Register<DeleteRequest, bool>(Methods.FiltersDelete, (r, _) =>
            {
                rules.DeleteFilter(Require(r).Id);
                return Task.FromResult(true);
            })
            .Register<EnsureAppFilterRequest, FilterDefinition>(Methods.FiltersEnsureForApp, (r, _) =>
                Task.FromResult(rules.EnsureAppFilter(Require(r).AppId, r!.DisplayName)))
            .Register<RuleDefinition, RuleDefinition>(Methods.RulesSave, (r, _) =>
                Task.FromResult(rules.SaveRule(r ?? throw new ArgumentException("Rule required."))))
            .Register<DeleteRequest, bool>(Methods.RulesDelete, (r, _) =>
            {
                rules.DeleteRule(Require(r).Id);
                return Task.FromResult(true);
            })
            .Register<SetRuleEnabledRequest, bool>(Methods.RulesSetEnabled, (r, _) =>
            {
                rules.SetEnabled(Require(r).Id, r!.IsEnabled);
                return Task.FromResult(true);
            })
            .Register<ReorderRulesRequest, bool>(Methods.RulesReorder, (r, _) =>
            {
                rules.Reorder(Require(r).RuleIds);
                return Task.FromResult(true);
            })
            .Register<EvaluateRequest, FlowDecision>(Methods.RulesEvaluate, (r, _) =>
            {
                Require(r);
                var flow = new FlowContext(r!.AppId, r.AppPath, r.ProcessId, r.Protocol, r.Kind,
                    IPAddress.Parse(r.LocalAddress), r.LocalPort, IPAddress.Parse(r.RemoteAddress), r.RemotePort,
                    r.RemoteHost, r.UserSid);
                var s = settings.Current;
                return Task.FromResult(rules.Current.Evaluate(flow, s.DefaultFirewallIn, s.DefaultFirewallOut, time.GetUtcNow()));
            });
    }

    private static T Require<T>(T? value) where T : class =>
        value ?? throw new ArgumentException($"{typeof(T).Name} required.");

    private static ServiceInfo CreateServiceInfo()
    {
        using var process = Process.GetCurrentProcess();
        using var identity = WindowsIdentity.GetCurrent();
        return new ServiceInfo(
            Version: typeof(ServiceHost).Assembly.GetName().Version?.ToString(3) ?? "0.0.0",
            ProcessId: Environment.ProcessId,
            StartedAt: process.StartTime.ToUniversalTime(),
            IsElevated: new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator),
            IsWindowsService: WindowsServiceHelpers.IsWindowsService(),
            MachineName: Environment.MachineName);
    }
}
