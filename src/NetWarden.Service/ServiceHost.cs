using System.Diagnostics;
using System.Net;
using System.Security.Principal;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Options;
using NetWarden.Core;
using NetWarden.Core.Apps;
using NetWarden.Core.Ipc;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Settings;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;

namespace NetWarden.Service;

public sealed class ServiceOptions
{
    public const string SectionName = "NetWarden";

    public string PipeName { get; set; } = PipeNames.Default;

    /// <summary>When false the pipe uses default security (tests only).</summary>
    public bool RestrictPipeToAdmins { get; set; } = true;

    public string? SettingsPath { get; set; }

    /// <summary>When false no ETW session is started (tests, which must not steal the real service's session).</summary>
    public bool EnableTrafficSource { get; set; } = true;

    public string TrafficSessionName { get; set; } = EtwTrafficSource.DefaultSessionName;
}

public static class ServiceHost
{
    public const string ServiceName = "NetWarden";

    public static IHost Build(string[] args, IDictionary<string, string?>? configOverrides = null)
    {
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            Args = args,
            ContentRootPath = AppContext.BaseDirectory,
        });
        if (configOverrides is not null)
            builder.Configuration.AddInMemoryCollection(configOverrides);

        builder.Services.AddWindowsService(o => o.ServiceName = ServiceName);
        builder.Services.Configure<ServiceOptions>(builder.Configuration.GetSection(ServiceOptions.SectionName));

        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<AppIdentityResolver>();
        builder.Services.AddSingleton(sp => new JsonFileStore<ServiceSettings>(
            Options(sp).SettingsPath ?? AppPaths.SettingsFile,
            sp.GetRequiredService<ILogger<JsonFileStore<ServiceSettings>>>()));

        builder.Services.AddSingleton<ISocketTable, SocketTable>();
        builder.Services.AddSingleton<HostNameCache>(_ => new HostNameCache());
        builder.Services.AddSingleton(sp => new TrafficMonitor(
            sp.GetRequiredService<ISocketTable>(),
            sp.GetRequiredService<AppIdentityResolver>().Resolve,
            sp.GetRequiredService<TimeProvider>()));
        builder.Services.AddSingleton<ITrafficSource>(sp => Options(sp).EnableTrafficSource
            ? new EtwTrafficSource(sp.GetRequiredService<ILogger<EtwTrafficSource>>(), Options(sp).TrafficSessionName)
            : new NullTrafficSource());

        builder.Services.AddSingleton(CreateDispatcher);
        builder.Services.AddSingleton(sp => new IpcServer(
            Options(sp).PipeName,
            sp.GetRequiredService<IpcDispatcher>(),
            sp.GetRequiredService<ILogger<IpcServer>>(),
            Options(sp).RestrictPipeToAdmins ? PipeSecurityFactory.AdminsAndSystem() : null));

        builder.Services.AddHostedService<IpcHostedService>();
        builder.Services.AddHostedService<ActivityService>();

        return builder.Build();
    }

    private static ServiceOptions Options(IServiceProvider sp) => sp.GetRequiredService<IOptions<ServiceOptions>>().Value;

    private static IpcDispatcher CreateDispatcher(IServiceProvider sp)
    {
        var resolver = sp.GetRequiredService<AppIdentityResolver>();
        var settings = sp.GetRequiredService<JsonFileStore<ServiceSettings>>();
        var monitor = sp.GetRequiredService<TrafficMonitor>();
        var hostNames = sp.GetRequiredService<HostNameCache>();
        var info = CreateServiceInfo();

        return new IpcDispatcher()
            .Register(Methods.ServiceInfo, _ => Task.FromResult(info))
            .Register(Methods.SettingsGet, _ => Task.FromResult(settings.Load()))
            .Register<ResolveAppRequest, AppInfo?>(Methods.AppsResolve, (request, _) =>
                Task.FromResult(request is null ? null : resolver.Resolve(request.ProcessId)))
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
