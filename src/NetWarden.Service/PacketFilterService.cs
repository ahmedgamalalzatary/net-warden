using Microsoft.Extensions.Options;
using NetWarden.Core;
using NetWarden.Core.Ipc;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Packets;
using NetWarden.Core.Rules;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;

namespace NetWarden.Service;

/// <summary>Opens a packet device for a WinDivert filter at a priority; replaced by a fake in tests.</summary>
public delegate IPacketDevice PacketDeviceFactory(string filter, short priority);

/// <summary>
/// Runs the WinDivert packet filters only while something needs them: the blocker's
/// (blocker rules or a non-Allow default) and the limiter's (limit rules with the
/// Limiter on, or priority rules with Priorities on). Answers Ask requests and resets established connections that newly
/// denied rules cover. Stopping a filter returns Windows to normal traffic.
/// </summary>
public sealed class PacketFilterService(
    Blocker blocker,
    Limiter limiter,
    RuleRepository rules,
    SettingsService settings,
    ISocketTable sockets,
    FlowContextFactory contexts,
    IpcServer server,
    PacketDeviceFactory openDevice,
    IOptions<ServiceOptions> options,
    TimeProvider time,
    ILogger<PacketFilterService> logger) : BackgroundService
{
    public static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(1);
    public static readonly TimeSpan RetryInterval = TimeSpan.FromSeconds(30);

    private readonly Lock _lock = new();
    private readonly Slot _blocker = new();
    private readonly Slot _limiter = new();
    private LimiterPump? _pump;

    public PacketFilterStatus Status
    {
        get
        {
            lock (_lock)
                return StatusLocked();
        }
    }

    private PacketFilterStatus StatusLocked() =>
        new(_blocker.IsRunning, _blocker.Needed, _blocker.Error, _blocker.Filter?.PacketsSeen ?? 0, blocker.Dropped,
            new LimiterStatus(_limiter.IsRunning, _limiter.Needed, _limiter.Error, _limiter.Filter?.PacketsSeen ?? 0,
                limiter.Delayed, limiter.Dropped, limiter.QueuedBytes, limiter.Priorities));

    /// <summary>Whether the current rules and settings require the blocker's filter.</summary>
    public static bool IsNeeded(ServiceSettings s, CompiledRuleSet r) =>
        s.IsBlockerEnabled && (r.HasFirewallRules || s.DefaultFirewallIn != FirewallAction.Allow || s.DefaultFirewallOut != FirewallAction.Allow);

    /// <summary>Whether the current rules and settings require the limiter's filter (limits or priorities).</summary>
    public static bool IsLimiterNeeded(ServiceSettings s, CompiledRuleSet r) => Limiter.UsesLimits(s, r) || Limiter.UsesPriorities(s, r);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        blocker.RequestCreated += r => _ = server.BroadcastAsync(Events.BlockerRequest, r);
        // Change events fire inside the repository's lock; do the work elsewhere.
        rules.Changed += _ => Task.Run(OnConfigurationChanged);
        settings.Changed += _ => Task.Run(OnConfigurationChanged);
        Reconcile(force: true);

        using var timer = new PeriodicTimer(TickInterval, time);
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                foreach (Guid id in blocker.ExpireTimeouts())
                    _ = server.BroadcastAsync(Events.BlockerResolved, new BlockerResolved(id, false, TimedOut: true));
                Reconcile(force: false);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Packet filter tick failed.");
            }
        }
    }

    private void OnConfigurationChanged()
    {
        Reconcile(force: true);
        SweepDeniedConnections();
    }

    /// <summary>Starts or stops the filters to match the configuration; retries failed starts slowly.</summary>
    private void Reconcile(bool force)
    {
        PacketFilterStatus? changed = null;
        lock (_lock)
        {
            var before = StatusLocked();
            bool enabled = options.Value.EnablePacketFilter;
            _blocker.Needed = enabled && IsNeeded(settings.Current, rules.Current);
            _limiter.Needed = enabled && IsLimiterNeeded(settings.Current, rules.Current);

            ReconcileSlot(_blocker, "Blocker", force, StartBlocker, StopBlockerLocked);
            ReconcileSlot(_limiter, "Limiter", force, StartLimiter, StopLimiterLocked);

            var after = StatusLocked();
            if ((before.IsRunning, before.Error, before.Limiter!.IsRunning, before.Limiter.Error)
                != (after.IsRunning, after.Error, after.Limiter!.IsRunning, after.Limiter.Error))
                changed = after;
        }
        if (changed is not null)
            _ = server.BroadcastAsync(Events.FilterStatus, changed);
    }

    private void ReconcileSlot(Slot slot, string name, bool force, Func<PacketFilter> start, Action stop)
    {
        if (slot.Filter is { IsRunning: false } dead)
        {
            slot.Error = dead.Fault?.Message ?? "Packet filter stopped.";
            stop();
        }

        if (slot.Needed && slot.Filter is null && (force || time.GetUtcNow() - slot.LastAttempt > RetryInterval))
        {
            slot.LastAttempt = time.GetUtcNow();
            try
            {
                slot.Filter = start();
                slot.Error = null;
                logger.LogInformation("{Name} packet filter started.", name);
            }
            catch (Exception ex)
            {
                slot.Error = ex.Message;
                logger.LogError(ex, "{Name} packet filter failed to start.", name);
            }
        }
        else if (!slot.Needed && slot.Filter is not null)
        {
            stop();
            logger.LogInformation("{Name} packet filter stopped: not needed.", name);
        }
    }

    private PacketFilter StartBlocker() =>
        new(openDevice(PacketFilter.BlockerFilter, PacketFilter.BlockerPriority), blocker, logger, "blocker filter");

    private PacketFilter StartLimiter()
    {
        limiter.Reset();
        var filter = new PacketFilter(openDevice(PacketFilter.LimiterFilter, PacketFilter.LimiterPriority), limiter, logger, "limiter filter");
        _pump = new LimiterPump(limiter, filter.Inject);
        return filter;
    }

    private void StopBlockerLocked()
    {
        // Let waiting connections through rather than leaving them hanging.
        foreach (var request in blocker.Pending)
        {
            _blocker.Filter?.Inject(blocker.Resolve(request.Id, allow: true));
            _ = server.BroadcastAsync(Events.BlockerResolved, new BlockerResolved(request.Id, true, TimedOut: false));
        }
        _blocker.Filter?.Dispose();
        _blocker.Filter = null;
        blocker.ClearCache();
    }

    private void StopLimiterLocked()
    {
        // The pump sends what is still queued before the device closes.
        _pump?.Dispose();
        _pump = null;
        _limiter.Filter?.Dispose();
        _limiter.Filter = null;
        limiter.Reset();
    }

    private sealed class Slot
    {
        public PacketFilter? Filter;
        public string? Error;
        public bool Needed;
        public DateTimeOffset LastAttempt = DateTimeOffset.MinValue;

        public bool IsRunning => Filter?.IsRunning == true;
    }

    private void SweepDeniedConnections()
    {
        if (!settings.Current.IsBlockerEnabled || !options.Value.EnablePacketFilter)
            return;
        try
        {
            var denied = BlockedConnectionSweeper.FindDenied(sockets.Snapshot(), rules.Current, settings.Current, contexts, time.GetUtcNow());
            foreach (var s in denied)
            {
                uint rc = ConnectionKiller.KillTcp(s.LocalAddress, s.LocalPort, s.RemoteAddress!, s.RemotePort);
                logger.LogInformation("Reset blocked connection {Local}:{LocalPort} -> {Remote}:{RemotePort} (pid {Pid}): {Result}",
                    s.LocalAddress, s.LocalPort, s.RemoteAddress, s.RemotePort, s.ProcessId, rc == 0 ? "ok" : $"error {rc}");
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Resetting blocked connections failed.");
        }
    }

    /// <summary>Applies an answer: optionally remembers it as a rule, then releases or drops the waiting packets.</summary>
    public bool Answer(BlockerAnswer answer)
    {
        var request = blocker.Pending.FirstOrDefault(r => r.Id == answer.RequestId);
        if (request is null)
            return false;

        if (answer.Remember != RememberMode.Once)
            RememberAsRule(request, answer);

        var packets = blocker.Resolve(request.Id, answer.Allow);
        lock (_lock)
            _blocker.Filter?.Inject(packets);
        _ = server.BroadcastAsync(Events.BlockerResolved, new BlockerResolved(request.Id, answer.Allow, TimedOut: false));
        return true;
    }

    private void RememberAsRule(BlockerRequest request, BlockerAnswer answer)
    {
        var app = new FilterFunction(FilterFunctionKind.AppId, true, [request.App.Id]);
        FilterDefinition filter = answer.Scope switch
        {
            RuleScope.AppAndRemoteAddress => rules.EnsureFilter($"{request.App.DisplayName} → {request.RemoteAddress}",
                [app, new FilterFunction(FilterFunctionKind.RemoteAddressInRange, true, [request.RemoteAddress])]),
            RuleScope.AppAndRemotePort => rules.EnsureFilter($"{request.App.DisplayName} → {request.Protocol.ToString().ToUpperInvariant()} {request.RemotePort}",
                [app, new FilterFunction(FilterFunctionKind.Protocol, true, [request.Protocol.ToString().ToUpperInvariant()]),
                 new FilterFunction(FilterFunctionKind.RemotePortInRange, true, [request.RemotePort.ToString()])]),
            _ => rules.EnsureAppFilter(request.App.Id, request.App.DisplayName),
        };
        DateTimeOffset? expires = answer.Remember == RememberMode.Temporary
            ? time.GetUtcNow().AddMinutes(Math.Clamp(answer.TemporaryMinutes, 1, 7 * 24 * 60))
            : null;
        rules.SaveRule(new RuleDefinition(Guid.Empty, filter.Id, RuleKind.Firewall,
            request.Kind == ConnectionKind.Connect ? RuleDirection.Out : RuleDirection.In,
            Action: answer.Allow ? FirewallAction.Allow : FirewallAction.Deny,
            ExpiresAt: expires,
            Notes: answer.Remember == RememberMode.Temporary ? "Temporary answer to a blocker prompt" : "Answer to a blocker prompt"));
    }

    public override void Dispose()
    {
        lock (_lock)
        {
            StopBlockerLocked();
            StopLimiterLocked();
        }
        base.Dispose();
    }
}
