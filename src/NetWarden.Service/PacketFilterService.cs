using Microsoft.Extensions.Options;
using NetWarden.Core;
using NetWarden.Core.Ipc;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Packets;
using NetWarden.Core.Rules;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;

namespace NetWarden.Service;

/// <summary>Opens the packet device; replaced by a fake in tests.</summary>
public delegate IPacketDevice PacketDeviceFactory(string filter);

/// <summary>
/// Runs the WinDivert packet filter only while something needs it (blocker rules or a
/// non-Allow default), answers Ask requests, and resets established connections that
/// newly denied rules cover. Stopping the filter returns Windows to normal traffic.
/// </summary>
public sealed class PacketFilterService(
    Blocker blocker,
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
    private PacketFilter? _filter;
    private string? _error;
    private DateTimeOffset _lastAttempt = DateTimeOffset.MinValue;
    private bool _needed;

    public PacketFilterStatus Status
    {
        get
        {
            lock (_lock)
                return new PacketFilterStatus(_filter?.IsRunning == true, _needed, _error, _filter?.PacketsSeen ?? 0, blocker.Dropped);
        }
    }

    /// <summary>Whether the current rules and settings require diverting packets.</summary>
    public static bool IsNeeded(ServiceSettings s, CompiledRuleSet r) =>
        s.IsBlockerEnabled && (r.HasFirewallRules || s.DefaultFirewallIn != FirewallAction.Allow || s.DefaultFirewallOut != FirewallAction.Allow);

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

    /// <summary>Starts or stops the filter to match the configuration; retries failed starts slowly.</summary>
    private void Reconcile(bool force)
    {
        PacketFilterStatus? changed = null;
        lock (_lock)
        {
            bool before = _filter?.IsRunning == true;
            string? errorBefore = _error;
            _needed = options.Value.EnablePacketFilter && IsNeeded(settings.Current, rules.Current);

            if (_filter is { IsRunning: false } dead)
            {
                _error = dead.Fault?.Message ?? "Packet filter stopped.";
                dead.Dispose();
                _filter = null;
            }

            if (_needed && _filter is null && (force || time.GetUtcNow() - _lastAttempt > RetryInterval))
            {
                _lastAttempt = time.GetUtcNow();
                try
                {
                    _filter = new PacketFilter(openDevice(PacketFilter.BlockerFilter), blocker, logger);
                    _error = null;
                    logger.LogInformation("Packet filter started.");
                }
                catch (Exception ex)
                {
                    _error = ex.Message;
                    logger.LogError(ex, "Packet filter failed to start.");
                }
            }
            else if (!_needed && _filter is not null)
            {
                StopLocked();
                logger.LogInformation("Packet filter stopped: not needed.");
            }

            if (before != (_filter?.IsRunning == true) || errorBefore != _error)
                changed = new PacketFilterStatus(_filter?.IsRunning == true, _needed, _error, _filter?.PacketsSeen ?? 0, blocker.Dropped);
        }
        if (changed is not null)
            _ = server.BroadcastAsync(Events.FilterStatus, changed);
    }

    private void StopLocked()
    {
        // Let waiting connections through rather than leaving them hanging.
        foreach (var request in blocker.Pending)
        {
            _filter?.Inject(blocker.Resolve(request.Id, allow: true));
            _ = server.BroadcastAsync(Events.BlockerResolved, new BlockerResolved(request.Id, true, TimedOut: false));
        }
        _filter?.Dispose();
        _filter = null;
        blocker.ClearCache();
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
            _filter?.Inject(packets);
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
            StopLocked();
        base.Dispose();
    }
}
