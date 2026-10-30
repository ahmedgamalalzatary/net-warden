using Microsoft.Extensions.Options;
using NetWarden.Core.Ipc;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Packets;
using NetWarden.Core.Quotas;
using NetWarden.Core.Rules;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;

namespace NetWarden.Service;

/// <summary>
/// Feeds monitored traffic to the quota tracker, ticks it every second, saves its counters and carries
/// out the overflow actions that need the outside world: alerting clients and killing connections.
/// </summary>
public sealed class QuotaService(
    QuotaTracker tracker,
    TrafficMonitor monitor,
    StatsService stats,
    RuleRepository rules,
    ISocketTable sockets,
    FlowContextFactory flows,
    IpcServer server,
    IOptions<ServiceOptions> options,
    TimeProvider time,
    ILogger<QuotaService> logger) : BackgroundService
{
    public static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(1);
    private const int SaveEveryTicks = 60;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        monitor.TrafficRecorded += tracker.Add;
        tracker.Exceeded += OnExceeded;
        int ticks = 0;
        using var timer = new PeriodicTimer(TickInterval, time);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                try
                {
                    tracker.Tick();
                    if (++ticks % SaveEveryTicks == 0)
                        tracker.Save();
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Quota tick failed.");
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
        monitor.TrafficRecorded -= tracker.Add;
        tracker.Exceeded -= OnExceeded;
        tracker.Save();
    }

    /// <summary>Sets a quota's counter from the statistics of its current period.</summary>
    public void InitFromStats(Guid ruleId) =>
        tracker.InitFromStats(ruleId, stats.Flows(tracker.PeriodStart(ruleId), time.GetUtcNow().AddMinutes(1)));

    private void OnExceeded(RuleDefinition rule, QuotaAlert alert)
    {
        logger.LogInformation("Quota for {Filter} exceeded: {Used} of {Limit} bytes.", alert.FilterName, alert.Used, alert.Limit);
        if (rule.OverflowAlert)
            _ = server.BroadcastAsync(Events.QuotaAlert, alert);
        if (rule.OverflowKillConnections && options.Value.EnablePacketFilter)
            _ = Task.Run(() => KillConnections(rule));
    }

    private void KillConnections(RuleDefinition rule)
    {
        try
        {
            foreach (var s in BlockedConnectionSweeper.FindMatching(sockets.Snapshot(), rules.Current, rule.FilterId, flows))
            {
                uint rc = ConnectionKiller.KillTcp(s.LocalAddress, s.LocalPort, s.RemoteAddress!, s.RemotePort);
                logger.LogInformation("Quota reset {Local}:{LocalPort} -> {Remote}:{RemotePort} (pid {Pid}): {Result}",
                    s.LocalAddress, s.LocalPort, s.RemoteAddress, s.RemotePort, s.ProcessId, rc == 0 ? "ok" : $"error {rc}");
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Killing the connections of an exceeded quota failed.");
        }
    }
}
