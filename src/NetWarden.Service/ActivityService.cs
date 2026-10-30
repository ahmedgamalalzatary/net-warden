using NetWarden.Core.Apps;
using NetWarden.Core.Ipc;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Packets;
using NetWarden.Shared.Ipc;

namespace NetWarden.Service;

/// <summary>Feeds traffic events into the monitor and pushes a snapshot to clients every second.</summary>
public sealed class ActivityService(
    ITrafficSource source,
    TrafficMonitor monitor,
    ConnectionLog log,
    AppRegistry apps,
    Blocker blocker,
    IpcServer server,
    ILogger<ActivityService> logger) : BackgroundService
{
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(1);
    private const int SaveAppsEveryTicks = 60;
    private int _ticks;

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
        apps.Save();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        source.Traffic += e => monitor.Record(e);
        blocker.ConnectionBlocked += log.AddBlocked;
        try
        {
            source.Start();
        }
        catch (Exception ex)
        {
            // Without ETW (e.g. not elevated) connections are still listed, just without byte counts.
            logger.LogError(ex, "Traffic source failed to start; rates will be unavailable.");
        }

        using var timer = new PeriodicTimer(Interval);
        monitor.Tick();
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                var snapshot = monitor.Tick();
                log.Update(snapshot);
                apps.Observe(snapshot);
                if (++_ticks % SaveAppsEveryTicks == 0)
                    apps.Save();
                if (server.ClientCount > 0)
                    await server.BroadcastAsync(Events.ActivitySnapshot, snapshot).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Activity tick failed.");
            }
        }
    }

    public override void Dispose()
    {
        source.Dispose();
        base.Dispose();
    }
}
