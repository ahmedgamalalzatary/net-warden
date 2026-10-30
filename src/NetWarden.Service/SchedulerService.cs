using NetWarden.Core.Rules;

namespace NetWarden.Service;

/// <summary>Runs the rule scheduler every second and saves how far it got.</summary>
public sealed class SchedulerService(RuleScheduler scheduler, TimeProvider time, ILogger<SchedulerService> logger) : BackgroundService
{
    public static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(1);
    private const int SaveEveryTicks = 60;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        int ticks = 0;
        using var timer = new PeriodicTimer(TickInterval, time);
        try
        {
            do
            {
                try
                {
                    scheduler.Tick();
                    if (++ticks % SaveEveryTicks == 1)
                        scheduler.Save();
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Scheduler tick failed.");
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
        scheduler.Save();
    }
}
