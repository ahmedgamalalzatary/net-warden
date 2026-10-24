using NetWarden.Core;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Stats;
using NetWarden.Shared.Contracts;

namespace NetWarden.Service;

/// <summary>
/// Records traffic into the stats database: the recorder collects every monitor tick, and its
/// records are written every <see cref="StatsSettings.SaveIntervalSeconds"/> and when the service stops.
/// </summary>
public sealed class StatsService(
    StatsDatabase database,
    StatsRecorder recorder,
    TrafficMonitor monitor,
    SettingsService settings,
    CountryLookup geo,
    TimeProvider time,
    ILogger<StatsService> logger) : BackgroundService
{
    /// <summary>Longest range a query may cover.</summary>
    public static readonly TimeSpan MaxQueryRange = TimeSpan.FromDays(366 * 20);

    private readonly Lock _flushLock = new();
    private long _lastRollUpHour = -1;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        monitor.TrafficRecorded += recorder.Add;
        try
        {
            RollUpHourly();
            while (!stoppingToken.IsCancellationRequested)
            {
                var interval = TimeSpan.FromSeconds(settings.Current.Stats.SaveIntervalSeconds);
                await Task.Delay(interval, time, stoppingToken).ConfigureAwait(false);
                Flush();
                RollUpHourly();
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
        monitor.TrafficRecorded -= recorder.Add;
        Flush();
    }

    /// <summary>Writes what the recorder collected. Records that fail to write are dropped (and logged).</summary>
    public void Flush()
    {
        lock (_flushLock)
        {
            var records = recorder.Drain();
            try
            {
                database.Write(records);
            }
            catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or IOException)
            {
                logger.LogError(ex, "Writing {Count} stats records failed; they are lost.", records.Count);
            }
        }
    }

    public StatsResult Query(StatsQuery query)
    {
        if (query.To <= query.From)
            throw new ArgumentException("The end of the range must be after its start.");
        if (query.To - query.From > MaxQueryRange)
            throw new ArgumentException("The range is too long.");
        Flush();
        return database.Query(query, geo, ResolveTimeZone(query.TimeZoneId));
    }

    public StatsInfo Info()
    {
        Flush();
        return database.Info(geo.DatabaseDate);
    }

    public long Delete(StatsDeleteRequest request)
    {
        Flush();
        long deleted = database.Delete(request);
        logger.LogInformation("Deleted {Count} stats records ({From} - {To}, app {App}).", deleted,
            request.From?.ToString() ?? "start", request.To?.ToString() ?? "now", request.AppId ?? "all");
        return deleted;
    }

    public StatsInfo Compact()
    {
        Flush();
        database.Compact(time.GetUtcNow());
        return database.Info(geo.DatabaseDate);
    }

    private void RollUpHourly()
    {
        long hour = time.GetUtcNow().ToUnixTimeSeconds() / 3600;
        if (hour == _lastRollUpHour)
            return;
        _lastRollUpHour = hour;
        try
        {
            long merged = database.RollUp(time.GetUtcNow());
            if (merged > 0)
                logger.LogDebug("Rolled {Count} minute stats records up into hours.", merged);
        }
        catch (Microsoft.Data.Sqlite.SqliteException ex)
        {
            logger.LogError(ex, "Rolling up stats failed.");
        }
    }

    internal static TimeZoneInfo ResolveTimeZone(string? id) =>
        id is not null && TimeZoneInfo.TryFindSystemTimeZoneById(id, out var zone) ? zone : TimeZoneInfo.Local;
}
