namespace NetWarden.Shared.Contracts;

/// <summary>Zone of the remote end, as stored with each stats record.</summary>
public enum StatsZone
{
    Internet,
    LocalNetwork,
    Loopback,
}

/// <summary>What the breakdown table of a stats query lists.</summary>
public enum StatsGroupBy
{
    App,
    /// <summary>Remote IP address, labelled with its domain name when known.</summary>
    Host,
    /// <summary>Service port: the remote port of outgoing connections, the local port of incoming ones.</summary>
    Port,
    Country,
    User,
}

/// <summary>Width of one bar in the time chart; buckets follow the caller's time zone.</summary>
public enum StatsBucket
{
    Minute,
    Hour,
    Day,
    Month,
}

/// <summary>
/// Traffic between <see cref="From"/> (inclusive) and <see cref="To"/> (exclusive), optionally
/// narrowed to zones, a protocol and one app. <see cref="TimeZoneId"/> (Windows id) decides where
/// days and hours start; the service's local zone when null.
/// </summary>
public sealed record StatsQuery(
    DateTimeOffset From,
    DateTimeOffset To,
    StatsBucket Bucket,
    StatsGroupBy GroupBy,
    IReadOnlyList<StatsZone>? Zones = null,
    TransportProtocol? Protocol = null,
    string? AppId = null,
    string? TimeZoneId = null,
    int MaxRows = 500);

/// <summary>Bytes transferred in one time bucket (or one hour of the day for the histogram).</summary>
public sealed record StatsPoint(DateTimeOffset Time, long In, long Out);

/// <summary>Bytes transferred at each hour of the day (0-23), summed over the queried range.</summary>
public sealed record StatsHour(int Hour, long In, long Out);

/// <summary>
/// One line of the breakdown. <see cref="Key"/> identifies it (app id, IP, "Tcp/443", country code,
/// user SID); <see cref="Detail"/> is secondary text (app path, IP of a named host, protocol, country).
/// </summary>
public sealed record StatsRow(string Key, string Label, string? Detail, long In, long Out);

public sealed record StatsResult(
    DateTimeOffset From,
    DateTimeOffset To,
    StatsBucket Bucket,
    long TotalIn,
    long TotalOut,
    IReadOnlyList<StatsPoint> Series,
    IReadOnlyList<StatsHour> Hours,
    IReadOnlyList<StatsRow> Rows,
    /// <summary>True when the breakdown had more rows than <see cref="StatsQuery.MaxRows"/>.</summary>
    bool IsTruncated);

/// <summary>The stats database as the stats manager shows it.</summary>
public sealed record StatsInfo(
    string Path,
    long FileBytes,
    long Records,
    int Apps,
    DateTimeOffset? FirstRecord,
    DateTimeOffset? LastRecord,
    /// <summary>Month of the country database (DB-IP Lite), e.g. "2026-10"; null when it is missing.</summary>
    string? GeoDatabaseDate);

/// <summary>
/// Deletes records in [<see cref="From"/>, <see cref="To"/>) (open-ended when null) for one app,
/// or for every app when <see cref="AppId"/> is null. Everything when all are null.
/// </summary>
public sealed record StatsDeleteRequest(DateTimeOffset? From = null, DateTimeOffset? To = null, string? AppId = null);

/// <summary>Which traffic is written to the stats database.</summary>
public sealed class StatsSettings
{
    public const int MinSaveIntervalSeconds = 10;
    public const int MaxSaveIntervalSeconds = 3600;

    public bool SaveInternet { get; set; } = true;
    public bool SaveLocalNetwork { get; set; } = true;
    public bool SaveLoopback { get; set; }

    /// <summary>How often collected traffic is written to disk. Records are per minute either way.</summary>
    public int SaveIntervalSeconds { get; set; } = 60;

    public bool Saves(StatsZone zone) => zone switch
    {
        StatsZone.Internet => SaveInternet,
        StatsZone.LocalNetwork => SaveLocalNetwork,
        _ => SaveLoopback,
    };
}
