namespace NetWarden.Shared.Contracts;

/// <summary>Settings persisted by the service.</summary>
public sealed class ServiceSettings
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; set; } = CurrentSchemaVersion;
    public bool IsBlockerEnabled { get; set; } = true;
    public bool IsLimiterEnabled { get; set; } = true;
    public bool IsPriorityEnabled { get; set; } = true;
    public bool IsStatsEnabled { get; set; } = true;

    /// <summary>Blocker action for incoming connections no rule matches.</summary>
    public FirewallAction DefaultFirewallIn { get; set; } = FirewallAction.Allow;

    /// <summary>Blocker action for outgoing connections no rule matches.</summary>
    public FirewallAction DefaultFirewallOut { get; set; } = FirewallAction.Allow;

    public PrioritySettings Priorities { get; set; } = new();

    public StatsSettings Stats { get; set; } = new();
}

public enum ReactionSpeed
{
    Low,
    Normal,
    Fast,
    Custom,
}

/// <summary>
/// How priorities share the line. While a higher level has traffic, every level below it
/// gets what the higher levels leave: the line capacity minus their reservations.
/// </summary>
public sealed class PrioritySettings
{
    public const int MinReactionMillis = 50;
    public const int MaxReactionMillis = 5000;

    /// <summary>How quickly lower levels are restricted when a higher level starts (and released when it stops).</summary>
    public ReactionSpeed ReactionSpeed { get; set; } = ReactionSpeed.Normal;

    /// <summary>Used when <see cref="ReactionSpeed"/> is Custom.</summary>
    public int ReactionMillis { get; set; } = 250;

    /// <summary>
    /// Reserve a level's share only while it has traffic. Off: the share stays reserved while
    /// the level has open connections, even idle ones (steadier for games, but wastes bandwidth).
    /// </summary>
    public bool Adaptive { get; set; } = true;

    /// <summary>Share of the line (%) reserved for Critical traffic while it is active.</summary>
    public int CriticalPercent { get; set; } = 70;
    public int HighPercent { get; set; } = 60;
    public int NormalPercent { get; set; } = 50;

    /// <summary>Extra room (%) over a level's current rate, so it can speed up before lower levels yield.</summary>
    public int HeadroomPercent { get; set; } = 20;

    /// <summary>Line capacity bounds in bytes/s (0 = detect automatically). Setting Max to your line speed is the most accurate.</summary>
    public long MinDownloadBytesPerSecond { get; set; }
    public long MaxDownloadBytesPerSecond { get; set; }
    public long MinUploadBytesPerSecond { get; set; }
    public long MaxUploadBytesPerSecond { get; set; }

    [System.Text.Json.Serialization.JsonIgnore]
    public TimeSpan ReactionTime => TimeSpan.FromMilliseconds(ReactionSpeed switch
    {
        ReactionSpeed.Low => 1000,
        ReactionSpeed.Fast => 100,
        ReactionSpeed.Custom => Math.Clamp(ReactionMillis, MinReactionMillis, MaxReactionMillis),
        _ => 250,
    });

    public int ReservedPercent(PriorityLevel level) => level switch
    {
        PriorityLevel.Critical => CriticalPercent,
        PriorityLevel.High => HighPercent,
        PriorityLevel.Normal => NormalPercent,
        _ => 0,
    };
}
