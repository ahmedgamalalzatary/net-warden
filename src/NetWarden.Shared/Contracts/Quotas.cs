namespace NetWarden.Shared.Contracts;

/// <summary>
/// A quota's persisted counter. <see cref="EnabledRuleIds"/> are the rules the overflow actually
/// turned on, so ending the overflow never turns off a rule the user had enabled.
/// </summary>
public sealed class QuotaState
{
    public Guid RuleId { get; set; }
    public long Used { get; set; }
    /// <summary>The last reset moment this counter has seen; null before the first one.</summary>
    public DateTimeOffset? LastReset { get; set; }
    public DateTimeOffset? OverflowedAt { get; set; }
    public List<Guid> EnabledRuleIds { get; set; } = [];
}

public sealed class QuotaDocument
{
    public List<QuotaState> Quotas { get; set; } = [];
}

/// <summary>One quota as the client shows it.</summary>
public sealed record QuotaStatus(
    Guid RuleId,
    Guid FilterId,
    string FilterName,
    RuleDirection Direction,
    bool IsEnabled,
    long Used,
    long Limit,
    TimeSchedule? Reset,
    DateTimeOffset? NextReset,
    DateTimeOffset? OverflowedAt);

/// <summary>Sent to clients when a quota with an alert is exceeded.</summary>
public sealed record QuotaAlert(Guid RuleId, string FilterName, long Used, long Limit, DateTimeOffset Time);

public sealed record QuotaRequest(Guid RuleId);
