namespace NetWarden.Shared.Contracts;

public enum FilterType
{
    /// <summary>Matches when all its functions match.</summary>
    Filter,
    /// <summary>A network zone (Internet, local network, loopback).</summary>
    Zone,
    /// <summary>Matches when any base filter matches and all its own functions match.</summary>
    Composite,
}

/// <summary>How a filter splits traffic into separate limit buckets.</summary>
public enum FilterPerType
{
    None,
    PerApp,
    PerProcess,
    PerConnection,
}

public enum FilterFunctionKind
{
    AppId,
    PathEquals,
    PathContains,
    RemoteAddressInRange,
    LocalAddressInRange,
    RemotePortInRange,
    LocalPortInRange,
    Protocol,
    DomainName,
    User,
    ProcessId,
    Tag,
    IsInternet,
    IsLocalNetwork,
    IsLoopback,
}

/// <summary>
/// One test of a filter. It matches when any of <see cref="Values"/> matches
/// (zone functions take no values); <see cref="Match"/> false negates it ("is not").
/// </summary>
public sealed record FilterFunction(FilterFunctionKind Kind, bool Match = true, IReadOnlyList<string>? Values = null);

public sealed record FilterDefinition(
    Guid Id,
    string Name,
    FilterType Type,
    FilterPerType PerType,
    IReadOnlyList<FilterFunction> Functions,
    IReadOnlyList<Guid> BaseFilterIds,
    bool IsPredefined = false,
    string? Notes = null,
    DateTimeOffset Created = default,
    DateTimeOffset Updated = default);

public enum RuleDirection
{
    /// <summary>Download, or for the blocker: incoming connections.</summary>
    In,
    /// <summary>Upload, or for the blocker: outgoing connections.</summary>
    Out,
    Both,
}

public enum RuleKind
{
    Limit,
    Firewall,
    Ignore,
}

public enum FirewallAction
{
    Allow,
    Deny,
    Ask,
}

public enum RuleState
{
    Active,
    Inactive,
    Disabled,
}

/// <summary>
/// A rule attached to a filter. Kind-specific fields: <see cref="LimitBytesPerSecond"/>
/// for limits, <see cref="Action"/> for the blocker, <see cref="IgnoreLimit"/> /
/// <see cref="IgnoreData"/> for ignore rules. Weight 0 means "default for the filter".
/// </summary>
public sealed record RuleDefinition(
    Guid Id,
    Guid FilterId,
    RuleKind Kind,
    RuleDirection Direction,
    bool IsEnabled = true,
    int Weight = 0,
    string? Notes = null,
    long? LimitBytesPerSecond = null,
    FirewallAction? Action = null,
    bool IgnoreLimit = false,
    bool IgnoreData = false,
    DateTimeOffset? ExpiresAt = null,
    DateTimeOffset Created = default,
    DateTimeOffset Updated = default);

/// <summary>The persisted rule configuration. Rule list order breaks weight ties.</summary>
public sealed class RulesDocument
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; set; } = CurrentSchemaVersion;
    public List<FilterDefinition> Filters { get; set; } = [];
    public List<RuleDefinition> Rules { get; set; } = [];
}

public sealed record RuleView(RuleDefinition Rule, RuleState State, int EffectiveWeight, string FilterName);

/// <summary>Everything the client needs to show filters and rules.</summary>
public sealed record RulesSnapshot(long Generation, IReadOnlyList<FilterDefinition> Filters, IReadOnlyList<RuleView> Rules);

public sealed record DeleteRequest(Guid Id);
public sealed record SetRuleEnabledRequest(Guid Id, bool IsEnabled);
public sealed record ReorderRulesRequest(IReadOnlyList<Guid> RuleIds);
public sealed record EnsureAppFilterRequest(string AppId, string DisplayName);

/// <summary>A flow description for asking the service which rules apply.</summary>
public sealed record EvaluateRequest(
    string AppId,
    string AppPath,
    int ProcessId,
    TransportProtocol Protocol,
    ConnectionKind Kind,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    string? RemoteHost = null,
    string? UserSid = null);

public sealed record LimitBinding(Guid RuleId, long BytesPerSecond, string BucketKey);

public sealed record FlowDecision(
    FirewallAction Firewall,
    Guid? FirewallRuleId,
    IReadOnlyList<LimitBinding> DownloadLimits,
    IReadOnlyList<LimitBinding> UploadLimits,
    bool IgnoreData,
    IReadOnlyList<Guid> MatchedFilterIds);
