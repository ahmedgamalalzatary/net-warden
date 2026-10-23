namespace NetWarden.Shared.Contracts;

/// <summary>Filters that always exist. Their ids are fixed so rules and clients can refer to them.</summary>
public static class PredefinedFilters
{
    public static readonly Guid AnyTraffic = new("0b6c1c7e-0000-4000-8000-000000000001");
    public static readonly Guid Internet = new("0b6c1c7e-0000-4000-8000-000000000002");
    public static readonly Guid LocalNetwork = new("0b6c1c7e-0000-4000-8000-000000000003");
    public static readonly Guid Loopback = new("0b6c1c7e-0000-4000-8000-000000000004");

    public static IReadOnlyList<FilterDefinition> All { get; } =
    [
        new(AnyTraffic, "Any traffic", FilterType.Filter, FilterPerType.None, [], [], IsPredefined: true,
            Notes: "The whole computer."),
        new(Internet, "Internet", FilterType.Zone, FilterPerType.None,
            [new FilterFunction(FilterFunctionKind.IsInternet)], [], IsPredefined: true),
        new(LocalNetwork, "Local network", FilterType.Zone, FilterPerType.None,
            [new FilterFunction(FilterFunctionKind.IsLocalNetwork)], [], IsPredefined: true),
        new(Loopback, "Loopback", FilterType.Zone, FilterPerType.None,
            [new FilterFunction(FilterFunctionKind.IsLoopback)], [], IsPredefined: true),
    ];

    public static bool IsPredefined(Guid id) => All.Any(f => f.Id == id);

    /// <summary>Rules created on first run: like NetLimiter, limits never throttle LAN or loopback traffic.</summary>
    public static IReadOnlyList<RuleDefinition> DefaultRules { get; } =
    [
        new(new Guid("0b6c1c7e-0000-4000-8000-000000000101"), LocalNetwork, RuleKind.Ignore, RuleDirection.Both,
            IgnoreLimit: true, Notes: "Do not limit local network traffic."),
        new(new Guid("0b6c1c7e-0000-4000-8000-000000000102"), Loopback, RuleKind.Ignore, RuleDirection.Both,
            IgnoreLimit: true, Notes: "Do not limit loopback traffic."),
    ];
}
