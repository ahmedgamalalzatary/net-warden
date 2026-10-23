using System.Net;
using NetWarden.Shared.Contracts;

namespace NetWarden.Core.Rules;

/// <summary>Everything a filter can test about one flow.</summary>
public sealed record FlowContext(
    string AppId,
    string AppPath,
    int ProcessId,
    TransportProtocol Protocol,
    ConnectionKind Kind,
    IPAddress LocalAddress,
    int LocalPort,
    IPAddress RemoteAddress,
    int RemotePort,
    string? RemoteHost = null,
    string? UserSid = null,
    string? UserName = null,
    IReadOnlyCollection<string>? Tags = null)
{
    /// <summary>Stable id of this flow, used for per-connection limit buckets.</summary>
    public string FlowKey => $"{ProcessId}|{Protocol}|{LocalAddress}|{LocalPort}|{RemoteAddress}|{RemotePort}";

    /// <summary>The blocker treats listening sockets like incoming connections.</summary>
    public bool IsOutgoing => Kind == ConnectionKind.Connect;
}

/// <summary>
/// An immutable, compiled set of filters and rules. Swapped atomically when the
/// configuration changes, so evaluation never takes a lock.
/// </summary>
public sealed class CompiledRuleSet
{
    private readonly Dictionary<Guid, CompiledFilter> _filters;
    private readonly CompiledRule[] _firewall;
    private readonly CompiledRule[] _limits;
    private readonly CompiledRule[] _ignores;

    internal CompiledRuleSet(long generation, Dictionary<Guid, CompiledFilter> filters, IReadOnlyList<CompiledRule> rules)
    {
        Generation = generation;
        _filters = filters;
        // Highest weight first; list order breaks ties (stable sort).
        var ordered = rules.Select((r, i) => (r, i)).OrderByDescending(x => x.r.Weight).ThenBy(x => x.i).Select(x => x.r).ToArray();
        _firewall = ordered.Where(r => r.Rule.Kind == RuleKind.Firewall).ToArray();
        _limits = ordered.Where(r => r.Rule.Kind == RuleKind.Limit).ToArray();
        _ignores = ordered.Where(r => r.Rule.Kind == RuleKind.Ignore).ToArray();
    }

    public long Generation { get; }

    public static CompiledRuleSet Empty { get; } = new(0, [], []);

    public bool HasFirewallRules => _firewall.Length > 0;
    public bool HasLimitRules => _limits.Length > 0;

    /// <summary>
    /// Decides a flow. <paramref name="defaultIn"/>/<paramref name="defaultOut"/> apply when no
    /// blocker rule matches. <paramref name="now"/> excludes expired rules.
    /// </summary>
    public FlowDecision Evaluate(FlowContext flow, FirewallAction defaultIn, FirewallAction defaultOut, DateTimeOffset now)
    {
        var matched = new Dictionary<Guid, bool>();
        bool Matches(Guid filterId)
        {
            if (!matched.TryGetValue(filterId, out bool m))
                matched[filterId] = m = _filters.TryGetValue(filterId, out var f) && f.Matches(flow, _filters);
            return m;
        }

        RuleDirection connectionDirection = flow.IsOutgoing ? RuleDirection.Out : RuleDirection.In;
        FirewallAction action = flow.IsOutgoing ? defaultOut : defaultIn;
        Guid? firewallRule = null;
        foreach (var rule in _firewall)
        {
            if (rule.IsLive(now) && Applies(rule.Rule.Direction, connectionDirection) && Matches(rule.Rule.FilterId))
            {
                action = rule.Rule.Action ?? FirewallAction.Allow;
                firewallRule = rule.Rule.Id;
                break;
            }
        }

        int ignoreLimitIn = int.MinValue, ignoreLimitOut = int.MinValue;
        bool ignoreData = false;
        foreach (var rule in _ignores)
        {
            if (!rule.IsLive(now) || !Matches(rule.Rule.FilterId))
                continue;
            if (rule.Rule.IgnoreData)
                ignoreData = true;
            if (rule.Rule.IgnoreLimit)
            {
                if (Applies(rule.Rule.Direction, RuleDirection.In))
                    ignoreLimitIn = Math.Max(ignoreLimitIn, rule.Weight);
                if (Applies(rule.Rule.Direction, RuleDirection.Out))
                    ignoreLimitOut = Math.Max(ignoreLimitOut, rule.Weight);
            }
        }

        // Every matching limit applies (traffic must fit all of them), except limits
        // whose weight is not above a matching "ignore limit" rule.
        var download = new List<LimitBinding>();
        var upload = new List<LimitBinding>();
        foreach (var rule in _limits)
        {
            if (!rule.IsLive(now) || rule.Rule.LimitBytesPerSecond is not > 0 || !Matches(rule.Rule.FilterId))
                continue;
            string bucket = BucketKey(rule, flow);
            if (Applies(rule.Rule.Direction, RuleDirection.In) && rule.Weight > ignoreLimitIn)
                download.Add(new LimitBinding(rule.Rule.Id, rule.Rule.LimitBytesPerSecond.Value, bucket + "|in"));
            if (Applies(rule.Rule.Direction, RuleDirection.Out) && rule.Weight > ignoreLimitOut)
                upload.Add(new LimitBinding(rule.Rule.Id, rule.Rule.LimitBytesPerSecond.Value, bucket + "|out"));
        }

        return new FlowDecision(action, firewallRule, download, upload, ignoreData,
            matched.Where(kv => kv.Value).Select(kv => kv.Key).ToList());
    }

    private string BucketKey(CompiledRule rule, FlowContext flow)
    {
        FilterPerType perType = _filters.TryGetValue(rule.Rule.FilterId, out var f) ? f.Definition.PerType : FilterPerType.None;
        string id = rule.Rule.Id.ToString("N");
        return perType switch
        {
            FilterPerType.PerApp => $"{id}|app:{flow.AppId}",
            FilterPerType.PerProcess => $"{id}|pid:{flow.ProcessId}",
            FilterPerType.PerConnection => $"{id}|flow:{flow.FlowKey}",
            _ => id,
        };
    }

    private static bool Applies(RuleDirection rule, RuleDirection wanted) => rule == RuleDirection.Both || rule == wanted;
}

internal sealed class CompiledRule(RuleDefinition rule, int weight)
{
    public RuleDefinition Rule { get; } = rule;
    public int Weight { get; } = weight;

    public bool IsLive(DateTimeOffset now) => Rule.IsEnabled && (Rule.ExpiresAt is not { } expires || expires > now);
}

internal sealed class CompiledFilter
{
    private readonly Func<FlowContext, bool>[] _functions;

    public CompiledFilter(FilterDefinition definition, ZoneClassifier zones)
    {
        Definition = definition;
        _functions = definition.Functions.Select(f => FilterCompiler.Compile(f, zones)).ToArray();
    }

    public FilterDefinition Definition { get; }

    public bool Matches(FlowContext flow, IReadOnlyDictionary<Guid, CompiledFilter> all)
    {
        if (Definition.Type == FilterType.Composite)
        {
            // Base filters are never composite (validated), so this does not recurse further.
            bool anyBase = Definition.BaseFilterIds.Any(id => all.TryGetValue(id, out var b) && b.Matches(flow, all));
            if (!anyBase)
                return false;
        }
        foreach (var function in _functions)
            if (!function(flow))
                return false;
        return true;
    }
}

public static class FilterCompiler
{
    /// <summary>Builds a predicate for one function. Values must already be validated.</summary>
    public static Func<FlowContext, bool> Compile(FilterFunction function, ZoneClassifier zones)
    {
        IReadOnlyList<string> values = function.Values ?? [];
        Func<FlowContext, bool> test = function.Kind switch
        {
            FilterFunctionKind.AppId => AnyString(values, (f, v) => string.Equals(f.AppId, v, StringComparison.OrdinalIgnoreCase)),
            FilterFunctionKind.PathEquals => Wildcards(values, f => f.AppPath),
            FilterFunctionKind.PathContains => AnyString(values, (f, v) => f.AppPath.Contains(v, StringComparison.OrdinalIgnoreCase)),
            FilterFunctionKind.RemoteAddressInRange => Ranges(values, f => f.RemoteAddress),
            FilterFunctionKind.LocalAddressInRange => Ranges(values, f => f.LocalAddress),
            FilterFunctionKind.RemotePortInRange => Ports(values, f => f.RemotePort),
            FilterFunctionKind.LocalPortInRange => Ports(values, f => f.LocalPort),
            FilterFunctionKind.Protocol => AnyString(values, (f, v) => string.Equals(f.Protocol.ToString(), v, StringComparison.OrdinalIgnoreCase)),
            FilterFunctionKind.DomainName => Wildcards(values, f => f.RemoteHost),
            FilterFunctionKind.User => AnyString(values, (f, v) =>
                string.Equals(f.UserSid, v, StringComparison.OrdinalIgnoreCase) || string.Equals(f.UserName, v, StringComparison.OrdinalIgnoreCase)),
            FilterFunctionKind.ProcessId => ProcessIds(values),
            FilterFunctionKind.Tag => AnyString(values, (f, v) => f.Tags?.Contains(v, StringComparer.OrdinalIgnoreCase) == true),
            FilterFunctionKind.IsInternet => f => zones.IsInternet(f.RemoteAddress, f.LocalAddress),
            FilterFunctionKind.IsLocalNetwork => f => zones.IsLocalNetwork(f.RemoteAddress, f.LocalAddress),
            FilterFunctionKind.IsLoopback => f => ZoneClassifier.IsLoopback(f.RemoteAddress, f.LocalAddress),
            _ => throw new ArgumentOutOfRangeException(nameof(function), function.Kind, "Unknown filter function."),
        };
        return function.Match ? test : f => !test(f);
    }

    private static Func<FlowContext, bool> AnyString(IReadOnlyList<string> values, Func<FlowContext, string, bool> test)
    {
        string[] v = values.Select(s => s.Trim()).ToArray();
        return f => v.Any(x => test(f, x));
    }

    private static Func<FlowContext, bool> Wildcards(IReadOnlyList<string> values, Func<FlowContext, string?> field)
    {
        Wildcard[] patterns = values.Select(v => new Wildcard(v)).ToArray();
        return f => { string? s = field(f); return patterns.Any(p => p.IsMatch(s)); };
    }

    private static Func<FlowContext, bool> Ranges(IReadOnlyList<string> values, Func<FlowContext, IPAddress> field)
    {
        IpRange[] ranges = values.Select(v => IpRange.TryParse(v, out var r) ? r : throw new FormatException($"Invalid IP range '{v}'.")).ToArray();
        return f => { var a = field(f); return ranges.Any(r => r.Contains(a)); };
    }

    private static Func<FlowContext, bool> Ports(IReadOnlyList<string> values, Func<FlowContext, int> field)
    {
        PortRange[] ranges = values.Select(v => PortRange.TryParse(v, out var r) ? r : throw new FormatException($"Invalid port range '{v}'.")).ToArray();
        return f => { int p = field(f); return ranges.Any(r => r.Contains(p)); };
    }

    private static Func<FlowContext, bool> ProcessIds(IReadOnlyList<string> values)
    {
        var pids = values.Select(v => int.TryParse(v.Trim(), out int p) ? p : throw new FormatException($"Invalid process id '{v}'.")).ToHashSet();
        return f => pids.Contains(f.ProcessId);
    }
}
