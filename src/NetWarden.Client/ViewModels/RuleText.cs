using NetWarden.Shared.Contracts;
using NetWarden.Shared.Formatting;

namespace NetWarden.Client.ViewModels;

/// <summary>Human-readable descriptions of filters and rules.</summary>
public static class RuleText
{
    public static string FunctionName(FilterFunctionKind kind) => kind switch
    {
        FilterFunctionKind.AppId => "Application",
        FilterFunctionKind.PathEquals => "Application path",
        FilterFunctionKind.PathContains => "Application path contains",
        FilterFunctionKind.RemoteAddressInRange => "Remote address",
        FilterFunctionKind.LocalAddressInRange => "Local address",
        FilterFunctionKind.RemotePortInRange => "Remote port",
        FilterFunctionKind.LocalPortInRange => "Local port",
        FilterFunctionKind.Protocol => "Protocol",
        FilterFunctionKind.DomainName => "Domain name",
        FilterFunctionKind.User => "User",
        FilterFunctionKind.ProcessId => "Process id",
        FilterFunctionKind.Tag => "Tag",
        FilterFunctionKind.IsInternet => "Remote host is on Internet",
        FilterFunctionKind.IsLocalNetwork => "Remote host is on local network",
        FilterFunctionKind.IsLoopback => "Loopback traffic",
        _ => kind.ToString(),
    };

    public static bool TakesValues(FilterFunctionKind kind) =>
        kind is not (FilterFunctionKind.IsInternet or FilterFunctionKind.IsLocalNetwork or FilterFunctionKind.IsLoopback);

    public static string ValueHint(FilterFunctionKind kind) => kind switch
    {
        FilterFunctionKind.AppId => "One app id (lower-case path) per line",
        FilterFunctionKind.PathEquals => "Wildcards * and ?, e.g. *\\chrome.exe",
        FilterFunctionKind.PathContains => "Part of the path, e.g. \\Steam\\",
        FilterFunctionKind.RemoteAddressInRange or FilterFunctionKind.LocalAddressInRange =>
            "192.168.1.1, 192.168.1.0 - 192.168.1.10, 192.168.0.0/16",
        FilterFunctionKind.RemotePortInRange or FilterFunctionKind.LocalPortInRange => "80, 1000 - 1100",
        FilterFunctionKind.Protocol => "TCP or UDP",
        FilterFunctionKind.DomainName => "Wildcards, e.g. *.google.com",
        FilterFunctionKind.User => "SID or DOMAIN\\user",
        FilterFunctionKind.ProcessId => "Process id numbers",
        FilterFunctionKind.Tag => "Tag names",
        _ => "No values",
    };

    public static string Describe(FilterFunction f)
    {
        if (!TakesValues(f.Kind))
            return f.Match ? FunctionName(f.Kind) : "Not: " + FunctionName(f.Kind);
        string values = string.Join(", ", f.Values ?? []);
        return $"{FunctionName(f.Kind)} {(f.Match ? "is" : "is not")} {values}";
    }

    public static string Describe(FilterDefinition filter) =>
        filter.Functions.Count == 0 && filter.Type != FilterType.Composite
            ? "Any traffic"
            : string.Join(" and ", filter.Functions.Select(Describe));

    public static string Value(RuleDefinition rule) => rule.Kind switch
    {
        RuleKind.Limit => rule.LimitBytesPerSecond is { } bps ? ByteFormatter.Rate(bps, UnitMode.Bytes) : "?",
        RuleKind.Firewall => rule.Action?.ToString() ?? "?",
        RuleKind.Ignore => (rule.IgnoreLimit, rule.IgnoreData) switch
        {
            (true, true) => "Ignore limit and data",
            (true, false) => "Ignore limit",
            (false, true) => "Ignore data",
            _ => "?",
        },
        _ => "",
    };

    public static string Kind(RuleKind kind) => kind switch
    {
        RuleKind.Firewall => "Blocker",
        _ => kind.ToString(),
    };
}
