using System.Net;
using NetWarden.Shared.Contracts;

namespace NetWarden.Core.Rules;

public sealed class RuleValidationException(string message) : Exception(message);

public static class RuleValidator
{
    public const int MaxNameLength = 100;
    public const long MaxLimitBytesPerSecond = 100L * 1024 * 1024 * 1024;

    private static readonly FilterFunctionKind[] ZoneKinds =
        [FilterFunctionKind.IsInternet, FilterFunctionKind.IsLocalNetwork, FilterFunctionKind.IsLoopback];

    public static void ValidateFilter(FilterDefinition filter, IReadOnlyList<FilterDefinition> all)
    {
        if (string.IsNullOrWhiteSpace(filter.Name))
            throw new RuleValidationException("Filter name can't be empty.");
        if (filter.Name.Length > MaxNameLength)
            throw new RuleValidationException("Filter name is too long.");
        if (all.Any(f => f.Id != filter.Id && string.Equals(f.Name.Trim(), filter.Name.Trim(), StringComparison.OrdinalIgnoreCase)))
            throw new RuleValidationException($"A filter named '{filter.Name.Trim()}' already exists.");

        foreach (var function in filter.Functions)
            ValidateFunction(function);

        if (filter.Type == FilterType.Composite)
        {
            if (filter.BaseFilterIds.Count == 0)
                throw new RuleValidationException("A composite filter needs at least one base filter.");
            foreach (Guid id in filter.BaseFilterIds)
            {
                var b = all.FirstOrDefault(f => f.Id == id)
                    ?? throw new RuleValidationException($"Base filter {id} not found.");
                if (b.Type == FilterType.Composite)
                    throw new RuleValidationException($"Composite filter '{b.Name}' can't be used as a base filter.");
                if (b.Id == filter.Id)
                    throw new RuleValidationException("A filter can't be its own base filter.");
            }
        }
        else if (filter.BaseFilterIds.Count > 0)
        {
            throw new RuleValidationException("Only composite filters have base filters.");
        }
    }

    public static void ValidateFunction(FilterFunction function)
    {
        IReadOnlyList<string> values = function.Values ?? [];
        if (ZoneKinds.Contains(function.Kind))
        {
            if (values.Count > 0)
                throw new RuleValidationException($"{function.Kind} takes no values.");
            return;
        }
        if (values.Count == 0 || values.Any(string.IsNullOrWhiteSpace))
            throw new RuleValidationException($"{function.Kind} needs at least one non-empty value.");

        foreach (string v in values)
        {
            bool ok = function.Kind switch
            {
                FilterFunctionKind.RemoteAddressInRange or FilterFunctionKind.LocalAddressInRange => IpRange.TryParse(v, out _),
                FilterFunctionKind.RemotePortInRange or FilterFunctionKind.LocalPortInRange => PortRange.TryParse(v, out _),
                FilterFunctionKind.Protocol => v.Trim().Equals("TCP", StringComparison.OrdinalIgnoreCase) || v.Trim().Equals("UDP", StringComparison.OrdinalIgnoreCase),
                FilterFunctionKind.ProcessId => int.TryParse(v.Trim(), out int pid) && pid >= 0,
                _ => true,
            };
            if (!ok)
                throw new RuleValidationException($"Invalid value '{v}' for {function.Kind}.");
        }
    }

    public static void ValidateRule(RuleDefinition rule, IReadOnlyList<FilterDefinition> filters)
    {
        if (filters.All(f => f.Id != rule.FilterId))
            throw new RuleValidationException($"Filter {rule.FilterId} not found.");
        switch (rule.Kind)
        {
            case RuleKind.Limit:
                if (rule.LimitBytesPerSecond is not > 0)
                    throw new RuleValidationException("A limit must be greater than zero.");
                if (rule.LimitBytesPerSecond > MaxLimitBytesPerSecond)
                    throw new RuleValidationException("The limit is too large.");
                break;
            case RuleKind.Firewall:
                if (rule.Action is null)
                    throw new RuleValidationException("A blocker rule needs an action.");
                break;
            case RuleKind.Ignore:
                if (!rule.IgnoreLimit && !rule.IgnoreData)
                    throw new RuleValidationException("An ignore rule must ignore the limit, the data, or both.");
                break;
            case RuleKind.Priority:
                if (rule.Priority is not { } level || !Enum.IsDefined(level))
                    throw new RuleValidationException("A priority rule needs a priority level.");
                break;
        }
        if (rule.Weight < 0)
            throw new RuleValidationException("Weight can't be negative.");
    }

    /// <summary>Address or "*" for the UI's quick checks; true if the text is a valid range.</summary>
    public static bool IsValidAddressRange(string text) => IpRange.TryParse(text, out _) || IPAddress.TryParse(text, out _);
}
