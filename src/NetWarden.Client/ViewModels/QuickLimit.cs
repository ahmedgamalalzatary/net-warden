using NetWarden.Shared.Contracts;

namespace NetWarden.Client.ViewModels;

/// <summary>
/// The rule behind the DL/UL limit cells of the activity grid: one permanent Limit
/// rule on the app's filter per direction. Unchecking disables it, keeping the value.
/// </summary>
public static class QuickLimit
{
    public const double DefaultKilobytes = 100;

    public static RuleDefinition? Find(RulesSnapshot? rules, Guid? filterId, RuleDirection direction) =>
        filterId is { } id && rules is not null
            ? rules.Rules.Select(r => r.Rule).FirstOrDefault(r => r.FilterId == id && r.Kind == RuleKind.Limit
                && r.Direction == direction && r.ExpiresAt is null && r.LimitBytesPerSecond > 0)
            : null;

    public static bool IsLimited(RuleDefinition? rule) => rule is { IsEnabled: true };

    public static double Kilobytes(RuleDefinition? rule) => rule?.LimitBytesPerSecond is { } bps ? bps / 1024.0 : DefaultKilobytes;

    /// <summary>The rule to save to turn the limit on or off, or null when nothing changes.</summary>
    public static RuleDefinition? Toggle(RuleDefinition? existing, Guid filterId, RuleDirection direction, bool enable)
    {
        if (existing is null)
            return enable ? New(filterId, direction, DefaultKilobytes) : null;
        return existing.IsEnabled == enable ? null : existing with { IsEnabled = enable };
    }

    /// <summary>The rule to save for a new value (which also turns the limit on).</summary>
    public static RuleDefinition SetValue(RuleDefinition? existing, Guid filterId, RuleDirection direction, double kilobytes) =>
        existing is null
            ? New(filterId, direction, kilobytes)
            : existing with { IsEnabled = true, LimitBytesPerSecond = ToBytes(kilobytes) };

    /// <summary>Parses what the user typed in a limit cell (KB/s); null if it is not a positive number.</summary>
    public static double? Parse(string? text)
    {
        string t = (text ?? "").Trim();
        if (t.EndsWith("KB/s", StringComparison.OrdinalIgnoreCase))
            t = t[..^4].Trim();
        return double.TryParse(t, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.CurrentCulture, out double v)
               && v > 0 && v <= 100 * 1024 * 1024 ? v : null;
    }

    public static string Format(double kilobytes) => kilobytes.ToString(kilobytes % 1 == 0 ? "0" : "0.##");

    private static RuleDefinition New(Guid filterId, RuleDirection direction, double kilobytes) =>
        new(Guid.Empty, filterId, RuleKind.Limit, direction, LimitBytesPerSecond: ToBytes(kilobytes), Notes: "Quick limit");

    private static long ToBytes(double kilobytes) => Math.Max(1, (long)Math.Round(kilobytes * 1024));
}
