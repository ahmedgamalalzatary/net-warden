using NetWarden.Client.ViewModels;
using NetWarden.Shared.Contracts;

namespace NetWarden.Tests.Client;

public class QuickLimitTests
{
    private static readonly Guid Filter = Guid.NewGuid();

    private static RulesSnapshot With(params RuleDefinition[] rules) =>
        new(1, PredefinedFilters.All, rules.Select(r => new RuleView(r, RuleState.Active, 3, "f")).ToList());

    private static RuleDefinition Limit(RuleDirection dir, long bps = 51200, bool enabled = true) =>
        new(Guid.NewGuid(), Filter, RuleKind.Limit, dir, IsEnabled: enabled, LimitBytesPerSecond: bps);

    [Fact]
    public void Finds_the_permanent_limit_for_the_exact_direction()
    {
        var down = Limit(RuleDirection.In);
        var temporary = Limit(RuleDirection.Out) with { ExpiresAt = DateTimeOffset.UtcNow.AddHours(1) };
        var snapshot = With(down, temporary, Limit(RuleDirection.Both));

        Assert.Same(down, QuickLimit.Find(snapshot, Filter, RuleDirection.In));
        Assert.Null(QuickLimit.Find(snapshot, Filter, RuleDirection.Out));
        Assert.Null(QuickLimit.Find(snapshot, null, RuleDirection.In));
    }

    [Fact]
    public void Toggle_creates_enables_or_disables_keeping_the_value()
    {
        var created = QuickLimit.Toggle(null, Filter, RuleDirection.In, enable: true)!;
        Assert.Equal((RuleKind.Limit, RuleDirection.In, 100 * 1024L, true), (created.Kind, created.Direction, created.LimitBytesPerSecond!.Value, created.IsEnabled));
        Assert.Null(QuickLimit.Toggle(null, Filter, RuleDirection.In, enable: false));

        var on = Limit(RuleDirection.Out, 20480);
        var off = QuickLimit.Toggle(on, Filter, RuleDirection.Out, enable: false)!;
        Assert.Equal((on.Id, false, 20480L), (off.Id, off.IsEnabled, off.LimitBytesPerSecond!.Value));
        Assert.Null(QuickLimit.Toggle(on, Filter, RuleDirection.Out, enable: true));
    }

    [Fact]
    public void Setting_a_value_turns_the_limit_on()
    {
        var off = Limit(RuleDirection.In, enabled: false);

        var rule = QuickLimit.SetValue(off, Filter, RuleDirection.In, 12.5);

        Assert.Equal((off.Id, true, 12800L), (rule.Id, rule.IsEnabled, rule.LimitBytesPerSecond!.Value));
        Assert.Equal(Guid.Empty, QuickLimit.SetValue(null, Filter, RuleDirection.In, 5).Id);
    }

    [Theory]
    [InlineData("250", 250.0)]
    [InlineData(" 40 KB/s", 40.0)]
    [InlineData("0", null)]
    [InlineData("-5", null)]
    [InlineData("fast", null)]
    [InlineData("", null)]
    public void Parses_typed_values(string text, double? expected)
    {
        Assert.Equal(expected, QuickLimit.Parse(text));
    }

    [Fact]
    public void Formats_whole_and_fractional_values()
    {
        Assert.Equal("100", QuickLimit.Format(100));
        Assert.Equal(12.5.ToString("0.##"), QuickLimit.Format(12.5));
        Assert.Equal("100", QuickLimit.Format(QuickLimit.Kilobytes(null)));
    }
}
