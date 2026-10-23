using NetWarden.Client.ViewModels;
using NetWarden.Shared.Contracts;

namespace NetWarden.Tests.Client;

public class QuickPriorityTests
{
    private static readonly Guid Filter = Guid.NewGuid();

    private static RulesSnapshot With(params RuleDefinition[] rules) =>
        new(1, PredefinedFilters.All, rules.Select(r => new RuleView(r, RuleState.Active, 3, "f")).ToList());

    private static RuleDefinition Rule(PriorityLevel level, RuleDirection dir = RuleDirection.Both, bool enabled = true) =>
        new(Guid.NewGuid(), Filter, RuleKind.Priority, dir, IsEnabled: enabled, Priority: level);

    [Fact]
    public void Finds_the_permanent_both_directions_rule()
    {
        var quick = Rule(PriorityLevel.High);
        var snapshot = With(Rule(PriorityLevel.Low, RuleDirection.In), Rule(PriorityLevel.Low) with { ExpiresAt = DateTimeOffset.UtcNow.AddHours(1) }, quick);

        Assert.Same(quick, QuickPriority.Find(snapshot, Filter));
        Assert.Null(QuickPriority.Find(snapshot, null));
        Assert.Null(QuickPriority.Find(With(), Filter));
    }

    [Fact]
    public void Level_is_normal_without_an_enabled_rule()
    {
        Assert.Equal(PriorityLevel.Normal, QuickPriority.Level(null));
        Assert.Equal(PriorityLevel.Normal, QuickPriority.Level(Rule(PriorityLevel.Critical, enabled: false)));
        Assert.Equal(PriorityLevel.Critical, QuickPriority.Level(Rule(PriorityLevel.Critical)));
    }

    [Fact]
    public void Plan_creates_changes_or_deletes()
    {
        var (created, none) = QuickPriority.Plan(null, Filter, PriorityLevel.Low);
        Assert.Equal((RuleKind.Priority, RuleDirection.Both, PriorityLevel.Low), (created!.Kind, created.Direction, created.Priority!.Value));
        Assert.Null(none);

        Assert.Equal((null, null), QuickPriority.Plan(null, Filter, PriorityLevel.Normal));

        var existing = Rule(PriorityLevel.Low, enabled: false);
        var (changed, _) = QuickPriority.Plan(existing, Filter, PriorityLevel.High);
        Assert.Equal((existing.Id, true, PriorityLevel.High), (changed!.Id, changed.IsEnabled, changed.Priority!.Value));

        Assert.Equal((null, existing.Id), QuickPriority.Plan(existing, Filter, PriorityLevel.Normal));
        var on = Rule(PriorityLevel.High);
        Assert.Equal((null, null), QuickPriority.Plan(on, Filter, PriorityLevel.High));
    }

    [Fact]
    public void Rule_editor_builds_priority_rules()
    {
        var vm = new RuleEditorViewModel(null, PredefinedFilters.All, PredefinedFilters.Internet, RuleKind.Priority) { Priority = PriorityLevel.Critical };

        var rule = vm.Build()!;

        Assert.Equal((RuleKind.Priority, PriorityLevel.Critical), (rule.Kind, rule.Priority!.Value));
        Assert.True(vm.IsPriority);
        Assert.Equal("Critical", RuleText.Value(rule));
        vm.Kind = RuleKind.Limit;
        Assert.Null(vm.Build()!.Priority);
    }
}
