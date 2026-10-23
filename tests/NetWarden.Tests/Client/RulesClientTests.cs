using NetWarden.Client.ViewModels;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;

namespace NetWarden.Tests.Client;

public class RuleTextTests
{
    [Fact]
    public void Describes_functions_filters_and_rule_values()
    {
        System.Globalization.CultureInfo.CurrentCulture = System.Globalization.CultureInfo.InvariantCulture;

        Assert.Equal("Remote port is 80, 443",
            RuleText.Describe(new FilterFunction(FilterFunctionKind.RemotePortInRange, true, ["80", "443"])));
        Assert.Equal("Domain name is not *.ads.com",
            RuleText.Describe(new FilterFunction(FilterFunctionKind.DomainName, false, ["*.ads.com"])));
        Assert.Equal("Remote host is on Internet", RuleText.Describe(new FilterFunction(FilterFunctionKind.IsInternet)));
        Assert.Equal("Any traffic", RuleText.Describe(PredefinedFilters.All[0]));

        Assert.Equal("100 KB/s", RuleText.Value(new RuleDefinition(Guid.Empty, Guid.Empty, RuleKind.Limit, RuleDirection.In, LimitBytesPerSecond: 102400)));
        Assert.Equal("Deny", RuleText.Value(new RuleDefinition(Guid.Empty, Guid.Empty, RuleKind.Firewall, RuleDirection.In, Action: FirewallAction.Deny)));
        Assert.Equal("Ignore limit and data", RuleText.Value(new RuleDefinition(Guid.Empty, Guid.Empty, RuleKind.Ignore, RuleDirection.In, IgnoreLimit: true, IgnoreData: true)));
        Assert.Equal("Blocker", RuleText.Kind(RuleKind.Firewall));
    }
}

public class FilterEditorViewModelTests
{
    [Fact]
    public void Builds_filter_with_values_split_by_lines_and_commas_for_ports()
    {
        var vm = new FilterEditorViewModel(null, PredefinedFilters.All) { Name = "  Web  " };
        vm.AddFunctionCommand.Execute(null);
        vm.Functions[0].Kind = FilterFunctionKind.RemotePortInRange;
        vm.Functions[0].ValuesText = "80, 443\r\n8000 - 8080";
        vm.AddFunctionCommand.Execute(null);
        vm.Functions[1].Kind = FilterFunctionKind.PathEquals;
        vm.Functions[1].Match = false;
        vm.Functions[1].ValuesText = @"C:\a,b\x.exe";

        var filter = vm.Build()!;

        Assert.Equal("Web", filter.Name);
        Assert.Equal(Guid.Empty, filter.Id);
        Assert.Equal(["80", "443", "8000 - 8080"], filter.Functions[0].Values);
        Assert.Equal([@"C:\a,b\x.exe"], filter.Functions[1].Values);
        Assert.False(filter.Functions[1].Match);
    }

    [Fact]
    public void Editing_keeps_id_and_round_trips_functions()
    {
        var original = new FilterDefinition(Guid.NewGuid(), "Games", FilterType.Filter, FilterPerType.PerProcess,
            [new FilterFunction(FilterFunctionKind.PathContains, true, [@"\Steam\", @"\Epic\"])], [], Notes: "n");

        var filter = new FilterEditorViewModel(original, PredefinedFilters.All).Build()!;

        Assert.Equal(original.Id, filter.Id);
        Assert.Equal(FilterPerType.PerProcess, filter.PerType);
        Assert.Equal(original.Functions[0].Values, filter.Functions[0].Values);
        Assert.Equal("n", filter.Notes);
    }

    [Fact]
    public void Zone_functions_have_no_values_and_empty_values_are_rejected()
    {
        var vm = new FilterEditorViewModel(null, PredefinedFilters.All) { Name = "x" };
        vm.AddFunctionCommand.Execute(null);
        vm.Functions[0].Kind = FilterFunctionKind.IsLocalNetwork;
        vm.Functions[0].ValuesText = "ignored";
        Assert.Null(vm.Build()!.Functions[0].Values);

        vm.Functions[0].Kind = FilterFunctionKind.DomainName;
        vm.Functions[0].ValuesText = "  ";
        Assert.Null(vm.Build());
        Assert.Contains("Domain name", vm.Error);
    }

    [Fact]
    public void Composite_needs_a_base_filter_and_offers_only_non_composites()
    {
        var composite = new FilterDefinition(Guid.NewGuid(), "C", FilterType.Composite, FilterPerType.None, [], [PredefinedFilters.Internet]);
        var vm = new FilterEditorViewModel(null, [.. PredefinedFilters.All, composite]) { Name = "x", Type = FilterType.Composite };

        Assert.DoesNotContain(vm.BaseFilters, b => b.Filter.Id == composite.Id);
        Assert.Null(vm.Build());

        vm.BaseFilters.First(b => b.Filter.Id == PredefinedFilters.Internet).IsSelected = true;
        Assert.Equal([PredefinedFilters.Internet], vm.Build()!.BaseFilterIds);
    }

    [Fact]
    public void Name_is_required()
    {
        var vm = new FilterEditorViewModel(null, PredefinedFilters.All);
        Assert.Null(vm.Build());
        Assert.NotNull(vm.Error);
    }
}

public class RuleEditorViewModelTests
{
    [Fact]
    public void Limit_is_entered_in_kilobytes()
    {
        var vm = new RuleEditorViewModel(null, PredefinedFilters.All, PredefinedFilters.Internet) { LimitKilobytes = 1.5 };

        var rule = vm.Build()!;

        Assert.Equal(RuleKind.Limit, rule.Kind);
        Assert.Equal(1536, rule.LimitBytesPerSecond);
        Assert.Equal(PredefinedFilters.Internet, rule.FilterId);
        Assert.Null(rule.Action);
    }

    [Fact]
    public void New_blocker_rule_defaults_to_both_directions_and_deny()
    {
        var rule = new RuleEditorViewModel(null, PredefinedFilters.All, PredefinedFilters.Internet, RuleKind.Firewall).Build()!;

        Assert.Equal(RuleDirection.Both, rule.Direction);
        Assert.Equal(FirewallAction.Deny, rule.Action);
        Assert.Null(rule.LimitBytesPerSecond);
    }

    [Fact]
    public void Editing_preserves_id_and_expiry_and_only_keeps_fields_of_the_kind()
    {
        var expires = DateTimeOffset.UtcNow.AddHours(1);
        var original = new RuleDefinition(Guid.NewGuid(), PredefinedFilters.Loopback, RuleKind.Ignore, RuleDirection.Both,
            IgnoreLimit: true, ExpiresAt: expires);
        var vm = new RuleEditorViewModel(original, PredefinedFilters.All);

        vm.IgnoreData = true;
        var rule = vm.Build()!;

        Assert.Equal(original.Id, rule.Id);
        Assert.Equal(expires, rule.ExpiresAt);
        Assert.True(rule.IgnoreLimit && rule.IgnoreData);
        Assert.Null(rule.LimitBytesPerSecond);
    }

    [Theory]
    [InlineData(RuleKind.Limit)]
    [InlineData(RuleKind.Ignore)]
    public void Invalid_input_sets_error(RuleKind kind)
    {
        var vm = new RuleEditorViewModel(null, PredefinedFilters.All, PredefinedFilters.Internet, kind)
        {
            LimitKilobytes = 0,
            IgnoreLimit = false,
            IgnoreData = false,
        };

        Assert.Null(vm.Build());
        Assert.NotNull(vm.Error);
    }
}

public class RulesViewModelTests
{
    private readonly FakeService _service = new();
    private readonly RulesViewModel _vm;
    private readonly RuleView[] _rules;

    public RulesViewModelTests()
    {
        _rules = PredefinedFilters.DefaultRules
            .Select(r => new RuleView(r, RuleState.Active, 2, "Local network"))
            .Append(new RuleView(new RuleDefinition(Guid.NewGuid(), PredefinedFilters.Internet, RuleKind.Limit, RuleDirection.In,
                IsEnabled: false, LimitBytesPerSecond: 2048), RuleState.Disabled, 2, "Internet"))
            .ToArray();
        _service.Handler = (method, _) => method switch
        {
            Methods.RulesGet => new RulesSnapshot(7, PredefinedFilters.All, _rules),
            _ => true,
        };
        _vm = new RulesViewModel(_service);
    }

    [Fact]
    public async Task Reload_fills_lists_and_counts_rules_per_filter()
    {
        await _vm.ReloadAsync();

        Assert.Equal(3, _vm.Rules.Count);
        Assert.Equal(4, _vm.Filters.Count);
        Assert.Equal(1, _vm.Filters.Single(f => f.Filter.Id == PredefinedFilters.Internet).RuleCount);
        Assert.Equal("Disabled", _vm.Rules[2].State);
    }

    [Fact]
    public async Task Known_generation_skips_reload()
    {
        await _vm.ReloadAsync();
        _service.Calls.Clear();

        await _vm.ReloadAsync(7);
        Assert.Empty(_service.Calls);

        await _vm.ReloadAsync(8);
        Assert.Single(_service.Calls);
    }

    [Fact]
    public async Task Selection_survives_reload()
    {
        await _vm.ReloadAsync();
        _vm.SelectedRule = _vm.Rules[1];

        await _vm.ReloadAsync(99);

        Assert.Equal(_rules[1].Rule.Id, _vm.SelectedRule!.Rule.Id);
    }

    [Fact]
    public async Task Move_down_sends_swapped_order()
    {
        await _vm.ReloadAsync();

        await _vm.MoveDownCommand.ExecuteAsync(_vm.Rules[0]);

        var request = (ReorderRulesRequest)_service.Calls.Single(c => c.Method == Methods.RulesReorder).Payload!;
        Assert.Equal([_rules[1].Rule.Id, _rules[0].Rule.Id, _rules[2].Rule.Id], request.RuleIds);
    }

    [Fact]
    public async Task Move_beyond_edges_does_nothing()
    {
        await _vm.ReloadAsync();
        _service.Calls.Clear();

        await _vm.MoveUpCommand.ExecuteAsync(_vm.Rules[0]);
        await _vm.MoveDownCommand.ExecuteAsync(_vm.Rules[2]);

        Assert.Empty(_service.Calls);
    }

    [Fact]
    public async Task Toggle_flips_enabled_state()
    {
        await _vm.ReloadAsync();

        await _vm.ToggleEnabledCommand.ExecuteAsync(_vm.Rules[2]);

        var request = (SetRuleEnabledRequest)_service.Calls.Single(c => c.Method == Methods.RulesSetEnabled).Payload!;
        Assert.True(request.IsEnabled);
    }

    [Fact]
    public async Task Service_validation_errors_are_shown_and_save_reports_failure()
    {
        _service.Handler = (method, _) => method == Methods.RulesSave
            ? new IpcRemoteException(Methods.RulesSave, "A limit must be greater than zero.")
            : new RulesSnapshot(1, PredefinedFilters.All, []);

        bool ok = await _vm.SaveRuleAsync(new RuleDefinition(Guid.Empty, PredefinedFilters.Internet, RuleKind.Limit, RuleDirection.In));

        Assert.False(ok);
        Assert.Equal("A limit must be greater than zero.", _vm.LastError);
    }
}
