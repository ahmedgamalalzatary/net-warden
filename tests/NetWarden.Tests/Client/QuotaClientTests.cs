using NetWarden.Client.ViewModels;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;

namespace NetWarden.Tests.Client;

public class QuotaEditorTests
{
    private static RuleEditorViewModel New(RuleDefinition? original = null, IReadOnlyList<RuleView>? rules = null) =>
        new(original, PredefinedFilters.All, PredefinedFilters.Internet, RuleKind.Quota, rules);

    private static RuleView View(RuleDefinition rule) => new(rule, RuleState.Disabled, 3, "Internet");

    [Theory]
    [InlineData(QuotaUnit.Megabytes, 2, 2L * 1024 * 1024)]
    [InlineData(QuotaUnit.Gigabytes, 1.5, 1610612736L)]
    [InlineData(QuotaUnit.Megabits, 8, 1024L * 1024)]
    public void Amount_and_unit_become_bytes(QuotaUnit unit, double amount, long bytes)
    {
        var vm = New();
        vm.QuotaAmount = amount;
        vm.QuotaUnit = unit;

        Assert.Equal(bytes, vm.Build()!.QuotaBytes);
    }

    [Fact]
    public void Quota_must_be_positive()
    {
        var vm = New();
        vm.QuotaAmount = 0;

        Assert.Null(vm.Build());
        Assert.NotNull(vm.Error);
    }

    [Fact]
    public void Never_resets_by_default()
    {
        Assert.Null(New().Build()!.QuotaReset);
    }

    [Fact]
    public void Builds_a_day_of_month_reset_with_time()
    {
        var vm = New();
        vm.ResetRepeat = QuotaResetRepeat.DayOfMonth;
        vm.ResetDayOfMonth = 15;
        vm.ResetTime = "06:30";

        Assert.Equal(new TimeSchedule(ScheduleRepeat.DayOfMonth, 390, DayOfMonth: 15), vm.Build()!.QuotaReset);
    }

    [Fact]
    public void Builds_a_selected_days_reset_and_needs_a_day()
    {
        var vm = New();
        vm.ResetRepeat = QuotaResetRepeat.Days;
        Assert.Null(vm.Build());

        vm.ResetDays.Single(d => d.Day == DayOfWeek.Friday).IsSelected = true;

        Assert.Equal([DayOfWeek.Friday], vm.Build()!.QuotaReset!.Days);
    }

    [Fact]
    public void Once_needs_a_date()
    {
        var vm = New();
        vm.ResetRepeat = QuotaResetRepeat.Once;
        Assert.Null(vm.Build());

        vm.ResetDate = new DateTime(2026, 11, 1);

        Assert.Equal(new DateOnly(2026, 11, 1), vm.Build()!.QuotaReset!.Date);
    }

    [Theory]
    [InlineData("25:00")]
    [InlineData("soon")]
    public void Bad_reset_time_is_rejected(string time)
    {
        var vm = New();
        vm.ResetRepeat = QuotaResetRepeat.EveryDay;
        vm.ResetTime = time;

        Assert.Null(vm.Build());
    }

    [Fact]
    public void Editing_round_trips_every_quota_field()
    {
        var target = new RuleDefinition(Guid.NewGuid(), PredefinedFilters.Internet, RuleKind.Firewall, RuleDirection.Both, false, Action: FirewallAction.Deny);
        var original = new RuleDefinition(Guid.NewGuid(), PredefinedFilters.Internet, RuleKind.Quota, RuleDirection.In,
            QuotaBytes: 3L * 1024 * 1024 * 1024, QuotaReset: new TimeSchedule(ScheduleRepeat.Days, 90, Days: [DayOfWeek.Monday]),
            OverflowRuleIds: [target.Id], OverflowAlert: true, OverflowKillConnections: true);

        var rule = New(original, [View(target), View(original)]).Build()!;

        Assert.Equal(original.QuotaBytes, rule.QuotaBytes);
        Assert.Equal(90, rule.QuotaReset!.MinuteOfDay);
        Assert.Equal([DayOfWeek.Monday], rule.QuotaReset.Days);
        Assert.Equal([target.Id], rule.OverflowRuleIds);
        Assert.True(rule.OverflowAlert);
        Assert.True(rule.OverflowKillConnections);
    }

    [Fact]
    public void Overflow_choices_leave_out_the_quota_itself_and_unselected_rules()
    {
        var other = new RuleDefinition(Guid.NewGuid(), PredefinedFilters.Internet, RuleKind.Limit, RuleDirection.In, false, LimitBytesPerSecond: 1024);
        var original = new RuleDefinition(Guid.NewGuid(), PredefinedFilters.Internet, RuleKind.Quota, RuleDirection.In, QuotaBytes: 5);

        var vm = New(original, [View(other), View(original)]);

        Assert.Equal([other.Id], vm.OverflowChoices.Select(c => c.Rule.Id));
        Assert.Empty(vm.Build()!.OverflowRuleIds ?? []);
    }

    [Fact]
    public async Task Add_block_rule_creates_a_disabled_deny_rule_and_selects_it()
    {
        RuleDefinition? created = null;
        var vm = New();
        vm.CreateRule = r =>
        {
            created = r with { Id = Guid.NewGuid() };
            return Task.FromResult<RuleDefinition?>(created);
        };

        await vm.AddBlockRuleCommand.ExecuteAsync(null);

        Assert.NotNull(created);
        Assert.Equal((RuleKind.Firewall, FirewallAction.Deny, false, PredefinedFilters.Internet, RuleDirection.Both),
            (created!.Kind, created.Action, created.IsEnabled, created.FilterId, created.Direction));
        Assert.Equal([created.Id], vm.Build()!.OverflowRuleIds);
    }

    [Fact]
    public async Task Add_limit_rule_uses_the_typed_speed_and_the_quota_direction()
    {
        RuleDefinition? created = null;
        var vm = New();
        vm.Direction = RuleDirection.In;
        vm.OverflowLimitKilobytes = 50;
        vm.CreateRule = r =>
        {
            created = r with { Id = Guid.NewGuid() };
            return Task.FromResult<RuleDefinition?>(created);
        };

        await vm.AddLimitRuleCommand.ExecuteAsync(null);

        Assert.Equal((RuleKind.Limit, 51200L, false, RuleDirection.In),
            (created!.Kind, created.LimitBytesPerSecond, created.IsEnabled, created.Direction));
    }

    [Fact]
    public void Rule_text_shows_size_of_a_quota()
    {
        System.Globalization.CultureInfo.CurrentCulture = System.Globalization.CultureInfo.InvariantCulture;
        Assert.Equal("2 MB", RuleText.Value(new RuleDefinition(Guid.Empty, Guid.Empty, RuleKind.Quota, RuleDirection.In, QuotaBytes: 2L * 1024 * 1024)));
    }
}

public class QuotasViewModelTests
{
    private static readonly Guid Id = Guid.NewGuid();

    private static QuotaStatus Status(long used, long limit = 1000, DateTimeOffset? overflowed = null, bool enabled = true) =>
        new(Id, Guid.NewGuid(), "Browser", RuleDirection.Both, enabled, used, limit, null, null, overflowed);

    private static FakeService Service(params QuotaStatus[] statuses)
    {
        var service = new FakeService();
        service.Handler = (method, _) => method switch
        {
            Methods.QuotasStatus => statuses.ToList(),
            Methods.QuotasReset or Methods.QuotasInitFromStats => true,
            _ => null,
        };
        return service;
    }

    [Fact]
    public async Task Refresh_shows_usage_share_and_state()
    {
        System.Globalization.CultureInfo.CurrentCulture = System.Globalization.CultureInfo.InvariantCulture;
        var vm = new QuotasViewModel(Service(Status(250)));

        await vm.RefreshAsync();

        var row = Assert.Single(vm.Rows);
        Assert.Equal(0.25, row.Share);
        Assert.Equal("Browser", row.Name);
        Assert.Equal("Counting", row.State);
        Assert.Equal("Never", row.NextReset);
    }

    [Fact]
    public void State_and_share_follow_the_status()
    {
        Assert.Equal("Exceeded", new QuotaRow(Status(2000, overflowed: DateTimeOffset.UtcNow)).State);
        Assert.Equal(1, new QuotaRow(Status(2000, overflowed: DateTimeOffset.UtcNow)).Share);
        Assert.Equal("Off", new QuotaRow(Status(0, enabled: false)).State);
    }

    [Fact]
    public async Task Refresh_keeps_the_selected_quota()
    {
        long used = 250;
        var service = new FakeService { Handler = (_, _) => new List<QuotaStatus> { Status(used) } };
        var vm = new QuotasViewModel(service);
        await vm.RefreshAsync();
        vm.Selected = vm.Rows[0];

        used = 300;
        await vm.RefreshAsync();

        Assert.Equal(300, vm.Selected!.Status.Used);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Reset_and_init_call_the_service_for_the_row(bool reset)
    {
        var service = Service(Status(250));
        var vm = new QuotasViewModel(service);
        await vm.RefreshAsync();

        if (reset)
            await vm.ResetCommand.ExecuteAsync(vm.Rows[0]);
        else
            await vm.InitFromStatsCommand.ExecuteAsync(vm.Rows[0]);

        var (method, payload) = service.Calls.Single(r => r.Method is Methods.QuotasReset or Methods.QuotasInitFromStats);
        Assert.Equal(reset ? Methods.QuotasReset : Methods.QuotasInitFromStats, method);
        Assert.Equal(new QuotaRequest(Id), payload);
    }
}
