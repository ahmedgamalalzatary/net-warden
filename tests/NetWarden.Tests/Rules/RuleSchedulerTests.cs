using Microsoft.Extensions.Time.Testing;
using NetWarden.Client.ViewModels;
using NetWarden.Core.Rules;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Storage;

namespace NetWarden.Tests.Rules;

public sealed class RuleSchedulerTests : IDisposable
{
    private readonly TempDir _dir = new();
    // 2026-10-30 is a Friday.
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 10, 30, 12, 0, 0, TimeSpan.Zero));
    private readonly RuleRepository _rules;
    private readonly List<Guid> _resets = [];
    private RuleScheduler _scheduler;

    public RuleSchedulerTests()
    {
        _rules = new RuleRepository(new JsonFileStore<RulesDocument>(_dir.File("rules.json")), new ZoneClassifier([]), _time);
        _scheduler = NewScheduler();
        _scheduler.Tick();
    }

    public void Dispose() => _dir.Dispose();

    private RuleScheduler NewScheduler() =>
        new(_rules, new JsonFileStore<SchedulerState>(_dir.File("scheduler.json")), _time, TimeZoneInfo.Utc, _resets.Add);

    private static TimeSchedule Daily(int hour, int minute = 0) => new(ScheduleRepeat.EveryDay, hour * 60 + minute);

    private RuleDefinition Rule(bool enabled, params ScheduleCondition[] conditions) =>
        _rules.SaveRule(new RuleDefinition(Guid.Empty, PredefinedFilters.Internet, RuleKind.Limit, RuleDirection.In, enabled,
            LimitBytesPerSecond: 1024, Schedule: conditions));

    private RuleDefinition? Find(Guid id) => _rules.Snapshot().Rules.FirstOrDefault(r => r.Rule.Id == id)?.Rule;

    [Fact]
    public void Start_enables_and_stop_disables_at_their_moments()
    {
        var rule = Rule(false, new ScheduleCondition(ScheduleAction.Start, Daily(13)), new ScheduleCondition(ScheduleAction.Stop, Daily(14)));

        _time.Advance(TimeSpan.FromMinutes(59));
        _scheduler.Tick();
        Assert.False(Find(rule.Id)!.IsEnabled);

        _time.Advance(TimeSpan.FromMinutes(1));
        _scheduler.Tick();
        Assert.True(Find(rule.Id)!.IsEnabled);

        _time.Advance(TimeSpan.FromHours(1));
        _scheduler.Tick();
        Assert.False(Find(rule.Id)!.IsEnabled);
    }

    [Fact]
    public void A_moment_fires_once_so_a_manual_change_afterwards_sticks()
    {
        var rule = Rule(false, new ScheduleCondition(ScheduleAction.Start, Daily(13)));
        _time.Advance(TimeSpan.FromHours(1));
        _scheduler.Tick();

        _rules.SetEnabled(rule.Id, false);
        _time.Advance(TimeSpan.FromSeconds(1));
        _scheduler.Tick();

        Assert.False(Find(rule.Id)!.IsEnabled);
    }

    [Fact]
    public void Moments_before_the_rule_was_scheduled_do_not_fire()
    {
        var rule = Rule(false, new ScheduleCondition(ScheduleAction.Start, Daily(8)));

        _time.Advance(TimeSpan.FromSeconds(1));
        _scheduler.Tick();

        Assert.False(Find(rule.Id)!.IsEnabled);
    }

    [Fact]
    public void Disabled_condition_does_nothing()
    {
        var rule = Rule(false, new ScheduleCondition(ScheduleAction.Start, Daily(13), IsEnabled: false));

        _time.Advance(TimeSpan.FromHours(2));
        _scheduler.Tick();

        Assert.False(Find(rule.Id)!.IsEnabled);
    }

    [Fact]
    public void Delete_removes_the_rule()
    {
        var rule = Rule(true, new ScheduleCondition(ScheduleAction.Delete, Daily(13)));

        _time.Advance(TimeSpan.FromHours(2));
        _scheduler.Tick();

        Assert.Null(Find(rule.Id));
    }

    [Fact]
    public void Reset_calls_back_for_the_quota()
    {
        var quota = _rules.SaveRule(new RuleDefinition(Guid.Empty, PredefinedFilters.Internet, RuleKind.Quota, RuleDirection.In, QuotaBytes: 10,
            Schedule: [new ScheduleCondition(ScheduleAction.Reset, Daily(13))]));

        _time.Advance(TimeSpan.FromHours(2));
        _scheduler.Tick();

        Assert.Equal([quota.Id], _resets);
    }

    [Fact]
    public void Moments_missed_while_stopped_apply_on_start_in_order()
    {
        var rule = Rule(false, new ScheduleCondition(ScheduleAction.Stop, Daily(14)), new ScheduleCondition(ScheduleAction.Start, Daily(13)));
        _scheduler.Save();

        // Off from 12:00 to 15:00: Start at 13:00 and Stop at 14:00 both passed; Stop is the later one.
        _time.Advance(TimeSpan.FromHours(3));
        _scheduler = NewScheduler();
        _rules.SetEnabled(rule.Id, true);
        _scheduler.Tick();

        Assert.False(Find(rule.Id)!.IsEnabled);
    }

    [Fact]
    public void Clock_moved_back_fires_nothing()
    {
        var rule = Rule(false, new ScheduleCondition(ScheduleAction.Start, Daily(11)));
        var clock = new SettableClock { Now = _time.GetUtcNow() };
        var scheduler = new RuleScheduler(_rules, new JsonFileStore<SchedulerState>(_dir.File("clock.json")), clock, TimeZoneInfo.Utc, _resets.Add);
        scheduler.Tick();

        clock.Now = clock.Now.AddHours(-2);
        scheduler.Tick();

        Assert.False(Find(rule.Id)!.IsEnabled);
    }

    private sealed class SettableClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; }
        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Fact]
    public void First_run_ever_does_not_replay_the_past()
    {
        var rule = Rule(false, new ScheduleCondition(ScheduleAction.Start, Daily(8)));
        File.Delete(_dir.File("scheduler.json"));

        _scheduler = NewScheduler();
        _scheduler.Tick();

        Assert.False(Find(rule.Id)!.IsEnabled);
    }
}

public sealed class ScheduleValidationTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly RuleRepository _rules;

    public ScheduleValidationTests() =>
        _rules = new RuleRepository(new JsonFileStore<RulesDocument>(_dir.File("rules.json")), new ZoneClassifier([]), TimeProvider.System);

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void Reset_condition_is_only_for_quotas() =>
        Assert.Throws<RuleValidationException>(() => _rules.SaveRule(new RuleDefinition(Guid.Empty, PredefinedFilters.Internet, RuleKind.Limit, RuleDirection.In,
            LimitBytesPerSecond: 1, Schedule: [new ScheduleCondition(ScheduleAction.Reset, new TimeSchedule(ScheduleRepeat.EveryDay))])));

    [Fact]
    public void Bad_condition_schedule_is_rejected() =>
        Assert.Throws<RuleValidationException>(() => _rules.SaveRule(new RuleDefinition(Guid.Empty, PredefinedFilters.Internet, RuleKind.Limit, RuleDirection.In,
            LimitBytesPerSecond: 1, Schedule: [new ScheduleCondition(ScheduleAction.Start, new TimeSchedule(ScheduleRepeat.Once))])));
}

public class ScheduleEditorTests
{
    private static RuleEditorViewModel New(RuleDefinition? original = null) =>
        new(original, PredefinedFilters.All, PredefinedFilters.Internet, RuleKind.Limit);

    [Fact]
    public void Added_condition_is_built_into_the_rule()
    {
        var vm = New();
        vm.AddConditionCommand.Execute(null);
        vm.Conditions[0].Action = ScheduleAction.Stop;
        vm.Conditions[0].Repeat = ScheduleRepeat.DayOfMonth;
        vm.Conditions[0].DayOfMonth = 3;
        vm.Conditions[0].Time = "22:15";

        var condition = Assert.Single(vm.Build()!.Schedule!);

        Assert.Equal(ScheduleAction.Stop, condition.Action);
        Assert.Equal(new TimeSchedule(ScheduleRepeat.DayOfMonth, 22 * 60 + 15, DayOfMonth: 3), condition.When);
        Assert.True(condition.IsEnabled);
    }

    [Fact]
    public void Incomplete_condition_blocks_saving()
    {
        var vm = New();
        vm.AddConditionCommand.Execute(null);
        vm.Conditions[0].Repeat = ScheduleRepeat.Days;

        Assert.Null(vm.Build());
        Assert.NotNull(vm.Error);
    }

    [Fact]
    public void Removed_condition_is_gone()
    {
        var vm = New();
        vm.AddConditionCommand.Execute(null);
        vm.RemoveConditionCommand.Execute(vm.Conditions[0]);

        Assert.Empty(vm.Build()!.Schedule ?? []);
    }

    [Fact]
    public void Editing_round_trips_conditions()
    {
        var original = new RuleDefinition(Guid.NewGuid(), PredefinedFilters.Internet, RuleKind.Limit, RuleDirection.In, LimitBytesPerSecond: 1024,
            Schedule:
            [
                new ScheduleCondition(ScheduleAction.Start, new TimeSchedule(ScheduleRepeat.Days, 480, Days: [DayOfWeek.Monday]), IsEnabled: false),
                new ScheduleCondition(ScheduleAction.Delete, new TimeSchedule(ScheduleRepeat.Once, 0, new DateOnly(2027, 1, 1))),
            ]);

        var schedule = New(original).Build()!.Schedule!;

        Assert.Equal(ScheduleAction.Start, schedule[0].Action);
        Assert.False(schedule[0].IsEnabled);
        Assert.Equal([DayOfWeek.Monday], schedule[0].When.Days);
        Assert.Equal(480, schedule[0].When.MinuteOfDay);
        Assert.Equal(new DateOnly(2027, 1, 1), schedule[1].When.Date);
    }

    [Fact]
    public void Rule_list_summarises_the_schedule()
    {
        var rule = new RuleDefinition(Guid.Empty, Guid.Empty, RuleKind.Limit, RuleDirection.In, Schedule:
        [
            new ScheduleCondition(ScheduleAction.Start, new TimeSchedule(ScheduleRepeat.EveryDay, 480)),
            new ScheduleCondition(ScheduleAction.Stop, new TimeSchedule(ScheduleRepeat.Days, 1020, Days: [DayOfWeek.Monday, DayOfWeek.Friday])),
            new ScheduleCondition(ScheduleAction.Delete, new TimeSchedule(ScheduleRepeat.DayOfMonth, 0, DayOfMonth: 5), IsEnabled: false),
        ]);

        Assert.Equal("Start every day 08:00; Stop Mon, Fri 17:00", RuleText.Schedule(rule));
    }
}
