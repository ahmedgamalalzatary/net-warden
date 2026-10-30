using System.Net;
using Microsoft.Extensions.Time.Testing;
using NetWarden.Core.Apps;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Quotas;
using NetWarden.Core.Rules;
using NetWarden.Core.Stats;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Storage;

namespace NetWarden.Tests.Quotas;

public class TimeSchedulesTests
{
    // UTC+2, no daylight saving.
    private static readonly TimeZoneInfo Zone = TimeZoneInfo.CreateCustomTimeZone("t", TimeSpan.FromHours(2), "t", "t");

    private static DateTimeOffset Local(int y, int mo, int d, int h = 0, int mi = 0) => new(y, mo, d, h, mi, 0, TimeSpan.FromHours(2));

    [Fact]
    public void Every_day_uses_the_time_of_day()
    {
        var at0630 = new TimeSchedule(ScheduleRepeat.EveryDay, MinuteOfDay: 390);

        Assert.Equal(Local(2026, 10, 29, 6, 30), TimeSchedules.Last(at0630, Local(2026, 10, 30, 6, 29), Zone));
        Assert.Equal(Local(2026, 10, 30, 6, 30), TimeSchedules.Next(at0630, Local(2026, 10, 30, 6, 29), Zone));
        Assert.Equal(Local(2026, 10, 30, 6, 30), TimeSchedules.Last(at0630, Local(2026, 10, 30, 6, 30), Zone));
        Assert.Equal(Local(2026, 10, 31, 6, 30), TimeSchedules.Next(at0630, Local(2026, 10, 30, 6, 30), Zone));
    }

    [Fact]
    public void Selected_days_skip_the_others()
    {
        // 2026-10-30 is a Friday.
        var schedule = new TimeSchedule(ScheduleRepeat.Days, Days: [DayOfWeek.Monday, DayOfWeek.Wednesday]);

        Assert.Equal(Local(2026, 10, 28), TimeSchedules.Last(schedule, Local(2026, 10, 30, 12), Zone));
        Assert.Equal(Local(2026, 11, 2), TimeSchedules.Next(schedule, Local(2026, 10, 30, 12), Zone));
    }

    [Fact]
    public void Day_of_month_crosses_month_and_year()
    {
        var schedule = new TimeSchedule(ScheduleRepeat.DayOfMonth, DayOfMonth: 15);

        Assert.Equal(Local(2026, 10, 15), TimeSchedules.Last(schedule, Local(2026, 10, 30), Zone));
        Assert.Equal(Local(2026, 11, 15), TimeSchedules.Next(schedule, Local(2026, 10, 30), Zone));
        Assert.Equal(Local(2025, 12, 15), TimeSchedules.Last(schedule, Local(2026, 1, 3), Zone));
    }

    [Fact]
    public void Day_of_month_is_clamped_to_short_months()
    {
        var schedule = new TimeSchedule(ScheduleRepeat.DayOfMonth, DayOfMonth: 31);

        Assert.Equal(Local(2026, 2, 28), TimeSchedules.Last(schedule, Local(2026, 3, 10), Zone));
        Assert.Equal(Local(2026, 3, 31), TimeSchedules.Next(schedule, Local(2026, 3, 10), Zone));
    }

    [Fact]
    public void Once_happens_only_on_its_date()
    {
        var schedule = new TimeSchedule(ScheduleRepeat.Once, MinuteOfDay: 60, Date: new DateOnly(2026, 11, 1));

        Assert.Null(TimeSchedules.Last(schedule, Local(2026, 10, 30), Zone));
        Assert.Equal(Local(2026, 11, 1, 1), TimeSchedules.Next(schedule, Local(2026, 10, 30), Zone));
        Assert.Equal(Local(2026, 11, 1, 1), TimeSchedules.Last(schedule, Local(2026, 12, 25), Zone));
        Assert.Null(TimeSchedules.Next(schedule, Local(2026, 12, 25), Zone));
    }
}

public sealed class QuotaTrackerTests : IDisposable
{
    private static readonly AppInfo Browser = new("c:\\browser.exe", AppKind.Desktop, "c:\\browser.exe", "Browser", null, null, null, [], null);
    private static readonly AppInfo Game = new("c:\\game.exe", AppKind.Desktop, "c:\\game.exe", "Game", null, null, null, [], null);
    private static readonly TimeZoneInfo Zone = TimeZoneInfo.Utc;

    private readonly TempDir _dir = new();
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 10, 30, 12, 0, 0, TimeSpan.Zero));
    private readonly RuleRepository _rules;
    private readonly FlowContextFactory _flows;
    private readonly List<QuotaAlert> _exceeded = [];
    private QuotaTracker _tracker;
    private readonly Guid _browserFilter;

    public QuotaTrackerTests()
    {
        _rules = new RuleRepository(new JsonFileStore<RulesDocument>(_dir.File("rules.json")), new ZoneClassifier([]), _time);
        var apps = new Dictionary<int, AppInfo> { [100] = Browser, [200] = Game };
        _flows = new FlowContextFactory(pid => apps.GetValueOrDefault(pid), _ => null, new DnsMap());
        _browserFilter = _rules.EnsureAppFilter(Browser.Id, "Browser").Id;
        _tracker = NewTracker();
    }

    public void Dispose() => _dir.Dispose();

    private QuotaTracker NewTracker()
    {
        var tracker = new QuotaTracker(_rules, _flows, new JsonFileStore<QuotaDocument>(_dir.File("quotas.json")), _time, Zone);
        tracker.Exceeded += (_, alert) => _exceeded.Add(alert);
        return tracker;
    }

    private RuleDefinition Quota(long bytes, RuleDirection direction = RuleDirection.Both, TimeSchedule? reset = null,
        IReadOnlyList<Guid>? overflow = null) =>
        _rules.SaveRule(new RuleDefinition(Guid.Empty, _browserFilter, RuleKind.Quota, direction,
            QuotaBytes: bytes, QuotaReset: reset, OverflowRuleIds: overflow));

    private RuleDefinition DisabledBlock() =>
        _rules.SaveRule(new RuleDefinition(Guid.Empty, _browserFilter, RuleKind.Firewall, RuleDirection.Both, IsEnabled: false, Action: FirewallAction.Deny));

    private FlowTraffic Traffic(long bytesIn, long bytesOut, int pid = 100) =>
        new(pid == 100 ? Browser : Game, pid, TransportProtocol.Tcp, ConnectionKind.Connect,
            IPAddress.Parse("192.168.1.14"), 50000, IPAddress.Parse("8.8.8.8"), 443, bytesIn, bytesOut, _time.GetUtcNow());

    private bool IsEnabled(Guid rule) => _rules.Snapshot().Rules.Single(r => r.Rule.Id == rule).Rule.IsEnabled;

    private QuotaStatus StatusOf(RuleDefinition quota) => _tracker.Status().Single(s => s.RuleId == quota.Id);

    [Theory]
    [InlineData(RuleDirection.In, 100)]
    [InlineData(RuleDirection.Out, 30)]
    [InlineData(RuleDirection.Both, 130)]
    public void Counts_the_rules_direction(RuleDirection direction, long expected)
    {
        var quota = Quota(1000, direction);

        _tracker.Add([Traffic(100, 30)]);

        Assert.Equal(expected, StatusOf(quota).Used);
    }

    [Fact]
    public void Traffic_outside_the_filter_is_not_counted()
    {
        var quota = Quota(1000);

        _tracker.Add([Traffic(100, 30, pid: 200)]);

        Assert.Equal(0, StatusOf(quota).Used);
    }

    [Fact]
    public void Ignore_data_rule_keeps_traffic_out_of_the_quota()
    {
        var quota = Quota(1000);
        _rules.SaveRule(new RuleDefinition(Guid.Empty, _browserFilter, RuleKind.Ignore, RuleDirection.Both, IgnoreData: true));

        _tracker.Add([Traffic(100, 30)]);

        Assert.Equal(0, StatusOf(quota).Used);
    }

    [Fact]
    public void Disabled_quota_does_not_count()
    {
        var quota = Quota(1000);
        _rules.SetEnabled(quota.Id, false);

        _tracker.Add([Traffic(100, 30)]);

        Assert.Equal(0, StatusOf(quota).Used);
    }

    [Fact]
    public void Overflow_enables_target_rules_and_raises_exceeded_once()
    {
        var block = DisabledBlock();
        var quota = Quota(100, overflow: [block.Id]);

        _tracker.Add([Traffic(99, 0)]);
        _tracker.Tick();
        Assert.False(IsEnabled(block.Id));
        Assert.Empty(_exceeded);

        _tracker.Add([Traffic(1, 0)]);
        _tracker.Tick();
        _tracker.Tick();

        Assert.True(IsEnabled(block.Id));
        var alert = Assert.Single(_exceeded);
        Assert.Equal((quota.Id, 100L, 100L), (alert.RuleId, alert.Used, alert.Limit));
        Assert.Equal(_time.GetUtcNow(), StatusOf(quota).OverflowedAt);
    }

    [Fact]
    public void Manual_reset_turns_off_only_the_rules_the_overflow_turned_on()
    {
        var block = DisabledBlock();
        var alreadyOn = _rules.SaveRule(new RuleDefinition(Guid.Empty, _browserFilter, RuleKind.Limit, RuleDirection.In, LimitBytesPerSecond: 1024));
        var quota = Quota(100, overflow: [block.Id, alreadyOn.Id]);
        _tracker.Add([Traffic(200, 0)]);
        _tracker.Tick();

        _tracker.Reset(quota.Id);

        Assert.False(IsEnabled(block.Id));
        Assert.True(IsEnabled(alreadyOn.Id));
        Assert.Equal(0, StatusOf(quota).Used);
        Assert.Null(StatusOf(quota).OverflowedAt);
    }

    [Fact]
    public void New_period_resets_the_counter_and_ends_the_overflow()
    {
        var block = DisabledBlock();
        var quota = Quota(100, reset: new TimeSchedule(ScheduleRepeat.EveryDay), overflow: [block.Id]);
        _tracker.Add([Traffic(200, 0)]);
        _tracker.Tick();
        Assert.True(IsEnabled(block.Id));

        _time.Advance(TimeSpan.FromHours(12));
        _tracker.Tick();

        Assert.False(IsEnabled(block.Id));
        Assert.Equal(0, StatusOf(quota).Used);
    }

    [Fact]
    public void Raising_the_limit_above_the_usage_ends_the_overflow()
    {
        var block = DisabledBlock();
        var quota = Quota(100, overflow: [block.Id]);
        _tracker.Add([Traffic(200, 0)]);
        _tracker.Tick();

        _rules.SaveRule(quota with { QuotaBytes = 1000 });
        _tracker.Tick();

        Assert.False(IsEnabled(block.Id));
        Assert.Equal(200, StatusOf(quota).Used);
        Assert.Null(StatusOf(quota).OverflowedAt);
    }

    [Fact]
    public void Disabling_an_overflowed_quota_releases_its_rules()
    {
        var block = DisabledBlock();
        var quota = Quota(100, overflow: [block.Id]);
        _tracker.Add([Traffic(200, 0)]);
        _tracker.Tick();

        _rules.SetEnabled(quota.Id, false);
        _tracker.Tick();

        Assert.False(IsEnabled(block.Id));
    }

    [Fact]
    public void Deleting_an_overflowed_quota_releases_its_rules()
    {
        var block = DisabledBlock();
        var quota = Quota(100, overflow: [block.Id]);
        _tracker.Add([Traffic(200, 0)]);
        _tracker.Tick();

        _rules.DeleteRule(quota.Id);
        _tracker.Tick();

        Assert.False(IsEnabled(block.Id));
    }

    [Fact]
    public void Usage_and_overflow_survive_a_restart()
    {
        var block = DisabledBlock();
        var quota = Quota(100, overflow: [block.Id]);
        _tracker.Add([Traffic(200, 0)]);
        _tracker.Tick();
        _tracker.Save();

        _tracker = NewTracker();
        _tracker.Tick();

        Assert.Equal(200, StatusOf(quota).Used);
        Assert.Single(_exceeded); // Not alerted again.
        _tracker.Reset(quota.Id);
        Assert.False(IsEnabled(block.Id));
    }

    [Fact]
    public void Period_that_ended_while_stopped_resets_on_start()
    {
        var quota = Quota(1000, reset: new TimeSchedule(ScheduleRepeat.EveryDay));
        _tracker.Add([Traffic(200, 0)]);
        _tracker.Save();

        _time.Advance(TimeSpan.FromDays(2));
        _tracker = NewTracker();
        _tracker.Tick();

        Assert.Equal(0, StatusOf(quota).Used);
    }

    [Fact]
    public void Init_from_stats_sums_matching_rows_in_the_rules_direction()
    {
        var quota = Quota(1000, RuleDirection.In);

        _tracker.InitFromStats(quota.Id,
        [
            new StatsFlowSummary(Browser.Id, Browser.Path, "8.8.8.8", null, 443, TransportProtocol.Tcp, "", 300, 7),
            new StatsFlowSummary(Browser.Id, Browser.Path, "1.1.1.1", null, 443, TransportProtocol.Tcp, "", 50, 7),
            new StatsFlowSummary(Game.Id, Game.Path, "8.8.8.8", null, 443, TransportProtocol.Tcp, "", 999, 7),
        ]);

        Assert.Equal(350, StatusOf(quota).Used);
    }

    [Fact]
    public void Status_gives_limit_and_next_reset()
    {
        var quota = Quota(1000, reset: new TimeSchedule(ScheduleRepeat.EveryDay));

        var status = StatusOf(quota);

        Assert.Equal(1000, status.Limit);
        Assert.Equal(new DateTimeOffset(2026, 10, 31, 0, 0, 0, TimeSpan.Zero), status.NextReset);
        Assert.Equal("Browser", status.FilterName);
    }
}

public sealed class QuotaRuleValidationTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly RuleRepository _rules;
    private readonly Guid _filter;

    public QuotaRuleValidationTests()
    {
        _rules = new RuleRepository(new JsonFileStore<RulesDocument>(_dir.File("rules.json")), new ZoneClassifier([]), TimeProvider.System);
        _filter = PredefinedFilters.Internet;
    }

    public void Dispose() => _dir.Dispose();

    private RuleDefinition Rule(long? bytes = 100, TimeSchedule? reset = null, IReadOnlyList<Guid>? overflow = null) =>
        new(Guid.Empty, _filter, RuleKind.Quota, RuleDirection.Both, QuotaBytes: bytes, QuotaReset: reset, OverflowRuleIds: overflow);

    [Theory]
    [InlineData(null)]
    [InlineData(0L)]
    public void Quota_needs_a_positive_size(long? bytes) =>
        Assert.Throws<RuleValidationException>(() => _rules.SaveRule(Rule(bytes)));

    public static TheoryData<TimeSchedule> BadSchedules =>
    [
        new TimeSchedule(ScheduleRepeat.EveryDay, MinuteOfDay: 1440),
        new TimeSchedule(ScheduleRepeat.EveryDay, MinuteOfDay: -1),
        new TimeSchedule(ScheduleRepeat.Once),
        new TimeSchedule(ScheduleRepeat.Days),
        new TimeSchedule(ScheduleRepeat.Days, Days: []),
        new TimeSchedule(ScheduleRepeat.DayOfMonth, DayOfMonth: 0),
        new TimeSchedule(ScheduleRepeat.DayOfMonth, DayOfMonth: 32),
    ];

    [Theory]
    [MemberData(nameof(BadSchedules))]
    public void Reset_schedule_must_be_valid(TimeSchedule schedule) =>
        Assert.Throws<RuleValidationException>(() => _rules.SaveRule(Rule(reset: schedule)));

    [Fact]
    public void Overflow_targets_must_exist() =>
        Assert.Throws<RuleValidationException>(() => _rules.SaveRule(Rule(overflow: [Guid.NewGuid()])));

    [Fact]
    public void Quota_cant_target_itself()
    {
        var saved = _rules.SaveRule(Rule());
        Assert.Throws<RuleValidationException>(() => _rules.SaveRule(saved with { OverflowRuleIds = [saved.Id] }));
    }

    [Fact]
    public void Deleting_a_target_rule_removes_the_reference()
    {
        var target = _rules.SaveRule(new RuleDefinition(Guid.Empty, _filter, RuleKind.Firewall, RuleDirection.Both, IsEnabled: false, Action: FirewallAction.Deny));
        var quota = _rules.SaveRule(Rule(overflow: [target.Id]));

        _rules.DeleteRule(target.Id);

        Assert.Empty(_rules.Snapshot().Rules.Single(r => r.Rule.Id == quota.Id).Rule.OverflowRuleIds!);
        _rules.SetEnabled(quota.Id, false); // Would fail validation with a dangling reference.
    }
}
