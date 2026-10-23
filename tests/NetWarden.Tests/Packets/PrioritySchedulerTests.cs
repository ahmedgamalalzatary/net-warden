using Microsoft.Extensions.Time.Testing;
using NetWarden.Core.Packets;
using NetWarden.Shared.Contracts;

namespace NetWarden.Tests.Packets;

public sealed class PrioritySchedulerTests
{
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 10, 23, 12, 0, 0, TimeSpan.Zero));
    private readonly PriorityScheduler _scheduler;
    private readonly PrioritySettings _settings = new() { ReactionSpeed = ReactionSpeed.Fast }; // 100 ms
    private long _min;
    private long _max;

    public PrioritySchedulerTests() => _scheduler = new PriorityScheduler(_time);

    /// <summary>Feeds each level at a steady rate (bytes/s) for <paramref name="seconds"/>, updating every 10 ms.</summary>
    private void Run(double seconds, params (PriorityLevel Level, long Rate)[] traffic)
    {
        for (int step = 0; step < seconds * 100; step++)
        {
            _time.Advance(TimeSpan.FromMilliseconds(10));
            long now = _time.GetTimestamp();
            foreach (var (level, rate) in traffic)
                _scheduler.Record(level, (int)(rate / 100), now);
            _scheduler.UpdateIfDue(now, _settings, _min, _max);
        }
    }

    private long? Cap(PriorityLevel level) => _scheduler.Bucket(level)?.BytesPerSecond;

    [Fact]
    public void One_level_alone_is_never_restricted()
    {
        Run(2, (PriorityLevel.Low, 1_000_000));

        Assert.False(_scheduler.IsRestricting);
        Assert.Null(Cap(PriorityLevel.Low));
        Assert.InRange(_scheduler.Capacity, 900_000, 1_000_000);
    }

    [Fact]
    public void Lower_level_gets_what_the_higher_reservation_leaves()
    {
        Run(2, (PriorityLevel.Normal, 1_000_000)); // learns a 1 MB/s line
        Run(1, (PriorityLevel.Normal, 900_000), (PriorityLevel.Critical, 50_000));

        // Critical reserves 70% of ~1 MB/s; Normal keeps the remaining 30%.
        Assert.Null(Cap(PriorityLevel.Critical));
        Assert.InRange(Cap(PriorityLevel.Normal)!.Value, 280_000, 310_000);
        Assert.True(_scheduler.IsRestricting);
    }

    [Fact]
    public void A_busy_higher_level_takes_more_than_its_reservation()
    {
        _min = _max = 1_000_000;
        Run(2, (PriorityLevel.Low, 500_000), (PriorityLevel.High, 900_000));

        // High's 900 KB/s plus 20% headroom is more than its 60% share: Low gets the floor.
        Assert.Equal((long)(1_000_000 * PriorityScheduler.MinCapShare), Cap(PriorityLevel.Low));
    }

    [Fact]
    public void Levels_below_two_active_levels_get_what_both_leave()
    {
        _min = _max = 1_000_000;
        _settings.CriticalPercent = 30;
        _settings.HighPercent = 30;
        Run(2, (PriorityLevel.Low, 100_000), (PriorityLevel.High, 100_000), (PriorityLevel.Critical, 100_000));

        Assert.Null(Cap(PriorityLevel.Critical));
        Assert.InRange(Cap(PriorityLevel.High)!.Value, 690_000, 710_000);
        Assert.InRange(Cap(PriorityLevel.Low)!.Value, 390_000, 410_000);
    }

    [Fact]
    public void Restriction_ends_once_the_higher_level_goes_quiet()
    {
        _min = _max = 1_000_000;
        Run(1, (PriorityLevel.Low, 500_000), (PriorityLevel.Critical, 100_000));
        Assert.NotNull(Cap(PriorityLevel.Low));

        Run(2, (PriorityLevel.Low, 500_000));

        Assert.Null(Cap(PriorityLevel.Low));
    }

    [Fact]
    public void Without_adaptive_allocation_an_idle_level_keeps_its_reservation()
    {
        _min = _max = 1_000_000;
        _settings.Adaptive = false;
        Run(0.5, (PriorityLevel.Low, 500_000), (PriorityLevel.Critical, 100_000));

        Run(10, (PriorityLevel.Low, 500_000)); // Critical silent but within the hold time
        Assert.InRange(Cap(PriorityLevel.Low)!.Value, 290_000, 310_000);

        Run(25, (PriorityLevel.Low, 500_000));
        Assert.Null(Cap(PriorityLevel.Low));
    }

    [Fact]
    public void Max_bandwidth_caps_the_estimate_and_min_raises_it()
    {
        _max = 200_000;
        Run(2, (PriorityLevel.Normal, 1_000_000));
        Assert.Equal(200_000, _scheduler.Capacity);

        _max = 0;
        _min = 5_000_000;
        Run(0.2, (PriorityLevel.Normal, 1_000_000));
        Assert.Equal(5_000_000, _scheduler.Capacity);
    }

    [Fact]
    public void Capacity_holds_while_restricting_and_decays_otherwise()
    {
        Run(2, (PriorityLevel.Normal, 1_000_000));
        long learned = _scheduler.Capacity;

        Run(60, (PriorityLevel.Normal, 100_000), (PriorityLevel.Critical, 50_000));
        Assert.InRange(_scheduler.Capacity, learned * 0.99, learned);

        Run(600, (PriorityLevel.Normal, 100_000)); // ten minutes unrestricted: one half-life
        Assert.InRange(_scheduler.Capacity, learned * 0.45, learned * 0.55);
    }

    [Fact]
    public void Updates_wait_for_the_reaction_time()
    {
        _settings.ReactionSpeed = ReactionSpeed.Low; // 1 s
        _min = _max = 1_000_000;
        Run(0.5, (PriorityLevel.Low, 500_000), (PriorityLevel.Critical, 100_000));
        Assert.Null(Cap(PriorityLevel.Low));

        Run(0.6, (PriorityLevel.Low, 500_000), (PriorityLevel.Critical, 100_000));
        Assert.NotNull(Cap(PriorityLevel.Low));
    }

    [Fact]
    public void Status_lists_every_level_low_first()
    {
        _min = _max = 1_000_000;
        Run(1, (PriorityLevel.Low, 500_000), (PriorityLevel.Critical, 100_000));

        var status = _scheduler.Status();

        Assert.Equal(1_000_000, status.CapacityBytesPerSecond);
        Assert.Equal([PriorityLevel.Low, PriorityLevel.Normal, PriorityLevel.High, PriorityLevel.Critical], status.Levels.Select(l => l.Level));
        Assert.True(status.Levels[0].IsActive);
        Assert.NotNull(status.Levels[0].CapBytesPerSecond);
        Assert.True(status.Levels[3].IsActive);
        Assert.Null(status.Levels[3].CapBytesPerSecond);
        Assert.InRange(status.Levels[3].BytesPerSecond, 90_000, 110_000);
    }
}
