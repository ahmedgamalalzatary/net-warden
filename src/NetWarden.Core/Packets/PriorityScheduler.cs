using NetWarden.Shared.Contracts;

namespace NetWarden.Core.Packets;

/// <summary>
/// Shares one direction of the line between priority levels. Packets are recorded per
/// level; every reaction interval the scheduler measures each level's rate, estimates the
/// line capacity and caps every level below the highest active one to what the levels
/// above it leave over. The highest active level is never restricted.
/// Not thread-safe: the <see cref="Limiter"/> calls it under its lock.
/// </summary>
public sealed class PriorityScheduler
{
    /// <summary>A level counts as active (adaptive mode) while it moves at least this much.</summary>
    public const long ActiveBytesPerSecond = 2048;
    /// <summary>Capacity assumed before any traffic was seen and the lowest estimate allowed.</summary>
    public const long MinCapacity = 16 * 1024;
    /// <summary>Restricted levels always keep this share of the line (and at least <see cref="MinCapBytes"/>), so their connections survive.</summary>
    public const double MinCapShare = 0.03;
    public const long MinCapBytes = 4096;
    /// <summary>Without adaptive allocation a level stays active this long after its last packet.</summary>
    public static readonly TimeSpan NonAdaptiveHold = TimeSpan.FromSeconds(30);
    /// <summary>The capacity estimate halves over this time while nothing is restricted (e.g. after moving to a slower network).</summary>
    public static readonly TimeSpan CapacityHalfLife = TimeSpan.FromMinutes(10);

    private const int Levels = 4;
    private const double Smoothing = 0.5;

    private readonly TimeProvider _time;
    private readonly long[] _bytes = new long[Levels];
    private readonly double[] _rate = new double[Levels];
    private readonly long[] _lastActive = new long[Levels];
    private readonly long[] _lastSeen = new long[Levels];
    private readonly bool[] _active = new bool[Levels];
    private readonly TokenBucket?[] _buckets = new TokenBucket?[Levels];
    private long _lastUpdate;
    private double _peak;
    private long _capacity = MinCapacity;

    public PriorityScheduler(TimeProvider time)
    {
        _time = time;
        _lastUpdate = time.GetTimestamp();
        Array.Fill(_lastActive, long.MinValue);
        Array.Fill(_lastSeen, long.MinValue);
    }

    public long Capacity => _capacity;

    /// <summary>True while some active level is restricted (idle levels below an active one are capped too, in case they start).</summary>
    public bool IsRestricting { get; private set; }

    public void Record(PriorityLevel level, int bytes, long now)
    {
        _bytes[(int)level] += bytes;
        _lastSeen[(int)level] = now;
    }

    /// <summary>The bucket a level's packets draw from, or null while it is not restricted.</summary>
    public TokenBucket? Bucket(PriorityLevel level) => _buckets[(int)level];

    /// <summary>Recomputes rates and caps once the reaction interval has passed. <paramref name="min"/>/<paramref name="max"/> bound the capacity (0 = none).</summary>
    public void UpdateIfDue(long now, PrioritySettings settings, long min, long max)
    {
        TimeSpan elapsed = _time.GetElapsedTime(_lastUpdate, now);
        if (elapsed < settings.ReactionTime)
            return;
        _lastUpdate = now;
        double seconds = Math.Max(elapsed.TotalSeconds, 0.001);

        // Measure: smoothed rate per level, and which levels are active.
        long hold = Ticks(settings.Adaptive ? Max(settings.ReactionTime * 4, TimeSpan.FromMilliseconds(500)) : NonAdaptiveHold);
        double total = 0;
        for (int i = 0; i < Levels; i++)
        {
            double instant = _bytes[i] / seconds;
            _bytes[i] = 0;
            _rate[i] = _rate[i] * (1 - Smoothing) + instant * Smoothing;
            total += _rate[i];
            // Activity follows the latest interval (not the smoothed rate), so a level that stops is released after the hold time.
            if (settings.Adaptive ? instant >= ActiveBytesPerSecond : _lastSeen[i] != long.MinValue)
                _lastActive[i] = settings.Adaptive ? now : _lastSeen[i];
            _active[i] = _lastActive[i] != long.MinValue && now - _lastActive[i] <= hold;
        }

        // Capacity: the highest total seen. While something is restricted the total
        // understates the line, so the estimate only decays while nothing is.
        if (!IsRestricting && _peak > 0)
            _peak *= Math.Pow(0.5, elapsed / CapacityHalfLife);
        _peak = Math.Max(_peak, total);
        double capacity = Math.Max(_peak, min > 0 ? min : MinCapacity);
        if (max > 0)
            capacity = Math.Min(capacity, max);
        _capacity = (long)capacity;

        // Allocate from the top: the highest active level is free; every level below it
        // gets what is left after the reservations of the active levels above it.
        double remaining = capacity;
        bool higherActive = false;
        double floor = Math.Max(capacity * MinCapShare, MinCapBytes);
        bool restricting = false;
        for (int i = Levels - 1; i >= 0; i--)
        {
            if (!higherActive)
            {
                _buckets[i] = null;
            }
            else
            {
                long cap = (long)Math.Max(floor, remaining);
                if (_buckets[i] is { } bucket)
                {
                    bucket.Refill(now, _time.TimestampFrequency);
                    bucket.SetRate(cap);
                }
                else
                {
                    _buckets[i] = new TokenBucket(cap, now);
                }
                restricting |= _active[i];
            }
            if (_active[i])
            {
                double reserve = Math.Max(capacity * settings.ReservedPercent((PriorityLevel)i) / 100.0,
                    _rate[i] * (1 + settings.HeadroomPercent / 100.0));
                remaining -= reserve;
                higherActive = true;
            }
        }
        IsRestricting = restricting;
    }

    public PriorityDirectionStatus Status() => new(_capacity,
        Enumerable.Range(0, Levels).Select(i => new PriorityLevelStatus((PriorityLevel)i, (long)_rate[i], _active[i], _buckets[i]?.BytesPerSecond)).ToList());

    private long Ticks(TimeSpan span) => (long)(span.TotalSeconds * _time.TimestampFrequency);

    private static TimeSpan Max(TimeSpan a, TimeSpan b) => a > b ? a : b;
}
