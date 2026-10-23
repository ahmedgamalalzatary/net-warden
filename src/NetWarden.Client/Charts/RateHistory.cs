namespace NetWarden.Client.Charts;

public readonly record struct RatePoint(DateTimeOffset Time, long In, long Out);

/// <summary>Fixed-size ring buffer of rate samples, oldest first.</summary>
public sealed class RateHistory(int capacity)
{
    private readonly RatePoint[] _points = new RatePoint[capacity];
    private int _start;

    public int Count { get; private set; }
    public int Capacity => _points.Length;

    public void Add(RatePoint point)
    {
        if (Count < _points.Length)
        {
            _points[(_start + Count) % _points.Length] = point;
            Count++;
        }
        else
        {
            _points[_start] = point;
            _start = (_start + 1) % _points.Length;
        }
    }

    public RatePoint this[int index] =>
        (uint)index < (uint)Count ? _points[(_start + index) % _points.Length] : throw new ArgumentOutOfRangeException(nameof(index));

    /// <summary>Samples no older than <paramref name="window"/> before the newest sample.</summary>
    public IReadOnlyList<RatePoint> Last(TimeSpan window)
    {
        if (Count == 0)
            return [];
        DateTimeOffset cutoff = this[Count - 1].Time - window;
        var result = new List<RatePoint>();
        for (int i = 0; i < Count; i++)
            if (this[i].Time >= cutoff)
                result.Add(this[i]);
        return result;
    }
}

/// <summary>One history per key (an app id, or the whole computer).</summary>
public sealed class RateHistoryStore(int capacity)
{
    private readonly Dictionary<string, RateHistory> _histories = new(StringComparer.Ordinal);

    public void Add(string key, DateTimeOffset time, long rateIn, long rateOut)
    {
        if (!_histories.TryGetValue(key, out var history))
            _histories[key] = history = new RateHistory(capacity);
        history.Add(new RatePoint(time, rateIn, rateOut));
    }

    public RateHistory? Get(string key) => _histories.GetValueOrDefault(key);

    /// <summary>Drops histories of apps that are no longer reported.</summary>
    public void Retain(IEnumerable<string> keys)
    {
        var keep = keys.ToHashSet(StringComparer.Ordinal);
        foreach (string key in _histories.Keys.Where(k => !keep.Contains(k)).ToList())
            _histories.Remove(key);
    }
}
