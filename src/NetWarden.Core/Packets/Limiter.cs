using NetWarden.Core.Rules;
using NetWarden.Shared.Contracts;

namespace NetWarden.Core.Packets;

/// <summary>Something that judges diverted packets.</summary>
public interface IPacketProcessor
{
    PacketVerdict Process(in PacketInfo packet, ReadOnlySpan<byte> data, in WinDivertAddress address);
}

/// <summary>
/// Shapes traffic to the limit rules. Each packet's payload (what the Activity view
/// counts, so a limit means the same there) draws on the token buckets of every
/// limit that applies to its flow; when a bucket is short the packet is queued until
/// it can go (TCP then settles at the limit), and when a bucket's backlog is already
/// longer than <see cref="MaxQueueDelay"/> the packet is dropped instead.
/// Thread-safe: packets arrive on the filter thread, due packets leave on the pump thread.
/// </summary>
public sealed class Limiter : IPacketProcessor
{
    public static readonly TimeSpan MaxQueueDelay = TimeSpan.FromMilliseconds(500);
    public static readonly TimeSpan FlowCacheLifetime = TimeSpan.FromMinutes(2);
    /// <summary>How long a flow without a known owner stays unlimited before it is looked up again.</summary>
    public static readonly TimeSpan UnknownOwnerRetry = TimeSpan.FromSeconds(5);
    public const long MaxQueuedBytes = 64L * 1024 * 1024;
    /// <summary>Smallest burst a bucket allows, so one full-size packet always fits.</summary>
    public const long MinBurstBytes = 1514;

    private readonly Func<CompiledRuleSet> _rules;
    private readonly IFlowOwnerLookup _owners;
    private readonly FlowContextFactory _contexts;
    private readonly TimeProvider _time;
    private readonly Lock _lock = new();
    private readonly Dictionary<FlowId, FlowState> _flows = [];
    private readonly Dictionary<string, TokenBucket> _buckets = [];
    private readonly PriorityQueue<(HeldPacket Packet, FlowState Flow), (long Due, long Seq)> _queue = new();
    private long _seq;
    private long _queuedBytes;
    private long _delayed;
    private long _dropped;
    private long _lastPrune;

    public Limiter(Func<CompiledRuleSet> rules, IFlowOwnerLookup owners, FlowContextFactory contexts, TimeProvider time)
    {
        _rules = rules;
        _owners = owners;
        _contexts = contexts;
        _time = time;
        _lastPrune = time.GetTimestamp();
    }

    /// <summary>Raised (outside the lock) when a queued packet became the earliest one, so the pump can wake up.</summary>
    public event Action? QueueHeadChanged;

    public long Delayed => Interlocked.Read(ref _delayed);
    public long Dropped => Interlocked.Read(ref _dropped);

    public long QueuedBytes
    {
        get { lock (_lock) return _queuedBytes; }
    }

    public PacketVerdict Process(in PacketInfo packet, ReadOnlySpan<byte> data, in WinDivertAddress address)
    {
        bool wake;
        lock (_lock)
        {
            long now = _time.GetTimestamp();
            PruneIfDue(now);
            var state = Lookup(packet, now);
            TokenBucket[] buckets = packet.Outbound ? state.Upload : state.Download;
            if (buckets.Length == 0)
                return PacketVerdict.Pass;

            // Drop when any bucket is already backed up; otherwise draw from all of them
            // and send when the slowest one has caught up.
            long delay = 0;
            foreach (var bucket in buckets)
            {
                bucket.Refill(now, _time.TimestampFrequency);
                if (bucket.Backlog(_time.TimestampFrequency) > MaxQueueDelay.Ticks * _time.TimestampFrequency / TimeSpan.TicksPerSecond
                    || _queuedBytes + data.Length > MaxQueuedBytes)
                {
                    Interlocked.Increment(ref _dropped);
                    return PacketVerdict.Drop;
                }
            }
            foreach (var bucket in buckets)
                delay = Math.Max(delay, bucket.Take(packet.PayloadLength, _time.TimestampFrequency));
            if (delay == 0 && state.Queued == 0)
                return PacketVerdict.Pass;

            // Packets of this flow are queued: even an undelayed one waits its turn, to keep order.
            long due = now + delay;
            wake = !_queue.TryPeek(out _, out var head) || due < head.Due;
            _queue.Enqueue((new HeldPacket(data.ToArray(), address), state), (due, _seq++));
            _queuedBytes += data.Length;
            state.Queued++;
            Interlocked.Increment(ref _delayed);
        }
        if (wake)
            QueueHeadChanged?.Invoke();
        return PacketVerdict.Hold;
    }

    /// <summary>Removes and returns packets whose time has come; <paramref name="wait"/> is the time to the next one.</summary>
    public List<HeldPacket> TakeDue(out TimeSpan? wait)
    {
        var due = new List<HeldPacket>();
        lock (_lock)
        {
            long now = _time.GetTimestamp();
            while (_queue.TryPeek(out var entry, out var key) && key.Due <= now)
            {
                _queue.Dequeue();
                _queuedBytes -= entry.Packet.Data.Length;
                entry.Flow.Queued--;
                due.Add(entry.Packet);
            }
            wait = _queue.TryPeek(out _, out var next) ? _time.GetElapsedTime(now, next.Due) : null;
        }
        return due;
    }

    /// <summary>Empties the queue (in order) and forgets all flows and buckets, e.g. when the limiter stops.</summary>
    public List<HeldPacket> Reset()
    {
        var all = new List<HeldPacket>();
        lock (_lock)
        {
            while (_queue.TryDequeue(out var entry, out _))
                all.Add(entry.Packet);
            _queuedBytes = 0;
            _flows.Clear();
            _buckets.Clear();
        }
        return all;
    }

    private FlowState Lookup(in PacketInfo packet, long now)
    {
        long generation = _rules().Generation;
        if (_flows.TryGetValue(packet.Flow, out var state) && state.Generation == generation
            && (state.Known || _time.GetElapsedTime(state.Created, now) < UnknownOwnerRetry))
        {
            state.LastSeen = now;
            return state;
        }

        state = new FlowState { Generation = generation, Created = now, LastSeen = now };
        _flows[packet.Flow] = state;
        if (_owners.FindOwner(packet) is not { } pid)
            return state;
        var flow = _contexts.Create(pid, packet.Protocol, packet.Outbound ? ConnectionKind.Connect : ConnectionKind.Accept,
            packet.LocalAddress, packet.LocalPort, packet.RemoteAddress, packet.RemotePort);
        if (flow is null)
            return state;
        state.Known = true;
        // Firewall defaults do not matter here; only the limit bindings are used.
        var decision = _rules().Evaluate(flow, FirewallAction.Allow, FirewallAction.Allow, _time.GetUtcNow());
        state.Download = decision.DownloadLimits.Select(Bucket).ToArray();
        state.Upload = decision.UploadLimits.Select(Bucket).ToArray();
        return state;
    }

    private TokenBucket Bucket(LimitBinding binding)
    {
        if (!_buckets.TryGetValue(binding.BucketKey, out var bucket))
            _buckets[binding.BucketKey] = bucket = new TokenBucket(binding.BytesPerSecond, _time.GetTimestamp());
        bucket.SetRate(binding.BytesPerSecond);
        return bucket;
    }

    private void PruneIfDue(long now)
    {
        if (_time.GetElapsedTime(_lastPrune, now) < TimeSpan.FromSeconds(10))
            return;
        _lastPrune = now;
        foreach (var key in _flows.Where(kv => _time.GetElapsedTime(kv.Value.LastSeen, now) > FlowCacheLifetime).Select(kv => kv.Key).ToList())
            _flows.Remove(key);
        var live = _flows.Values.SelectMany(f => f.Download.Concat(f.Upload)).ToHashSet();
        foreach (var key in _buckets.Where(kv => !live.Contains(kv.Value)).Select(kv => kv.Key).ToList())
            _buckets.Remove(key);
    }

    private sealed class FlowState
    {
        public long Generation;
        public long Created;
        public long LastSeen;
        public bool Known;
        public int Queued;
        public TokenBucket[] Download = [];
        public TokenBucket[] Upload = [];
    }
}

/// <summary>
/// A token bucket that may go into debt: a packet larger than the available tokens is
/// still accepted, and the debt is the time it must wait. Times are <see cref="TimeProvider"/> timestamps.
/// </summary>
public sealed class TokenBucket
{
    private double _tokens;
    private long _last;

    public TokenBucket(long bytesPerSecond, long now)
    {
        SetRate(bytesPerSecond);
        _tokens = Capacity;
        _last = now;
    }

    public long BytesPerSecond { get; private set; }

    /// <summary>Burst size: 50 ms of traffic, but at least one full packet.</summary>
    public double Capacity { get; private set; }

    public double Tokens => _tokens;

    public void SetRate(long bytesPerSecond)
    {
        BytesPerSecond = Math.Max(1, bytesPerSecond);
        Capacity = Math.Max(BytesPerSecond / 20.0, Limiter.MinBurstBytes);
        _tokens = Math.Min(_tokens, Capacity);
    }

    public void Refill(long now, long frequency)
    {
        if (now <= _last)
            return;
        _tokens = Math.Min(Capacity, _tokens + (now - _last) * (double)BytesPerSecond / frequency);
        _last = now;
    }

    /// <summary>Time (in timestamp units) until the debt is paid off.</summary>
    public long Backlog(long frequency) => _tokens >= 0 ? 0 : (long)Math.Ceiling(-_tokens * frequency / BytesPerSecond);

    /// <summary>Takes <paramref name="bytes"/>; returns how long (timestamp units) the packet must wait.</summary>
    public long Take(int bytes, long frequency)
    {
        _tokens -= bytes;
        return Backlog(frequency);
    }
}

/// <summary>Sends the limiter's queued packets when they are due, on its own thread.</summary>
public sealed partial class LimiterPump : IDisposable
{
    private readonly Limiter _limiter;
    private readonly Action<IReadOnlyList<HeldPacket>> _send;
    private readonly AutoResetEvent _wake = new(false);
    private readonly Thread _thread;
    private volatile bool _stopping;

    public LimiterPump(Limiter limiter, Action<IReadOnlyList<HeldPacket>> send)
    {
        _limiter = limiter;
        _send = send;
        limiter.QueueHeadChanged += OnHeadChanged;
        _thread = new Thread(Run) { IsBackground = true, Name = "NetWarden limiter pump", Priority = ThreadPriority.AboveNormal };
        _thread.Start();
    }

    private void OnHeadChanged() => _wake.Set();

    private void Run()
    {
        // 1 ms timer resolution while limiting; the default 15.6 ms makes traffic bursty.
        _ = TimeBeginPeriod(1);
        try
        {
            while (!_stopping)
            {
                var due = _limiter.TakeDue(out TimeSpan? wait);
                if (due.Count > 0)
                    _send(due);
                if (wait is not { } w || w > TimeSpan.Zero)
                    _wake.WaitOne(wait is { } t ? Math.Clamp((int)Math.Ceiling(t.TotalMilliseconds), 1, 1000) : 1000);
            }
        }
        finally
        {
            _ = TimeEndPeriod(1);
        }
    }

    /// <summary>Stops the thread and sends everything still queued.</summary>
    public void Dispose()
    {
        _limiter.QueueHeadChanged -= OnHeadChanged;
        _stopping = true;
        _wake.Set();
        _thread.Join(TimeSpan.FromSeconds(5));
        var rest = _limiter.Reset();
        if (rest.Count > 0)
            _send(rest);
        _wake.Dispose();
    }

    [System.Runtime.InteropServices.LibraryImport("winmm.dll", EntryPoint = "timeBeginPeriod")]
    private static partial uint TimeBeginPeriod(uint period);

    [System.Runtime.InteropServices.LibraryImport("winmm.dll", EntryPoint = "timeEndPeriod")]
    private static partial uint TimeEndPeriod(uint period);
}
