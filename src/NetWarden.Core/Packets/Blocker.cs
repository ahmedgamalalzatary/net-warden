using NetWarden.Core.Rules;
using NetWarden.Shared.Contracts;

namespace NetWarden.Core.Packets;

public enum PacketVerdict
{
    Pass,
    Drop,
    /// <summary>Kept by the blocker until an Ask request is answered.</summary>
    Hold,
}

/// <summary>A packet copied while its flow waits for an answer, to be re-injected if allowed.</summary>
public sealed record HeldPacket(byte[] Data, WinDivertAddress Address);

/// <summary>
/// Decides connection attempts: finds the owner, evaluates blocker rules once per
/// flow, caches the verdict, and parks Ask flows until they are answered or time out.
/// Thread-safe: packets arrive on the filter thread, answers on IPC threads.
/// </summary>
public sealed class Blocker
{
    public static readonly TimeSpan DefaultAskTimeout = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan FlowCacheLifetime = TimeSpan.FromMinutes(2);
    public const int MaxHeldPacketsPerFlow = 8;

    private readonly Func<CompiledRuleSet> _rules;
    private readonly Func<ServiceSettings> _settings;
    private readonly IFlowOwnerLookup _owners;
    private readonly FlowContextFactory _contexts;
    private readonly TimeProvider _time;
    private readonly TimeSpan _askTimeout;
    private readonly Lock _lock = new();
    private readonly Dictionary<FlowId, FlowState> _flows = [];
    private readonly Dictionary<Guid, PendingRequest> _pending = [];
    private DateTimeOffset _lastPrune;

    public Blocker(Func<CompiledRuleSet> rules, Func<ServiceSettings> settings, IFlowOwnerLookup owners,
        FlowContextFactory contexts, TimeProvider time, TimeSpan? askTimeout = null)
    {
        _rules = rules;
        _settings = settings;
        _owners = owners;
        _contexts = contexts;
        _time = time;
        _askTimeout = askTimeout ?? DefaultAskTimeout;
        _lastPrune = time.GetUtcNow();
    }

    /// <summary>Raised (outside the lock) when a new Ask request is created.</summary>
    public event Action<BlockerRequest>? RequestCreated;

    public IReadOnlyList<BlockerRequest> Pending
    {
        get { lock (_lock) return _pending.Values.Select(p => p.Request).OrderBy(r => r.Created).ToList(); }
    }

    public long Dropped => Interlocked.Read(ref _dropped);
    private long _dropped;

    public PacketVerdict Process(in PacketInfo packet, ReadOnlySpan<byte> data, in WinDivertAddress address)
    {
        BlockerRequest? created = null;
        PacketVerdict verdict;
        lock (_lock)
        {
            DateTimeOffset now = _time.GetUtcNow();
            PruneIfDue(now);
            long generation = _rules().Generation;

            if (_flows.TryGetValue(packet.Flow, out var state) && (state.Generation == generation || state.RequestId is not null))
            {
                state.LastSeen = now;
                verdict = Continue(state, packet, data, address);
            }
            else if (!packet.IsConnectionStart && packet.Protocol == TransportProtocol.Tcp)
            {
                // Mid-stream TCP packet of a flow we never saw start: not ours to judge.
                verdict = PacketVerdict.Pass;
            }
            else
            {
                (verdict, created) = Decide(packet, data, address, now, generation);
            }
        }
        if (verdict == PacketVerdict.Drop)
            Interlocked.Increment(ref _dropped);
        if (created is not null)
            RequestCreated?.Invoke(created);
        return verdict;
    }

    private PacketVerdict Continue(FlowState state, in PacketInfo packet, ReadOnlySpan<byte> data, in WinDivertAddress address)
    {
        if (state.RequestId is { } id && _pending.TryGetValue(id, out var pending))
        {
            // Keep the first SYN only (later ones are retransmits); keep a few UDP packets.
            bool keep = packet.Protocol == TransportProtocol.Udp
                ? state.Held.Count < MaxHeldPacketsPerFlow
                : state.Held.Count == 0;
            if (keep)
                state.Held.Add(new HeldPacket(data.ToArray(), address));
            return PacketVerdict.Hold;
        }
        return state.Action == FirewallAction.Deny ? PacketVerdict.Drop : PacketVerdict.Pass;
    }

    private (PacketVerdict, BlockerRequest?) Decide(in PacketInfo packet, ReadOnlySpan<byte> data, in WinDivertAddress address,
        DateTimeOffset now, long generation)
    {
        // Unknown owners (e.g. a SYN to a closed port) pass: the stack handles them, and
        // failing open is safer than cutting off traffic we cannot attribute.
        if (_owners.FindOwner(packet) is not { } pid)
            return (PacketVerdict.Pass, null);
        ConnectionKind kind = packet.Outbound ? ConnectionKind.Connect : ConnectionKind.Accept;
        var flow = _contexts.Create(pid, packet.Protocol, kind, packet.LocalAddress, packet.LocalPort,
            packet.RemoteAddress, packet.RemotePort);
        if (flow is null)
            return (PacketVerdict.Pass, null);

        var settings = _settings();
        var decision = _rules().Evaluate(flow, settings.DefaultFirewallIn, settings.DefaultFirewallOut, now);
        var state = new FlowState { Action = decision.Firewall, Generation = generation, LastSeen = now };
        _flows[packet.Flow] = state;

        if (decision.Firewall != FirewallAction.Ask)
            return (decision.Firewall == FirewallAction.Deny ? PacketVerdict.Drop : PacketVerdict.Pass, null);

        // Group connections that would get the same answer (browsers open several at once).
        var key = (flow.AppId, kind, packet.Protocol, packet.RemoteAddress, packet.RemotePort);
        BlockerRequest? created = null;
        // Equals, not ==: tuple == compares IPAddress by reference.
        var existing = _pending.Values.FirstOrDefault(p => p.Key.Equals(key));
        if (existing is null)
        {
            var app = _contexts.ResolveApp(pid)!;
            var request = new BlockerRequest(Guid.NewGuid(), app, pid, packet.Protocol, kind,
                packet.LocalAddress.ToString(), packet.LocalPort, packet.RemoteAddress.ToString(), packet.RemotePort,
                flow.RemoteHost, now, now + _askTimeout, decision.FirewallRuleId);
            existing = new PendingRequest(request, key);
            _pending[request.Id] = existing;
            created = request;
        }
        existing.Flows.Add(packet.Flow);
        state.RequestId = existing.Request.Id;
        state.Held.Add(new HeldPacket(data.ToArray(), address));
        return (PacketVerdict.Hold, created);
    }

    /// <summary>Answers a request; returns the packets to re-inject (empty when denied or unknown).</summary>
    public IReadOnlyList<HeldPacket> Resolve(Guid requestId, bool allow)
    {
        lock (_lock)
            return ResolveLocked(requestId, allow);
    }

    private IReadOnlyList<HeldPacket> ResolveLocked(Guid requestId, bool allow)
    {
        if (!_pending.Remove(requestId, out var pending))
            return [];
        var release = new List<HeldPacket>();
        foreach (var id in pending.Flows)
        {
            if (!_flows.TryGetValue(id, out var state))
                continue;
            state.RequestId = null;
            state.Action = allow ? FirewallAction.Allow : FirewallAction.Deny;
            if (allow)
                release.AddRange(state.Held);
            else
                Interlocked.Add(ref _dropped, state.Held.Count);
            state.Held.Clear();
        }
        return release;
    }

    /// <summary>Denies requests whose deadline passed. Returns their ids.</summary>
    public IReadOnlyList<Guid> ExpireTimeouts()
    {
        lock (_lock)
        {
            DateTimeOffset now = _time.GetUtcNow();
            var expired = _pending.Values.Where(p => p.Request.Deadline <= now).Select(p => p.Request.Id).ToList();
            foreach (var id in expired)
                ResolveLocked(id, allow: false);
            return expired;
        }
    }

    /// <summary>Forgets cached verdicts (pending requests stay), e.g. when the blocker is switched off.</summary>
    public void ClearCache()
    {
        lock (_lock)
        {
            foreach (var key in _flows.Where(kv => kv.Value.RequestId is null).Select(kv => kv.Key).ToList())
                _flows.Remove(key);
        }
    }

    private void PruneIfDue(DateTimeOffset now)
    {
        if (now - _lastPrune < TimeSpan.FromSeconds(10))
            return;
        _lastPrune = now;
        foreach (var key in _flows.Where(kv => kv.Value.RequestId is null && now - kv.Value.LastSeen > FlowCacheLifetime)
                     .Select(kv => kv.Key).ToList())
            _flows.Remove(key);
    }

    private sealed class FlowState
    {
        public FirewallAction Action;
        public long Generation;
        public DateTimeOffset LastSeen;
        public Guid? RequestId;
        public List<HeldPacket> Held { get; } = [];
    }

    private sealed class PendingRequest(BlockerRequest request, (string, ConnectionKind, TransportProtocol, System.Net.IPAddress, int) key)
    {
        public BlockerRequest Request { get; } = request;
        public (string, ConnectionKind, TransportProtocol, System.Net.IPAddress, int) Key { get; } = key;
        public List<FlowId> Flows { get; } = [];
    }
}
