using System.Net;
using NetWarden.Shared.Contracts;

namespace NetWarden.Core.Monitoring;

/// <summary>
/// Aggregates traffic events into per-connection and per-app rates and totals.
/// <see cref="Record"/> is called from the event thread; <see cref="Tick"/> once per
/// interval builds a snapshot by joining traffic with the OS socket tables.
/// </summary>
public sealed class TrafficMonitor
{
    /// <summary>A flow with no socket stays visible this long after its last byte.</summary>
    public static readonly TimeSpan ClosedFlowLinger = TimeSpan.FromSeconds(5);

    private readonly ISocketTable _sockets;
    private readonly Func<int, AppInfo?> _resolve;
    private readonly TimeProvider _time;

    private readonly Lock _pendingLock = new();
    private Dictionary<FlowKey, Pending> _pending = [];

    // Only touched from Tick/ResetTotals, which are serialized by _tickLock.
    private readonly Lock _tickLock = new();
    private readonly Dictionary<FlowKey, Flow> _flows = [];
    private readonly Dictionary<string, AppTotals> _apps = new(StringComparer.Ordinal);
    private readonly Dictionary<int, AppInfo> _pidApps = [];
    private readonly Dictionary<int, AppInfo?> _tickApps = [];
    private DateTimeOffset? _lastTick;

    public TrafficMonitor(ISocketTable sockets, Func<int, AppInfo?> resolve, TimeProvider time)
    {
        _sockets = sockets;
        _resolve = resolve;
        _time = time;
    }

    public ActivitySnapshot? Latest { get; private set; }

    public void Record(in TrafficEvent e)
    {
        FlowKey key = FlowKey.For(e.ProcessId, e.Protocol, e.LocalAddress, e.LocalPort, e.RemoteAddress, e.RemotePort);
        lock (_pendingLock)
        {
            ref Pending p = ref System.Runtime.InteropServices.CollectionsMarshal.GetValueRefOrAddDefault(_pending, key, out _);
            if (e.Direction == TrafficDirection.In)
                p.In += e.Bytes;
            else
                p.Out += e.Bytes;
            if (e.Protocol == TransportProtocol.Udp)
                p.LastRemote = new IPEndPoint(Endpoints.Normalize(e.RemoteAddress), e.RemotePort);
            else
                p.Local = Endpoints.Normalize(e.LocalAddress);
        }
    }

    public void ResetTotals()
    {
        lock (_tickLock)
        {
            foreach (var flow in _flows.Values)
                flow.TotalIn = flow.TotalOut = 0;
            foreach (var app in _apps.Values)
                app.TotalIn = app.TotalOut = 0;
        }
    }

    public ActivitySnapshot Tick()
    {
        lock (_tickLock)
        {
            DateTimeOffset now = _time.GetUtcNow();
            double seconds = _lastTick is { } last ? Math.Max((now - last).TotalSeconds, 0.001) : 1.0;
            _lastTick = now;
            _tickApps.Clear();

            Dictionary<FlowKey, Pending> pending;
            lock (_pendingLock)
            {
                pending = _pending;
                _pending = new Dictionary<FlowKey, Pending>(pending.Count);
            }

            IReadOnlyList<SocketEntry> sockets = _sockets.Snapshot();
            var listening = new HashSet<(int Pid, int Port)>();
            foreach (var s in sockets)
                if (s.Protocol == TransportProtocol.Tcp && s.State == TcpState.Listen)
                    listening.Add((s.ProcessId, s.LocalPort));

            foreach (var flow in _flows.Values)
                flow.Socket = null;

            foreach (var s in sockets)
            {
                // TIME_WAIT and other orphaned rows belong to pid 0.
                if (s.ProcessId == 0)
                    continue;
                FlowKey key = FlowKey.For(s.ProcessId, s.Protocol, s.LocalAddress, s.LocalPort, s.RemoteAddress, s.RemotePort);
                Flow flow = GetFlow(key);
                flow.Socket = s;
            }

            foreach (var (key, delta) in pending)
            {
                Flow flow = GetFlow(key);
                flow.TotalIn += delta.In;
                flow.TotalOut += delta.Out;
                flow.LastActive = now;
                flow.LastRemote = delta.LastRemote ?? flow.LastRemote;
                flow.EtwLocal = delta.Local ?? flow.EtwLocal;

                AppInfo? app = AppFor(key.ProcessId);
                if (app is not null)
                {
                    AppTotals totals = GetApp(app);
                    totals.TotalIn += delta.In;
                    totals.TotalOut += delta.Out;
                }
            }

            // ETW delivers events in ~1 s batches that beat against the tick, so a single
            // interval alternates between 0 and double. Rates span the last two intervals.
            foreach (var (key, flow) in _flows)
            {
                pending.TryGetValue(key, out Pending delta);
                double span = seconds + flow.PrevSeconds;
                flow.RateIn = (long)((delta.In + flow.PrevIn) / span);
                flow.RateOut = (long)((delta.Out + flow.PrevOut) / span);
                flow.PrevIn = delta.In;
                flow.PrevOut = delta.Out;
                flow.PrevSeconds = seconds;
            }

            // Forget flows whose socket is gone and that have been quiet for a while.
            var livePids = new HashSet<int>();
            foreach (var (key, flow) in _flows.ToList())
            {
                if (flow.Socket is null && now - flow.LastActive > ClosedFlowLinger)
                    _flows.Remove(key);
                else
                    livePids.Add(key.ProcessId);
            }
            foreach (int pid in _pidApps.Keys.ToList())
                if (!livePids.Contains(pid))
                    _pidApps.Remove(pid);

            Latest = BuildSnapshot(now, listening);
            return Latest;
        }
    }

    private ActivitySnapshot BuildSnapshot(DateTimeOffset now, HashSet<(int Pid, int Port)> listening)
    {
        var byApp = new Dictionary<string, List<(FlowKey Key, Flow Flow)>>(StringComparer.Ordinal);
        foreach (var (key, flow) in _flows)
        {
            AppInfo? app = AppFor(key.ProcessId);
            if (app is null)
                continue;
            GetApp(app);
            if (!byApp.TryGetValue(app.Id, out var list))
                byApp[app.Id] = list = [];
            list.Add((key, flow));
        }

        var apps = new List<AppActivity>(_apps.Count);
        long rateIn = 0, rateOut = 0, totalIn = 0, totalOut = 0;
        foreach (var totals in _apps.Values)
        {
            byApp.TryGetValue(totals.App.Id, out var flows);
            var connections = flows is null
                ? []
                : flows.Select(f => ToActivity(f.Key, f.Flow, listening))
                    .OrderByDescending(c => c.RateIn + c.RateOut)
                    .ThenBy(c => c.Kind)
                    .ThenBy(c => c.LocalPort)
                    .ToList();

            long appRateIn = connections.Sum(c => c.RateIn);
            long appRateOut = connections.Sum(c => c.RateOut);
            rateIn += appRateIn;
            rateOut += appRateOut;
            totalIn += totals.TotalIn;
            totalOut += totals.TotalOut;

            apps.Add(new AppActivity(
                totals.App,
                IsOnline: connections.Count > 0,
                ProcessIds: connections.Select(c => c.ProcessId).Distinct().Order().ToList(),
                appRateIn, appRateOut, totals.TotalIn, totals.TotalOut,
                connections));
        }

        apps.Sort((a, b) =>
        {
            int c = (b.RateIn + b.RateOut).CompareTo(a.RateIn + a.RateOut);
            return c != 0 ? c : string.Compare(a.App.DisplayName, b.App.DisplayName, StringComparison.OrdinalIgnoreCase);
        });

        return new ActivitySnapshot(now, rateIn, rateOut, totalIn, totalOut, apps);
    }

    private static ConnectionActivity ToActivity(FlowKey key, Flow flow, HashSet<(int Pid, int Port)> listening)
    {
        SocketEntry? s = flow.Socket;
        ConnectionKind kind;
        string state;
        IPAddress local;
        IPAddress? remote;
        int remotePort;

        if (key.Protocol == TransportProtocol.Udp)
        {
            kind = ConnectionKind.Listen;
            state = s is null ? "Closed" : "Bound";
            local = s?.LocalAddress ?? IPAddress.Any;
            remote = flow.LastRemote?.Address;
            remotePort = flow.LastRemote?.Port ?? 0;
        }
        else
        {
            TcpState tcpState = s?.State ?? TcpState.Closed;
            kind = tcpState == TcpState.Listen ? ConnectionKind.Listen
                : listening.Contains((key.ProcessId, key.LocalPort)) ? ConnectionKind.Accept
                : ConnectionKind.Connect;
            state = tcpState.ToString();
            local = key.LocalAddress ?? flow.EtwLocal ?? IPAddress.Any;
            remote = tcpState == TcpState.Listen ? null : key.RemoteAddress;
            remotePort = tcpState == TcpState.Listen ? 0 : key.RemotePort;
        }

        return new ConnectionActivity(
            key.ToString(), key.ProcessId, key.Protocol, kind, state,
            local.ToString(), key.LocalPort, remote?.ToString(), remotePort,
            flow.RateIn, flow.RateOut, flow.TotalIn, flow.TotalOut);
    }

    private Flow GetFlow(FlowKey key)
    {
        if (!_flows.TryGetValue(key, out Flow? flow))
            _flows[key] = flow = new Flow();
        return flow;
    }

    private AppTotals GetApp(AppInfo app)
    {
        if (!_apps.TryGetValue(app.Id, out AppTotals? totals))
            _apps[app.Id] = totals = new AppTotals(app);
        else
            totals.App = app;
        return totals;
    }

    /// <summary>Resolves once per pid per tick; falls back to the last identity of a pid that has exited.</summary>
    private AppInfo? AppFor(int pid)
    {
        if (_tickApps.TryGetValue(pid, out AppInfo? known))
            return known;
        AppInfo? app = _resolve(pid);
        if (app is not null)
            _pidApps[pid] = app;
        else
            _pidApps.TryGetValue(pid, out app);
        _tickApps[pid] = app;
        return app;
    }

    /// <summary>
    /// Identifies a flow. TCP uses the full 4-tuple. UDP sockets are usually bound to
    /// the unspecified address while traffic reports a concrete one, so UDP is keyed by
    /// process and local port only.
    /// </summary>
    internal readonly record struct FlowKey(
        int ProcessId,
        TransportProtocol Protocol,
        IPAddress? LocalAddress,
        int LocalPort,
        IPAddress? RemoteAddress,
        int RemotePort)
    {
        public static FlowKey For(int pid, TransportProtocol protocol, IPAddress local, int localPort, IPAddress? remote, int remotePort)
        {
            if (protocol == TransportProtocol.Udp)
                return new FlowKey(pid, protocol, null, localPort, null, 0);

            // A listening socket has no remote end; keep it distinct from established flows.
            IPAddress? r = remote is null || Endpoints.IsUnspecified(remote) ? null : Endpoints.Normalize(remote);
            IPAddress? l = r is null && Endpoints.IsUnspecified(local) ? null : Endpoints.Normalize(local);
            return new FlowKey(pid, protocol, l, localPort, r, r is null ? 0 : remotePort);
        }

        public override string ToString() =>
            $"{ProcessId}|{Protocol}|{LocalAddress}|{LocalPort}|{RemoteAddress}|{RemotePort}";
    }

    private struct Pending
    {
        public long In;
        public long Out;
        public IPEndPoint? LastRemote;
        public IPAddress? Local;
    }

    private sealed class Flow
    {
        public SocketEntry? Socket;
        public long RateIn;
        public long RateOut;
        public long TotalIn;
        public long TotalOut;
        public long PrevIn;
        public long PrevOut;
        public double PrevSeconds;
        public DateTimeOffset LastActive;
        public IPEndPoint? LastRemote;
        public IPAddress? EtwLocal;
    }

    private sealed class AppTotals(AppInfo app)
    {
        public AppInfo App = app;
        public long TotalIn;
        public long TotalOut;
    }
}
