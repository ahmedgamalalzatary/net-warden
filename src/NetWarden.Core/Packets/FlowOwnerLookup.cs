using System.Net;
using NetWarden.Core.Monitoring;
using NetWarden.Shared.Contracts;

namespace NetWarden.Core.Packets;

public interface IFlowOwnerLookup
{
    /// <summary>The process owning the socket a packet belongs to, or null if none is known.</summary>
    int? FindOwner(in PacketInfo packet);
}

/// <summary>
/// Finds packet owners in the OS socket tables. A connecting socket is in the table
/// (SYN_SENT) before its SYN leaves, and accepted/UDP traffic maps to the listening or
/// bound socket's port. The snapshot is reused briefly and refreshed on a miss.
/// </summary>
public sealed class SocketOwnerLookup(ISocketTable table, TimeProvider time) : IFlowOwnerLookup
{
    public static readonly TimeSpan MaxAge = TimeSpan.FromSeconds(2);
    public static readonly TimeSpan MinRefreshInterval = TimeSpan.FromMilliseconds(20);

    private readonly Lock _lock = new();
    private Index _index = Index.Empty;
    private DateTimeOffset _loadedAt = DateTimeOffset.MinValue;

    public int? FindOwner(in PacketInfo packet)
    {
        lock (_lock)
        {
            DateTimeOffset now = time.GetUtcNow();
            if (now - _loadedAt > MaxAge)
                Reload(now);
            int? owner = _index.Find(packet);
            if (owner is null && now - _loadedAt > MinRefreshInterval)
            {
                Reload(now);
                owner = _index.Find(packet);
            }
            return owner;
        }
    }

    private void Reload(DateTimeOffset now)
    {
        _index = new Index(table.Snapshot());
        _loadedAt = now;
    }

    private sealed class Index
    {
        public static readonly Index Empty = new([]);

        private readonly Dictionary<(IPAddress, int, IPAddress, int), int> _tcp = [];
        private readonly Dictionary<int, List<(IPAddress Address, int Pid)>> _tcpListen = [];
        private readonly Dictionary<int, List<(IPAddress Address, int Pid)>> _udp = [];

        public Index(IReadOnlyList<SocketEntry> rows)
        {
            foreach (var r in rows)
            {
                if (r.ProcessId == 0)
                    continue;
                var local = Endpoints.Normalize(r.LocalAddress);
                if (r.Protocol == TransportProtocol.Udp)
                    Add(_udp, r.LocalPort, local, r.ProcessId);
                else if (r.State == TcpState.Listen)
                    Add(_tcpListen, r.LocalPort, local, r.ProcessId);
                else if (r.RemoteAddress is not null)
                    _tcp[(local, r.LocalPort, Endpoints.Normalize(r.RemoteAddress), r.RemotePort)] = r.ProcessId;
            }
        }

        private static void Add(Dictionary<int, List<(IPAddress, int)>> map, int port, IPAddress address, int pid)
        {
            if (!map.TryGetValue(port, out var list))
                map[port] = list = [];
            list.Add((address, pid));
        }

        public int? Find(in PacketInfo p)
        {
            var local = Endpoints.Normalize(p.LocalAddress);
            if (p.Protocol == TransportProtocol.Tcp)
            {
                if (_tcp.TryGetValue((local, p.LocalPort, Endpoints.Normalize(p.RemoteAddress), p.RemotePort), out int pid))
                    return pid;
                return Bound(_tcpListen, p.LocalPort, local);
            }
            return Bound(_udp, p.LocalPort, local);
        }

        /// <summary>Exact local address first, then a wildcard bind of the same family (or dual-stack ::).</summary>
        private static int? Bound(Dictionary<int, List<(IPAddress Address, int Pid)>> map, int port, IPAddress local)
        {
            if (!map.TryGetValue(port, out var list))
                return null;
            foreach (var (address, pid) in list)
                if (address.Equals(local))
                    return pid;
            foreach (var (address, pid) in list)
                if (address.Equals(IPAddress.Any) && local.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    return pid;
            foreach (var (address, pid) in list)
                if (address.Equals(IPAddress.IPv6Any))
                    return pid;
            return null;
        }
    }
}
