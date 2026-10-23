using System.Net;
using NetWarden.Core.Native;
using NetWarden.Shared.Contracts;
using static NetWarden.Core.Native.IpHelper;

namespace NetWarden.Core.Monitoring;

/// <summary>MIB_TCP_STATE values.</summary>
public enum TcpState
{
    None = 0,
    Closed = 1,
    Listen = 2,
    SynSent = 3,
    SynReceived = 4,
    Established = 5,
    FinWait1 = 6,
    FinWait2 = 7,
    CloseWait = 8,
    Closing = 9,
    LastAck = 10,
    TimeWait = 11,
    DeleteTcb = 12,
}

/// <summary>One row of the OS socket tables. UDP rows have no remote end and state <see cref="TcpState.None"/>.</summary>
public sealed record SocketEntry(
    TransportProtocol Protocol,
    IPAddress LocalAddress,
    int LocalPort,
    IPAddress? RemoteAddress,
    int RemotePort,
    TcpState State,
    int ProcessId);

public interface ISocketTable
{
    IReadOnlyList<SocketEntry> Snapshot();
}

/// <summary>Reads TCP and UDP (IPv4 and IPv6) tables with owning process ids.</summary>
public sealed unsafe class SocketTable : ISocketTable
{
    public IReadOnlyList<SocketEntry> Snapshot()
    {
        var result = new List<SocketEntry>(512);
        ReadTable(AF_INET, tcp: true, result);
        ReadTable(AF_INET6, tcp: true, result);
        ReadTable(AF_INET, tcp: false, result);
        ReadTable(AF_INET6, tcp: false, result);
        return result;
    }

    private static void ReadTable(int af, bool tcp, List<SocketEntry> result)
    {
        int size = 0;
        Call(af, tcp, null, ref size);
        for (int attempt = 0; attempt < 5; attempt++)
        {
            // Pad: the table can grow between the size query and the read.
            size += 4096;
            byte[] buffer = new byte[size];
            fixed (byte* p = buffer)
            {
                uint rc = Call(af, tcp, p, ref size);
                if (rc == ERROR_INSUFFICIENT_BUFFER)
                    continue;
                if (rc != NO_ERROR)
                    return;
                Parse(af, tcp, p, result);
                return;
            }
        }
    }

    private static uint Call(int af, bool tcp, void* buffer, ref int size) => tcp
        ? GetExtendedTcpTable(buffer, ref size, false, af, TCP_TABLE_OWNER_PID_ALL, 0)
        : GetExtendedUdpTable(buffer, ref size, false, af, UDP_TABLE_OWNER_PID, 0);

    private static void Parse(int af, bool tcp, byte* table, List<SocketEntry> result)
    {
        uint count = *(uint*)table;
        // Rows start after dwNumEntries; all row types are 4-byte aligned.
        byte* rows = table + 4;
        for (uint i = 0; i < count; i++)
        {
            switch (af, tcp)
            {
                case (AF_INET, true):
                {
                    var r = ((MIB_TCPROW_OWNER_PID*)rows)[i];
                    result.Add(new SocketEntry(TransportProtocol.Tcp, V4(r.LocalAddr), Port(r.LocalPort),
                        V4(r.RemoteAddr), Port(r.RemotePort), (TcpState)r.State, (int)r.OwningPid));
                    break;
                }
                case (AF_INET6, true):
                {
                    var r = ((MIB_TCP6ROW_OWNER_PID*)rows)[i];
                    result.Add(new SocketEntry(TransportProtocol.Tcp, V6(r.LocalAddr), Port(r.LocalPort),
                        V6(r.RemoteAddr), Port(r.RemotePort), (TcpState)r.State, (int)r.OwningPid));
                    break;
                }
                case (AF_INET, false):
                {
                    var r = ((MIB_UDPROW_OWNER_PID*)rows)[i];
                    result.Add(new SocketEntry(TransportProtocol.Udp, V4(r.LocalAddr), Port(r.LocalPort),
                        null, 0, TcpState.None, (int)r.OwningPid));
                    break;
                }
                default:
                {
                    var r = ((MIB_UDP6ROW_OWNER_PID*)rows)[i];
                    result.Add(new SocketEntry(TransportProtocol.Udp, V6(r.LocalAddr), Port(r.LocalPort),
                        null, 0, TcpState.None, (int)r.OwningPid));
                    break;
                }
            }
        }
    }

    private static IPAddress V4(uint raw) => new(raw);

    private static IPAddress V6(byte* bytes) => new(new ReadOnlySpan<byte>(bytes, 16));
}

public static class ConnectionKiller
{
    /// <summary>
    /// Resets an IPv4 TCP connection. Windows offers no equivalent for IPv6 or UDP.
    /// Returns a Win32 error code (0 on success).
    /// </summary>
    public static uint KillTcp(IPAddress local, int localPort, IPAddress remote, int remotePort)
    {
        local = Endpoints.Normalize(local);
        remote = Endpoints.Normalize(remote);
        if (local.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
            || remote.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            throw new NotSupportedException("Windows can only kill IPv4 TCP connections.");

        var row = new MIB_TCPROW
        {
            State = MIB_TCP_STATE_DELETE_TCB,
            LocalAddr = ToRaw(local),
            LocalPort = RawPort(localPort),
            RemoteAddr = ToRaw(remote),
            RemotePort = RawPort(remotePort),
        };
        return SetTcpEntry(ref row);
    }

    private static uint ToRaw(IPAddress v4)
    {
        Span<byte> b = stackalloc byte[4];
        v4.TryWriteBytes(b, out _);
        return BitConverter.ToUInt32(b);
    }
}
