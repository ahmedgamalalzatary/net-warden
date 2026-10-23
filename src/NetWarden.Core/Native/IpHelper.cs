using System.Runtime.InteropServices;

namespace NetWarden.Core.Native;

internal static unsafe partial class IpHelper
{
    public const int AF_INET = 2;
    public const int AF_INET6 = 23;
    public const int TCP_TABLE_OWNER_PID_ALL = 5;
    public const int UDP_TABLE_OWNER_PID = 1;
    public const uint NO_ERROR = 0;
    public const uint ERROR_INSUFFICIENT_BUFFER = 122;
    public const uint MIB_TCP_STATE_DELETE_TCB = 12;

    [LibraryImport("iphlpapi.dll")]
    public static partial uint GetExtendedTcpTable(void* table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, int af, int tableClass, uint reserved);

    [LibraryImport("iphlpapi.dll")]
    public static partial uint GetExtendedUdpTable(void* table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, int af, int tableClass, uint reserved);

    [LibraryImport("iphlpapi.dll")]
    public static partial uint SetTcpEntry(ref MIB_TCPROW row);

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCP6ROW_OWNER_PID
    {
        public fixed byte LocalAddr[16];
        public uint LocalScopeId;
        public uint LocalPort;
        public fixed byte RemoteAddr[16];
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDPROW_OWNER_PID
    {
        public uint LocalAddr;
        public uint LocalPort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDP6ROW_OWNER_PID
    {
        public fixed byte LocalAddr[16];
        public uint LocalScopeId;
        public uint LocalPort;
        public uint OwningPid;
    }

    /// <summary>Ports in the tables are 16-bit network order stored in a DWORD.</summary>
    public static int Port(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));

    public static uint RawPort(int port) => (uint)(((port & 0xFF) << 8) | ((port >> 8) & 0xFF));
}
