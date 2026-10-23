using System.Net;
using System.Runtime.InteropServices;

namespace NetWarden.Core.Packets;

/// <summary>WINDIVERT_ADDRESS (80 bytes). Bitfields are allocated LSB first (MSVC).</summary>
[StructLayout(LayoutKind.Explicit, Size = 80)]
public struct WinDivertAddress
{
    [FieldOffset(0)] public long Timestamp;
    [FieldOffset(8)] public uint Bits;
    [FieldOffset(12)] public uint Reserved2;

    // NETWORK layer data.
    [FieldOffset(16)] public uint IfIdx;
    [FieldOffset(20)] public uint SubIfIdx;

    // SOCKET / FLOW layer data shares the union at offset 16.
    [FieldOffset(16)] public ulong EndpointId;
    [FieldOffset(24)] public ulong ParentEndpointId;
    [FieldOffset(32)] public uint ProcessId;
    [FieldOffset(36)] public uint LocalAddr0;
    [FieldOffset(40)] public uint LocalAddr1;
    [FieldOffset(44)] public uint LocalAddr2;
    [FieldOffset(48)] public uint LocalAddr3;
    [FieldOffset(52)] public uint RemoteAddr0;
    [FieldOffset(56)] public uint RemoteAddr1;
    [FieldOffset(60)] public uint RemoteAddr2;
    [FieldOffset(64)] public uint RemoteAddr3;
    [FieldOffset(68)] public ushort LocalPort;
    [FieldOffset(70)] public ushort RemotePort;
    [FieldOffset(72)] public byte Protocol;

    public readonly int Layer => (int)(Bits & 0xFF);
    public readonly int Event => (int)((Bits >> 8) & 0xFF);
    public readonly bool Sniffed => (Bits & (1u << 16)) != 0;
    public bool Outbound
    {
        readonly get => (Bits & (1u << 17)) != 0;
        set => Bits = value ? Bits | (1u << 17) : Bits & ~(1u << 17);
    }
    public readonly bool Loopback => (Bits & (1u << 18)) != 0;
    public readonly bool Impostor => (Bits & (1u << 19)) != 0;
    public readonly bool IPv6 => (Bits & (1u << 20)) != 0;

    /// <summary>
    /// Converts WinDivert's UINT32[4] address (host-order words, [3] most significant;
    /// IPv4 as ::ffff:a.b.c.d) to an <see cref="IPAddress"/>, unmapping IPv4.
    /// </summary>
    public static IPAddress ToAddress(uint w0, uint w1, uint w2, uint w3)
    {
        if (w3 == 0 && w2 == 0 && w1 == 0x0000FFFF)
            return new IPAddress([(byte)(w0 >> 24), (byte)(w0 >> 16), (byte)(w0 >> 8), (byte)w0]);
        Span<byte> bytes = stackalloc byte[16];
        Span<uint> words = [w3, w2, w1, w0];
        for (int i = 0; i < 4; i++)
        {
            bytes[i * 4] = (byte)(words[i] >> 24);
            bytes[i * 4 + 1] = (byte)(words[i] >> 16);
            bytes[i * 4 + 2] = (byte)(words[i] >> 8);
            bytes[i * 4 + 3] = (byte)words[i];
        }
        return new IPAddress(bytes);
    }
}

public enum WinDivertLayer : int
{
    Network = 0,
    NetworkForward = 1,
    Flow = 2,
    Socket = 3,
    Reflect = 4,
}

internal static unsafe partial class WinDivertNative
{
    public const ulong FlagSniff = 0x0001;
    public const ulong FlagDrop = 0x0002;
    public const ulong FlagRecvOnly = 0x0004;
    public const int ParamQueueLength = 0;
    public const int ParamQueueTime = 1;
    public const int ParamQueueSize = 2;
    public const int ShutdownBoth = 3;
    public const int ErrorNoData = 232;          // ERROR_NO_DATA: handle shut down
    public const int ErrorInsufficientBuffer = 122;
    public const int ErrorOperationAborted = 995;
    public const int ErrorInvalidHandle = 6;

    private const string Dll = "WinDivert.dll";

    [LibraryImport(Dll, SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint WinDivertOpen(string filter, WinDivertLayer layer, short priority, ulong flags);

    [LibraryImport(Dll, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool WinDivertRecv(nint handle, byte* packet, uint packetLen, out uint recvLen, WinDivertAddress* addr);

    [LibraryImport(Dll, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool WinDivertSend(nint handle, byte* packet, uint packetLen, out uint sendLen, WinDivertAddress* addr);

    [LibraryImport(Dll, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool WinDivertShutdown(nint handle, int how);

    [LibraryImport(Dll, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool WinDivertClose(nint handle);

    [LibraryImport(Dll, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool WinDivertSetParam(nint handle, int param, ulong value);

    [LibraryImport(Dll, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool WinDivertHelperCalcChecksums(byte* packet, uint packetLen, WinDivertAddress* addr, ulong flags);
}
