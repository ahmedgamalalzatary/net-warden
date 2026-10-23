using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using static NetWarden.Core.Packets.WinDivertNative;

namespace NetWarden.Core.Packets;

/// <summary>A source and sink of diverted packets.</summary>
public interface IPacketDevice : IDisposable
{
    /// <summary>Blocks for the next packet; false once the device is shut down.</summary>
    bool Receive(byte[] buffer, out int length, out WinDivertAddress address);

    void Send(ReadOnlySpan<byte> packet, in WinDivertAddress address);

    /// <summary>Unblocks <see cref="Receive"/> so the reader can exit.</summary>
    void Shutdown();
}

public sealed class WinDivertException(string message, int error) : Exception($"{message} (Win32 error {error}: {Describe(error)})")
{
    public int Error { get; } = error;

    private static string Describe(int error) => error switch
    {
        2 => "WinDivert64.sys not found next to WinDivert.dll",
        5 => "access denied; run elevated",
        87 => "invalid filter or parameter",
        577 => "driver signature rejected",
        654 => "an incompatible WinDivert driver is already loaded",
        1060 or 1275 => "driver blocked or failed to load",
        _ => new System.ComponentModel.Win32Exception(error).Message,
    };
}

public sealed unsafe class WinDivertDevice : IPacketDevice
{
    private nint _handle;

    public WinDivertDevice(string filter, short priority = 0, WinDivertLayer layer = WinDivertLayer.Network, ulong flags = 0)
    {
        nint handle;
        try
        {
            handle = WinDivertOpen(filter, layer, priority, flags);
        }
        catch (DllNotFoundException ex)
        {
            throw new WinDivertException("WinDivert.dll is missing: " + ex.Message, 126);
        }
        if (handle == -1)
            throw new WinDivertException("WinDivertOpen failed", Marshal.GetLastPInvokeError());
        _handle = handle;
        // Generous queue so short pauses (GC, slow rule lookups) never drop packets.
        WinDivertSetParam(handle, ParamQueueLength, 8192);
        WinDivertSetParam(handle, ParamQueueTime, 2000);
        WinDivertSetParam(handle, ParamQueueSize, 16 * 1024 * 1024);
    }

    public bool Receive(byte[] buffer, out int length, out WinDivertAddress address)
    {
        WinDivertAddress addr = default;
        fixed (byte* p = buffer)
        {
            if (WinDivertRecv(_handle, p, (uint)buffer.Length, out uint read, &addr))
            {
                length = (int)read;
                address = addr;
                return true;
            }
        }
        length = 0;
        address = default;
        int error = Marshal.GetLastPInvokeError();
        if (error is ErrorNoData or ErrorOperationAborted or ErrorInvalidHandle)
            return false;
        if (error == ErrorInsufficientBuffer)
            return Receive(buffer, out length, out address); // oversized packet was dropped; continue
        throw new WinDivertException("WinDivertRecv failed", error);
    }

    public void Send(ReadOnlySpan<byte> packet, in WinDivertAddress address)
    {
        WinDivertAddress addr = address;
        fixed (byte* p = packet)
        {
            if (!WinDivertSend(_handle, p, (uint)packet.Length, out _, &addr))
            {
                int error = Marshal.GetLastPInvokeError();
                if (error is not (ErrorNoData or ErrorInvalidHandle))
                    throw new WinDivertException("WinDivertSend failed", error);
            }
        }
    }

    public void Shutdown()
    {
        if (_handle != 0)
            WinDivertShutdown(_handle, ShutdownBoth);
    }

    public void Dispose()
    {
        nint handle = Interlocked.Exchange(ref _handle, 0);
        if (handle != 0)
            WinDivertClose(handle);
    }
}

/// <summary>
/// Reads diverted packets on a dedicated thread and applies a processor's verdicts.
/// Disposing closes the device, after which Windows passes traffic normally.
/// </summary>
public sealed class PacketFilter : IDisposable
{
    /// <summary>Connection attempts only: TCP SYNs and all UDP. Loopback is never diverted.</summary>
    public const string BlockerFilter = "!loopback and !impostor and ((tcp and tcp.Syn and !tcp.Ack) or udp)";

    /// <summary>Every TCP and UDP packet, for the limiter. Loopback is never diverted.</summary>
    public const string LimiterFilter = "!loopback and !impostor and (tcp or udp)";

    /// <summary>The blocker sees packets first; what it lets through then reaches the limiter.</summary>
    public const short BlockerPriority = 100;
    public const short LimiterPriority = 0;

    private readonly IPacketDevice _device;
    private readonly IPacketProcessor _processor;
    private readonly ILogger _logger;
    private readonly Thread _thread;
    private long _seen;

    public PacketFilter(IPacketDevice device, IPacketProcessor processor, ILogger logger, string name = "packet filter")
    {
        _device = device;
        _processor = processor;
        _logger = logger;
        _thread = new Thread(Run) { IsBackground = true, Name = "NetWarden " + name, Priority = ThreadPriority.AboveNormal };
        _thread.Start();
    }

    public long PacketsSeen => Interlocked.Read(ref _seen);

    /// <summary>Set if the reader stopped because of an error.</summary>
    public Exception? Fault { get; private set; }

    public bool IsRunning => _thread.IsAlive;

    public void Inject(IEnumerable<HeldPacket> packets)
    {
        foreach (var packet in packets)
        {
            try
            {
                _device.Send(packet.Data, packet.Address);
            }
            catch (WinDivertException ex)
            {
                _logger.LogWarning(ex, "Re-injecting a packet failed.");
            }
        }
    }

    private void Run()
    {
        byte[] buffer = new byte[65535 + 40];
        try
        {
            while (_device.Receive(buffer, out int length, out var address))
            {
                Interlocked.Increment(ref _seen);
                ReadOnlySpan<byte> data = buffer.AsSpan(0, length);
                PacketVerdict verdict;
                try
                {
                    verdict = PacketParser.Parse(data, address.Outbound) is { } info
                        ? _processor.Process(info, data, address)
                        : PacketVerdict.Pass;
                }
                catch (Exception ex)
                {
                    // Never let one bad packet or lookup take the network down.
                    _logger.LogError(ex, "Packet decision failed; passing the packet.");
                    verdict = PacketVerdict.Pass;
                }
                if (verdict == PacketVerdict.Pass)
                    _device.Send(data, address);
            }
        }
        catch (Exception ex)
        {
            Fault = ex;
            _logger.LogError(ex, "Packet filter stopped.");
        }
    }

    public void Dispose()
    {
        _device.Shutdown();
        _thread.Join(TimeSpan.FromSeconds(5));
        _device.Dispose();
    }
}
