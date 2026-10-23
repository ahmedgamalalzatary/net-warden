using System.Buffers.Binary;
using System.Net;
using NetWarden.Shared.Contracts;

namespace NetWarden.Core.Packets;

/// <summary>Transport-level facts about one IP packet, oriented to this machine.</summary>
public readonly record struct PacketInfo(
    TransportProtocol Protocol,
    bool Outbound,
    IPAddress LocalAddress,
    int LocalPort,
    IPAddress RemoteAddress,
    int RemotePort,
    int Length,
    bool IsSyn,
    bool IsAck,
    bool IsFin,
    bool IsRst)
{
    /// <summary>A connection attempt: SYN without ACK.</summary>
    public bool IsConnectionStart => Protocol == TransportProtocol.Tcp && IsSyn && !IsAck;

    public FlowId Flow => new(Protocol, LocalAddress, LocalPort, RemoteAddress, RemotePort);
}

/// <summary>A transport flow seen from this machine.</summary>
public readonly record struct FlowId(TransportProtocol Protocol, IPAddress LocalAddress, int LocalPort, IPAddress RemoteAddress, int RemotePort)
{
    public override string ToString() => $"{Protocol} {LocalAddress}:{LocalPort} <-> {RemoteAddress}:{RemotePort}";
}

public static class PacketParser
{
    private const byte ProtoTcp = 6;
    private const byte ProtoUdp = 17;

    // IPv6 extension headers we can step over to reach TCP/UDP.
    private static readonly byte[] Ipv6Extensions = [0, 43, 60];

    /// <summary>Parses IPv4/IPv6 TCP or UDP; returns null for anything else or malformed packets.</summary>
    public static PacketInfo? Parse(ReadOnlySpan<byte> packet, bool outbound)
    {
        if (packet.Length < 1)
            return null;
        int version = packet[0] >> 4;
        IPAddress src, dst;
        byte protocol;
        int offset;

        if (version == 4)
        {
            if (packet.Length < 20)
                return null;
            int ihl = (packet[0] & 0x0F) * 4;
            if (ihl < 20 || packet.Length < ihl)
                return null;
            // Non-first fragments carry no transport header.
            if ((BinaryPrimitives.ReadUInt16BigEndian(packet[6..]) & 0x1FFF) != 0)
                return null;
            protocol = packet[9];
            src = new IPAddress(packet.Slice(12, 4));
            dst = new IPAddress(packet.Slice(16, 4));
            offset = ihl;
        }
        else if (version == 6)
        {
            if (packet.Length < 40)
                return null;
            protocol = packet[6];
            src = new IPAddress(packet.Slice(8, 16));
            dst = new IPAddress(packet.Slice(24, 16));
            offset = 40;
            while (Array.IndexOf(Ipv6Extensions, protocol) >= 0)
            {
                if (packet.Length < offset + 8)
                    return null;
                protocol = packet[offset];
                offset += (packet[offset + 1] + 1) * 8;
            }
        }
        else
        {
            return null;
        }

        TransportProtocol transport;
        int srcPort, dstPort;
        bool syn = false, ack = false, fin = false, rst = false;
        if (protocol == ProtoTcp)
        {
            if (packet.Length < offset + 20)
                return null;
            transport = TransportProtocol.Tcp;
            srcPort = BinaryPrimitives.ReadUInt16BigEndian(packet[offset..]);
            dstPort = BinaryPrimitives.ReadUInt16BigEndian(packet[(offset + 2)..]);
            byte flags = packet[offset + 13];
            fin = (flags & 0x01) != 0;
            syn = (flags & 0x02) != 0;
            rst = (flags & 0x04) != 0;
            ack = (flags & 0x10) != 0;
        }
        else if (protocol == ProtoUdp)
        {
            if (packet.Length < offset + 8)
                return null;
            transport = TransportProtocol.Udp;
            srcPort = BinaryPrimitives.ReadUInt16BigEndian(packet[offset..]);
            dstPort = BinaryPrimitives.ReadUInt16BigEndian(packet[(offset + 2)..]);
        }
        else
        {
            return null;
        }

        return outbound
            ? new PacketInfo(transport, true, src, srcPort, dst, dstPort, packet.Length, syn, ack, fin, rst)
            : new PacketInfo(transport, false, dst, dstPort, src, srcPort, packet.Length, syn, ack, fin, rst);
    }
}
