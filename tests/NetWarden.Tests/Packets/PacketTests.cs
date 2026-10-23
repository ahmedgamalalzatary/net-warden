using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Time.Testing;
using NetWarden.Core.Apps;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Packets;
using NetWarden.Core.Rules;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Storage;

namespace NetWarden.Tests.Packets;

/// <summary>Builds raw IP packets for tests.</summary>
internal static class Raw
{
    public static byte[] Tcp4(string src, int srcPort, string dst, int dstPort, byte flags = 0x02, int payload = 0)
    {
        var p = new byte[40 + payload];
        p[0] = 0x45;
        p[2] = (byte)(p.Length >> 8);
        p[3] = (byte)p.Length;
        p[8] = 64;
        p[9] = 6;
        IPAddress.Parse(src).GetAddressBytes().CopyTo(p, 12);
        IPAddress.Parse(dst).GetAddressBytes().CopyTo(p, 16);
        Ports(p, 20, srcPort, dstPort);
        p[32] = 0x50;
        p[33] = flags;
        return p;
    }

    public static byte[] Udp6(string src, int srcPort, string dst, int dstPort, int payload = 0)
    {
        var p = new byte[48 + payload];
        p[0] = 0x60;
        p[6] = 17;
        p[7] = 64;
        IPAddress.Parse(src).GetAddressBytes().CopyTo(p, 8);
        IPAddress.Parse(dst).GetAddressBytes().CopyTo(p, 24);
        Ports(p, 40, srcPort, dstPort);
        return p;
    }

    public static byte[] Udp4(string src, int srcPort, string dst, int dstPort)
    {
        var p = Tcp4(src, srcPort, dst, dstPort);
        p[9] = 17;
        return p[..28];
    }

    private static void Ports(byte[] p, int offset, int src, int dst)
    {
        p[offset] = (byte)(src >> 8);
        p[offset + 1] = (byte)src;
        p[offset + 2] = (byte)(dst >> 8);
        p[offset + 3] = (byte)dst;
    }

    public static WinDivertAddress Address(bool outbound) => new() { Outbound = outbound };
}

public class PacketParserTests
{
    [Fact]
    public void Outbound_ipv4_syn_is_oriented_local_to_remote()
    {
        var info = PacketParser.Parse(Raw.Tcp4("192.168.1.14", 50000, "1.1.1.1", 443, flags: 0x02), outbound: true)!.Value;

        Assert.Equal(TransportProtocol.Tcp, info.Protocol);
        Assert.Equal(IPAddress.Parse("192.168.1.14"), info.LocalAddress);
        Assert.Equal(50000, info.LocalPort);
        Assert.Equal(IPAddress.Parse("1.1.1.1"), info.RemoteAddress);
        Assert.Equal(443, info.RemotePort);
        Assert.True(info.IsConnectionStart);
    }

    [Fact]
    public void Inbound_packet_swaps_source_and_destination()
    {
        var info = PacketParser.Parse(Raw.Tcp4("1.1.1.1", 443, "192.168.1.14", 50000, flags: 0x12), outbound: false)!.Value;

        Assert.Equal(50000, info.LocalPort);
        Assert.Equal(IPAddress.Parse("1.1.1.1"), info.RemoteAddress);
        Assert.True(info.IsSyn && info.IsAck);
        Assert.False(info.IsConnectionStart);
    }

    [Theory]
    [InlineData((byte)0x01, false, false, true, false)]
    [InlineData((byte)0x04, false, false, false, true)]
    [InlineData((byte)0x10, false, true, false, false)]
    public void Tcp_flags(byte flags, bool syn, bool ack, bool fin, bool rst)
    {
        var info = PacketParser.Parse(Raw.Tcp4("10.0.0.1", 1, "10.0.0.2", 2, flags), true)!.Value;
        Assert.Equal((syn, ack, fin, rst), (info.IsSyn, info.IsAck, info.IsFin, info.IsRst));
    }

    [Fact]
    public void Ipv6_udp()
    {
        var info = PacketParser.Parse(Raw.Udp6("2001:db8::1", 5353, "2001:db8::2", 53, payload: 10), true)!.Value;

        Assert.Equal(TransportProtocol.Udp, info.Protocol);
        Assert.Equal(IPAddress.Parse("2001:db8::2"), info.RemoteAddress);
        Assert.Equal(53, info.RemotePort);
        Assert.Equal(58, info.Length);
    }

    [Fact]
    public void Ipv6_hop_by_hop_extension_is_skipped()
    {
        var basic = Raw.Udp6("2001:db8::1", 1000, "2001:db8::2", 2000);
        var p = new byte[basic.Length + 8];
        basic.AsSpan(0, 40).CopyTo(p);
        p[6] = 0;          // next header: hop-by-hop
        p[40] = 17;        // its next header: UDP
        p[41] = 0;         // length: 8 bytes
        basic.AsSpan(40).CopyTo(p.AsSpan(48));

        Assert.Equal(2000, PacketParser.Parse(p, true)!.Value.RemotePort);
    }

    [Fact]
    public void Non_first_fragments_and_garbage_are_not_parsed()
    {
        var fragment = Raw.Tcp4("10.0.0.1", 1, "10.0.0.2", 2);
        fragment[7] = 0x10; // fragment offset != 0

        Assert.Null(PacketParser.Parse(fragment, true));
        Assert.Null(PacketParser.Parse([], true));
        Assert.Null(PacketParser.Parse([0x45, 0, 0], true));
        Assert.Null(PacketParser.Parse(new byte[60], true)); // version 0
        var icmp = Raw.Tcp4("10.0.0.1", 1, "10.0.0.2", 2);
        icmp[9] = 1;
        Assert.Null(PacketParser.Parse(icmp, true));
    }
}

public class WinDivertAddressTests
{
    [Fact]
    public void Struct_matches_native_layout()
    {
        Assert.Equal(80, Marshal.SizeOf<WinDivertAddress>());
        Assert.Equal(32, (int)Marshal.OffsetOf<WinDivertAddress>(nameof(WinDivertAddress.ProcessId)));
        Assert.Equal(68, (int)Marshal.OffsetOf<WinDivertAddress>(nameof(WinDivertAddress.LocalPort)));
    }

    [Fact]
    public void Outbound_bit_round_trips_and_does_not_touch_other_bits()
    {
        var a = new WinDivertAddress { Bits = 1u << 20 };
        a.Outbound = true;
        Assert.True(a.Outbound && a.IPv6);
        a.Outbound = false;
        Assert.False(a.Outbound);
        Assert.True(a.IPv6);
    }

    [Fact]
    public void Converts_mapped_ipv4_and_ipv6_words()
    {
        Assert.Equal(IPAddress.Parse("192.168.1.14"), WinDivertAddress.ToAddress(0xC0A8010E, 0x0000FFFF, 0, 0));
        Assert.Equal(IPAddress.Parse("2001:db8::1"), WinDivertAddress.ToAddress(0x00000001, 0, 0, 0x20010DB8));
    }
}

public class SocketOwnerLookupTests
{
    private sealed class FakeTable : ISocketTable
    {
        public List<SocketEntry> Rows { get; } = [];
        public int Reads { get; private set; }
        public IReadOnlyList<SocketEntry> Snapshot() { Reads++; return Rows.ToList(); }
    }

    private readonly FakeTable _table = new();
    private readonly FakeTimeProvider _time = new();

    private static PacketInfo P(string remote = "1.1.1.1", int remotePort = 443, int localPort = 50000, bool outbound = true,
        TransportProtocol protocol = TransportProtocol.Tcp, string local = "192.168.1.14") =>
        new(protocol, outbound, IPAddress.Parse(local), localPort, IPAddress.Parse(remote), remotePort, 60, true, false, false, false);

    [Fact]
    public void Connecting_tcp_socket_matches_exactly()
    {
        _table.Rows.Add(new SocketEntry(TransportProtocol.Tcp, IPAddress.Parse("192.168.1.14"), 50000, IPAddress.Parse("1.1.1.1"), 443, TcpState.SynSent, 77));

        Assert.Equal(77, new SocketOwnerLookup(_table, _time).FindOwner(P()));
    }

    [Fact]
    public void Inbound_syn_maps_to_listener_including_wildcard_and_dual_stack()
    {
        _table.Rows.Add(new SocketEntry(TransportProtocol.Tcp, IPAddress.Any, 8080, IPAddress.Any, 0, TcpState.Listen, 10));
        _table.Rows.Add(new SocketEntry(TransportProtocol.Tcp, IPAddress.IPv6Any, 9090, IPAddress.IPv6Any, 0, TcpState.Listen, 20));
        var lookup = new SocketOwnerLookup(_table, _time);

        Assert.Equal(10, lookup.FindOwner(P(localPort: 8080, outbound: false)));
        Assert.Equal(20, lookup.FindOwner(P(localPort: 9090, outbound: false)));
        Assert.Equal(20, lookup.FindOwner(P(localPort: 9090, outbound: false, local: "2001:db8::5", remote: "2001:db8::9")));
        Assert.Null(lookup.FindOwner(P(localPort: 7070, outbound: false)));
    }

    [Fact]
    public void Udp_maps_by_bound_port_preferring_exact_address()
    {
        _table.Rows.Add(new SocketEntry(TransportProtocol.Udp, IPAddress.Any, 5353, null, 0, TcpState.None, 1));
        _table.Rows.Add(new SocketEntry(TransportProtocol.Udp, IPAddress.Parse("192.168.1.14"), 5353, null, 0, TcpState.None, 2));

        Assert.Equal(2, new SocketOwnerLookup(_table, _time).FindOwner(P(protocol: TransportProtocol.Udp, localPort: 5353)));
    }

    [Fact]
    public void Miss_triggers_one_refresh_but_not_more_than_the_minimum_interval()
    {
        var lookup = new SocketOwnerLookup(_table, _time);
        Assert.Null(lookup.FindOwner(P()));
        int reads = _table.Reads;

        _table.Rows.Add(new SocketEntry(TransportProtocol.Tcp, IPAddress.Parse("192.168.1.14"), 50000, IPAddress.Parse("1.1.1.1"), 443, TcpState.SynSent, 5));
        Assert.Null(lookup.FindOwner(P()));
        Assert.Equal(reads, _table.Reads);

        _time.Advance(TimeSpan.FromMilliseconds(50));
        Assert.Equal(5, lookup.FindOwner(P()));
    }
}

public sealed class BlockerTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 10, 23, 12, 0, 0, TimeSpan.Zero));
    private readonly RuleRepository _rules;
    private readonly ServiceSettings _settings = new();
    private readonly Dictionary<FlowId, int> _owners = [];
    private readonly Blocker _blocker;
    private readonly List<BlockerRequest> _requests = [];

    private static readonly AppInfo Browser = new(@"c:\apps\browser.exe", AppKind.Desktop, @"c:\apps\browser.exe", "Browser", null, null, null, [], null);

    private sealed class Owners(Dictionary<FlowId, int> map) : IFlowOwnerLookup
    {
        public int? FindOwner(in PacketInfo packet) => map.TryGetValue(packet.Flow, out int pid) ? pid : null;
    }

    public BlockerTests()
    {
        _rules = new RuleRepository(new JsonFileStore<RulesDocument>(_dir.File("rules.json")), new ZoneClassifier([]), _time);
        var contexts = new FlowContextFactory(pid => pid == 100 ? Browser : null, _ => null, new DnsMap());
        _blocker = new Blocker(() => _rules.Current, () => _settings, new Owners(_owners), contexts, _time, TimeSpan.FromSeconds(30));
        _blocker.RequestCreated += _requests.Add;
    }

    public void Dispose() => _dir.Dispose();

    private PacketVerdict Send(byte[] raw, bool outbound = true, int? owner = 100)
    {
        var info = PacketParser.Parse(raw, outbound)!.Value;
        if (owner is { } pid)
            _owners[info.Flow] = pid;
        return _blocker.Process(info, raw, Raw.Address(outbound));
    }

    private static byte[] Syn(string remote = "1.1.1.1", int port = 443, int localPort = 50000) =>
        Raw.Tcp4("192.168.1.14", localPort, remote, port);

    private void BrowserRule(FirewallAction action, RuleDirection dir = RuleDirection.Both) =>
        _rules.SaveRule(new RuleDefinition(Guid.Empty, _rules.EnsureAppFilter(Browser.Id, "Browser").Id, RuleKind.Firewall, dir, Action: action));

    [Fact]
    public void No_rules_and_allow_defaults_pass()
    {
        Assert.Equal(PacketVerdict.Pass, Send(Syn()));
    }

    [Fact]
    public void Deny_rule_drops_and_retransmits_stay_dropped()
    {
        BrowserRule(FirewallAction.Deny);

        Assert.Equal(PacketVerdict.Drop, Send(Syn()));
        Assert.Equal(PacketVerdict.Drop, Send(Syn()));
        Assert.Equal(2, _blocker.Dropped);
    }

    [Fact]
    public void Direction_in_blocks_incoming_but_not_outgoing()
    {
        BrowserRule(FirewallAction.Deny, RuleDirection.In);

        Assert.Equal(PacketVerdict.Pass, Send(Syn()));
        Assert.Equal(PacketVerdict.Drop, Send(Raw.Tcp4("1.1.1.1", 61000, "192.168.1.14", 8080), outbound: false));
    }

    [Fact]
    public void Unknown_owner_and_unknown_app_fail_open()
    {
        _settings.DefaultFirewallOut = FirewallAction.Deny;

        Assert.Equal(PacketVerdict.Pass, Send(Syn(), owner: null));
        Assert.Equal(PacketVerdict.Pass, Send(Syn(localPort: 50001), owner: 999));
        Assert.Equal(PacketVerdict.Drop, Send(Syn(localPort: 50002)));
    }

    [Fact]
    public void Mid_stream_tcp_of_unseen_flow_passes()
    {
        BrowserRule(FirewallAction.Deny);

        Assert.Equal(PacketVerdict.Pass, Send(Raw.Tcp4("192.168.1.14", 50000, "1.1.1.1", 443, flags: 0x10)));
    }

    [Fact]
    public void Rule_change_reevaluates_cached_flows()
    {
        Assert.Equal(PacketVerdict.Pass, Send(Raw.Udp4("192.168.1.14", 5000, "8.8.8.8", 53)));

        BrowserRule(FirewallAction.Deny);

        Assert.Equal(PacketVerdict.Drop, Send(Raw.Udp4("192.168.1.14", 5000, "8.8.8.8", 53)));
    }

    [Fact]
    public void Ask_holds_packets_groups_similar_flows_and_allow_releases_them()
    {
        BrowserRule(FirewallAction.Ask);

        Assert.Equal(PacketVerdict.Hold, Send(Syn(localPort: 50000)));
        Assert.Equal(PacketVerdict.Hold, Send(Syn(localPort: 50000)));  // retransmit: not kept twice
        Assert.Equal(PacketVerdict.Hold, Send(Syn(localPort: 50001)));  // same app/remote: same request
        Assert.Equal(PacketVerdict.Hold, Send(Syn(remote: "9.9.9.9"))); // different remote: new request

        Assert.Equal(2, _requests.Count);
        var request = _requests[0];
        Assert.Equal("Browser", request.App.DisplayName);
        Assert.Equal(ConnectionKind.Connect, request.Kind);
        Assert.Equal("1.1.1.1", request.RemoteAddress);

        var released = _blocker.Resolve(request.Id, allow: true);

        Assert.Equal(2, released.Count);
        Assert.Equal(PacketVerdict.Pass, Send(Syn(localPort: 50000)));
        Assert.Single(_blocker.Pending);
    }

    [Fact]
    public void Ask_keeps_several_udp_packets_and_deny_drops_them()
    {
        BrowserRule(FirewallAction.Ask);
        for (int i = 0; i < Blocker.MaxHeldPacketsPerFlow + 3; i++)
            Assert.Equal(PacketVerdict.Hold, Send(Raw.Udp4("192.168.1.14", 5000, "8.8.8.8", 53)));

        var released = _blocker.Resolve(_requests.Single().Id, allow: false);

        Assert.Empty(released);
        Assert.Equal(Blocker.MaxHeldPacketsPerFlow, _blocker.Dropped);
        Assert.Equal(PacketVerdict.Drop, Send(Raw.Udp4("192.168.1.14", 5000, "8.8.8.8", 53)));
    }

    [Fact]
    public void Unanswered_requests_time_out_to_deny()
    {
        BrowserRule(FirewallAction.Ask);
        Send(Syn());

        Assert.Empty(_blocker.ExpireTimeouts());
        _time.Advance(TimeSpan.FromSeconds(31));
        var expired = _blocker.ExpireTimeouts();

        Assert.Equal(_requests.Single().Id, Assert.Single(expired));
        Assert.Empty(_blocker.Pending);
        Assert.Equal(PacketVerdict.Drop, Send(Syn()));
    }

    [Fact]
    public void Resolving_unknown_request_is_harmless()
    {
        Assert.Empty(_blocker.Resolve(Guid.NewGuid(), true));
    }

    [Fact]
    public void Pending_flows_stay_pending_across_rule_changes()
    {
        BrowserRule(FirewallAction.Ask);
        Send(Syn());

        _rules.SaveFilter(new FilterDefinition(Guid.Empty, "unrelated", FilterType.Filter, FilterPerType.None, [], []));

        Assert.Equal(PacketVerdict.Hold, Send(Syn()));
        Assert.Single(_requests);
    }
}
