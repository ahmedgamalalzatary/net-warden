using System.Net;
using Microsoft.Extensions.Time.Testing;
using NetWarden.Core.Apps;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Rules;
using NetWarden.Core.Stats;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Storage;

namespace NetWarden.Tests.Stats;

public sealed class StatsRecorderTests : IDisposable
{
    private static readonly IPAddress Local = IPAddress.Parse("192.168.1.14");
    private readonly TempDir _dir = new();
    private readonly FakeTimeProvider _time = new(StatsData.Noon);
    private readonly ServiceSettings _settings = new();
    private readonly DnsMap _dns = new();
    private readonly RuleRepository _rules;
    private readonly StatsRecorder _recorder;

    public StatsRecorderTests()
    {
        var zones = new ZoneClassifier([]);
        _rules = new RuleRepository(new JsonFileStore<RulesDocument>(_dir.File("rules.json")), zones, _time);
        var apps = new Dictionary<int, AppInfo> { [100] = StatsData.Browser, [200] = StatsData.Game };
        var flows = new FlowContextFactory(pid => apps.GetValueOrDefault(pid), _ => new ProcessUser("S-1-5-21-1", "PC\\alice"), _dns);
        _recorder = new StatsRecorder(() => _rules.Current, () => _settings, flows, zones);
    }

    public void Dispose() => _dir.Dispose();

    private FlowTraffic Tcp(long bytesIn, long bytesOut = 0, string remote = "8.8.8.8", int remotePort = 443, int localPort = 50000,
        ConnectionKind kind = ConnectionKind.Connect, int pid = 100, double secondsLater = 0) =>
        new(pid == 200 ? StatsData.Game : StatsData.Browser, pid, TransportProtocol.Tcp, kind, Local, localPort,
            IPAddress.Parse(remote), remotePort, bytesIn, bytesOut, _time.GetUtcNow().AddSeconds(secondsLater));

    [Fact]
    public void Ticks_of_one_minute_become_one_record()
    {
        _recorder.Add([Tcp(100, 10)]);
        _recorder.Add([Tcp(200, 20, secondsLater: 30)]);
        _recorder.Add([Tcp(400, 40, secondsLater: 61)]);

        var records = _recorder.Drain().OrderBy(r => r.Slot).ToList();

        Assert.Equal(2, records.Count);
        var first = records[0];
        Assert.Equal((300L, 30L), (first.In, first.Out));
        Assert.Equal(StatsData.Noon.ToUnixTimeSeconds(), first.Slot);
        Assert.Equal(("8.8.8.8", 443, StatsZone.Internet), (first.Address, first.Port, first.Zone));
        Assert.Equal(("S-1-5-21-1", "PC\\alice"), (first.UserSid, first.UserName));
        Assert.Equal(StatsData.Browser, first.App);
        Assert.Empty(_recorder.Drain());
    }

    [Fact]
    public void Host_names_come_from_dns()
    {
        _dns.Record("dns.google", [IPAddress.Parse("8.8.8.8")]);

        _recorder.Add([Tcp(100)]);

        Assert.Equal("dns.google", Assert.Single(_recorder.Drain()).HostName);
    }

    [Fact]
    public void Zones_are_saved_as_the_settings_say()
    {
        _settings.Stats.SaveLoopback = false;
        _settings.Stats.SaveLocalNetwork = false;

        _recorder.Add([Tcp(1), Tcp(2, remote: "192.168.1.1"), Tcp(4, remote: "127.0.0.1")]);
        Assert.Equal(StatsZone.Internet, Assert.Single(_recorder.Drain()).Zone);

        _settings.Stats.SaveLoopback = true;
        _settings.Stats.SaveInternet = false;
        _recorder.Add([Tcp(1), Tcp(4, remote: "127.0.0.1")]);
        Assert.Equal(StatsZone.Loopback, Assert.Single(_recorder.Drain()).Zone);
    }

    [Fact]
    public void Nothing_is_recorded_while_stats_are_off()
    {
        _settings.IsStatsEnabled = false;

        _recorder.Add([Tcp(100)]);

        Assert.Equal(0, _recorder.PendingCount);
    }

    [Fact]
    public void Ignore_data_rules_keep_traffic_out_of_stats()
    {
        var filter = _rules.EnsureAppFilter(StatsData.Game.Id, "Game");
        _rules.SaveRule(new RuleDefinition(Guid.Empty, filter.Id, RuleKind.Ignore, RuleDirection.Both, IgnoreData: true));

        _recorder.Add([Tcp(100), Tcp(200, pid: 200)]);

        Assert.Equal(StatsData.Browser, Assert.Single(_recorder.Drain()).App);
    }

    [Fact]
    public void Rule_changes_apply_to_flows_already_seen()
    {
        _recorder.Add([Tcp(1, pid: 200)]);
        var filter = _rules.EnsureAppFilter(StatsData.Game.Id, "Game");
        _rules.SaveRule(new RuleDefinition(Guid.Empty, filter.Id, RuleKind.Ignore, RuleDirection.Both, IgnoreData: true));

        _recorder.Add([Tcp(2, pid: 200, secondsLater: 1)]);

        Assert.Equal(1, Assert.Single(_recorder.Drain()).In);
    }

    [Fact]
    public void Service_port_is_the_well_known_side()
    {
        FlowTraffic Udp(int localPort, string? remote, int remotePort) =>
            new(StatsData.Browser, 100, TransportProtocol.Udp, ConnectionKind.Listen, IPAddress.Any, localPort,
                remote is null ? null : IPAddress.Parse(remote), remotePort, 1, 0, StatsData.Noon);

        Assert.Equal(443, StatsRecorder.ServicePort(Tcp(1, remotePort: 443, localPort: 50000)));
        Assert.Equal(3389, StatsRecorder.ServicePort(Tcp(1, remotePort: 50000, localPort: 3389, kind: ConnectionKind.Accept)));
        Assert.Equal(53, StatsRecorder.ServicePort(Udp(60000, "1.1.1.1", 53)));
        Assert.Equal(5353, StatsRecorder.ServicePort(Udp(5353, null, 0)));
    }

    [Fact]
    public void Udp_without_a_remote_end_has_no_address()
    {
        var udp = new FlowTraffic(StatsData.Browser, 100, TransportProtocol.Udp, ConnectionKind.Listen, IPAddress.Any, 5353,
            null, 0, 7, 0, StatsData.Noon);

        _recorder.Add([udp]);

        var record = Assert.Single(_recorder.Drain());
        Assert.Equal(("", 5353, StatsZone.Internet), (record.Address, record.Port, record.Zone));
    }
}

public class TrafficMonitorStatsTests
{
    private sealed class FakeSockets : ISocketTable
    {
        public List<SocketEntry> Entries { get; } = [];
        public IReadOnlyList<SocketEntry> Snapshot() => Entries.ToList();
    }

    [Fact]
    public void Each_tick_reports_what_every_flow_moved()
    {
        var local = IPAddress.Parse("192.168.1.14");
        var remote = IPAddress.Parse("151.101.1.1");
        var sockets = new FakeSockets();
        sockets.Entries.Add(new SocketEntry(TransportProtocol.Tcp, local, 50000, remote, 443, TcpState.Established, 100));
        sockets.Entries.Add(new SocketEntry(TransportProtocol.Tcp, local, 3389, IPAddress.Any, 0, TcpState.Listen, 100));
        sockets.Entries.Add(new SocketEntry(TransportProtocol.Tcp, local, 3389, remote, 61000, TcpState.Established, 100));
        var time = new FakeTimeProvider(StatsData.Noon);
        var monitor = new TrafficMonitor(sockets, pid => pid == 100 ? StatsData.Browser : null, time);
        var reported = new List<IReadOnlyList<FlowTraffic>>();
        monitor.TrafficRecorded += reported.Add;

        monitor.Record(new TrafficEvent(100, TransportProtocol.Tcp, TrafficDirection.In, 3000, local, 50000, remote, 443));
        monitor.Record(new TrafficEvent(100, TransportProtocol.Tcp, TrafficDirection.Out, 100, local, 3389, remote, 61000));
        monitor.Record(new TrafficEvent(999, TransportProtocol.Tcp, TrafficDirection.In, 5, local, 1, remote, 2)); // unknown app
        monitor.Tick();
        time.Advance(TimeSpan.FromSeconds(1));
        monitor.Tick(); // nothing moved: no report

        var flows = Assert.Single(reported).OrderBy(f => f.LocalPort).ToList();
        Assert.Equal(2, flows.Count);
        Assert.Equal((ConnectionKind.Accept, 0L, 100L, 61000), (flows[0].Kind, flows[0].In, flows[0].Out, flows[0].RemotePort));
        Assert.Equal((ConnectionKind.Connect, 3000L, remote), (flows[1].Kind, flows[1].In, flows[1].RemoteAddress));
        Assert.Equal(StatsData.Noon, flows[1].Time);
    }
}
