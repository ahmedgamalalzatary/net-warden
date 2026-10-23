using System.Net;
using Microsoft.Extensions.Time.Testing;
using NetWarden.Core.Monitoring;
using NetWarden.Shared.Contracts;

namespace NetWarden.Tests.Monitoring;

public class TrafficMonitorTests
{
    private static readonly IPAddress Local = IPAddress.Parse("192.168.1.14");
    private static readonly IPAddress Remote = IPAddress.Parse("151.101.1.1");

    private sealed class FakeSockets : ISocketTable
    {
        public List<SocketEntry> Entries { get; } = [];
        public IReadOnlyList<SocketEntry> Snapshot() => Entries.ToList();
    }

    private readonly FakeSockets _sockets = new();
    private readonly FakeTimeProvider _time = new();
    private readonly Dictionary<int, AppInfo> _apps = new()
    {
        [100] = App("c:\\apps\\browser.exe", "Browser"),
        [101] = App("c:\\apps\\browser.exe", "Browser"),
        [200] = App("c:\\apps\\game.exe", "Game"),
    };
    private readonly TrafficMonitor _monitor;

    public TrafficMonitorTests()
    {
        _monitor = new TrafficMonitor(_sockets, pid => _apps.GetValueOrDefault(pid), _time);
    }

    private static AppInfo App(string path, string name) =>
        new(path, AppKind.Desktop, path, name, null, null, null, [], null);

    private static TrafficEvent Tcp(int pid, TrafficDirection dir, int bytes, int localPort = 50000, int remotePort = 443) =>
        new(pid, TransportProtocol.Tcp, dir, bytes, Local, localPort, Remote, remotePort);

    private static SocketEntry TcpSocket(int pid, int localPort = 50000, int remotePort = 443, TcpState state = TcpState.Established) =>
        new(TransportProtocol.Tcp, Local, localPort, Remote, remotePort, state, pid);

    private ActivitySnapshot TickAfter(double seconds)
    {
        _time.Advance(TimeSpan.FromSeconds(seconds));
        return _monitor.Tick();
    }

    [Fact]
    public void Rates_are_bytes_per_second_over_the_tick_interval()
    {
        _monitor.Tick();
        _sockets.Entries.Add(TcpSocket(100));
        _monitor.Record(Tcp(100, TrafficDirection.In, 3000));
        _monitor.Record(Tcp(100, TrafficDirection.Out, 1000));

        var snap = TickAfter(2);

        var app = Assert.Single(snap.Apps);
        Assert.Equal(1500, app.RateIn);
        Assert.Equal(500, app.RateOut);
        Assert.Equal(3000, app.TotalIn);
        Assert.Equal(1000, app.TotalOut);
        Assert.Equal(1500, snap.RateIn);
        Assert.Equal(3000, snap.TotalIn);
    }

    [Fact]
    public void Rate_drops_to_zero_when_idle_but_totals_remain()
    {
        _monitor.Tick();
        _sockets.Entries.Add(TcpSocket(100));
        _monitor.Record(Tcp(100, TrafficDirection.In, 1000));
        TickAfter(1);

        // One idle tick still averages in the previous interval; the second is fully idle.
        Assert.Equal(500, Assert.Single(TickAfter(1).Apps).RateIn);
        var snap = TickAfter(1);

        var app = Assert.Single(snap.Apps);
        Assert.Equal(0, app.RateIn);
        Assert.Equal(1000, app.TotalIn);
        Assert.True(app.IsOnline);
    }

    [Fact]
    public void Bursty_delivery_is_smoothed_over_two_intervals()
    {
        _monitor.Tick();
        _sockets.Entries.Add(TcpSocket(100));
        var rates = new List<long>();
        for (int i = 0; i < 6; i++)
        {
            // Events arrive every other tick in double-size batches.
            if (i % 2 == 1)
                _monitor.Record(Tcp(100, TrafficDirection.In, 2000));
            rates.Add(Assert.Single(TickAfter(1).Apps).RateIn);
        }

        Assert.All(rates.Skip(2), r => Assert.Equal(1000, r));
    }

    [Fact]
    public void Processes_of_the_same_program_are_grouped_into_one_app()
    {
        _monitor.Tick();
        _sockets.Entries.Add(TcpSocket(100, localPort: 50000));
        _sockets.Entries.Add(TcpSocket(101, localPort: 50001));
        _monitor.Record(Tcp(100, TrafficDirection.In, 100, localPort: 50000));
        _monitor.Record(Tcp(101, TrafficDirection.In, 200, localPort: 50001));

        var snap = TickAfter(1);

        var app = Assert.Single(snap.Apps);
        Assert.Equal(300, app.TotalIn);
        Assert.Equal([100, 101], app.ProcessIds);
        Assert.Equal(2, app.Connections.Count);
    }

    [Fact]
    public void Apps_are_sorted_by_current_rate()
    {
        _monitor.Tick();
        _sockets.Entries.Add(TcpSocket(100, localPort: 1));
        _sockets.Entries.Add(TcpSocket(200, localPort: 2));
        _monitor.Record(Tcp(100, TrafficDirection.In, 10, localPort: 1));
        _monitor.Record(Tcp(200, TrafficDirection.In, 999, localPort: 2));

        var snap = TickAfter(1);

        Assert.Equal(["Game", "Browser"], snap.Apps.Select(a => a.App.DisplayName));
    }

    [Fact]
    public void Traffic_is_matched_to_socket_even_with_ipv4_mapped_addresses()
    {
        _monitor.Tick();
        _sockets.Entries.Add(TcpSocket(100));
        _monitor.Record(new TrafficEvent(100, TransportProtocol.Tcp, TrafficDirection.In, 50,
            Local.MapToIPv6(), 50000, Remote.MapToIPv6(), 443));

        var snap = TickAfter(1);

        var conn = Assert.Single(Assert.Single(snap.Apps).Connections);
        Assert.Equal(50, conn.TotalIn);
        Assert.Equal("Established", conn.State);
    }

    [Fact]
    public void Connection_kind_distinguishes_listen_accept_and_connect()
    {
        _monitor.Tick();
        _sockets.Entries.Add(new SocketEntry(TransportProtocol.Tcp, IPAddress.Any, 8080, IPAddress.Any, 0, TcpState.Listen, 200));
        _sockets.Entries.Add(TcpSocket(200, localPort: 8080, remotePort: 61000));
        _sockets.Entries.Add(TcpSocket(200, localPort: 52000, remotePort: 443));

        var snap = TickAfter(1);

        var conns = Assert.Single(snap.Apps).Connections;
        Assert.Single(conns, c => c.Kind == ConnectionKind.Listen && c.LocalPort == 8080 && c.RemoteAddress is null);
        Assert.Single(conns, c => c.Kind == ConnectionKind.Accept && c.RemotePort == 61000);
        Assert.Single(conns, c => c.Kind == ConnectionKind.Connect && c.LocalPort == 52000);
    }

    [Fact]
    public void Udp_traffic_is_attributed_to_the_bound_socket_by_port()
    {
        _monitor.Tick();
        _sockets.Entries.Add(new SocketEntry(TransportProtocol.Udp, IPAddress.Any, 5353, null, 0, TcpState.None, 200));
        _monitor.Record(new TrafficEvent(200, TransportProtocol.Udp, TrafficDirection.Out, 70, Local, 5353, IPAddress.Parse("8.8.8.8"), 53));
        _monitor.Record(new TrafficEvent(200, TransportProtocol.Udp, TrafficDirection.In, 90, Local, 5353, IPAddress.Parse("1.1.1.1"), 53));

        var snap = TickAfter(1);

        var conn = Assert.Single(Assert.Single(snap.Apps).Connections);
        Assert.Equal(ConnectionKind.Listen, conn.Kind);
        Assert.Equal(70, conn.TotalOut);
        Assert.Equal(90, conn.TotalIn);
        Assert.Equal("1.1.1.1", conn.RemoteAddress);
    }

    [Fact]
    public void Closed_flow_lingers_then_disappears_and_app_goes_offline_keeping_totals()
    {
        _monitor.Tick();
        _monitor.Record(Tcp(100, TrafficDirection.In, 400));
        var snap = TickAfter(1);
        Assert.Equal("Closed", Assert.Single(Assert.Single(snap.Apps).Connections).State);

        snap = TickAfter(TrafficMonitor.ClosedFlowLinger.TotalSeconds + 1);

        var app = Assert.Single(snap.Apps);
        Assert.False(app.IsOnline);
        Assert.Empty(app.Connections);
        Assert.Equal(400, app.TotalIn);
    }

    [Fact]
    public void Exited_process_keeps_its_last_known_identity()
    {
        _monitor.Tick();
        _sockets.Entries.Add(TcpSocket(200));
        TickAfter(1);

        // The process exits: resolver no longer knows it, but its final bytes still arrive.
        _apps.Remove(200);
        _sockets.Entries.Clear();
        _monitor.Record(Tcp(200, TrafficDirection.Out, 77));
        var snap = TickAfter(1);

        Assert.Equal(77, Assert.Single(snap.Apps, a => a.App.DisplayName == "Game").TotalOut);
    }

    [Fact]
    public void Pid_zero_socket_rows_are_ignored()
    {
        _monitor.Tick();
        _sockets.Entries.Add(TcpSocket(0, state: TcpState.TimeWait));

        Assert.Empty(TickAfter(1).Apps);
    }

    [Fact]
    public void Unresolvable_pid_is_skipped()
    {
        _monitor.Tick();
        _monitor.Record(Tcp(999, TrafficDirection.In, 5));

        var snap = TickAfter(1);

        Assert.Empty(snap.Apps);
    }

    [Fact]
    public void Reset_totals_zeroes_apps_and_connections()
    {
        _monitor.Tick();
        _sockets.Entries.Add(TcpSocket(100));
        _monitor.Record(Tcp(100, TrafficDirection.In, 1000));
        TickAfter(1);

        _monitor.ResetTotals();
        _monitor.Record(Tcp(100, TrafficDirection.In, 10));
        var snap = TickAfter(1);

        var app = Assert.Single(snap.Apps);
        Assert.Equal(10, app.TotalIn);
        Assert.Equal(10, Assert.Single(app.Connections).TotalIn);
        Assert.Equal(10, snap.TotalIn);
    }

    [Fact]
    public void Record_is_safe_while_ticking_concurrently()
    {
        _monitor.Tick();
        _sockets.Entries.Add(TcpSocket(100));
        const int perThread = 20_000;

        var writers = Enumerable.Range(0, 4).Select(_ => Task.Run(() =>
        {
            for (int i = 0; i < perThread; i++)
                _monitor.Record(Tcp(100, TrafficDirection.In, 1));
        })).ToArray();
        while (!writers.All(w => w.IsCompleted))
            TickAfter(0.01);
        var snap = TickAfter(0.01);

        Assert.Equal(4 * perThread, Assert.Single(snap.Apps).TotalIn);
    }
}
