using System.Net;
using Microsoft.Extensions.Time.Testing;
using NetWarden.Client.ViewModels;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Stats;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;
using NetWarden.Tests.Client;
using NetWarden.Tests.Stats;

namespace NetWarden.Tests.Monitoring;

public class ConnectionLogTests
{
    private static readonly AppInfo Browser = StatsData.Browser;
    private readonly DnsMap _dns = new();
    private readonly ConnectionLog _log;

    public ConnectionLogTests() => _log = new ConnectionLog(_dns.Lookup, capacity: 5);

    private static ConnectionActivity Conn(string key, ConnectionKind kind = ConnectionKind.Connect, string state = "Established",
        string? remote = "8.8.8.8", int remotePort = 443) =>
        new(key, 100, TransportProtocol.Tcp, kind, state, "192.168.1.14", 50000, remote, remotePort, 0, 0, 0, 0);

    private static ActivitySnapshot Snap(int second, params ConnectionActivity[] connections) =>
        new(Snapshots.T0.AddSeconds(second), 0, 0, 0, 0, [new AppActivity(Browser, true, [100], 0, 0, 0, 0, connections)]);

    private IReadOnlyList<ConnectionLogEntry> All() => _log.Get(0).Entries;

    [Fact]
    public void Connections_present_at_the_first_look_are_not_news()
    {
        _log.Update(Snap(0, Conn("a")));

        Assert.Empty(All());
    }

    [Theory]
    [InlineData(ConnectionKind.Connect, ConnectionLogEvent.Connect)]
    [InlineData(ConnectionKind.Accept, ConnectionLogEvent.Accept)]
    [InlineData(ConnectionKind.Listen, ConnectionLogEvent.Listen)]
    public void New_connection_is_logged_by_kind(ConnectionKind kind, ConnectionLogEvent expected)
    {
        _dns.Record("dns.google", [IPAddress.Parse("8.8.8.8")]);
        _log.Update(Snap(0));

        _log.Update(Snap(1, Conn("a", kind)));

        var entry = Assert.Single(All());
        Assert.Equal(expected, entry.Event);
        Assert.Equal((Browser.Id, Browser.DisplayName, 100), (entry.AppId, entry.AppName, entry.ProcessId));
        Assert.Equal(("8.8.8.8", 443, "dns.google"), (entry.RemoteAddress, entry.RemotePort, entry.RemoteHost));
        Assert.Equal(Snapshots.T0.AddSeconds(1), entry.Time);
    }

    [Fact]
    public void Connection_going_away_is_logged_once_as_closed()
    {
        _log.Update(Snap(0));
        _log.Update(Snap(1, Conn("a")));

        _log.Update(Snap(2, Conn("a", state: "Closed")));
        _log.Update(Snap(3));

        Assert.Equal([ConnectionLogEvent.Connect, ConnectionLogEvent.Closed], All().Select(e => e.Event));
    }

    [Fact]
    public void Connection_that_stays_is_logged_once()
    {
        _log.Update(Snap(0));
        _log.Update(Snap(1, Conn("a")));
        _log.Update(Snap(2, Conn("a")));

        Assert.Single(All());
    }

    [Fact]
    public void Stopped_log_records_nothing_and_does_not_flood_when_started()
    {
        _log.Update(Snap(0));
        _log.SetRunning(false);
        _log.Update(Snap(1, Conn("a")));
        _log.AddBlocked(new BlockedConnection(Browser, 100, TransportProtocol.Tcp, "192.168.1.14", 50000, "1.1.1.1", 443, null, Snapshots.T0));
        Assert.Empty(All());

        _log.SetRunning(true);
        _log.Update(Snap(2, Conn("a")));

        Assert.Empty(All());
        Assert.True(_log.Get(0).IsRunning);
    }

    [Fact]
    public void Blocked_connections_are_logged()
    {
        _log.AddBlocked(new BlockedConnection(Browser, 100, TransportProtocol.Udp, "192.168.1.14", 50000, "1.1.1.1", 53, "one.one", Snapshots.T0));

        var entry = Assert.Single(All());
        Assert.Equal(ConnectionLogEvent.Blocked, entry.Event);
        Assert.Equal((TransportProtocol.Udp, "1.1.1.1", 53, "one.one"), (entry.Protocol, entry.RemoteAddress, entry.RemotePort, entry.RemoteHost));
    }

    [Fact]
    public void Get_returns_only_entries_after_an_id_and_old_ones_drop_out()
    {
        _log.Update(Snap(0));
        for (int i = 0; i < 7; i++)
            _log.Update(Snap(i + 1, Enumerable.Range(0, i + 1).Select(n => Conn("c" + n)).ToArray()));

        var all = All();
        Assert.Equal(5, all.Count);
        Assert.Equal(7, all[^1].Id);
        Assert.Equal([6L, 7L], _log.Get(5).Entries.Select(e => e.Id));
        Assert.Empty(_log.Get(7).Entries);
    }

    [Fact]
    public void Clear_empties_the_log_but_keeps_ids_growing()
    {
        _log.Update(Snap(0));
        _log.Update(Snap(1, Conn("a")));

        _log.Clear();
        Assert.Empty(All());

        _log.Update(Snap(2, Conn("a"), Conn("b")));
        Assert.Equal(2, Assert.Single(All()).Id);
    }
}

public sealed class ConnectionHistoryDatabaseTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly StatsDatabase _db;
    private static readonly DateTimeOffset Noon = StatsData.Noon;

    public ConnectionHistoryDatabaseTests() => _db = new StatsDatabase(_dir.File("stats.db"));

    public void Dispose()
    {
        _db.Dispose();
        _dir.Dispose();
    }

    [Fact]
    public void Sums_per_host_port_protocol_with_first_and_last_transfer_newest_first()
    {
        _db.Write(
        [
            StatsData.Record(Noon, StatsData.Browser, 100, 10, host: "dns.google"),
            StatsData.Record(Noon.AddHours(1), StatsData.Browser, 200, 20),
            StatsData.Record(Noon.AddHours(2), StatsData.Browser, 1, 2, address: "1.1.1.1"),
            StatsData.Record(Noon, StatsData.Game, 9, 9),
        ]);

        var rows = _db.History(new ConnectionHistoryQuery(StatsData.Browser.Id, null, Noon.AddDays(1)));

        Assert.Equal(["1.1.1.1", "8.8.8.8"], rows.Select(r => r.Address));
        var google = rows[1];
        Assert.Equal(("dns.google", 443, TransportProtocol.Tcp, 300L, 30L), (google.HostName, google.Port, google.Protocol, google.In, google.Out));
        Assert.Equal((Noon, Noon.AddHours(1)), (google.First, google.Last));
        Assert.Equal((StatsData.Browser.Id, "Browser"), (google.AppId, google.AppName));
    }

    [Fact]
    public void Without_an_app_lists_every_app_and_respects_the_range_and_row_limit()
    {
        _db.Write(
        [
            StatsData.Record(Noon.AddDays(-2), StatsData.Browser, 100),
            StatsData.Record(Noon, StatsData.Browser, 100),
            StatsData.Record(Noon.AddHours(1), StatsData.Game, 9),
        ]);

        Assert.Equal(2, _db.History(new ConnectionHistoryQuery(null, Noon.AddDays(-1), Noon.AddDays(1))).Count);
        Assert.Equal("Game", Assert.Single(_db.History(new ConnectionHistoryQuery(null, null, Noon.AddDays(1), MaxRows: 1))).AppName);
    }
}

public class ConnectionLogViewModelTests
{
    private static ConnectionLogEntry Entry(long id, ConnectionLogEvent e = ConnectionLogEvent.Connect, string app = "Browser", string remote = "8.8.8.8") =>
        new(id, Snapshots.T0, e, "a", app, 100, TransportProtocol.Tcp, "192.168.1.14", 50000, remote, 443, null);

    private static FakeService Service(Queue<ConnectionLogPage> pages) =>
        new() { Handler = (m, _) => m == Methods.ConnectionLogGet ? pages.Dequeue() : true };

    [Fact]
    public async Task Refresh_asks_for_entries_after_the_last_seen_and_shows_newest_first()
    {
        var service = Service(new([new ConnectionLogPage(true, [Entry(1), Entry(2)]), new ConnectionLogPage(true, [Entry(3)])]));
        var vm = new ConnectionLogViewModel(service);

        await vm.RefreshAsync();
        await vm.RefreshAsync();

        Assert.Equal([3L, 2L, 1L], vm.Entries.Select(e => e.Entry.Id));
        Assert.Equal(new ConnectionLogRequest(2), service.Calls.Last(c => c.Method == Methods.ConnectionLogGet).Payload);
    }

    [Fact]
    public async Task Search_narrows_what_is_shown_and_keeps_the_rest()
    {
        var service = Service(new([new ConnectionLogPage(true, [Entry(1, app: "Browser"), Entry(2, app: "Game", remote: "1.1.1.1")])]));
        var vm = new ConnectionLogViewModel(service);
        await vm.RefreshAsync();

        vm.Search = "game";
        Assert.Equal([2L], vm.Entries.Select(e => e.Entry.Id));

        vm.Search = "";
        Assert.Equal(2, vm.Entries.Count);
    }

    [Fact]
    public async Task Clear_tells_the_service_and_empties_the_list()
    {
        var service = Service(new([new ConnectionLogPage(true, [Entry(1)])]));
        var vm = new ConnectionLogViewModel(service);
        await vm.RefreshAsync();

        await vm.ClearCommand.ExecuteAsync(null);

        Assert.Empty(vm.Entries);
        Assert.Contains(service.Calls, c => c.Method == Methods.ConnectionLogClear);
    }

    [Fact]
    public async Task Start_stop_follows_the_service()
    {
        var service = Service(new([new ConnectionLogPage(true, []), new ConnectionLogPage(false, [])]));
        var vm = new ConnectionLogViewModel(service);
        await vm.RefreshAsync();
        Assert.True(vm.IsRunning);

        await vm.ToggleRunningCommand.ExecuteAsync(null);

        Assert.Equal(new ConnectionLogRunning(false), service.Calls.Single(c => c.Method == Methods.ConnectionLogSetRunning).Payload);
        Assert.False(vm.IsRunning);
    }

    [Fact]
    public async Task Csv_has_a_row_per_shown_entry()
    {
        var service = Service(new([new ConnectionLogPage(true, [Entry(1, ConnectionLogEvent.Blocked)])]));
        var vm = new ConnectionLogViewModel(service);
        await vm.RefreshAsync();

        string[] lines = vm.Csv().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);

        Assert.Equal(2, lines.Length);
        Assert.Contains("Blocked", lines[1]);
        Assert.Contains("8.8.8.8", lines[1]);
    }
}

public class ConnectionHistoryViewModelTests
{
    private static ConnectionHistoryRow Row(string app = "Browser", string address = "8.8.8.8") =>
        new("id", app, address, "dns.google", 443, TransportProtocol.Tcp, 2048, 1024, Snapshots.T0, Snapshots.T0.AddHours(1));

    [Fact]
    public async Task Show_app_loads_that_apps_history_and_clearing_loads_all()
    {
        var service = new FakeService { Handler = (_, _) => new List<ConnectionHistoryRow> { Row() } };
        var vm = new ConnectionHistoryViewModel(service, () => Snapshots.T0);

        await vm.ShowAppAsync(StatsData.Browser);

        var query = (ConnectionHistoryQuery)service.Calls.Last().Payload!;
        Assert.Equal(StatsData.Browser.Id, query.AppId);
        Assert.True(vm.HasApp);
        Assert.Contains("Browser", vm.AppText);

        await vm.ClearAppCommand.ExecuteAsync(null);
        Assert.Null(((ConnectionHistoryQuery)service.Calls.Last().Payload!).AppId);
        Assert.False(vm.HasApp);
    }

    [Theory]
    [InlineData(HistoryRange.Day, 1)]
    [InlineData(HistoryRange.Week, 7)]
    [InlineData(HistoryRange.Month, 30)]
    public async Task Range_sets_the_start_of_the_query(HistoryRange range, int days)
    {
        var service = new FakeService { Handler = (_, _) => new List<ConnectionHistoryRow>() };
        var vm = new ConnectionHistoryViewModel(service, () => Snapshots.T0);

        vm.Range = range;
        await vm.RefreshAsync();

        Assert.Equal(Snapshots.T0.AddDays(-days), ((ConnectionHistoryQuery)service.Calls.Last().Payload!).From);
    }

    [Fact]
    public async Task All_time_has_no_start_and_search_narrows_rows_for_csv()
    {
        var service = new FakeService { Handler = (_, _) => new List<ConnectionHistoryRow> { Row(), Row("Game", "1.1.1.1") } };
        var vm = new ConnectionHistoryViewModel(service, () => Snapshots.T0) { Range = HistoryRange.All };
        await vm.RefreshAsync();
        Assert.Null(((ConnectionHistoryQuery)service.Calls.Last().Payload!).From);

        vm.Search = "1.1.1";

        Assert.Equal("Game", Assert.Single(vm.Rows).Row.AppName);
        string[] lines = vm.Csv().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);
        Assert.Contains("2048", lines[1]);
    }
}
