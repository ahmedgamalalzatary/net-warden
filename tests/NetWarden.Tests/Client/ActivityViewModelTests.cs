using NetWarden.Client;
using NetWarden.Client.ViewModels;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Formatting;
using NetWarden.Shared.Ipc;

namespace NetWarden.Tests.Client;

/// <summary>Records requests and answers them from a handler.</summary>
internal sealed class FakeService : IServiceRequester
{
    public List<(string Method, object? Payload)> Calls { get; } = [];
    public Func<string, object?, object?> Handler { get; set; } = (_, _) => true;

    public Task<T?> RequestAsync<T>(string method, object? payload = null, CancellationToken ct = default)
    {
        Calls.Add((method, payload));
        object? result = Handler(method, payload);
        return result is Exception ex ? Task.FromException<T?>(ex) : Task.FromResult((T?)result);
    }
}

internal static class Snapshots
{
    public static readonly DateTimeOffset T0 = new(2026, 10, 23, 12, 0, 0, TimeSpan.Zero);

    public static AppInfo App(string id, string name, AppKind kind = AppKind.Desktop) =>
        new(id, kind, $"c:\\apps\\{name.ToLowerInvariant()}.exe", name, null, null, null, [], null);

    public static ConnectionActivity Conn(string key, int localPort, string remote = "151.101.1.1", int remotePort = 443,
        long rateIn = 0, long rateOut = 0, ConnectionKind kind = ConnectionKind.Connect,
        TransportProtocol protocol = TransportProtocol.Tcp, string local = "192.168.1.14", string state = "Established") =>
        new(key, 100, protocol, kind, state, local, localPort, remote, remotePort, rateIn, rateOut, rateIn * 10, rateOut * 10);

    public static AppActivity Activity(AppInfo app, bool online = true, long rateIn = 0, long rateOut = 0,
        long totalIn = 0, long totalOut = 0, params ConnectionActivity[] connections) =>
        new(app, online, online ? [100] : [], rateIn, rateOut, totalIn, totalOut, connections);

    public static ActivitySnapshot Snapshot(int second, params AppActivity[] apps) =>
        new(T0.AddSeconds(second), apps.Sum(a => a.RateIn), apps.Sum(a => a.RateOut),
            apps.Sum(a => a.TotalIn), apps.Sum(a => a.TotalOut), apps);
}

public class ActivityViewModelTests
{
    private readonly FakeService _service = new();
    private readonly ClientSettings _settings = new();
    private int _saves;
    private readonly ActivityViewModel _vm;

    private static readonly AppInfo Browser = Snapshots.App("browser", "Browser");
    private static readonly AppInfo Game = Snapshots.App("game", "Game");
    private static readonly AppInfo Updater = Snapshots.App("updater", "Updater");

    public ActivityViewModelTests()
    {
        _vm = new ActivityViewModel(_service, _settings, () => _saves++, _ => null, new PortNames(["https 443/tcp"]));
    }

    private ActivitySnapshot Standard(int second = 0) => Snapshots.Snapshot(second,
        Snapshots.Activity(Browser, rateIn: 500, totalIn: 9000,
            connections: [Snapshots.Conn("b1", 50000, rateIn: 300), Snapshots.Conn("b2", 50001, rateIn: 200)]),
        Snapshots.Activity(Game, rateIn: 2000, totalIn: 100, connections: [Snapshots.Conn("g1", 60000, rateIn: 2000)]),
        Snapshots.Activity(Updater, online: false, totalIn: 50));

    private string[] Names() => _vm.Rows.Select(r => r.Name).ToArray();

    [Fact]
    public void Online_filter_shows_only_online_apps_sorted_by_name()
    {
        _vm.Apply(Standard());

        Assert.Equal(["Browser", "Game"], Names());
    }

    [Theory]
    [InlineData(ActivityFilter.Offline, new[] { "Updater" })]
    [InlineData(ActivityFilter.All, new[] { "Browser", "Game", "Updater" })]
    [InlineData(ActivityFilter.Hidden, new string[0])]
    public void Filters_select_rows(ActivityFilter filter, string[] expected)
    {
        _vm.Apply(Standard());
        _vm.Filter = filter;

        Assert.Equal(expected, Names());
        Assert.Equal(filter, _settings.Filter);
    }

    [Fact]
    public void Hidden_apps_move_to_hidden_view_and_are_persisted()
    {
        _vm.Apply(Standard());
        var game = _vm.Rows.Single(r => r.Name == "Game");

        _vm.ToggleHiddenCommand.Execute(game);

        Assert.Equal(["Browser"], Names());
        Assert.Contains("game", _settings.HiddenAppIds);
        Assert.True(_saves > 0);
        _vm.Filter = ActivityFilter.Hidden;
        Assert.Equal(["Game"], Names());

        _vm.ToggleHiddenCommand.Execute(_vm.Rows.Single());
        Assert.Empty(Names());
        Assert.DoesNotContain("game", _settings.HiddenAppIds);
    }

    [Fact]
    public void Search_matches_name_path_and_connection_addresses()
    {
        _vm.Apply(Snapshots.Snapshot(0,
            Snapshots.Activity(Browser, connections: [Snapshots.Conn("b1", 1, remote: "10.9.8.7")]),
            Snapshots.Activity(Game, connections: [Snapshots.Conn("g1", 2)])));

        _vm.Search = "gam";
        Assert.Equal(["Game"], Names());

        _vm.Search = "browser.exe";
        Assert.Equal(["Browser"], Names());

        _vm.Search = "10.9.8";
        Assert.Equal(["Browser"], Names());

        _vm.Search = "  ";
        Assert.Equal(2, Names().Length);
    }

    [Fact]
    public void Expanding_shows_connections_under_their_app()
    {
        _vm.Apply(Standard());
        var browser = _vm.Rows.Single(r => r.Name == "Browser");

        browser.IsExpanded = true;

        Assert.Equal(4, _vm.Rows.Count);
        Assert.Same(browser, _vm.Rows[0]);
        Assert.All(_vm.Rows.Skip(1).Take(2), r => Assert.Same(browser, r.Parent));
        Assert.Equal("Game", _vm.Rows[3].Name);
        Assert.Equal("TCP → 151.101.1.1:443 (https)", _vm.Rows[1].Name);

        browser.IsExpanded = false;
        Assert.Equal(["Browser", "Game"], Names());
    }

    [Fact]
    public void Sorting_by_rate_puts_busiest_first_and_toggles_direction()
    {
        _vm.Apply(Standard());

        _vm.SortBy(ActivitySortColumn.RateIn);
        Assert.Equal(["Game", "Browser"], Names());
        Assert.True(_vm.SortDescending);

        _vm.SortBy(ActivitySortColumn.RateIn);
        Assert.Equal(["Browser", "Game"], Names());

        _vm.SortBy(ActivitySortColumn.TotalIn);
        Assert.Equal(["Browser", "Game"], Names());
    }

    [Fact]
    public void Children_are_sorted_with_the_same_column()
    {
        _vm.Apply(Standard());
        _vm.SortBy(ActivitySortColumn.RateIn);
        var browser = _vm.Rows.Single(r => r.Name == "Browser");
        browser.IsExpanded = true;

        var children = _vm.Rows.SkipWhile(r => r != browser).Skip(1).TakeWhile(r => !r.IsApp).ToList();
        Assert.Equal([300L, 200L], children.Select(c => c.RateIn));
    }

    [Fact]
    public void Rows_keep_identity_and_update_in_place_across_snapshots()
    {
        _vm.Apply(Standard(0));
        var game = _vm.Rows.Single(r => r.Name == "Game");
        game.IsExpanded = true;

        _vm.Apply(Snapshots.Snapshot(1,
            Snapshots.Activity(Game, rateIn: 42, totalIn: 142, connections: [Snapshots.Conn("g1", 60000, rateIn: 42)])));

        var after = _vm.Rows.Single(r => r.Name == "Game");
        Assert.Same(game, after);
        Assert.Equal(42, after.RateIn);
        Assert.True(after.IsExpanded);
        Assert.Equal(2, _vm.Rows.Count);
    }

    [Fact]
    public void Apps_missing_from_snapshot_disappear()
    {
        _vm.Apply(Standard(0));

        _vm.Apply(Snapshots.Snapshot(1, Snapshots.Activity(Game, connections: [Snapshots.Conn("g1", 1)])));

        Assert.Equal(["Game"], Names());
    }

    [Fact]
    public void Totals_and_units_are_reflected_in_text()
    {
        System.Globalization.CultureInfo.CurrentCulture = System.Globalization.CultureInfo.InvariantCulture;
        _vm.Apply(Standard());

        Assert.Equal(2500, _vm.RateIn);
        Assert.Contains("2.44 KB/s", _vm.TotalsText);
        var game = _vm.Rows.Single(r => r.Name == "Game");
        Assert.Equal("1.95 KB/s", game.RateInText);

        _vm.Units = UnitMode.Bits;

        Assert.Equal("16 Kbps", game.RateInText);
        Assert.Contains("20 Kbps", _vm.TotalsText);
        Assert.Equal(UnitMode.Bits, _settings.Units);
    }

    [Fact]
    public void History_records_computer_and_each_app()
    {
        _vm.Apply(Standard(0));
        _vm.Apply(Standard(1));

        Assert.Equal(2, _vm.History.Get(ActivityViewModel.ComputerKey)!.Count);
        Assert.Equal(2000, _vm.History.Get("game")![1].In);
    }

    [Fact]
    public void Killable_connections_are_established_ipv4_tcp_only()
    {
        _vm.Apply(Snapshots.Snapshot(0, Snapshots.Activity(Browser, connections:
        [
            Snapshots.Conn("ok", 1),
            Snapshots.Conn("v6", 2, remote: "2001:db8::1", local: "2001:db8::2"),
            Snapshots.Conn("udp", 3, protocol: TransportProtocol.Udp, kind: ConnectionKind.Listen),
            Snapshots.Conn("listen", 4, kind: ConnectionKind.Listen),
        ])));
        var app = _vm.Rows.Single();

        Assert.Equal(["ok"], _vm.KillableConnections(app).Select(c => c.Key));
    }

    [Fact]
    public async Task Kill_sends_one_request_per_killable_connection()
    {
        _vm.Apply(Standard());
        var browser = _vm.Rows.Single(r => r.Name == "Browser");

        int killed = await _vm.KillAsync(browser);

        Assert.Equal(2, killed);
        var requests = _service.Calls.Where(c => c.Method == Methods.ConnectionsKill).Select(c => (KillConnectionRequest)c.Payload!).ToList();
        Assert.Equal([50000, 50001], requests.Select(r => r.LocalPort));
        Assert.All(requests, r => Assert.Equal("151.101.1.1", r.RemoteAddress));
    }

    [Fact]
    public async Task Service_errors_are_surfaced_not_thrown()
    {
        _service.Handler = (_, _) => new IpcRemoteException(Methods.ActivityResetTotals, "nope");

        await _vm.ResetTotalsCommand.ExecuteAsync(null);

        Assert.Contains("nope", _vm.LastError);
    }

    [Fact]
    public async Task Reset_totals_calls_service()
    {
        await _vm.ResetTotalsCommand.ExecuteAsync(null);

        Assert.Equal(Methods.ActivityResetTotals, Assert.Single(_service.Calls).Method);
        Assert.Null(_vm.LastError);
    }
}
