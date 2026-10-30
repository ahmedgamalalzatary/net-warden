using System.Net;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Time.Testing;
using NetWarden.Client.ViewModels;
using NetWarden.Core.Apps;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Rules;
using NetWarden.Core.Stats;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Formatting;
using NetWarden.Shared.Ipc;
using NetWarden.Shared.Storage;
using NetWarden.Tests.Client;
using NetWarden.Tests.Stats;

namespace NetWarden.Tests.Apps;

public sealed class AppRegistryTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly FakeTimeProvider _time = new(StatsData.Noon);
    private readonly HashSet<string> _files = [StatsData.Browser.Path];
    private AppRegistry _apps;

    public AppRegistryTests() => _apps = New();

    public void Dispose() => _dir.Dispose();

    private AppRegistry New() => new(new JsonFileStore<AppsDocument>(_dir.File("apps.json")), _time, _files.Contains);

    private static ActivitySnapshot Snap(params (AppInfo App, bool Online)[] apps) =>
        new(StatsData.Noon, 0, 0, 0, 0, apps.Select(a => new AppActivity(a.App, a.Online, [], 0, 0, 0, 0, [])).ToList());

    [Fact]
    public void Online_apps_are_remembered_with_first_and_last_seen()
    {
        _apps.Observe(Snap((StatsData.Browser, true), (StatsData.Game, false)));
        _time.Advance(TimeSpan.FromHours(1));
        _apps.Observe(Snap((StatsData.Browser, true)));

        var view = Assert.Single(_apps.List());
        Assert.Equal(StatsData.Browser.Id, view.App.Id);
        Assert.Equal((StatsData.Noon, StatsData.Noon.AddHours(1)), (view.App.FirstSeen, view.App.LastSeen));
    }

    [Fact]
    public void Installed_means_the_file_exists_and_system_apps_always_are()
    {
        var system = StatsData.App("system", "System") with { Kind = AppKind.System };
        _apps.Observe(Snap((StatsData.Browser, true), (StatsData.Game, true), (system, true)));

        var views = _apps.List().ToDictionary(v => v.App.DisplayName, v => v.IsInstalled);

        Assert.True(views["Browser"]);
        Assert.False(views["Game"]);
        Assert.True(views["System"]);
    }

    [Fact]
    public void Tags_are_cleaned_saved_and_survive_a_restart_and_new_sightings()
    {
        _apps.Observe(Snap((StatsData.Browser, true)));

        _apps.SetTags(StatsData.Browser.Id, [" Work ", "work", "", "Games"]);
        _apps.Observe(Snap((StatsData.Browser, true)));
        _apps.Save();
        _apps = New();

        Assert.Equal(["Work", "Games"], _apps.TagsOf(StatsData.Browser.Id));
        Assert.Equal(["Games", "Work"], _apps.AllTags());
    }

    [Fact]
    public void Setting_tags_raises_changed_and_unknown_app_is_refused()
    {
        int changed = 0;
        _apps.TagsChanged += () => changed++;
        _apps.Observe(Snap((StatsData.Browser, true)));

        _apps.SetTags(StatsData.Browser.Id, ["a"]);

        Assert.Equal(1, changed);
        Assert.Throws<ArgumentException>(() => _apps.SetTags("nope", ["a"]));
    }

    [Fact]
    public void Delete_forgets_apps_and_a_running_one_comes_back()
    {
        _apps.Observe(Snap((StatsData.Browser, true), (StatsData.Game, true)));

        _apps.Delete([StatsData.Browser.Id]);
        Assert.Equal(["Game"], _apps.List().Select(v => v.App.DisplayName));

        _apps.Observe(Snap((StatsData.Browser, true)));
        Assert.Equal(2, _apps.List().Count);
    }
}

public sealed class NetworkRegistryTests : IDisposable
{
    private static readonly DetectedNetwork Home = new("Wi-Fi", "Intel AX200", true, "HomeNet", "AA-BB-CC-00-00-01", [IPAddress.Parse("192.168.1.14")]);
    private static readonly DetectedNetwork Office = new("Ethernet", "Realtek", false, null, "AA-BB-CC-00-00-02", [IPAddress.Parse("10.0.0.5")]);

    private readonly TempDir _dir = new();
    private readonly FakeTimeProvider _time = new(StatsData.Noon);
    private List<DetectedNetwork> _detected = [Home];
    private NetworkRegistry _networks;

    public NetworkRegistryTests() => _networks = New();

    public void Dispose() => _dir.Dispose();

    private NetworkRegistry New() => new(new JsonFileStore<NetworksDocument>(_dir.File("networks.json")), () => _detected, _time);

    [Fact]
    public void Id_identifies_ssid_and_gateway_not_the_adapter()
    {
        Assert.Equal(NetworkRegistry.IdOf(Home), NetworkRegistry.IdOf(Home with { InterfaceName = "Wi-Fi 2", InterfaceDescription = "Other card" }));
        Assert.NotEqual(NetworkRegistry.IdOf(Home), NetworkRegistry.IdOf(Home with { Ssid = "CoffeeShop" }));
        Assert.NotEqual(NetworkRegistry.IdOf(Home), NetworkRegistry.IdOf(Home with { GatewayMac = "AA-BB-CC-00-00-09" }));
    }

    [Fact]
    public void Refresh_lists_networks_with_active_state_and_remembers_old_ones()
    {
        _networks.Refresh();
        _detected = [Office];
        _time.Advance(TimeSpan.FromHours(1));
        _networks.Refresh();

        var views = _networks.List().ToDictionary(v => v.Network.Name);

        Assert.False(views["HomeNet"].IsActive);
        Assert.True(views["Ethernet"].IsActive);
        Assert.Equal(StatsData.Noon, views["HomeNet"].Network.LastSeen);
        Assert.True(views["HomeNet"].Network.IsWifi);
        Assert.Equal("AA-BB-CC-00-00-01", views["HomeNet"].Network.GatewayMac);
    }

    [Fact]
    public void Networks_survive_a_restart()
    {
        _networks.Refresh();
        _networks.Save();
        _detected = [];

        _networks = New();
        _networks.Refresh();

        Assert.False(Assert.Single(_networks.List()).IsActive);
    }

    [Fact]
    public void Flow_network_comes_from_its_local_address_falling_back_to_the_first_active()
    {
        _detected = [Home, Office];
        _networks.Refresh();

        Assert.Equal(NetworkRegistry.IdOf(Office), _networks.NetworkOf(IPAddress.Parse("10.0.0.5")));
        Assert.Equal(NetworkRegistry.IdOf(Home), _networks.NetworkOf(IPAddress.Any));
        Assert.Equal(NetworkRegistry.IdOf(Home), _networks.NetworkOf(IPAddress.Parse("::ffff:192.168.1.14")));
    }

    [Fact]
    public void No_network_means_no_id()
    {
        _detected = [];
        _networks.Refresh();

        Assert.Null(_networks.NetworkOf(IPAddress.Any));
    }

    [Fact]
    public void Changed_fires_only_when_the_active_set_changes()
    {
        int changed = 0;
        _networks.Changed += () => changed++;

        _networks.Refresh();
        _networks.Refresh();
        Assert.Equal(1, changed);

        _detected = [Office];
        _networks.Refresh();
        Assert.Equal(2, changed);
    }

    [Fact]
    public void Only_inactive_networks_can_be_deleted()
    {
        _networks.Refresh();
        string id = NetworkRegistry.IdOf(Home);
        Assert.Throws<ArgumentException>(() => _networks.Delete(id));

        _detected = [];
        _networks.Refresh();
        _networks.Delete(id);

        Assert.Empty(_networks.List());
    }

    [Fact]
    public void The_real_probe_runs_and_lists_no_loopback()
    {
        foreach (var network in NetworkProbe.Detect())
            Assert.DoesNotContain(network.Addresses, IPAddress.IsLoopback);
    }
}

public sealed class TagAndNetworkFilterTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly RuleRepository _rules;

    public TagAndNetworkFilterTests() =>
        _rules = new RuleRepository(new JsonFileStore<RulesDocument>(_dir.File("rules.json")), new ZoneClassifier([]), TimeProvider.System);

    public void Dispose() => _dir.Dispose();

    private FlowContextFactory Factory(string? tag, string? network) => new(
        _ => StatsData.Browser, _ => null, new DnsMap(),
        _ => tag is null ? [] : [tag],
        _ => network);

    private bool Blocked(FlowContextFactory factory, FilterFunction function)
    {
        var filter = _rules.EnsureFilter("f", [function]);
        _rules.SaveRule(new RuleDefinition(Guid.Empty, filter.Id, RuleKind.Firewall, RuleDirection.Both, Action: FirewallAction.Deny));
        var flow = factory.Create(100, TransportProtocol.Tcp, ConnectionKind.Connect, IPAddress.Parse("192.168.1.14"), 50000, IPAddress.Parse("8.8.8.8"), 443)!;
        return _rules.Current.Evaluate(flow, FirewallAction.Allow, FirewallAction.Allow, DateTimeOffset.UtcNow).Firewall == FirewallAction.Deny;
    }

    [Fact]
    public void Tag_filter_matches_the_apps_tags() =>
        Assert.True(Blocked(Factory("Games", null), new FilterFunction(FilterFunctionKind.Tag, true, ["games"])));

    [Fact]
    public void Tag_filter_skips_other_tags() =>
        Assert.False(Blocked(Factory("Work", null), new FilterFunction(FilterFunctionKind.Tag, true, ["Games"])));

    [Fact]
    public void Network_filter_matches_the_flows_network() =>
        Assert.True(Blocked(Factory(null, "net-1"), new FilterFunction(FilterFunctionKind.Network, true, ["net-1"])));

    [Fact]
    public void Network_filter_negated_matches_elsewhere() =>
        Assert.True(Blocked(Factory(null, "net-2"), new FilterFunction(FilterFunctionKind.Network, false, ["net-1"])));

    [Fact]
    public void Invalidate_publishes_a_new_generation()
    {
        long before = _rules.Current.Generation;
        long? raised = null;
        _rules.Changed += g => raised = g;

        _rules.Invalidate();

        Assert.True(_rules.Current.Generation > before);
        Assert.Equal(_rules.Current.Generation, raised);
    }
}

public sealed class StatsNetworkTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static readonly DateTimeOffset Noon = StatsData.Noon;

    private static StatsQuery Query(StatsGroupBy groupBy = StatsGroupBy.App, string? network = null) =>
        new(Noon, Noon.AddHours(1), StatsBucket.Minute, groupBy, NetworkId: network);

    [Fact]
    public void Query_filters_and_groups_by_network()
    {
        using var db = new StatsDatabase(_dir.File("stats.db"));
        db.Write(
        [
            StatsData.Record(Noon, StatsData.Browser, 100) with { Network = "home", NetworkName = "HomeNet" },
            StatsData.Record(Noon, StatsData.Browser, 50) with { Network = "office", NetworkName = "Ethernet" },
        ]);

        var geo = CountryLookup.Empty;
        Assert.Equal(100, db.Query(Query(network: "home"), geo, TimeZoneInfo.Utc).TotalIn);
        var rows = db.Query(Query(StatsGroupBy.Network), geo, TimeZoneInfo.Utc).Rows;
        Assert.Equal([("home", "HomeNet", 100L), ("office", "Ethernet", 50L)], rows.Select(r => (r.Key, r.Label, r.In)));
    }

    [Fact]
    public void Same_minute_on_two_networks_stays_two_records_and_roll_up_keeps_them_apart()
    {
        using var db = new StatsDatabase(_dir.File("stats.db"));
        db.Write(
        [
            StatsData.Record(Noon.AddMinutes(1), StatsData.Browser, 100) with { Network = "home" },
            StatsData.Record(Noon.AddMinutes(2), StatsData.Browser, 50) with { Network = "office" },
        ]);

        db.RollUp(Noon.AddDays(5));

        Assert.Equal(100, db.Query(Query(network: "home"), CountryLookup.Empty, TimeZoneInfo.Utc).TotalIn);
    }

    [Fact]
    public void A_database_from_before_networks_is_upgraded_and_keeps_its_data()
    {
        string path = _dir.File("old.db");
        using (var old = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            old.Open();
            using var cmd = old.CreateCommand();
            cmd.CommandText = $"""
                CREATE TABLE apps(id INTEGER PRIMARY KEY, app_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL, path TEXT NOT NULL);
                CREATE TABLE hosts(id INTEGER PRIMARY KEY, address TEXT NOT NULL UNIQUE, name TEXT);
                CREATE TABLE users(id INTEGER PRIMARY KEY, sid TEXT NOT NULL UNIQUE, name TEXT);
                CREATE TABLE traffic(slot INTEGER NOT NULL, app INTEGER NOT NULL, host INTEGER NOT NULL, port INTEGER NOT NULL, protocol INTEGER NOT NULL,
                    zone INTEGER NOT NULL, user INTEGER NOT NULL, bytes_in INTEGER NOT NULL, bytes_out INTEGER NOT NULL,
                    PRIMARY KEY(slot, app, host, port, protocol, zone, user)) WITHOUT ROWID;
                INSERT INTO apps VALUES(1, 'a', 'Old app', 'c:\a.exe');
                INSERT INTO hosts VALUES(1, '8.8.8.8', NULL);
                INSERT INTO users VALUES(1, 's', NULL);
                INSERT INTO traffic VALUES({Noon.ToUnixTimeSeconds()}, 1, 1, 443, 0, 0, 1, 777, 5);
                """;
            cmd.ExecuteNonQuery();
        }

        using var db = new StatsDatabase(path);
        db.Write([StatsData.Record(Noon, StatsData.Browser, 1) with { Network = "home" }]);

        Assert.Equal(778, db.Query(Query(), CountryLookup.Empty, TimeZoneInfo.Utc).TotalIn);
        Assert.Equal(1, db.Query(Query(network: "home"), CountryLookup.Empty, TimeZoneInfo.Utc).TotalIn);
    }

    [Fact]
    public void Deleting_stats_of_an_app_removes_only_its_records()
    {
        using var db = new StatsDatabase(_dir.File("stats.db"));
        db.Write([StatsData.Record(Noon, StatsData.Browser, 100), StatsData.Record(Noon, StatsData.Game, 5)]);

        db.Delete(new StatsDeleteRequest(null, null, StatsData.Browser.Id));

        Assert.Equal(5, db.Query(Query(), CountryLookup.Empty, TimeZoneInfo.Utc).TotalIn);
    }
}

public class WhoisClientTests
{
    private static WhoisClient Client(Dictionary<string, string> servers, List<(string Host, string Query)> asked) =>
        new((host, query, _) =>
        {
            asked.Add((host, query));
            return Task.FromResult(servers[host]);
        });

    [Fact]
    public async Task Follows_the_iana_referral_to_the_registry()
    {
        var asked = new List<(string, string)>();
        var client = Client(new()
        {
            ["whois.iana.org"] = "% IANA\nrefer:        whois.arin.net\nstatus: ALLOCATED",
            ["whois.arin.net"] = "NetName: GOOGLE",
        }, asked);

        string text = await client.LookupAsync(IPAddress.Parse("8.8.8.8"), default);

        Assert.Equal("NetName: GOOGLE", text);
        Assert.Equal([("whois.iana.org", "8.8.8.8"), ("whois.arin.net", "n + 8.8.8.8")], asked);
    }

    [Fact]
    public async Task Follows_a_registry_referral_and_stops_on_a_loop()
    {
        var asked = new List<(string, string)>();
        var client = Client(new()
        {
            ["whois.iana.org"] = "refer: whois.arin.net",
            ["whois.arin.net"] = "ReferralServer: whois://whois.ripe.net\nNetName: X",
            ["whois.ripe.net"] = "ReferralServer: whois://whois.arin.net\nnetname: Y",
        }, asked);

        string text = await client.LookupAsync(IPAddress.Parse("2.24.8.179"), default);

        Assert.Contains("netname: Y", text);
        Assert.Equal(3, asked.Count);
    }

    [Fact]
    public async Task Without_a_referral_returns_the_first_answer()
    {
        var client = Client(new() { ["whois.iana.org"] = "nothing here" }, []);

        Assert.Equal("nothing here", await client.LookupAsync(IPAddress.Parse("10.0.0.1"), default));
    }
}

public class AppsViewModelTests
{
    private static KnownAppView View(string id, string name, bool installed = true, params string[] tags) =>
        new(new KnownApp(id, AppKind.Desktop, $"c:\\{name}.exe", name, null, StatsData.Noon, StatsData.Noon, tags), installed);

    private static FakeService Service(params KnownAppView[] apps) => new()
    {
        Handler = (m, _) => m switch
        {
            Methods.AppsList => apps.ToList(),
            _ => true,
        },
    };

    [Fact]
    public async Task Loads_sorted_and_filters_by_search_and_availability()
    {
        var vm = new AppsViewModel(Service(View("z", "Zoom", tags: "Work"), View("b", "Browser", installed: false)));
        await vm.RefreshAsync();
        Assert.Equal(["Browser", "Zoom"], vm.Rows.Select(r => r.Name));

        vm.Search = "work";
        Assert.Equal(["Zoom"], vm.Rows.Select(r => r.Name));

        vm.Search = "";
        vm.Availability = AppAvailability.Uninstalled;
        Assert.Equal(["Browser"], vm.Rows.Select(r => r.Name));
    }

    [Fact]
    public async Task Save_tags_sends_the_comma_separated_text()
    {
        var service = Service(View("b", "Browser", true, "old"));
        var vm = new AppsViewModel(service);
        await vm.RefreshAsync();
        vm.Selected = vm.Rows[0];
        Assert.Equal("old", vm.TagsText);

        vm.TagsText = "Games, Work";
        await vm.SaveTagsCommand.ExecuteAsync(null);

        var request = (SetAppTagsRequest)service.Calls.Single(c => c.Method == Methods.AppsSetTags).Payload!;
        Assert.Equal("b", request.AppId);
        Assert.Equal(["Games", "Work"], request.Tags);
    }

    [Fact]
    public async Task Delete_sends_the_selection_and_the_stats_choice()
    {
        var service = Service(View("b", "Browser"));
        var vm = new AppsViewModel(service);
        await vm.RefreshAsync();

        await vm.DeleteAsync(vm.Rows[0], deleteStats: true);

        Assert.Equal(new[] { "b" }, ((DeleteAppsRequest)service.Calls.Single(c => c.Method == Methods.AppsDelete).Payload!).AppIds);
        Assert.True(((DeleteAppsRequest)service.Calls.Single(c => c.Method == Methods.AppsDelete).Payload!).DeleteStats);
    }

    [Fact]
    public async Task All_tags_lists_each_tag_once()
    {
        var vm = new AppsViewModel(Service(View("a", "A", true, "Work", "Games"), View("b", "B", true, "work")));
        await vm.RefreshAsync();

        Assert.Equal(["Games", "Work"], vm.AllTags);
    }
}

public class NetworksViewModelTests
{
    private static NetworkView View(string id, string name, bool active, bool wifi = false) =>
        new(new KnownNetwork(id, name, "Ethernet", "Realtek", wifi, wifi ? name : null, "AA-BB", StatsData.Noon, StatsData.Noon), active);

    [Fact]
    public async Task Rows_show_active_first_and_describe_the_type()
    {
        var vm = new NetworksViewModel(new FakeService { Handler = (_, _) => new List<NetworkView> { View("o", "Old", false), View("h", "Home", true, wifi: true) } });

        await vm.RefreshAsync();

        Assert.Equal(["Home", "Old"], vm.Rows.Select(r => r.Name));
        Assert.Equal("Wi-Fi", vm.Rows[0].Type);
        Assert.Equal("Wired", vm.Rows[1].Type);
    }

    [Fact]
    public async Task Delete_calls_the_service_for_the_row()
    {
        var service = new FakeService { Handler = (m, _) => m == Methods.NetworksList ? new List<NetworkView> { View("o", "Old", false) } : true };
        var vm = new NetworksViewModel(service);
        await vm.RefreshAsync();

        await vm.DeleteCommand.ExecuteAsync(vm.Rows[0]);

        Assert.Equal(new DeleteNetworkRequest("o"), service.Calls.Single(c => c.Method == Methods.NetworksDelete).Payload);
    }
}

public class InfoGeoTests
{
    private static ActivityRow ConnectionRow(string remote)
    {
        var app = Snapshots.Activity(Snapshots.App("a", "App"), connections: [Snapshots.Conn("c", 50000, remote)]);
        var parent = new ActivityRow("a", 0);
        parent.Update(app);
        var row = new ActivityRow("c", 1) { Parent = parent };
        row.Update(app.Connections[0], new PortNames([]));
        return row;
    }

    [Fact]
    public async Task Connection_info_shows_country_and_offers_lookups_for_public_addresses()
    {
        var service = new FakeService
        {
            Handler = (m, _) => m switch
            {
                Methods.GeoLookup => new GeoInfo("US", "United States"),
                _ => null,
            },
        };
        var vm = new InfoViewModel(service, new PortNames([]));

        await vm.ShowAsync(ConnectionRow("8.8.8.8"));

        Assert.Equal("United States (US)", vm.Items.Single(i => i.Label == "Country").Value);
        Assert.Equal("8.8.8.8", vm.LookupAddress);
        Assert.Equal("us", vm.FlagCode);
    }

    [Fact]
    public async Task Private_addresses_offer_no_lookup()
    {
        var service = new FakeService { Handler = (_, _) => null };
        var vm = new InfoViewModel(service, new PortNames([]));

        await vm.ShowAsync(ConnectionRow("192.168.1.1"));

        Assert.Null(vm.LookupAddress);
        Assert.DoesNotContain(vm.Items, i => i.Label == "Country");
    }

    [Fact]
    public void Web_links_escape_the_address()
    {
        Assert.Equal("https://ipinfo.io/2001:db8::1", InfoViewModel.WebLink("2001:db8::1"));
        Assert.Equal("https://www.openstreetmap.org/search?query=United%20States", InfoViewModel.MapLink("United States"));
    }
}
