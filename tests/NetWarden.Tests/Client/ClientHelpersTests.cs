using System.Collections.ObjectModel;
using NetWarden.Client.Charts;
using NetWarden.Client.ViewModels;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Formatting;
using NetWarden.Shared.Ipc;

namespace NetWarden.Tests.Client;

public class ListSyncTests
{
    private sealed class Item(int id)
    {
        public int Id { get; } = id;
        public override string ToString() => Id.ToString();
    }

    [Fact]
    public void Randomized_syncs_always_produce_desired_order_and_keep_identity()
    {
        var random = new Random(1234);
        var pool = Enumerable.Range(0, 30).Select(i => new Item(i)).ToArray();
        var target = new ObservableCollection<Item>();

        for (int round = 0; round < 500; round++)
        {
            var desired = pool.OrderBy(_ => random.Next()).Take(random.Next(0, pool.Length)).ToList();
            var before = target.ToHashSet();

            ListSync.Sync(target, desired);

            Assert.Equal(desired, target);
            // Items present before and after are the same instances (never recreated).
            Assert.All(target.Where(before.Contains), item => Assert.Contains(item, pool));
        }
    }

    [Fact]
    public void No_change_raises_no_collection_events()
    {
        var items = Enumerable.Range(0, 5).Select(i => new Item(i)).ToList();
        var target = new ObservableCollection<Item>(items);
        int events = 0;
        target.CollectionChanged += (_, _) => events++;

        ListSync.Sync(target, items);

        Assert.Equal(0, events);
    }
}

public class RateHistoryTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Ring_buffer_keeps_newest_samples_in_order()
    {
        var history = new RateHistory(3);
        for (int i = 0; i < 5; i++)
            history.Add(new RatePoint(T0.AddSeconds(i), i, 0));

        Assert.Equal(3, history.Count);
        Assert.Equal([2L, 3L, 4L], Enumerable.Range(0, 3).Select(i => history[i].In));
        Assert.Throws<ArgumentOutOfRangeException>(() => history[3]);
    }

    [Fact]
    public void Last_returns_window_relative_to_newest_sample()
    {
        var history = new RateHistory(100);
        for (int i = 0; i < 100; i++)
            history.Add(new RatePoint(T0.AddSeconds(i), i, 0));

        var last = history.Last(TimeSpan.FromSeconds(10));

        Assert.Equal(11, last.Count);
        Assert.Equal(89, last[0].In);
    }

    [Fact]
    public void Store_retains_only_listed_keys()
    {
        var store = new RateHistoryStore(10);
        store.Add("a", T0, 1, 1);
        store.Add("b", T0, 1, 1);

        store.Retain(["a"]);

        Assert.NotNull(store.Get("a"));
        Assert.Null(store.Get("b"));
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(3, 5)]
    [InlineData(1024, 2000)]
    [InlineData(2000, 2000)]
    [InlineData(2001, 5000)]
    [InlineData(99_999, 100_000)]
    public void Chart_scale_rounds_up_to_1_2_5_steps(long value, long expected)
    {
        Assert.Equal(expected, TrafficChart.NiceCeiling(value));
    }
}

public class InfoViewModelTests
{
    private readonly FakeService _service = new();
    private readonly InfoViewModel _vm;

    public InfoViewModelTests()
    {
        _vm = new InfoViewModel(_service, new PortNames(["https 443/tcp"]));
    }

    private static ActivityRow AppRow(AppActivity activity)
    {
        var row = new ActivityRow(activity.App.Id, 0);
        row.Update(activity);
        return row;
    }

    private string Value(string label) => _vm.Items.Single(i => i.Label == label).Value;

    [Fact]
    public async Task App_shows_identity_and_services()
    {
        var app = new AppInfo("svc:dnscache", AppKind.Service, @"C:\Windows\System32\svchost.exe", "DNS Client",
            "Microsoft Corporation", null, "10.0", [new ServiceEntry("Dnscache", "DNS Client")], null);

        await _vm.ShowAsync(AppRow(Snapshots.Activity(app, totalIn: 2048)));

        Assert.Equal("DNS Client", _vm.Title);
        Assert.Equal("System service", Value("Type"));
        Assert.Equal("DNS Client (Dnscache)", Value("Services"));
        Assert.Equal("2 KB", Value("Downloaded"));
        Assert.DoesNotContain(_vm.Items, i => i.Label == "Product");
    }

    [Fact]
    public async Task Connection_resolves_remote_host_through_service()
    {
        _service.Handler = (method, payload) =>
            method == Methods.DnsReverse && ((ReverseDnsRequest)payload!).Address == "151.101.1.1" ? "cdn.example" : null;
        var parent = AppRow(Snapshots.Activity(Snapshots.App("b", "Browser")));
        var row = new ActivityRow("c", 1) { Parent = parent };
        row.Update(Snapshots.Conn("c", 50000), new PortNames(["https 443/tcp"]));

        await _vm.ShowAsync(row);

        Assert.Equal("Browser", Value("Application"));
        Assert.Equal("Outgoing connection", Value("Type"));
        Assert.Equal("151.101.1.1 : 443 (https)", Value("Remote address"));
        Assert.Equal("cdn.example", Value("Remote host"));
    }

    [Fact]
    public async Task Unresolvable_host_and_service_errors_show_unresolved()
    {
        _service.Handler = (_, _) => new IpcDisconnectedException("gone");
        var row = new ActivityRow("c", 1);
        row.Update(Snapshots.Conn("c", 1), new PortNames([]));

        await _vm.ShowAsync(row);

        Assert.Equal("Unresolved", Value("Remote host"));
    }

    [Fact]
    public async Task Refresh_updates_values_in_place_after_snapshot()
    {
        var row = AppRow(Snapshots.Activity(Snapshots.App("x", "X"), totalIn: 1024));
        await _vm.ShowAsync(row);
        var downloaded = _vm.Items.Single(i => i.Label == "Downloaded");

        row.Update(Snapshots.Activity(Snapshots.App("x", "X"), totalIn: 4096));
        _vm.Refresh();

        Assert.Same(downloaded, _vm.Items.Single(i => i.Label == "Downloaded"));
        Assert.Equal("4 KB", downloaded.Value);
    }

    [Fact]
    public async Task Host_names_are_looked_up_once_per_address()
    {
        _service.Handler = (_, _) => "cdn.example";
        var row = new ActivityRow("c", 1);
        row.Update(Snapshots.Conn("c", 1), new PortNames([]));
        var other = new ActivityRow("d", 1);
        other.Update(Snapshots.Conn("d", 2), new PortNames([]));

        await _vm.ShowAsync(row);
        await _vm.ShowAsync(other);
        await _vm.ShowAsync(row);

        Assert.Single(_service.Calls, c => c.Method == Methods.DnsReverse);
        Assert.Equal("cdn.example", Value("Remote host"));
    }

    [Fact]
    public async Task Selecting_nothing_clears_the_pane()
    {
        await _vm.ShowAsync(AppRow(Snapshots.Activity(Snapshots.App("x", "X"))));

        await _vm.ShowAsync(null);

        Assert.Empty(_vm.Items);
        Assert.Equal("Nothing selected", _vm.Title);
    }
}
