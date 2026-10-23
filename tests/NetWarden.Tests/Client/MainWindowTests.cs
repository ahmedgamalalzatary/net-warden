using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using Microsoft.Extensions.Logging.Abstractions;
using NetWarden.Client;
using NetWarden.Client.Services;
using NetWarden.Client.ViewModels;
using NetWarden.Core.Ipc;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Formatting;
using NetWarden.Shared.Ipc;

namespace NetWarden.Tests.Client;

/// <summary>The real window against an in-process fake service.</summary>
[Collection(WpfCollection.Name)]
public sealed class MainWindowTests(WpfHarness wpf) : IAsyncLifetime
{
    private readonly string _pipe = TestPipes.NewName();
    private IpcServer _server = null!;
    private ServiceConnection _connection = null!;
    private MainWindow _window = null!;
    private MainViewModel _vm = null!;

    private static readonly AppInfo Browser = Snapshots.App("browser", "Browser");
    private static readonly AppInfo Game = Snapshots.App("game", "Game");

    private static ActivitySnapshot Snapshot() => Snapshots.Snapshot(0,
        Snapshots.Activity(Browser, rateIn: 10, connections: [Snapshots.Conn("b1", 50000), Snapshots.Conn("b2", 50001)]),
        Snapshots.Activity(Game, rateIn: 999, connections: [Snapshots.Conn("g1", 60000)]));

    public async Task InitializeAsync()
    {
        var dispatcher = new IpcDispatcher()
            .Register(Methods.ServiceInfo, _ => Task.FromResult(new ServiceInfo("0.1.0", 1, DateTimeOffset.UtcNow, true, false, "test")))
            .Register(Methods.SettingsGet, _ => Task.FromResult(new ServiceSettings()))
            .Register(Methods.ActivityGet, _ => Task.FromResult(Snapshot()));
        _server = new IpcServer(_pipe, dispatcher, NullLogger.Instance);
        _server.Start();

        await wpf.RunAsync(async () =>
        {
            _connection = new ServiceConnection(_pipe, TimeSpan.FromSeconds(2), TimeSpan.FromMilliseconds(100));
            _vm = new MainViewModel(_connection, wpf.Dispatcher, new ClientSettings(), () => { }, new IconCache(), new PortNames([]));
            _window = new MainWindow { DataContext = _vm, Width = 1000, Height = 700 };
            _window.Show();
            _connection.Start();
            for (int i = 0; i < 100 && _vm.Activity.Rows.Count == 0; i++)
                await WpfHarness.Settle(30);
        });
    }

    public async Task DisposeAsync()
    {
        wpf.Run(() => _window.Close());
        await _connection.DisposeAsync();
        await _server.DisposeAsync();
    }

    private DataGrid Grid => _window.ActivityGrid;

    private List<string> VisibleNames() =>
        WpfHarness.Descendants<DataGridRow>(Grid).OrderBy(r => r.GetIndex()).Select(r => ((ActivityRow)r.Item).Name).ToList();

    [Fact]
    public async Task Loads_rows_from_service()
    {
        var names = await wpf.RunAsync(async () => { await WpfHarness.Settle(); return VisibleNames(); });

        Assert.Equal(["Browser", "Game"], names);
    }

    [Fact]
    public async Task Clicking_expander_shows_connection_rows()
    {
        var names = await wpf.RunAsync(async () =>
        {
            await WpfHarness.Settle();
            var firstRow = WpfHarness.Descendants<DataGridRow>(Grid).Single(r => r.GetIndex() == 0);
            var expander = WpfHarness.Descendants<ToggleButton>(firstRow).First();
            // Same path as a mouse click or screen reader.
            ((IToggleProvider)new ToggleButtonAutomationPeer(expander)).Toggle();
            await WpfHarness.Settle();
            return VisibleNames();
        });

        Assert.Equal(4, names.Count);
        Assert.Equal("Browser", names[0]);
        Assert.StartsWith("TCP", names[1]);
        Assert.Equal("Game", names[3]);
    }

    [Fact]
    public async Task Default_name_order_is_stable_when_rates_change()
    {
        var names = await wpf.RunAsync(async () =>
        {
            for (int i = 1; i <= 3; i++)
            {
                _vm.Activity.Apply(Snapshots.Snapshot(i,
                    Snapshots.Activity(Browser, rateIn: i * 1000, connections: [Snapshots.Conn("b1", 1)]),
                    Snapshots.Activity(Game, rateIn: 5, connections: [Snapshots.Conn("g1", 2)])));
                await WpfHarness.Settle();
            }
            return VisibleNames();
        });

        Assert.Equal(["Browser", "Game"], names);
    }

    [Fact]
    public async Task Header_click_sorts_through_view_model()
    {
        var names = await wpf.RunAsync(async () =>
        {
            await WpfHarness.Settle();
            var header = WpfHarness.Descendants<DataGridColumnHeader>(Grid).First(h => (string?)h.Column?.Header == "DL Rate");
            // DataGridColumnHeader sorts in its protected OnClick, which is what a mouse click runs.
            typeof(ButtonBase).GetMethod("OnClick", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
                .Invoke(header, null);
            await WpfHarness.Settle();
            return VisibleNames();
        });

        Assert.Equal(["Game", "Browser"], names);
        Assert.Equal(ActivitySortColumn.RateIn, _vm.Activity.SortColumn);
    }
}
