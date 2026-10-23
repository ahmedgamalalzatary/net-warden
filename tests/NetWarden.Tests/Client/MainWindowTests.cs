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
    private static readonly FilterDefinition BrowserFilter = new(Guid.NewGuid(), "Browser", FilterType.Filter, FilterPerType.None,
        [new FilterFunction(FilterFunctionKind.AppId, true, ["browser"])], []);
    private readonly List<RuleDefinition> _savedRules = [];

    private static ActivitySnapshot Snapshot() => Snapshots.Snapshot(0,
        Snapshots.Activity(Browser, rateIn: 10, connections: [Snapshots.Conn("b1", 50000), Snapshots.Conn("b2", 50001)]),
        Snapshots.Activity(Game, rateIn: 999, connections: [Snapshots.Conn("g1", 60000)]));

    public async Task InitializeAsync()
    {
        var dispatcher = new IpcDispatcher()
            .Register(Methods.ServiceInfo, _ => Task.FromResult(new ServiceInfo("0.1.0", 1, DateTimeOffset.UtcNow, true, false, "test")))
            .Register(Methods.SettingsGet, _ => Task.FromResult(new ServiceSettings()))
            .Register(Methods.ActivityGet, _ => Task.FromResult(Snapshot()))
            .Register(Methods.FilterStatus, _ => Task.FromResult(new PacketFilterStatus(true, true, null, 10, 2)))
            .Register(Methods.BlockerPending, _ => Task.FromResult(new List<BlockerRequest>
            {
                new(Guid.NewGuid(), Browser, 100, TransportProtocol.Tcp, ConnectionKind.Connect, "192.168.1.14", 50000,
                    "1.1.1.1", 443, null, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(1), null),
            }))
            .Register<EnsureAppFilterRequest, FilterDefinition>(Methods.FiltersEnsureForApp, (_, _) => Task.FromResult(BrowserFilter))
            .Register<RuleDefinition, RuleDefinition>(Methods.RulesSave, (r, _) =>
            {
                _savedRules.Add(r!);
                return Task.FromResult(r!);
            })
            .Register(Methods.RulesGet, _ => Task.FromResult(new RulesSnapshot(1, PredefinedFilters.All,
                PredefinedFilters.DefaultRules.Select(r => new RuleView(r, RuleState.Active, 2, "Local network")).ToList())));
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

    private void SelectTab(string header) =>
        _window.Tabs.SelectedItem = _window.Tabs.Items.OfType<TabItem>().Single(t => (string)t.Header == header);

    private List<string> VisibleNames() =>
        WpfHarness.Descendants<DataGridRow>(Grid).OrderBy(r => r.GetIndex()).Select(r => ((ActivityRow)r.Item).Name).ToList();

    [Fact]
    public async Task Rules_and_filters_tabs_show_service_data()
    {
        var (rules, filters) = await wpf.RunAsync(async () =>
        {
            for (int i = 0; i < 50 && _vm.Rules.Rules.Count == 0; i++)
                await WpfHarness.Settle(30);
            SelectTab("Rules");
            await WpfHarness.Settle();
            int ruleRows = WpfHarness.Descendants<DataGridRow>(_window.RulesGrid).Count();
            SelectTab("Filters");
            await WpfHarness.Settle();
            return (ruleRows, WpfHarness.Descendants<DataGridRow>(_window.FiltersGrid).Count());
        });

        Assert.Equal(2, rules);
        Assert.Equal(4, filters);
    }

    [Fact]
    public async Task Editor_dialogs_load_without_errors()
    {
        await wpf.RunAsync(async () =>
        {
            var filterVm = new FilterEditorViewModel(null, PredefinedFilters.All) { Name = "x" };
            filterVm.AddFunctionCommand.Execute(null);
            var filterWindow = new NetWarden.Client.Dialogs.FilterEditorWindow(filterVm, _ => Task.FromResult<string?>(null));
            filterWindow.Show();
            await WpfHarness.Settle();
            filterVm.Type = FilterType.Composite;
            await WpfHarness.Settle();
            filterWindow.Close();

            var ruleWindow = new NetWarden.Client.Dialogs.RuleEditorWindow(
                new RuleEditorViewModel(null, PredefinedFilters.All, PredefinedFilters.Internet), _ => Task.FromResult<string?>(null));
            ruleWindow.Show();
            await WpfHarness.Settle();
            ruleWindow.Close();
        });
    }

    [Fact]
    public async Task Blocker_tab_shows_status_and_pending_requests()
    {
        var (pending, status) = await wpf.RunAsync(async () =>
        {
            for (int i = 0; i < 50 && _vm.Blocker.Pending.Count == 0; i++)
                await WpfHarness.Settle(30);
            SelectTab("Blocker");
            await WpfHarness.Settle();
            return (WpfHarness.Descendants<DataGridRow>(_window.PendingGrid).Count(), _vm.Blocker.StatusText);
        });

        Assert.Equal(1, pending);
        Assert.StartsWith("Filtering connections", status);
    }

    [Fact]
    public async Task Prompt_window_shows_pending_request()
    {
        string target = await wpf.RunAsync(async () =>
        {
            for (int i = 0; i < 50 && _vm.Blocker.Pending.Count == 0; i++)
                await WpfHarness.Settle(30);
            var prompt = new NetWarden.Client.Dialogs.BlockerPromptWindow(new BlockerPromptViewModel(_vm.Blocker));
            prompt.Show();
            await WpfHarness.Settle();
            string text = ((BlockerPromptViewModel)prompt.DataContext).Target;
            prompt.Close();
            return text;
        });

        Assert.Equal("1.1.1.1 : 443 (TCP)", target);
    }

    [Fact]
    public async Task Quick_block_checkbox_creates_deny_rule_for_the_app()
    {
        await wpf.RunAsync(async () =>
        {
            await WpfHarness.Settle();
            var row = WpfHarness.Descendants<DataGridRow>(Grid).Single(r => ((ActivityRow)r.Item).Name == "Browser");
            var box = WpfHarness.Descendants<CheckBox>(row).Single(c => (string)c.Tag == "Out");
            // OnClick is what a mouse click runs (it toggles and raises Click).
            typeof(ButtonBase).GetMethod("OnClick", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
                .Invoke(box, null);
            for (int i = 0; i < 50 && _savedRules.Count == 0; i++)
                await WpfHarness.Settle(30);
        });

        var rule = Assert.Single(_savedRules);
        Assert.Equal(BrowserFilter.Id, rule.FilterId);
        Assert.Equal((RuleDirection.Out, FirewallAction.Deny), (rule.Direction, rule.Action!.Value));
    }

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
