using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using NetWarden.Client;
using NetWarden.Client.Charts;
using NetWarden.Client.Services;
using NetWarden.Client.ViewModels;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Formatting;
using NetWarden.Shared.Ipc;
using NetWarden.Shared.Storage;

namespace NetWarden.Tests.Client;

[Collection(WpfCollection.Name)]
public sealed class LayoutMemoryTests(WpfHarness wpf)
{
    private sealed record Row(string Name, int Size);

    private static DataGrid NewGrid()
    {
        var grid = new DataGrid { AutoGenerateColumns = false, ItemsSource = new List<Row> { new("b", 1), new("a", 2) } };
        grid.Columns.Add(new DataGridTextColumn { Header = "Name", Binding = new Binding("Name"), SortMemberPath = "Name", Width = 100 });
        grid.Columns.Add(new DataGridTextColumn { Header = "Size", Binding = new Binding("Size"), SortMemberPath = "Size", Width = 80 });
        return grid;
    }

    [Fact]
    public void Sort_width_order_and_hidden_columns_come_back_in_a_new_grid()
    {
        wpf.Run(() =>
        {
            int saves = 0;
            var settings = new ClientSettings();
            var memory = new LayoutMemory(settings, () => saves++);
            var first = NewGrid();
            memory.Attach(first, "Test");

            first.Columns[0].Width = 222;
            first.Columns[1].DisplayIndex = 0;
            first.Columns[1].Visibility = Visibility.Collapsed;
            memory.Sort(first, first.Columns[0], ListSortDirection.Descending);
            memory.Capture(first, "Test");
            Assert.True(saves > 0);

            var second = NewGrid();
            new LayoutMemory(settings, () => { }).Attach(second, "Test");

            Assert.Equal(222, second.Columns[0].Width.Value);
            Assert.Equal(0, second.Columns[1].DisplayIndex);
            Assert.Equal(Visibility.Collapsed, second.Columns[1].Visibility);
            Assert.Equal(ListSortDirection.Descending, second.Columns[0].SortDirection);
            var sort = Assert.Single(CollectionViewSource.GetDefaultView(second.ItemsSource).SortDescriptions);
            Assert.Equal(("Name", ListSortDirection.Descending), (sort.PropertyName, sort.Direction));
        });
    }

    [Fact]
    public void Layouts_of_columns_that_no_longer_exist_are_ignored()
    {
        wpf.Run(() =>
        {
            var settings = new ClientSettings();
            settings.Grids["Test"] = new GridLayout
            {
                SortId = "Gone",
                SortDirection = ListSortDirection.Ascending,
                Columns = [new GridColumnLayout { Id = "Gone", DisplayIndex = 5, Width = 10 }],
            };
            var grid = NewGrid();

            new LayoutMemory(settings, () => { }).Attach(grid, "Test");

            Assert.Equal(100, grid.Columns[0].Width.Value);
            Assert.Empty(CollectionViewSource.GetDefaultView(grid.ItemsSource).SortDescriptions);
        });
    }

    [Fact]
    public void Column_menu_lists_columns_and_toggling_saves_but_keeps_the_last_one()
    {
        wpf.Run(() =>
        {
            var settings = new ClientSettings();
            var memory = new LayoutMemory(settings, () => { });
            var grid = NewGrid();
            memory.Attach(grid, "Test");

            var items = memory.ColumnMenu(grid, "Test");
            Assert.Equal(["Name", "Size"], items.Select(i => (string)i.Header));

            items[1].IsChecked = false;
            Assert.Equal(Visibility.Collapsed, grid.Columns[1].Visibility);
            Assert.False(settings.Grids["Test"].Columns.Single(c => c.Id == "Size").Visible);

            items[0].IsChecked = false;
            Assert.Equal(Visibility.Visible, grid.Columns[0].Visibility);
            Assert.True(items[0].IsChecked);
        });
    }
}

[Collection(WpfCollection.Name)]
public sealed class DesktopFeatureTests(WpfHarness wpf)
{
    [Fact]
    public async Task Tray_and_hotkeys_start_on_a_real_window_and_go_away_with_it()
    {
        await wpf.RunAsync(async () =>
        {
            var settings = new ClientSettings();
            settings.Hotkeys.Add(new HotkeyBinding { Gesture = "Ctrl+Alt+Shift+F24", Target = HotkeyTargets.Limiter });
            await using var connection = new ServiceConnection(TestPipes.NewName());
            var vm = new MainViewModel(connection, wpf.Dispatcher, settings, () => { }, new IconCache(), new PortNames([]));
            var window = new MainWindow { DataContext = vm, ShowInTaskbar = false };
            window.Show();

            var tray = new FakeTray();
            window.StartDesktopFeatures(_ => tray);
            await WpfHarness.Settle();

            Assert.Null(vm.AppSettings.HotkeyError);
            Assert.False(tray.IsDisposed);
            window.ExitForTest();
            Assert.True(tray.IsDisposed);
        });
    }

    private sealed class FakeTray : ITrayIcon
    {
        public bool IsDisposed { get; private set; }
        public void Notify(string title, string text) { }
        public void Dispose() => IsDisposed = true;
    }

    /// <summary>Asks Windows itself whether the icon exists, so a leftover in the notification area fails this test.</summary>
    [Fact]
    public void Real_tray_icon_is_gone_from_windows_after_dispose() => wpf.Run(() =>
    {
        var tray = new TrayIcon(new TrayActions(() => { }, () => { }, () => { }, () => { }, _ => { }, _ => { }, _ => { },
            () => new TrayState(false, false, false, 0)));
        NOTIFYICONIDENTIFIER id;
        try
        {
            id = IdentifierOf(tray);
            Assert.True(Shell_NotifyIconGetRect(ref id, out _) >= 0); // S_OK, or S_FALSE when it sits in the overflow area.
        }
        finally
        {
            tray.Dispose();
        }
        Assert.True(Shell_NotifyIconGetRect(ref id, out _) < 0);
    });

    private static NOTIFYICONIDENTIFIER IdentifierOf(TrayIcon tray)
    {
        const System.Reflection.BindingFlags Private = System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic;
        var icon = tray.Icon;
        var window = (System.Windows.Forms.NativeWindow)typeof(System.Windows.Forms.NotifyIcon).GetField("_window", Private)!.GetValue(icon)!;
        uint iconId = (uint)typeof(System.Windows.Forms.NotifyIcon).GetField("_id", Private)!.GetValue(icon)!;
        return new NOTIFYICONIDENTIFIER
        {
            cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<NOTIFYICONIDENTIFIER>(),
            hWnd = window.Handle,
            uID = iconId,
        };
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct NOTIFYICONIDENTIFIER
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public Guid guidItem;
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct RECT
    {
        public int Left, Top, Right, Bottom;
    }

    [System.Runtime.InteropServices.DllImport("shell32.dll")]
    private static extern int Shell_NotifyIconGetRect(ref NOTIFYICONIDENTIFIER identifier, out RECT rect);

    [Fact]
    public async Task Closing_hides_the_window_when_it_should_stay_in_the_tray()
    {
        await wpf.RunAsync(async () =>
        {
            var settings = new ClientSettings { CloseToTray = true };
            await using var connection = new ServiceConnection(TestPipes.NewName());
            var vm = new MainViewModel(connection, wpf.Dispatcher, settings, () => { }, new IconCache(), new PortNames([]));
            var window = new MainWindow { DataContext = vm, ShowInTaskbar = false };
            window.Show();
            await WpfHarness.Settle();

            window.Close();

            Assert.False(window.IsVisible);
            window.ExitForTest();
        });
    }

    [Fact]
    public async Task Window_size_is_remembered_when_it_closes_and_used_by_the_next_one()
    {
        await wpf.RunAsync(async () =>
        {
            var settings = new ClientSettings();
            await using var connection = new ServiceConnection(TestPipes.NewName());
            var vm = new MainViewModel(connection, wpf.Dispatcher, settings, () => { }, new IconCache(), new PortNames([]));
            var window = new MainWindow { DataContext = vm, ShowInTaskbar = false, Left = 30, Top = 40, Width = 1000, Height = 640 };
            window.Show();
            await WpfHarness.Settle();
            window.Close();

            Assert.Equal((30.0, 40.0, 1000.0, 640.0), (settings.WindowLeft, settings.WindowTop, settings.WindowWidth, settings.WindowHeight));

            var next = new MainWindow { DataContext = new MainViewModel(connection, wpf.Dispatcher, settings, () => { }, new IconCache(), new PortNames([])), ShowInTaskbar = false };
            Assert.Equal((1000.0, 640.0), (next.Width, next.Height));
            next.Close();
        });
    }
}

public class WindowPlacementTests
{
    private static readonly Rect Screen = new(0, 0, 1920, 1040);

    [Fact]
    public void A_window_that_fits_stays_where_it_was() =>
        Assert.Equal(new Rect(100, 50, 1200, 700), WindowMemory.Fit(new Rect(100, 50, 1200, 700), Screen));

    [Fact]
    public void A_window_left_on_a_removed_monitor_comes_back()
    {
        var fitted = WindowMemory.Fit(new Rect(3000, 200, 1200, 700), Screen);

        Assert.True(Screen.Contains(fitted));
        Assert.Equal((1200.0, 700.0), (fitted.Width, fitted.Height));
    }

    [Fact]
    public void A_window_larger_than_the_screen_shrinks_to_it() =>
        Assert.Equal(Screen, WindowMemory.Fit(new Rect(-10, -10, 4000, 3000), Screen));
}

public class RememberedChoicesTests
{
    private static ActivityViewModel Activity(ClientSettings settings) =>
        new(new FakeService(), settings, () => { }, _ => null, new PortNames([]));

    [Fact]
    public void Activity_sort_survives_a_restart()
    {
        var settings = new ClientSettings();
        Activity(settings).SortBy(ActivitySortColumn.RateOut);

        var next = Activity(settings);

        Assert.Equal((ActivitySortColumn.RateOut, true), (next.SortColumn, next.SortDescending));
    }

    [Fact]
    public async Task Rule_type_filter_narrows_the_list_and_is_remembered()
    {
        static RuleView View(RuleKind kind) => new(new RuleDefinition(Guid.NewGuid(), Guid.Empty, kind, RuleDirection.In), RuleState.Active, 3, "f");
        var snapshot = new RulesSnapshot(1, [], [View(RuleKind.Limit), View(RuleKind.Quota), View(RuleKind.Firewall)]);
        var settings = new ClientSettings();
        var vm = new RulesViewModel(new FakeService { Handler = (_, _) => snapshot }, settings, () => { });
        await vm.ReloadAsync();
        Assert.Equal(3, vm.VisibleRules.Count);

        vm.KindFilter = RuleKindFilter.Quotas;

        Assert.Equal(RuleKind.Quota, Assert.Single(vm.VisibleRules).Rule.Kind);
        Assert.Equal(3, vm.Rules.Count);
        var next = new RulesViewModel(new FakeService { Handler = (_, _) => snapshot }, settings, () => { });
        await next.ReloadAsync();
        Assert.Single(next.VisibleRules);
    }

    [Theory]
    [InlineData(false, false, false, false, "", "")]
    [InlineData(true, true, false, false, "", "Blocked")]
    [InlineData(true, false, false, false, "", "Blocked in")]
    [InlineData(false, true, true, false, "100", "Blocked out, down limit 100 KB/s")]
    public void Rule_status_says_what_applies_to_an_app(bool blockedIn, bool blockedOut, bool limitedIn, bool limitedOut, string limit, string expected) =>
        Assert.Equal(expected, RuleStatus.Describe(blockedIn, blockedOut, limitedIn, limit, limitedOut, "", PriorityLevel.Normal));

    [Fact]
    public void Rule_status_includes_a_priority_other_than_normal() =>
        Assert.Equal("High priority", RuleStatus.Describe(false, false, false, "", false, "", PriorityLevel.High));

    [Fact]
    public void Layout_profile_restores_panes_and_grids()
    {
        var settings = new ClientSettings { ShowChart = false, ChartWindowSeconds = 300 };
        settings.Grids["Rules"] = new GridLayout { SortId = "Kind" };
        var profiles = new LayoutProfiles(settings, () => { });
        profiles.Save("Work");

        settings.ShowChart = true;
        settings.ChartWindowSeconds = 60;
        settings.Grids.Clear();
        Assert.True(profiles.Apply("Work"));

        Assert.False(settings.ShowChart);
        Assert.Equal(300, settings.ChartWindowSeconds);
        Assert.Equal("Kind", settings.Grids["Rules"].SortId);
        Assert.False(profiles.Apply("Missing"));
        settings.Grids["Rules"].SortId = "Changed";
        Assert.Equal("Kind", settings.LayoutProfiles["Work"].Grids["Rules"].SortId);
    }
}

public class HotkeyTests
{
    [Theory]
    [InlineData("Ctrl+Alt+L", 0x0003u, 0x4Cu)]
    [InlineData("shift + win + F5", 0x000Cu, 0x74u)]
    [InlineData("Ctrl+1", 0x0002u, 0x31u)]
    public void Parses_gestures(string text, uint modifiers, uint key)
    {
        Assert.True(HotkeyGesture.TryParse(text, out var gesture));
        Assert.Equal((modifiers, key), (gesture.Modifiers, gesture.VirtualKey));
    }

    [Theory]
    [InlineData("")]
    [InlineData("L")]
    [InlineData("Ctrl+")]
    [InlineData("Ctrl+Nope")]
    [InlineData("Ctrl+Alt")]
    public void Refuses_gestures_without_a_modifier_and_a_key(string text) =>
        Assert.False(HotkeyGesture.TryParse(text, out _));

    [Fact]
    public async Task Rule_target_toggles_that_rule()
    {
        var id = Guid.NewGuid();
        var snapshot = new RulesSnapshot(1, [], [new RuleView(new RuleDefinition(id, Guid.Empty, RuleKind.Limit, RuleDirection.In, IsEnabled: true), RuleState.Active, 3, "f")]);
        var service = new FakeService { Handler = (m, _) => m == Methods.RulesGet ? snapshot : true };
        var rules = new RulesViewModel(service);
        await rules.ReloadAsync();

        await rules.ToggleByIdAsync(id);

        Assert.Equal(new SetRuleEnabledRequest(id, false), service.Calls.Single(c => c.Method == Methods.RulesSetEnabled).Payload);
    }
}

public class SettingsViewModelTests
{
    private sealed class Runner
    {
        public List<string> Args { get; } = [];
        public int ExitCode { get; set; }

        public int Run(string args)
        {
            Args.Add(args);
            return ExitCode;
        }
    }

    [Fact]
    public void Run_on_startup_creates_an_elevated_logon_task_with_the_tray_switch()
    {
        var runner = new Runner();
        var task = new StartupTask(@"C:\Program Files\NetWarden\NetWarden.exe", runner.Run);

        Assert.True(task.Set(true));

        string args = Assert.Single(runner.Args);
        Assert.Contains("/Create", args);
        Assert.Contains("/SC ONLOGON", args);
        Assert.Contains("/RL HIGHEST", args);
        Assert.Contains(@"\""C:\Program Files\NetWarden\NetWarden.exe\"" --tray", args);
    }

    [Fact]
    public void Turning_it_off_deletes_the_task_and_failure_is_reported()
    {
        var runner = new Runner { ExitCode = 1 };
        var task = new StartupTask("x.exe", runner.Run);

        Assert.False(task.Set(false));

        Assert.Contains("/Delete", runner.Args[0]);
    }

    [Theory]
    [InlineData(true, false, true)]
    [InlineData(false, false, false)]
    [InlineData(true, true, false)]
    public void Close_hides_to_the_tray_only_when_chosen_and_not_exiting(bool closeToTray, bool exiting, bool hide) =>
        Assert.Equal(hide, TrayPolicy.HideOnClose(closeToTray, exiting));

    [Fact]
    public void Hotkeys_are_validated_and_listed()
    {
        var settings = new ClientSettings();
        var vm = new SettingsViewModel(settings, () => { }, new StartupTask("x", _ => 0));

        vm.NewHotkeyText = "nonsense";
        vm.NewHotkeyTarget = vm.HotkeyTargets[0];
        vm.AddHotkeyCommand.Execute(null);
        Assert.Empty(vm.Hotkeys);
        Assert.NotNull(vm.HotkeyError);

        vm.NewHotkeyText = "Ctrl+Alt+L";
        vm.AddHotkeyCommand.Execute(null);

        Assert.Null(vm.HotkeyError);
        Assert.Equal(("Ctrl+Alt+L", HotkeyTargets.Limiter), (settings.Hotkeys[0].Gesture, settings.Hotkeys[0].Target));

        vm.AddHotkeyCommand.Execute(null);
        Assert.NotNull(vm.HotkeyError); // The same gesture twice can't work.

        vm.RemoveHotkeyCommand.Execute(vm.Hotkeys[0]);
        Assert.Empty(settings.Hotkeys);
    }

    [Fact]
    public void Failing_to_set_startup_shows_an_error_and_keeps_the_old_value()
    {
        var settings = new ClientSettings();
        var vm = new SettingsViewModel(settings, () => { }, new StartupTask("x", _ => 5));

        vm.RunOnStartup = true;

        Assert.False(vm.RunOnStartup);
        Assert.NotNull(vm.StartupError);
    }
}

public class LocalizationTests
{
    [Fact]
    public void Translates_known_text_and_falls_back_to_english()
    {
        var loc = new Loc("ar");

        Assert.Equal("النشاط", loc["Activity"]);
        Assert.Equal("Something not translated", loc["Something not translated"]);
        Assert.True(loc.IsRightToLeft);
    }

    [Fact]
    public void English_is_the_text_itself()
    {
        var loc = new Loc("en");

        Assert.Equal("Activity", loc["Activity"]);
        Assert.False(loc.IsRightToLeft);
    }

    [Fact]
    public void Unknown_language_behaves_like_english() =>
        Assert.Equal("Activity", new Loc("xx")["Activity"]);
}

[Collection(WpfCollection.Name)]
public sealed class ChartStyleTests(WpfHarness wpf)
{
    private static byte[] Render(ChartStyle style)
    {
        var history = new RateHistory(capacity: 100);
        var t = Snapshots.T0;
        for (int i = 0; i < 30; i++)
            history.Add(new RatePoint(t.AddSeconds(i), 1000 + i * 500, 800));
        var chart = new TrafficChart { History = history, ChartStyle = style, Width = 300, Height = 120 };
        chart.Measure(new Size(300, 120));
        chart.Arrange(new Rect(0, 0, 300, 120));
        var bitmap = new RenderTargetBitmap(300, 120, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(chart);
        byte[] pixels = new byte[300 * 120 * 4];
        bitmap.CopyPixels(pixels, 300 * 4, 0);
        return pixels;
    }

    [Fact]
    public void Each_style_draws_differently() => wpf.Run(() =>
    {
        byte[] line = Render(ChartStyle.Line), column = Render(ChartStyle.Column), stacked = Render(ChartStyle.Stacked);

        Assert.False(line.SequenceEqual(column));
        Assert.False(column.SequenceEqual(stacked));
    });
}
