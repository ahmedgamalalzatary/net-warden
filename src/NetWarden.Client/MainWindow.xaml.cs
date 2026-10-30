using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using NetWarden.Client.Dialogs;
using NetWarden.Client.Services;
using NetWarden.Client.ViewModels;
using NetWarden.Shared.Contracts;

namespace NetWarden.Client;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (ViewModel is not { } vm)
                return;
            vm.Activity.Updated += Chart.Refresh;
            vm.Activity.Updated += RailChart.Refresh;
            HotkeyTargetNameConverter.Settings = vm.AppSettings;
            AttachMemory(vm);
            vm.Blocker.RequestArrived += _ => ShowBlockerPrompt();
            vm.QuotaExceeded += ShowQuotaAlert;
            vm.PropertyChanged += OnViewModelPropertyChanged;
            UpdateInfoPaneWidth();
        };
        // Combo boxes and grids inside the tabs raise SelectionChanged too; only the tab control's own counts.
        Tabs.SelectionChanged += (_, e) =>
        {
            if (e.OriginalSource == Tabs && ViewModel is { } vm)
            {
                vm.IsPrioritiesTabVisible = Tabs.SelectedItem == PrioritiesTab;
                vm.IsStatsTabVisible = Tabs.SelectedItem == StatsTab;
                vm.IsQuotasTabVisible = Tabs.SelectedItem == QuotasTab;
                vm.IsLogTabVisible = Tabs.SelectedItem == LogTab;
                vm.IsHistoryTabVisible = Tabs.SelectedItem == HistoryTab;
                if (Tabs.SelectedItem is TabItem { Header: string page })
                {
                    SyncNav(page);
                    vm.Page = page;
                }
                if (Tabs.SelectedItem == AppsTab && vm.IsConnected)
                    _ = vm.Apps.RefreshAsync();
                if (Tabs.SelectedItem == NetworksTab && vm.IsConnected)
                    _ = vm.Networks.RefreshAsync();
                if (vm.IsLogTabVisible && vm.IsConnected)
                    _ = vm.Log.RefreshAsync();
            }
        };
    }

    private MainViewModel? ViewModel => DataContext as MainViewModel;

    /// <summary>The name of every page, in order.</summary>
    public IReadOnlyList<string> PageNames => Tabs.Items.OfType<TabItem>().Select(t => (string)t.Header).ToList();

    public void ShowPage(string name) => Tabs.SelectedItem = Tabs.Items.OfType<TabItem>().Single(t => (string)t.Header == name);

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(MainViewModel.ShowInfoPane) or nameof(MainViewModel.HasSelection))
            UpdateInfoPaneWidth();
    }

    /// <summary>The inspector takes room only when there is something to inspect.</summary>
    private void UpdateInfoPaneWidth()
    {
        bool show = ViewModel is { ShowInfoPane: true, HasSelection: true };
        var column = ActivityArea.ColumnDefinitions[2];
        column.MinWidth = show ? 240 : 0;
        column.Width = show ? new GridLength(ViewModel!.InfoPaneWidth) : new GridLength(0);
        InspectorPane.Visibility = InspectorSplitter.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
    }

    private void InspectorSplitter_DragCompleted(object sender, System.Windows.Controls.Primitives.DragCompletedEventArgs e)
    {
        if (ViewModel is { } vm)
            vm.InfoPaneWidth = ActivityArea.ColumnDefinitions[2].ActualWidth;
    }

    // ----- Navigation and what is remembered -----

    private LayoutMemory? _layout;
    private HotkeyManager? _hotkeys;
    private ITrayIcon? _tray;
    private bool _exiting;

    private void Nav_Click(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton { Tag: string page })
            ShowPage(page);
    }

    private void SyncNav(string page)
    {
        foreach (var item in Nav.Children.OfType<RadioButton>().Append(NavSettings))
            item.IsChecked = (string)item.Tag == page;
    }

    private IEnumerable<(DataGrid Grid, string Key, bool RememberSort)> Grids =>
    [
        (ActivityGrid, "Activity", false), (StatsGrid, "Statistics", true), (LogGrid, "Log", false), (HistoryGrid, "History", true),
        (RulesGrid, "Rules", true), (PendingGrid, "Pending", true), (QuotasGrid, "Quotas", true), (FiltersGrid, "Filters", true),
        (AppsGrid, "Apps", true), (NetworksGrid, "Networks", true),
    ];

    private void AttachMemory(MainViewModel vm)
    {
        _layout = new LayoutMemory(vm.Settings, vm.SaveSettings);
        foreach (var (grid, key, rememberSort) in Grids)
            _layout.Attach(grid, key, rememberSort);
        ShowActivitySort(vm);
        vm.AppSettings.ProfileApplied += () =>
        {
            foreach (var (grid, key, rememberSort) in Grids)
                _layout.Restore(grid, key, rememberSort);
            vm.RefreshLayoutChoices();
            UpdateInfoPaneWidth();
        };
        vm.AppSettings.AppearanceChanged += () => Chart.Refresh();

        var s = vm.Settings;
        if (!double.IsNaN(s.WindowLeft))
        {
            var fitted = WindowMemory.Fit(new Rect(s.WindowLeft, s.WindowTop, s.WindowWidth, s.WindowHeight), SystemParameters.WorkArea);
            WindowStartupLocation = WindowStartupLocation.Manual;
            (Left, Top, Width, Height) = (fitted.Left, fitted.Top, fitted.Width, fitted.Height);
        }
        if (s.WindowMaximized)
            WindowState = WindowState.Maximized;
        Closing += (_, e) =>
        {
            RememberWindow(s, vm);
            if (TrayPolicy.HideOnClose(s.CloseToTray, _exiting))
            {
                e.Cancel = true;
                Hide();
            }
        };
        StateChanged += (_, _) =>
        {
            if (WindowState == WindowState.Minimized && s.MinimizeToTray)
                Hide();
        };
        Dispatcher.BeginInvoke(() =>
        {
            ShowPage(PageNames.Contains(s.Page) ? s.Page : "Activity");
            SyncNav(s.Page);
        });
    }

    private void RememberWindow(ClientSettings s, MainViewModel vm)
    {
        s.WindowMaximized = WindowState == WindowState.Maximized;
        var bounds = WindowState == WindowState.Normal ? new Rect(Left, Top, Width, Height) : RestoreBounds;
        if (!bounds.IsEmpty)
            (s.WindowLeft, s.WindowTop, s.WindowWidth, s.WindowHeight) = (bounds.Left, bounds.Top, bounds.Width, bounds.Height);
        vm.SaveSettings();
    }

    private void ShowActivitySort(MainViewModel vm)
    {
        foreach (var c in ActivityGrid.Columns)
            c.SortDirection = c.SortMemberPath == vm.Activity.SortColumn.ToString()
                ? (vm.Activity.SortDescending ? ListSortDirection.Descending : ListSortDirection.Ascending)
                : null;
    }

    /// <summary>Sets up what needs a real, running desktop: the tray icon and system-wide hotkeys.</summary>
    /// <param name="createTray">Makes the tray icon; the real one unless a test supplies its own.</param>
    public void StartDesktopFeatures(Func<TrayActions, ITrayIcon>? createTray = null)
    {
        if (ViewModel is not { } vm)
            return;
        _tray = (createTray ?? (actions => new TrayIcon(actions)))(new TrayActions(
            ToggleWindow,
            ShowFromTray,
            () =>
            {
                ShowFromTray();
                ShowPage("Blocker");
            },
            ExitForReal,
            on => _ = vm.UpdateSettingsAsync(s => s.IsLimiterEnabled = on),
            on => _ = vm.UpdateSettingsAsync(s => s.IsBlockerEnabled = on),
            on => _ = vm.UpdateSettingsAsync(s => s.IsPriorityEnabled = on),
            () => new TrayState(vm.IsLimiterEnabled, vm.IsBlockerEnabled, vm.IsPriorityEnabled, vm.Blocker.Pending.Count)));
        Closed += (_, _) =>
        {
            _tray.Dispose();
            _hotkeys?.Dispose();
        };

        _hotkeys = new HotkeyManager(new System.Windows.Interop.WindowInteropHelper(this).EnsureHandle(), target =>
        {
            if (target == HotkeyTargets.ShowWindow)
                ToggleWindow();
            else
                _ = vm.RunTargetAsync(target);
        });
        void Register() => vm.AppSettings.ShowRefusedHotkeys(_hotkeys.Register(vm.AppSettings.Hotkeys));
        vm.AppSettings.HotkeysChanged += Register;
        Register();

        vm.Blocker.RequestArrived += _ =>
        {
            if (!IsVisible && vm.AppSettings.Notifications)
                _tray.Notify("NetWarden", vm.Blocker.Pending.Count + " " + Loc.Current["waiting connection requests"]);
        };
    }

    private void ToggleWindow()
    {
        if (IsVisible && WindowState != WindowState.Minimized)
            Hide();
        else
            ShowFromTray();
    }

    private void ShowFromTray()
    {
        Show();
        if (WindowState == WindowState.Minimized)
            WindowState = WindowState.Normal;
        Activate();
    }

    /// <summary>Closes for good, whatever the tray settings say.</summary>
    internal void ExitForTest() => ExitForReal();

    private void ExitForReal()
    {
        _exiting = true;
        Close();
    }

    private void RemoveHotkey_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is HotkeyBinding binding)
            ViewModel?.AppSettings.RemoveHotkeyCommand.Execute(binding);
    }

    /// <summary>Pressing a combination in the box writes it out.</summary>
    private void HotkeyBox_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        Key key = e.Key == Key.System ? e.SystemKey : e.Key;
        if (key is Key.Tab or Key.LeftCtrl or Key.RightCtrl or Key.LeftAlt or Key.RightAlt or Key.LeftShift or Key.RightShift or Key.LWin or Key.RWin || ViewModel is not { } vm)
            return;
        e.Handled = true;
        string name = key is >= Key.D0 and <= Key.D9 ? ((char)('0' + (key - Key.D0))).ToString() : key.ToString();
        var parts = new List<string>();
        if (Keyboard.Modifiers.HasFlag(ModifierKeys.Control))
            parts.Add("Ctrl");
        if (Keyboard.Modifiers.HasFlag(ModifierKeys.Alt))
            parts.Add("Alt");
        if (Keyboard.Modifiers.HasFlag(ModifierKeys.Shift))
            parts.Add("Shift");
        if (Keyboard.Modifiers.HasFlag(ModifierKeys.Windows))
            parts.Add("Win");
        parts.Add(name);
        vm.AppSettings.NewHotkeyText = string.Join("+", parts);
    }

    private void ActivityGrid_Sorting(object sender, DataGridSortingEventArgs e)
    {
        // The view model owns ordering (apps sorted, children kept under their app).
        e.Handled = true;
        if (ViewModel is not { } vm || !Enum.TryParse(e.Column.SortMemberPath, out ActivitySortColumn column))
            return;
        vm.Activity.SortBy(column);
        foreach (var c in ActivityGrid.Columns)
            c.SortDirection = null;
        e.Column.SortDirection = vm.Activity.SortDescending ? ListSortDirection.Descending : ListSortDirection.Ascending;
    }

    private void ActivityGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is DependencyObject source && ItemsControl.ContainerFromElement(ActivityGrid, source) is DataGridRow { Item: ActivityRow row })
            ViewModel?.Activity.ToggleExpandedCommand.Execute(row);
    }

    private static ActivityRow? RowOf(object sender) =>
        (sender as FrameworkElement)?.DataContext as ActivityRow;

    private void RowMenu_Opened(object sender, RoutedEventArgs e)
    {
        if (sender is not ContextMenu menu || menu.DataContext is not ActivityRow row || ViewModel is not { } vm)
            return;
        foreach (var item in menu.Items.OfType<MenuItem>())
        {
            switch (item.Tag)
            {
                case "rule":
                    item.IsEnabled = row.IsApp && vm.IsConnected;
                    break;
                case "expand":
                    item.IsEnabled = row is { IsApp: true, HasChildren: true };
                    break;
                case "history":
                    item.IsEnabled = row.IsApp && vm.IsConnected;
                    break;
                case "kill":
                    int n = vm.Activity.KillableConnections(row).Count;
                    item.IsEnabled = n > 0 && vm.IsConnected;
                    item.ToolTip = n > 0 ? null : "Only IPv4 TCP connections can be killed.";
                    break;
                case "hide":
                    item.IsEnabled = row.IsApp;
                    item.Header = row.IsApp && vm.Activity.IsHidden(row) ? "Unhide app" : "Hide app";
                    break;
                case "folder":
                    item.IsEnabled = row.IsApp && row.App?.App.Kind != AppKind.System && System.IO.File.Exists(row.App?.App.Path);
                    break;
            }
        }
    }

    private void Expand_Click(object sender, RoutedEventArgs e) => ViewModel?.Activity.ToggleExpandedCommand.Execute(RowOf(sender));

    private void Hide_Click(object sender, RoutedEventArgs e) => ViewModel?.Activity.ToggleHiddenCommand.Execute(RowOf(sender));

    private async void Kill_Click(object sender, RoutedEventArgs e)
    {
        if (RowOf(sender) is not { } row || ViewModel is not { } vm)
            return;
        int count = vm.Activity.KillableConnections(row).Count;
        if (count == 0)
        {
            ShowError("This app has no connection that can be killed. Windows only allows it for IPv4 TCP.");
            return;
        }
        string what = count == 1 ? "1 connection" : $"{count} connections";
        if (MessageBox.Show(this, $"Kill {what} of {(row.IsApp ? row.Name : row.Parent?.Name)}?", "Kill connections",
                MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK)
            return;
        await vm.Activity.KillAsync(row);
    }

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        if (RowOf(sender) is { } row)
            Clipboard.SetText(row.IsApp ? $"{row.Name}\t{row.Detail}" : row.Name);
    }

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        if (RowOf(sender)?.App?.App.Path is { } path && System.IO.File.Exists(path))
            Process.Start("explorer.exe", $"/select,\"{path}\"");
    }

    private async void ResetTotals_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm)
            return;
        if (MessageBox.Show(this, "Reset download and upload totals for all apps?", "Reset totals",
                MessageBoxButton.OKCancel, MessageBoxImage.Question) == MessageBoxResult.OK)
            await vm.Activity.ResetTotalsCommand.ExecuteAsync(null);
    }

    // ----- Filters and rules -----

    private async void AddRuleForRow_Click(object sender, RoutedEventArgs e)
    {
        if (RowOf(sender)?.App?.App is not { } app || ViewModel is not { } vm)
            return;
        if (await vm.Rules.EnsureAppFilterAsync(app) is { } filter)
            OpenRuleEditor(null, filter.Id);
        else
            ShowError(vm.Rules.LastError);
    }

    private void AddFilter_Click(object sender, RoutedEventArgs e) => OpenFilterEditor(null);

    private void EditFilter_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel?.Rules.SelectedFilter is { } item)
            OpenFilterEditor(item.Filter);
    }

    private void FiltersGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e) => EditFilter_Click(sender, e);

    private async void DeleteFilter_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm || vm.Rules.SelectedFilter is not { } item)
            return;
        if (item.IsPredefined)
        {
            ShowError("Predefined filters can't be deleted.");
            return;
        }
        string rules = item.RuleCount > 0 ? $" Its {item.RuleCount} rule(s) will be deleted too." : "";
        if (Confirm($"Delete filter '{item.Name}'?{rules}", "Delete filter") && !await vm.Rules.DeleteFilterAsync(item))
            ShowError(vm.Rules.LastError);
    }

    private void AddRuleForFilter_Click(object sender, RoutedEventArgs e) =>
        OpenRuleEditor(null, ViewModel?.Rules.SelectedFilter?.Filter.Id);

    private void AddRule_Click(object sender, RoutedEventArgs e) => OpenRuleEditor(null, null);

    private void EditRule_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel?.Rules.SelectedRule is { } item)
            OpenRuleEditor(item.Rule, null);
    }

    private void RulesGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e) => EditRule_Click(sender, e);

    private async void DeleteRule_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm || vm.Rules.SelectedRule is not { } item)
            return;
        if (Confirm($"Delete the {item.Kind.ToLowerInvariant()} rule for '{item.For}'?", "Delete rule") && !await vm.Rules.DeleteRuleAsync(item))
            ShowError(vm.Rules.LastError);
    }

    private void OpenFilterEditor(FilterDefinition? filter)
    {
        if (ViewModel is not { } vm || vm.Rules.Snapshot is not { } snapshot)
            return;
        if (filter?.IsPredefined == true)
        {
            ShowError("Predefined filters can't be edited.");
            return;
        }
        var editor = new FilterEditorWindow(new FilterEditorViewModel(filter, snapshot.Filters),
            async f => await vm.Rules.SaveFilterAsync(f) ? null : vm.Rules.LastError ?? "Saving failed.")
        { Owner = this };
        editor.ShowDialog();
    }

    private void OpenRuleEditor(RuleDefinition? rule, Guid? filterId, RuleKind? kind = null)
    {
        if (ViewModel is not { } vm || vm.Rules.Snapshot is not { } snapshot)
            return;
        var editorModel = new RuleEditorViewModel(rule, snapshot.Filters, filterId, kind, snapshot.Rules) { CreateRule = vm.Rules.CreateRuleAsync };
        var editor = new RuleEditorWindow(editorModel,
            async r => await vm.Rules.SaveRuleAsync(r) ? null : vm.Rules.LastError ?? "Saving failed.")
        { Owner = this };
        editor.ShowDialog();
    }

    private bool Confirm(string message, string title) =>
        MessageBox.Show(this, message, title, MessageBoxButton.OKCancel, MessageBoxImage.Question) == MessageBoxResult.OK;

    private void ShowError(string? message)
    {
        if (!string.IsNullOrEmpty(message))
            MessageBox.Show(this, message, "NetWarden", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    // ----- Apps and networks -----

    private async void DeleteApp_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { Apps.Selected: { } row } vm)
            return;
        var answer = MessageBox.Show(this, $"Forget {row.Name}? Choose Yes to delete its statistics too. Its rules stay.", "Delete app",
            MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
        if (answer != MessageBoxResult.Cancel)
            await vm.Apps.DeleteAsync(row, answer == MessageBoxResult.Yes);
    }

    private async void AddRuleForTag_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { Apps.SelectedTag: { } tag } vm)
            return;
        await OpenRuleEditorForAsync(vm, $"Tag {tag}", new FilterFunction(FilterFunctionKind.Tag, true, [tag]));
    }

    private async void AddRuleForNetwork_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { Networks.Selected: { } row } vm)
            return;
        await OpenRuleEditorForAsync(vm, $"Network {row.Name}", new FilterFunction(FilterFunctionKind.Network, true, [row.Network.Id]));
    }

    private async Task OpenRuleEditorForAsync(MainViewModel vm, string name, FilterFunction function)
    {
        if (await vm.Rules.EnsureFilterAsync(name, [function]) is { } filter)
            OpenRuleEditor(null, filter.Id);
        else
            ShowError(vm.Rules.LastError);
    }

    // ----- Address lookups -----

    private void Whois_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { Info.LookupAddress: { } address } vm)
            new WhoisWindow(vm.Service, address) { Owner = this }.Show();
    }

    private void AskWeb_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel?.Info.LookupAddress is { } address)
            OpenInBrowser(InfoViewModel.WebLink(address));
    }

    private void ShowMap_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel?.Info.MapPlace is { } place)
            OpenInBrowser(InfoViewModel.MapLink(place));
    }

    private static void OpenInBrowser(string url) => Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });

    // ----- Connection log and history -----

    private async void ShowHistory_Click(object sender, RoutedEventArgs e)
    {
        if (RowOf(sender)?.App?.App is not { } app || ViewModel is not { } vm)
            return;
        Tabs.SelectedItem = HistoryTab;
        await vm.History.ShowAppAsync(app);
    }

    private void LogExport_Click(object sender, RoutedEventArgs e) =>
        ExportCsv(_ => $"netwarden-connection-log-{DateTime.Now:yyyy-MM-dd-HHmm}.csv", vm => vm.Log.Csv());

    private void HistoryExport_Click(object sender, RoutedEventArgs e) =>
        ExportCsv(_ => $"netwarden-connection-history-{DateTime.Now:yyyy-MM-dd}.csv", vm => vm.History.Csv());

    // ----- Quotas -----

    private void AddQuota_Click(object sender, RoutedEventArgs e) => OpenRuleEditor(null, null, RuleKind.Quota);

    private void EditQuota_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is { Quotas.Selected: { } row, Rules.Snapshot: { } snapshot }
            && snapshot.Rules.FirstOrDefault(r => r.Rule.Id == row.Status.RuleId) is { } view)
            OpenRuleEditor(view.Rule, null);
    }

    private void QuotasGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e) => EditQuota_Click(sender, e);

    private void ShowQuotaAlert(QuotaAlert alert)
    {
        if (ViewModel is not { } vm)
            return;
        if (!IsVisible && vm.AppSettings.Notifications)
            _tray?.Notify("NetWarden", $"{alert.FilterName} has used its quota");
        new QuotaAlertWindow(alert, () => vm.Service.RequestAsync<bool>(Shared.Ipc.Methods.QuotasReset, new QuotaRequest(alert.RuleId))).Show();
    }

    // ----- Statistics -----

    private void StatsManager_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not { } vm)
            return;
        var manager = new StatsManagerWindow(new StatsManagerViewModel(vm.Service)) { Owner = this };
        manager.Changed += () => _ = vm.Stats.RefreshAsync();
        manager.ShowDialog();
    }

    private void StatsGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e) =>
        ViewModel?.Stats.DrillInto(StatsGrid.SelectedItem as StatsRowView);

    private void StatsExportRows_Click(object sender, RoutedEventArgs e) =>
        ExportCsv(vm => vm.Stats.ExportFileName(vm.Stats.GroupBy.ToString().ToLowerInvariant()), vm => vm.Stats.RowsCsv());

    private void StatsExportSeries_Click(object sender, RoutedEventArgs e) =>
        ExportCsv(vm => vm.Stats.ExportFileName("traffic"), vm => vm.Stats.SeriesCsv());

    private void ExportCsv(Func<MainViewModel, string> fileName, Func<MainViewModel, string> csv)
    {
        if (ViewModel is not { } vm)
            return;
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            FileName = fileName(vm),
            DefaultExt = ".csv",
            Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
        };
        if (dialog.ShowDialog(this) != true)
            return;
        try
        {
            StatsViewModel.WriteCsv(dialog.FileName, csv(vm));
        }
        catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException)
        {
            ShowError(ex.Message);
        }
    }

    // ----- Blocker -----

    private BlockerPromptWindow? _prompt;

    private void ShowBlockerPrompt()
    {
        if (ViewModel is not { } vm)
            return;
        if (_prompt is not null)
        {
            _prompt.Activate();
            return;
        }
        _prompt = new BlockerPromptWindow(new BlockerPromptViewModel(vm.Blocker));
        _prompt.Closed += (_, _) => _prompt = null;
        _prompt.Show();
    }

    private async void QuickBlock_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not CheckBox { DataContext: ActivityRow row } box || ViewModel is not { } vm)
            return;
        var direction = (string)box.Tag == "In" ? RuleDirection.In : RuleDirection.Out;
        bool block = direction == RuleDirection.In ? !row.IsBlockedIn : !row.IsBlockedOut;
        await vm.SetAppBlockedAsync(row, direction, block);
        // The binding is one-way; put the box back in line with the real state.
        box.IsChecked = direction == RuleDirection.In ? row.IsBlockedIn : row.IsBlockedOut;
        if (vm.Blocker.LastError is { } error)
            ShowError(error);
    }

    // ----- Quick limit -----

    private static RuleDirection DirectionOf(FrameworkElement element) => (string)element.Tag == "In" ? RuleDirection.In : RuleDirection.Out;

    private static string LimitText(ActivityRow row, RuleDirection direction) =>
        direction == RuleDirection.In ? row.LimitInText : row.LimitOutText;

    private async void QuickLimit_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not CheckBox { DataContext: ActivityRow row } box || ViewModel is not { } vm)
            return;
        var direction = DirectionOf(box);
        bool enable = direction == RuleDirection.In ? !row.IsLimitedIn : !row.IsLimitedOut;
        // A value typed but not yet committed is what the user means to apply.
        if (enable && box.Parent is Panel { Children: [_, TextBox text] } && text.Text.Trim() != LimitText(row, direction)
            && QuickLimit.Parse(text.Text) is { } typed)
            await vm.SetAppLimitAsync(row, direction, typed);
        else
            await vm.SetAppLimitedAsync(row, direction, enable);
        box.IsChecked = direction == RuleDirection.In ? row.IsLimitedIn : row.IsLimitedOut;
        if (vm.Rules.LastError is { } error)
            ShowError(error);
    }

    private async void LimitBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (sender is not TextBox box)
            return;
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            await CommitLimit(box);
        }
        else if (e.Key == Key.Escape && box.DataContext is ActivityRow row)
        {
            e.Handled = true;
            box.Text = LimitText(row, DirectionOf(box));
        }
    }

    private async void LimitBox_LostFocus(object sender, KeyboardFocusChangedEventArgs e)
    {
        if (sender is TextBox box)
            await CommitLimit(box);
    }

    private async Task CommitLimit(TextBox box)
    {
        if (box.DataContext is not ActivityRow row || ViewModel is not { } vm)
            return;
        var direction = DirectionOf(box);
        if (box.Text.Trim() == LimitText(row, direction))
            return;
        if (QuickLimit.Parse(box.Text) is not { } kilobytes)
        {
            box.Text = LimitText(row, direction);
            return;
        }
        await vm.SetAppLimitAsync(row, direction, kilobytes);
        box.Text = LimitText(row, direction);
        if (vm.Rules.LastError is { } error)
            ShowError(error);
    }

    private async void QuickPriority_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (sender is not ComboBox { DataContext: ActivityRow row, SelectedItem: PriorityLevel level } box || ViewModel is not { } vm
            || level == row.Priority)
            return;
        await vm.SetAppPriorityAsync(row, level);
        box.SelectedItem = row.Priority;
        if (vm.Rules.LastError is { } error)
            ShowError(error);
    }

    /// <summary>Enter commits a settings text box (the binding saves on lost focus).</summary>
    private void SettingBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && sender is TextBox box)
        {
            box.GetBindingExpression(TextBox.TextProperty)?.UpdateSource();
            e.Handled = true;
        }
    }

    private async void PendingAllow_Click(object sender, RoutedEventArgs e) => await AnswerPending(sender, true);

    private async void PendingDeny_Click(object sender, RoutedEventArgs e) => await AnswerPending(sender, false);

    private async Task AnswerPending(object sender, bool allow)
    {
        if ((sender as FrameworkElement)?.DataContext is BlockerRequest request && ViewModel is { } vm)
            await vm.Blocker.AnswerAsync(request, allow, RememberMode.Once, RuleScope.App, 0);
    }
}
