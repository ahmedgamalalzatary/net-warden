using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using NetWarden.Client.Dialogs;
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
            vm.Blocker.RequestArrived += _ => ShowBlockerPrompt();
            vm.PropertyChanged += OnViewModelPropertyChanged;
            UpdateInfoPaneWidth();
        };
    }

    private MainViewModel? ViewModel => DataContext as MainViewModel;

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.ShowInfoPane))
            UpdateInfoPaneWidth();
    }

    private void UpdateInfoPaneWidth()
    {
        var grid = (Grid)ActivityGrid.Parent;
        grid.ColumnDefinitions[2].Width = ViewModel?.ShowInfoPane == false ? new GridLength(0) : new GridLength(320);
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
        var editor = new RuleEditorWindow(new RuleEditorViewModel(rule, snapshot.Filters, filterId, kind),
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

    private async void PendingAllow_Click(object sender, RoutedEventArgs e) => await AnswerPending(sender, true);

    private async void PendingDeny_Click(object sender, RoutedEventArgs e) => await AnswerPending(sender, false);

    private async Task AnswerPending(object sender, bool allow)
    {
        if ((sender as FrameworkElement)?.DataContext is BlockerRequest request && ViewModel is { } vm)
            await vm.Blocker.AnswerAsync(request, allow, RememberMode.Once, RuleScope.App, 0);
    }
}
