using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
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
}
