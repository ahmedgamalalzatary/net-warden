using System.Globalization;
using System.Windows;
using NetWarden.Client.ViewModels;

namespace NetWarden.Client.Dialogs;

public partial class StatsManagerWindow : Window
{
    public StatsManagerWindow(StatsManagerViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        Loaded += async (_, _) => await viewModel.LoadAsync();
    }

    private StatsManagerViewModel ViewModel => (StatsManagerViewModel)DataContext;

    /// <summary>Raised after records were deleted or the file was compacted.</summary>
    public event Action? Changed;

    private async void DeleteOld_Click(object sender, RoutedEventArgs e)
    {
        if (Confirm($"Delete all statistics recorded before {ViewModel.DeleteBefore.ToString("d", CultureInfo.CurrentCulture)}?"))
            await Run(ViewModel.DeleteOlderThanAsync);
    }

    private async void DeleteApp_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.SelectedApp is not { } app)
        {
            ViewModel.Error = "Pick an app first.";
            return;
        }
        if (Confirm($"Delete all statistics of {app.Name}?"))
            await Run(ViewModel.DeleteSelectedAppAsync);
    }

    private async void DeleteAll_Click(object sender, RoutedEventArgs e)
    {
        if (Confirm("Delete all recorded statistics? This can't be undone."))
            await Run(ViewModel.DeleteAllAsync);
    }

    private async void Compact_Click(object sender, RoutedEventArgs e) => await Run(ViewModel.CompactAsync);

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private async Task Run(Func<Task> action)
    {
        await action();
        Changed?.Invoke();
    }

    private bool Confirm(string message) =>
        MessageBox.Show(this, message, "Stats database", MessageBoxButton.OKCancel, MessageBoxImage.Warning) == MessageBoxResult.OK;
}
