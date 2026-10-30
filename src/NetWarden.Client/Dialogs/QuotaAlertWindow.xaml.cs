using System.Windows;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Formatting;

namespace NetWarden.Client.Dialogs;

public partial class QuotaAlertWindow : Window
{
    private readonly Func<Task> _reset;

    public QuotaAlertWindow(QuotaAlert alert, Func<Task> reset)
    {
        InitializeComponent();
        _reset = reset;
        Heading.Text = $"{alert.FilterName} has used its quota";
        Detail.Text = $"{ByteFormatter.Size(alert.Used)} of {ByteFormatter.Size(alert.Limit)} at {alert.Time.ToLocalTime():t}.";
    }

    private async void Reset_Click(object sender, RoutedEventArgs e)
    {
        IsEnabled = false;
        await _reset();
        Close();
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
