using System.Windows;
using NetWarden.Client.ViewModels;
using NetWarden.Shared.Ipc;

namespace NetWarden.Client;

public partial class App : Application
{
    private ServiceConnection? _connection;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        _connection = new ServiceConnection();
        var viewModel = new MainViewModel(_connection, Dispatcher);
        MainWindow = new MainWindow { DataContext = viewModel };
        MainWindow.Show();
        _connection.Start();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _connection?.DisposeAsync().AsTask().Wait(TimeSpan.FromSeconds(2));
        base.OnExit(e);
    }
}
