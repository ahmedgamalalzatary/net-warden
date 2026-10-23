using System.IO;
using System.Windows;
using NetWarden.Client.Services;
using NetWarden.Client.ViewModels;
using NetWarden.Shared.Formatting;
using NetWarden.Shared.Ipc;
using NetWarden.Shared.Storage;

namespace NetWarden.Client;

public partial class App : Application
{
    private ServiceConnection? _connection;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += (_, args) =>
        {
            LogError(args.Exception);
            MessageBox.Show(args.Exception.Message, "NetWarden error", MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };

        var store = new JsonFileStore<ClientSettings>(ClientSettings.DefaultPath);
        ClientSettings settings = store.Load();
        void Save()
        {
            try
            {
                store.Save(settings);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Preferences are a convenience; never crash the UI over them.
            }
        }

        var themes = new ThemeManager(this);
        themes.Apply(settings.Theme);

        _connection = new ServiceConnection();
        var viewModel = new MainViewModel(_connection, Dispatcher, settings, Save, new IconCache(), PortNames.LoadSystem());
        viewModel.ThemeChanged += themes.Apply;
        MainWindow = new MainWindow { DataContext = viewModel };
        MainWindow.Show();
        _connection.Start();
    }

    public static string LogPath { get; } = Path.Combine(Path.GetDirectoryName(ClientSettings.DefaultPath)!, "client.log");

    public static void LogError(Exception ex)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!);
            File.AppendAllText(LogPath, $"{DateTimeOffset.Now:O} {ex}{Environment.NewLine}");
        }
        catch (IOException)
        {
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _connection?.DisposeAsync().AsTask().Wait(TimeSpan.FromSeconds(2));
        base.OnExit(e);
    }
}
