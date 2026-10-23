using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;

namespace NetWarden.Client.ViewModels;

public sealed partial class MainViewModel : ObservableObject
{
    private readonly ServiceConnection _connection;
    private readonly Dispatcher _dispatcher;

    [ObservableProperty]
    private ConnectionState _connectionState = ConnectionState.Disconnected;

    [ObservableProperty]
    private string _statusText = "Starting...";

    [ObservableProperty]
    private ServiceInfo? _serviceInfo;

    [ObservableProperty]
    private ServiceSettings? _settings;

    public MainViewModel(ServiceConnection connection, Dispatcher dispatcher)
    {
        _connection = connection;
        _dispatcher = dispatcher;
        _connection.StateChanged += state => _dispatcher.InvokeAsync(() => HandleStateChanged(state));
    }

    public bool IsConnected => ConnectionState == ConnectionState.Connected;

    public string ServiceSummary => ServiceInfo is { } i
        ? $"Service v{i.Version} · PID {i.ProcessId} · {(i.IsWindowsService ? "Windows service" : "console mode")}"
        : "";

    partial void OnConnectionStateChanged(ConnectionState value) => OnPropertyChanged(nameof(IsConnected));

    partial void OnServiceInfoChanged(ServiceInfo? value) => OnPropertyChanged(nameof(ServiceSummary));

    private async void HandleStateChanged(ConnectionState state)
    {
        ConnectionState = state;
        switch (state)
        {
            case ConnectionState.Connecting:
                // Keep the reason for the last failure visible while retrying.
                StatusText = _connection.LastError is { } error ? $"{error} Retrying..." : "Connecting to service...";
                break;
            case ConnectionState.Disconnected:
                StatusText = _connection.LastError ?? "Disconnected";
                ServiceInfo = null;
                Settings = null;
                break;
            case ConnectionState.Connected:
                StatusText = "Connected";
                await LoadAsync();
                break;
        }
    }

    private async Task LoadAsync()
    {
        try
        {
            ServiceInfo = await _connection.RequestAsync<ServiceInfo>(Methods.ServiceInfo);
            Settings = await _connection.RequestAsync<ServiceSettings>(Methods.SettingsGet);
        }
        catch (Exception ex) when (ex is IpcDisconnectedException or IpcRemoteException)
        {
            StatusText = ex.Message;
        }
    }
}
