using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;

namespace NetWarden.Client.ViewModels;

/// <summary>Letting other computers manage this one (or the one this client is connected to).</summary>
public sealed partial class RemoteAdminViewModel(IServiceRequester service) : ObservableObject
{
    [ObservableProperty]
    private bool _isEnabled;

    [ObservableProperty]
    private int _port = 5317;

    [ObservableProperty]
    private string? _thumbprint;

    [ObservableProperty]
    private string _stateText = "";

    [ObservableProperty]
    private string? _error;

    public async Task RefreshAsync() => Show(await RunAsync(() => service.RequestAsync<RemoteStatus>(Methods.RemoteGet)));

    /// <summary>The password comes from a password box; null keeps the current one.</summary>
    public async Task ApplyAsync(string? newPassword) =>
        Show(await RunAsync(() => service.RequestAsync<RemoteStatus>(Methods.RemoteConfigure, new RemoteConfigureRequest(IsEnabled, Port, newPassword))));

    private void Show(RemoteStatus? status)
    {
        if (status is null)
            return;
        IsEnabled = status.IsEnabled;
        Port = status.Port;
        Thumbprint = status.Thumbprint;
        StateText = status.Error is not null ? $"Not listening: {status.Error}"
            : status.IsListening ? $"Listening on port {status.Port}. Allow this port in Windows Firewall for other computers to reach it."
            : "Off.";
    }

    private async Task<T?> RunAsync<T>(Func<Task<T?>> action)
    {
        try
        {
            T? result = await action();
            Error = null;
            return result;
        }
        catch (IpcRemoteException ex)
        {
            Error = ex.RemoteMessage;
        }
        catch (IpcDisconnectedException ex)
        {
            Error = ex.Message;
        }
        return default;
    }
}

/// <summary>Connecting this client to another computer.</summary>
public sealed partial class RemoteConnectViewModel(ClientSettings settings, Action save, Action<RemoteTarget> connect, Action useLocal) : ObservableObject
{
    [ObservableProperty]
    private string _host = settings.LastRemoteHost;

    [ObservableProperty]
    private int _port = settings.LastRemotePort;

    [ObservableProperty]
    private bool _isRemote;

    [ObservableProperty]
    private string _statusText = "Managing this computer.";

    private string Key => $"{Host.Trim().ToLowerInvariant()}:{Port}";

    public void Connect(string password)
    {
        string host = Host.Trim();
        if (host.Length == 0)
        {
            StatusText = "Enter the computer's name or address.";
            return;
        }
        settings.LastRemoteHost = host;
        settings.LastRemotePort = Port;
        save();
        string key = Key;
        IsRemote = true;
        StatusText = $"Connecting to {host}...";
        connect(new RemoteTarget(host, Port, password, settings.KnownHosts.GetValueOrDefault(key), thumbprint =>
        {
            if (!settings.KnownHosts.ContainsKey(key))
            {
                settings.KnownHosts[key] = thumbprint;
                save();
            }
            StatusText = $"Managing {host}. Certificate {thumbprint}";
        }));
    }

    [RelayCommand]
    private void UseThisComputer()
    {
        IsRemote = false;
        StatusText = "Managing this computer.";
        useLocal();
    }

    /// <summary>For a server that was reinstalled and has a new certificate.</summary>
    [RelayCommand]
    private void ForgetCertificate()
    {
        if (settings.KnownHosts.Remove(Key))
            save();
        StatusText = $"The next connection to {Host.Trim()} accepts its certificate as new.";
    }
}

/// <summary>Which users and groups may use the service, besides Administrators.</summary>
public sealed partial class PermissionsViewModel(IServiceRequester service) : ObservableObject
{
    public ObservableCollection<AccessEntry> Entries { get; } = [];

    [ObservableProperty]
    private string _newAccount = "";

    [ObservableProperty]
    private bool _newIsAllowed = true;

    [ObservableProperty]
    private string? _error;

    public Task RefreshAsync() => SendAsync(() => service.RequestAsync<List<AccessEntry>>(Methods.AccessGet));

    [RelayCommand]
    private async Task AddAsync()
    {
        string account = NewAccount.Trim();
        if (account.Length == 0)
            return;
        await SaveAsync([.. Entries, new AccessEntry(account, null, NewIsAllowed)]);
        if (Error is null)
            NewAccount = "";
    }

    [RelayCommand]
    private Task RemoveAsync(AccessEntry? entry) =>
        entry is null ? Task.CompletedTask : SaveAsync(Entries.Where(e => e != entry).ToList());

    private Task SaveAsync(List<AccessEntry> entries) =>
        SendAsync(() => service.RequestAsync<List<AccessEntry>>(Methods.AccessSet, new AccessSetRequest(entries)));

    private async Task SendAsync(Func<Task<List<AccessEntry>?>> request)
    {
        try
        {
            var entries = await request();
            Error = null;
            Entries.Clear();
            foreach (var entry in entries ?? [])
                Entries.Add(entry);
        }
        catch (IpcRemoteException ex)
        {
            Error = ex.RemoteMessage;
        }
        catch (IpcDisconnectedException ex)
        {
            Error = ex.Message;
        }
    }
}
