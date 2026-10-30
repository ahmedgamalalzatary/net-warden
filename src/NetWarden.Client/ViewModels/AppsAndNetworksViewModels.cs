using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;

namespace NetWarden.Client.ViewModels;

public enum AppAvailability
{
    All,
    Installed,
    Uninstalled,
}

public sealed record AppRow(KnownAppView View)
{
    public KnownApp App => View.App;
    public string Name => App.DisplayName;
    public string Type => App.Kind switch
    {
        AppKind.Service => "System service",
        AppKind.Store => "Store app",
        AppKind.System => "System",
        _ => "Desktop app",
    };
    public string Availability => View.IsInstalled ? "Installed" : "Uninstalled";
    public string Path => App.Path;
    public string Tags => string.Join(", ", App.Tags);
    public string FirstSeen => App.FirstSeen.ToLocalTime().ToString("g");
    public string LastSeen => App.LastSeen.ToLocalTime().ToString("g");

    public bool Matches(string search) =>
        Name.Contains(search, StringComparison.OrdinalIgnoreCase) || Path.Contains(search, StringComparison.OrdinalIgnoreCase)
        || Tags.Contains(search, StringComparison.OrdinalIgnoreCase);
}

/// <summary>The Apps tab: every app seen, its tags, and forgetting apps.</summary>
public sealed partial class AppsViewModel(IServiceRequester service) : ObservableObject
{
    private List<AppRow> _all = [];

    public IReadOnlyList<AppAvailability> Availabilities { get; } = Enum.GetValues<AppAvailability>();
    public ObservableCollection<AppRow> Rows { get; } = [];

    /// <summary>Every tag in use, for making a filter of one.</summary>
    public IReadOnlyList<string> AllTags => _all.SelectMany(r => r.App.Tags).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToList();

    [ObservableProperty]
    private AppRow? _selected;

    [ObservableProperty]
    private string _search = "";

    [ObservableProperty]
    private AppAvailability _availability;

    /// <summary>Tags of the selected app, separated by commas.</summary>
    [ObservableProperty]
    private string _tagsText = "";

    [ObservableProperty]
    private string? _selectedTag;

    [ObservableProperty]
    private string? _lastError;

    partial void OnSearchChanged(string value) => Rebuild();
    partial void OnAvailabilityChanged(AppAvailability value) => Rebuild();
    partial void OnSelectedChanged(AppRow? value) => TagsText = value?.Tags ?? "";

    public async Task RefreshAsync()
    {
        var apps = await RunAsync(() => service.RequestAsync<List<KnownAppView>>(Methods.AppsList));
        if (apps is null)
            return;
        _all = apps.Select(a => new AppRow(a)).OrderBy(r => r.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
        Rebuild();
        OnPropertyChanged(nameof(AllTags));
    }

    [RelayCommand]
    private async Task SaveTagsAsync()
    {
        if (Selected is not { } row)
            return;
        var tags = TagsText.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        await RunAsync(() => service.RequestAsync<bool>(Methods.AppsSetTags, new SetAppTagsRequest(row.App.Id, tags)));
        await RefreshAsync();
    }

    public async Task DeleteAsync(AppRow row, bool deleteStats)
    {
        await RunAsync(() => service.RequestAsync<bool>(Methods.AppsDelete, new DeleteAppsRequest([row.App.Id], deleteStats)));
        await RefreshAsync();
    }

    private void Rebuild()
    {
        string? selected = Selected?.App.Id;
        string search = Search.Trim();
        Rows.Clear();
        foreach (var row in _all)
        {
            bool wanted = Availability switch
            {
                AppAvailability.Installed => row.View.IsInstalled,
                AppAvailability.Uninstalled => !row.View.IsInstalled,
                _ => true,
            };
            if (wanted && (search.Length == 0 || row.Matches(search)))
                Rows.Add(row);
        }
        Selected = Rows.FirstOrDefault(r => r.App.Id == selected);
    }

    private async Task<T?> RunAsync<T>(Func<Task<T?>> action)
    {
        try
        {
            T? result = await action();
            LastError = null;
            return result;
        }
        catch (Exception ex) when (ex is IpcRemoteException or IpcDisconnectedException)
        {
            LastError = ex is IpcRemoteException remote ? remote.RemoteMessage : ex.Message;
            return default;
        }
    }
}

public sealed record NetworkRow(NetworkView View)
{
    public KnownNetwork Network => View.Network;
    public string Name => Network.Name;
    public string Type => Network.IsWifi ? "Wi-Fi" : "Wired";
    public string Interface => Network.InterfaceDescription;
    public string Gateway => Network.GatewayMac ?? "";
    public string Active => View.IsActive ? "Active" : "";
    public string FirstSeen => Network.FirstSeen.ToLocalTime().ToString("g");
    public string LastSeen => Network.LastSeen.ToLocalTime().ToString("g");
}

/// <summary>The Networks tab: networks this computer has been on.</summary>
public sealed partial class NetworksViewModel(IServiceRequester service) : ObservableObject
{
    public ObservableCollection<NetworkRow> Rows { get; } = [];

    [ObservableProperty]
    private NetworkRow? _selected;

    [ObservableProperty]
    private string? _lastError;

    /// <summary>Raised after a reload with every known network.</summary>
    public event Action<IReadOnlyList<KnownNetwork>>? Reloaded;

    public async Task RefreshAsync()
    {
        try
        {
            var networks = await service.RequestAsync<List<NetworkView>>(Methods.NetworksList) ?? [];
            string? selected = Selected?.Network.Id;
            Rows.Clear();
            foreach (var n in networks.OrderByDescending(n => n.IsActive).ThenBy(n => n.Network.Name, StringComparer.CurrentCultureIgnoreCase))
                Rows.Add(new NetworkRow(n));
            Selected = Rows.FirstOrDefault(r => r.Network.Id == selected);
            LastError = null;
            Reloaded?.Invoke(networks.Select(n => n.Network).ToList());
        }
        catch (Exception ex) when (ex is IpcRemoteException or IpcDisconnectedException)
        {
            LastError = ex.Message;
        }
    }

    [RelayCommand]
    private async Task DeleteAsync(NetworkRow? row)
    {
        if (row is null)
            return;
        try
        {
            await service.RequestAsync<bool>(Methods.NetworksDelete, new DeleteNetworkRequest(row.Network.Id));
            await RefreshAsync();
        }
        catch (Exception ex) when (ex is IpcRemoteException or IpcDisconnectedException)
        {
            LastError = ex is IpcRemoteException remote ? remote.RemoteMessage : ex.Message;
        }
    }
}
