using System.Text.Json;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetWarden.Client.Charts;
using NetWarden.Client.Services;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Formatting;
using NetWarden.Shared.Ipc;

namespace NetWarden.Client.ViewModels;

public sealed partial class MainViewModel : ObservableObject
{
    private readonly ServiceConnection _connection;
    private readonly Dispatcher _dispatcher;
    private readonly ClientSettings _settings;
    private readonly Action _saveSettings;
    private int _ticks;

    [ObservableProperty]
    private ConnectionState _connectionState = ConnectionState.Disconnected;

    [ObservableProperty]
    private string _statusText = "Starting...";

    [ObservableProperty]
    private ServiceInfo? _serviceInfo;

    [ObservableProperty]
    private ServiceSettings? _settingsFromService;

    [ObservableProperty]
    private ActivityRow? _selectedRow;

    public MainViewModel(
        ServiceConnection connection, Dispatcher dispatcher, ClientSettings settings, Action saveSettings,
        IconCache icons, PortNames ports)
    {
        _connection = connection;
        _dispatcher = dispatcher;
        _settings = settings;
        _saveSettings = saveSettings;
        Activity = new ActivityViewModel(connection, settings, saveSettings, icons.Get, ports);
        Info = new InfoViewModel(connection, ports);
        Rules = new RulesViewModel(connection);
        Blocker = new BlockerViewModel(connection, Rules);
        Activity.Updated += () =>
        {
            OnPropertyChanged(nameof(ChartHistory));
            Info.Refresh();
            RefreshBlockStates();
            // Packet counters change constantly; refresh them every few snapshots.
            if (++_ticks % 3 == 0 && IsConnected)
                _ = Blocker.LoadAsync();
        };
        Rules.Reloaded += RefreshBlockStates;

        _connection.StateChanged += state => _dispatcher.InvokeAsync(() => HandleStateChanged(state));
        _connection.EventReceived += OnServiceEvent;
    }

    public ActivityViewModel Activity { get; }
    public InfoViewModel Info { get; }
    public RulesViewModel Rules { get; }
    public BlockerViewModel Blocker { get; }

    public IReadOnlyList<FirewallAction> FirewallActions { get; } = Enum.GetValues<FirewallAction>();

    // Global switches and blocker defaults, written straight to the service.
    public bool IsLimiterEnabled
    {
        get => SettingsFromService?.IsLimiterEnabled ?? false;
        set => _ = UpdateSettingsAsync(s => s.IsLimiterEnabled = value);
    }

    public bool IsBlockerEnabled
    {
        get => SettingsFromService?.IsBlockerEnabled ?? false;
        set => _ = UpdateSettingsAsync(s => s.IsBlockerEnabled = value);
    }

    public bool IsPriorityEnabled
    {
        get => SettingsFromService?.IsPriorityEnabled ?? false;
        set => _ = UpdateSettingsAsync(s => s.IsPriorityEnabled = value);
    }

    public FirewallAction DefaultFirewallIn
    {
        get => SettingsFromService?.DefaultFirewallIn ?? FirewallAction.Allow;
        set => _ = UpdateSettingsAsync(s => s.DefaultFirewallIn = value);
    }

    public FirewallAction DefaultFirewallOut
    {
        get => SettingsFromService?.DefaultFirewallOut ?? FirewallAction.Allow;
        set => _ = UpdateSettingsAsync(s => s.DefaultFirewallOut = value);
    }

    // Quick zone blocker: whole-computer block of the Internet or local network zone.
    public bool BlockInternetIn { get => ZoneBlocked(PredefinedFilters.Internet, RuleDirection.In); set => _ = SetZoneAsync(PredefinedFilters.Internet, RuleDirection.In, value); }
    public bool BlockInternetOut { get => ZoneBlocked(PredefinedFilters.Internet, RuleDirection.Out); set => _ = SetZoneAsync(PredefinedFilters.Internet, RuleDirection.Out, value); }
    public bool BlockLocalIn { get => ZoneBlocked(PredefinedFilters.LocalNetwork, RuleDirection.In); set => _ = SetZoneAsync(PredefinedFilters.LocalNetwork, RuleDirection.In, value); }
    public bool BlockLocalOut { get => ZoneBlocked(PredefinedFilters.LocalNetwork, RuleDirection.Out); set => _ = SetZoneAsync(PredefinedFilters.LocalNetwork, RuleDirection.Out, value); }

    private bool ZoneBlocked(Guid filter, RuleDirection direction) => QuickBlock.IsBlocked(Rules.Snapshot, filter, direction);

    private async Task SetZoneAsync(Guid filter, RuleDirection direction, bool block)
    {
        await Blocker.SetBlockedAsync(filter, null, direction, block);
        RefreshBlockStates();
    }

    /// <summary>Quick block for one app from the activity grid.</summary>
    public async Task SetAppBlockedAsync(ActivityRow row, RuleDirection direction, bool block)
    {
        if (row.App?.App is not { } app)
            return;
        await Blocker.SetBlockedAsync(null, app, direction, block);
        RefreshBlockStates();
    }

    private void RefreshBlockStates()
    {
        var snapshot = Rules.Snapshot;
        foreach (var row in Activity.Rows.Where(r => r.IsApp && r.App is not null))
        {
            Guid? filter = QuickBlock.AppFilterId(snapshot, row.App!.App.Id);
            row.IsBlockedIn = QuickBlock.IsBlocked(snapshot, filter, RuleDirection.In);
            row.IsBlockedOut = QuickBlock.IsBlocked(snapshot, filter, RuleDirection.Out);
        }
        foreach (string name in new[] { nameof(BlockInternetIn), nameof(BlockInternetOut), nameof(BlockLocalIn), nameof(BlockLocalOut) })
            OnPropertyChanged(name);
    }

    /// <summary>Copies the service settings, applies a change and saves it; the change event refreshes the UI.</summary>
    public async Task UpdateSettingsAsync(Action<ServiceSettings> change)
    {
        if (SettingsFromService is not { } current)
            return;
        var copy = IpcJson.FromElement<ServiceSettings>(IpcJson.ToElement(current))!;
        change(copy);
        try
        {
            SettingsFromService = await _connection.RequestAsync<ServiceSettings>(Methods.SettingsUpdate, copy);
        }
        catch (Exception ex) when (ex is IpcRemoteException or IpcDisconnectedException)
        {
            StatusText = ex.Message;
            OnSettingsFromServiceChanged(current);
        }
    }

    partial void OnSettingsFromServiceChanged(ServiceSettings? value)
    {
        foreach (string name in new[] { nameof(IsLimiterEnabled), nameof(IsBlockerEnabled), nameof(IsPriorityEnabled),
                     nameof(DefaultFirewallIn), nameof(DefaultFirewallOut) })
            OnPropertyChanged(name);
    }

    public bool IsConnected => ConnectionState == ConnectionState.Connected;

    public string ServiceSummary => ServiceInfo is { } i
        ? $"Service v{i.Version} · PID {i.ProcessId} · {(i.IsWindowsService ? "Windows service" : "console mode")}"
        : "";

    // Column visibility; ids are stable so settings survive column reordering.
    public bool ShowRateIn { get => IsColumnVisible("RateIn"); set => SetColumn("RateIn", value); }
    public bool ShowRateOut { get => IsColumnVisible("RateOut"); set => SetColumn("RateOut", value); }
    public bool ShowTotalIn { get => IsColumnVisible("TotalIn"); set => SetColumn("TotalIn", value); }
    public bool ShowTotalOut { get => IsColumnVisible("TotalOut"); set => SetColumn("TotalOut", value); }

    public bool ShowInfoPane
    {
        get => _settings.ShowInfoPane;
        set { _settings.ShowInfoPane = value; _saveSettings(); OnPropertyChanged(); }
    }

    public bool ShowChart
    {
        get => _settings.ShowChart;
        set { _settings.ShowChart = value; _saveSettings(); OnPropertyChanged(); }
    }

    public IReadOnlyList<int> ChartWindows { get; } = [60, 300, 600];

    public int ChartWindowSeconds
    {
        get => _settings.ChartWindowSeconds;
        set { _settings.ChartWindowSeconds = value; _saveSettings(); OnPropertyChanged(); }
    }

    /// <summary>The selected app's history (a connection shows its app), or the whole computer.</summary>
    public RateHistory? ChartHistory => Activity.History.Get(ChartKey);

    public string ChartTitle => SelectedAppRow is { } app ? $"Traffic · {app.Name}" : "Traffic · Whole computer";

    private ActivityRow? SelectedAppRow => SelectedRow is null ? null : SelectedRow.IsApp ? SelectedRow : SelectedRow.Parent;

    private string ChartKey => SelectedAppRow?.Key ?? ActivityViewModel.ComputerKey;

    private bool IsColumnVisible(string id) => !_settings.Columns.TryGetValue(id, out bool visible) || visible;

    private void SetColumn(string id, bool visible)
    {
        _settings.Columns[id] = visible;
        _saveSettings();
        OnPropertyChanged("Show" + id);
    }

    partial void OnConnectionStateChanged(ConnectionState value) => OnPropertyChanged(nameof(IsConnected));
    partial void OnServiceInfoChanged(ServiceInfo? value) => OnPropertyChanged(nameof(ServiceSummary));

    partial void OnSelectedRowChanged(ActivityRow? value)
    {
        _ = Info.ShowAsync(value);
        OnPropertyChanged(nameof(ChartHistory));
        OnPropertyChanged(nameof(ChartTitle));
    }

    private void OnServiceEvent(string method, JsonElement? payload)
    {
        switch (method)
        {
            case Events.ActivitySnapshot:
                // Deserialize on the pipe thread; only the cheap merge runs on the UI thread.
                if (IpcJson.FromElement<ActivitySnapshot>(payload) is { } snapshot)
                    _dispatcher.InvokeAsync(() => Activity.Apply(snapshot));
                break;
            case Events.RulesChanged:
                long generation = payload?.GetInt64() ?? -1;
                _dispatcher.InvokeAsync(() => Rules.ReloadAsync(generation));
                break;
            case Events.SettingsChanged:
                if (IpcJson.FromElement<ServiceSettings>(payload) is { } settings)
                    _dispatcher.InvokeAsync(() => SettingsFromService = settings);
                break;
            case Events.BlockerRequest:
                if (IpcJson.FromElement<BlockerRequest>(payload) is { } request)
                    _dispatcher.InvokeAsync(() => Blocker.OnRequest(request));
                break;
            case Events.BlockerResolved:
                if (IpcJson.FromElement<BlockerResolved>(payload) is { } resolved)
                    _dispatcher.InvokeAsync(() => Blocker.OnResolved(resolved));
                break;
            case Events.FilterStatus:
                if (IpcJson.FromElement<PacketFilterStatus>(payload) is { } status)
                    _dispatcher.InvokeAsync(() => Blocker.Status = status);
                break;
        }
    }

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
                SettingsFromService = null;
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
            SettingsFromService = await _connection.RequestAsync<ServiceSettings>(Methods.SettingsGet);
            await Rules.ReloadAsync();
            await Blocker.LoadAsync();
            if (await _connection.RequestAsync<ActivitySnapshot>(Methods.ActivityGet) is { } snapshot)
                Activity.Apply(snapshot);
        }
        catch (Exception ex) when (ex is IpcDisconnectedException or IpcRemoteException)
        {
            StatusText = ex.Message;
        }
    }

    [RelayCommand]
    private void SetUnits(UnitMode units) => Activity.Units = units;
}
