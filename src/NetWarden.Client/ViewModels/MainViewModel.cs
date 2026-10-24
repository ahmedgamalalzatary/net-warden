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
        Priorities = new PrioritiesViewModel(() => SettingsFromService, UpdateSettingsAsync);
        Stats = new StatsViewModel(connection, settings, saveSettings, ports, () => SettingsFromService, UpdateSettingsAsync);
        Activity.Updated += () =>
        {
            OnPropertyChanged(nameof(ChartHistory));
            Info.Refresh();
            RefreshRuleStates();
            // Packet counters change constantly; refresh them every few snapshots
            // (every snapshot while the Priorities tab shows live rates).
            if ((++_ticks % 3 == 0 || IsPrioritiesTabVisible) && IsConnected)
                _ = Blocker.LoadAsync();
            // The service writes stats every minute; follow along while a range that includes now is shown.
            if (IsStatsTabVisible && _ticks % StatsRefreshTicks == 0 && IsConnected && Stats.IsLive)
                _ = Stats.RefreshAsync();
        };
        Rules.Reloaded += RefreshRuleStates;
        Blocker.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(BlockerViewModel.Status))
                ShowPriorityStatus();
        };

        _connection.StateChanged += state => _dispatcher.InvokeAsync(() => HandleStateChanged(state));
        _connection.EventReceived += OnServiceEvent;
    }

    public ActivityViewModel Activity { get; }
    public InfoViewModel Info { get; }
    public RulesViewModel Rules { get; }
    public BlockerViewModel Blocker { get; }
    public PrioritiesViewModel Priorities { get; }
    public StatsViewModel Stats { get; }

    /// <summary>The service, for dialogs that talk to it directly.</summary>
    public IServiceRequester Service => _connection;

    /// <summary>Activity snapshots (seconds) between refreshes of a live stats range.</summary>
    public const int StatsRefreshTicks = 30;

    /// <summary>Set by the window while the Priorities tab is selected.</summary>
    public bool IsPrioritiesTabVisible { get; set; }

    /// <summary>Set by the window while the Statistics tab is selected; showing it loads the stats.</summary>
    public bool IsStatsTabVisible
    {
        get => _isStatsTabVisible;
        set
        {
            if (_isStatsTabVisible == value)
                return;
            _isStatsTabVisible = value;
            if (value && IsConnected)
                _ = Stats.RefreshAsync();
        }
    }

    private bool _isStatsTabVisible;

    public IReadOnlyList<PriorityLevel> PriorityLevels => QuickPriority.Levels;

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
        RefreshRuleStates();
    }

    /// <summary>Quick block for one app from the activity grid.</summary>
    public async Task SetAppBlockedAsync(ActivityRow row, RuleDirection direction, bool block)
    {
        if (row.App?.App is not { } app)
            return;
        await Blocker.SetBlockedAsync(null, app, direction, block);
        RefreshRuleStates();
    }

    /// <summary>Turns an app's quick limit on or off (In = download, Out = upload).</summary>
    public Task<bool> SetAppLimitedAsync(ActivityRow row, RuleDirection direction, bool enable) =>
        ChangeAppLimitAsync(row, enable, (existing, filter) => QuickLimit.Toggle(existing, filter, direction, enable), direction);

    /// <summary>Sets an app's quick-limit value in KB/s, turning the limit on.</summary>
    public Task<bool> SetAppLimitAsync(ActivityRow row, RuleDirection direction, double kilobytes) =>
        ChangeAppLimitAsync(row, true, (existing, filter) => QuickLimit.SetValue(existing, filter, direction, kilobytes), direction);

    /// <summary>Gives an app a priority (Normal removes its quick priority rule).</summary>
    public async Task<bool> SetAppPriorityAsync(ActivityRow row, PriorityLevel level)
    {
        if (row.App?.App is not { } app)
            return false;
        Guid? filter = QuickBlock.AppFilterId(Rules.Snapshot, app.Id);
        if (filter is null && level != PriorityLevel.Normal)
            filter = (await Rules.EnsureAppFilterAsync(app))?.Id;
        bool ok = filter is not null || level == PriorityLevel.Normal;
        if (filter is { } id)
        {
            var (save, delete) = QuickPriority.Plan(QuickPriority.Find(Rules.Snapshot, id), id, level);
            if (save is not null)
                ok = await Rules.SaveRuleAsync(save);
            if (delete is { } ruleId && Rules.Rules.FirstOrDefault(r => r.Rule.Id == ruleId) is { } item)
                ok = await Rules.DeleteRuleAsync(item);
        }
        RefreshRuleStates();
        return ok;
    }

    private void ShowPriorityStatus() =>
        Priorities.ShowStatus(Blocker.Status?.Limiter, Rules.Snapshot?.Rules.Any(r => r.Rule.Kind == RuleKind.Priority && r.Rule.IsEnabled) == true);

    private async Task<bool> ChangeAppLimitAsync(ActivityRow row, bool createFilter,
        Func<RuleDefinition?, Guid, RuleDefinition?> plan, RuleDirection direction)
    {
        if (row.App?.App is not { } app)
            return false;
        Guid? filter = QuickBlock.AppFilterId(Rules.Snapshot, app.Id);
        if (filter is null && createFilter)
            filter = (await Rules.EnsureAppFilterAsync(app))?.Id;
        bool ok = true;
        if (filter is { } id && plan(QuickLimit.Find(Rules.Snapshot, id, direction), id) is { } rule)
            ok = await Rules.SaveRuleAsync(rule);
        else if (filter is null && createFilter)
            ok = false;
        RefreshRuleStates();
        return ok;
    }

    /// <summary>Puts the quick block and quick limit cells in line with the rules.</summary>
    private void RefreshRuleStates()
    {
        var snapshot = Rules.Snapshot;
        foreach (var row in Activity.Rows.Where(r => r.IsApp && r.App is not null))
        {
            Guid? filter = QuickBlock.AppFilterId(snapshot, row.App!.App.Id);
            row.IsBlockedIn = QuickBlock.IsBlocked(snapshot, filter, RuleDirection.In);
            row.IsBlockedOut = QuickBlock.IsBlocked(snapshot, filter, RuleDirection.Out);
            var limitIn = QuickLimit.Find(snapshot, filter, RuleDirection.In);
            var limitOut = QuickLimit.Find(snapshot, filter, RuleDirection.Out);
            row.IsLimitedIn = QuickLimit.IsLimited(limitIn);
            row.IsLimitedOut = QuickLimit.IsLimited(limitOut);
            row.LimitInText = QuickLimit.Format(QuickLimit.Kilobytes(limitIn));
            row.LimitOutText = QuickLimit.Format(QuickLimit.Kilobytes(limitOut));
            row.Priority = QuickPriority.Level(QuickPriority.Find(snapshot, filter));
        }
        ShowPriorityStatus();
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
        Priorities.RefreshSettings();
        Stats.RefreshSettings();
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

    /// <summary>Light, dark or follow Windows; applied by the app's <see cref="ThemeManager"/>.</summary>
    public AppTheme Theme
    {
        get => _settings.Theme;
        set
        {
            if (_settings.Theme == value)
                return;
            _settings.Theme = value;
            _saveSettings();
            ThemeChanged?.Invoke(value);
            OnPropertyChanged();
        }
    }

    public event Action<AppTheme>? ThemeChanged;

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
            if (IsStatsTabVisible)
                await Stats.RefreshAsync();
        }
        catch (Exception ex) when (ex is IpcDisconnectedException or IpcRemoteException)
        {
            StatusText = ex.Message;
        }
    }

    [RelayCommand]
    private void SetUnits(UnitMode units) => Activity.Units = units;
}
