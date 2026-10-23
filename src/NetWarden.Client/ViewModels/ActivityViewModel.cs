using System.Collections.ObjectModel;
using System.Net;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetWarden.Client.Charts;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Formatting;
using NetWarden.Shared.Ipc;

namespace NetWarden.Client.ViewModels;

public enum ActivitySortColumn
{
    Name,
    RateIn,
    RateOut,
    TotalIn,
    TotalOut,
}

/// <summary>
/// The activity grid: apps with expandable connection rows, filtered, searched and
/// sorted. <see cref="Apply"/> must be called on the UI thread.
/// </summary>
public sealed partial class ActivityViewModel : ObservableObject
{
    public const string ComputerKey = "*";

    private readonly IServiceRequester _service;
    private readonly ClientSettings _settings;
    private readonly Action _saveSettings;
    private readonly Func<AppInfo, ImageSource?> _icons;
    private readonly PortNames _ports;
    private readonly Dictionary<string, ActivityRow> _appRows = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ActivityRow> _connectionRows = new(StringComparer.Ordinal);
    private ActivitySnapshot? _snapshot;
    private bool _suppressRebuild;

    public ActivityViewModel(
        IServiceRequester service,
        ClientSettings settings,
        Action saveSettings,
        Func<AppInfo, ImageSource?> icons,
        PortNames ports)
    {
        _service = service;
        _settings = settings;
        _saveSettings = saveSettings;
        _icons = icons;
        _ports = ports;
        _filter = settings.Filter;
        _units = settings.Units;
    }

    public ObservableCollection<ActivityRow> Rows { get; } = [];

    public RateHistoryStore History { get; } = new(capacity: 600);

    [ObservableProperty]
    private ActivityFilter _filter;

    [ObservableProperty]
    private string _search = "";

    [ObservableProperty]
    private UnitMode _units;

    [ObservableProperty]
    private ActivitySortColumn _sortColumn = ActivitySortColumn.Name;

    [ObservableProperty]
    private bool _sortDescending;

    [ObservableProperty]
    private long _rateIn;

    [ObservableProperty]
    private long _rateOut;

    [ObservableProperty]
    private long _totalIn;

    [ObservableProperty]
    private long _totalOut;

    [ObservableProperty]
    private string? _lastError;

    public string TotalsText =>
        $"↓ {ByteFormatter.Rate(RateIn, Units)}   ↑ {ByteFormatter.Rate(RateOut, Units)}   " +
        $"Total ↓ {ByteFormatter.Size(TotalIn)}  ↑ {ByteFormatter.Size(TotalOut)}";

    public IReadOnlyList<ActivityFilter> Filters { get; } = Enum.GetValues<ActivityFilter>();
    public IReadOnlyList<UnitMode> UnitModes { get; } = Enum.GetValues<UnitMode>();

    /// <summary>Raised after each snapshot so charts can redraw.</summary>
    public event Action? Updated;

    partial void OnFilterChanged(ActivityFilter value)
    {
        _settings.Filter = value;
        _saveSettings();
        Rebuild();
    }

    partial void OnSearchChanged(string value) => Rebuild();
    partial void OnSortColumnChanged(ActivitySortColumn value) => Rebuild();
    partial void OnSortDescendingChanged(bool value) => Rebuild();

    partial void OnUnitsChanged(UnitMode value)
    {
        _settings.Units = value;
        _saveSettings();
        foreach (var row in _appRows.Values.Concat(_connectionRows.Values))
            row.SetUnits(value);
        OnPropertyChanged(nameof(TotalsText));
    }

    partial void OnRateInChanged(long value) => OnPropertyChanged(nameof(TotalsText));
    partial void OnRateOutChanged(long value) => OnPropertyChanged(nameof(TotalsText));
    partial void OnTotalInChanged(long value) => OnPropertyChanged(nameof(TotalsText));
    partial void OnTotalOutChanged(long value) => OnPropertyChanged(nameof(TotalsText));

    /// <summary>Click on a column header: same column flips direction; a new column starts descending for numbers.</summary>
    public void SortBy(ActivitySortColumn column)
    {
        if (SortColumn == column)
        {
            SortDescending = !SortDescending;
            return;
        }
        // Change both before rebuilding once with the final state.
        _suppressRebuild = true;
        SortDescending = column != ActivitySortColumn.Name;
        SortColumn = column;
        _suppressRebuild = false;
        Rebuild();
    }

    public void Apply(ActivitySnapshot snapshot)
    {
        _snapshot = snapshot;
        RateIn = snapshot.RateIn;
        RateOut = snapshot.RateOut;
        TotalIn = snapshot.TotalIn;
        TotalOut = snapshot.TotalOut;
        History.Add(ComputerKey, snapshot.Timestamp, snapshot.RateIn, snapshot.RateOut);

        var seenApps = new HashSet<string>(StringComparer.Ordinal);
        var seenConnections = new HashSet<string>(StringComparer.Ordinal);
        foreach (var app in snapshot.Apps)
        {
            seenApps.Add(app.App.Id);
            if (!_appRows.TryGetValue(app.App.Id, out var row))
            {
                row = new ActivityRow(app.App.Id, 0) { Icon = _icons(app.App) };
                row.SetUnits(Units);
                row.PropertyChanged += (_, e) =>
                {
                    if (e.PropertyName == nameof(ActivityRow.IsExpanded))
                        Rebuild();
                };
                _appRows[app.App.Id] = row;
            }
            row.Update(app);
            History.Add(app.App.Id, snapshot.Timestamp, app.RateIn, app.RateOut);

            foreach (var c in app.Connections)
            {
                string key = app.App.Id + "#" + c.Key;
                seenConnections.Add(key);
                if (!_connectionRows.TryGetValue(key, out var child))
                {
                    child = new ActivityRow(key, 1) { Parent = row };
                    child.SetUnits(Units);
                    _connectionRows[key] = child;
                }
                child.Update(c, _ports);
            }
        }

        RemoveMissing(_appRows, seenApps);
        RemoveMissing(_connectionRows, seenConnections);
        History.Retain(seenApps.Append(ComputerKey));
        Rebuild();
        Updated?.Invoke();
    }

    private static void RemoveMissing(Dictionary<string, ActivityRow> rows, HashSet<string> keep)
    {
        foreach (string key in rows.Keys.Where(k => !keep.Contains(k)).ToList())
            rows.Remove(key);
    }

    private void Rebuild()
    {
        if (_snapshot is null || _suppressRebuild)
            return;

        var desired = new List<ActivityRow>(_appRows.Count);
        foreach (var app in Sort(_appRows.Values.Where(IsVisible)))
        {
            desired.Add(app);
            if (!app.IsExpanded)
                continue;
            var children = _connectionRows.Values.Where(c => ReferenceEquals(c.Parent, app));
            desired.AddRange(Sort(children));
        }
        ListSync.Sync(Rows, desired);
    }

    private bool IsVisible(ActivityRow row)
    {
        bool hidden = _settings.HiddenAppIds.Contains(row.Key);
        bool byFilter = Filter switch
        {
            ActivityFilter.Online => !hidden && row.IsOnline,
            ActivityFilter.Offline => !hidden && !row.IsOnline,
            ActivityFilter.All => !hidden,
            _ => hidden,
        };
        if (!byFilter)
            return false;

        string term = Search.Trim();
        if (term.Length == 0)
            return true;
        return Contains(row.Name, term) || Contains(row.Detail, term)
            || _connectionRows.Values.Any(c => ReferenceEquals(c.Parent, row) && Contains(c.Name, term));
    }

    private static bool Contains(string text, string term) => text.Contains(term, StringComparison.OrdinalIgnoreCase);

    private IEnumerable<ActivityRow> Sort(IEnumerable<ActivityRow> rows)
    {
        Func<ActivityRow, long> key = SortColumn switch
        {
            ActivitySortColumn.RateIn => r => r.RateIn,
            ActivitySortColumn.RateOut => r => r.RateOut,
            ActivitySortColumn.TotalIn => r => r.TotalIn,
            ActivitySortColumn.TotalOut => r => r.TotalOut,
            _ => _ => 0,
        };
        // Name breaks ties so equal rows never swap places between refreshes.
        var ordered = SortDescending ? rows.OrderByDescending(key) : rows.OrderBy(key);
        return SortColumn == ActivitySortColumn.Name && SortDescending
            ? ordered.ThenByDescending(r => r.Name, StringComparer.CurrentCultureIgnoreCase).ThenBy(r => r.Key, StringComparer.Ordinal)
            : ordered.ThenBy(r => r.Name, StringComparer.CurrentCultureIgnoreCase).ThenBy(r => r.Key, StringComparer.Ordinal);
    }

    public bool IsHidden(ActivityRow row) => _settings.HiddenAppIds.Contains(row.Key);

    [RelayCommand]
    private void ToggleHidden(ActivityRow? row)
    {
        if (row is not { IsApp: true })
            return;
        if (!_settings.HiddenAppIds.Remove(row.Key))
            _settings.HiddenAppIds.Add(row.Key);
        _saveSettings();
        Rebuild();
    }

    [RelayCommand]
    private void ToggleExpanded(ActivityRow? row)
    {
        if (row is { IsApp: true, HasChildren: true })
            row.IsExpanded = !row.IsExpanded;
    }

    [RelayCommand]
    private async Task ResetTotalsAsync()
    {
        await RunAsync(() => _service.RequestAsync<bool>(Methods.ActivityResetTotals));
    }

    /// <summary>Connections of a row that Windows can kill: established IPv4 TCP.</summary>
    public IReadOnlyList<ConnectionActivity> KillableConnections(ActivityRow row)
    {
        IEnumerable<ConnectionActivity> candidates = row.IsApp
            ? row.App?.Connections ?? []
            : row.Connection is { } c ? [c] : [];
        return candidates.Where(IsKillable).ToList();
    }

    private static bool IsKillable(ConnectionActivity c) =>
        c.Protocol == TransportProtocol.Tcp
        && c.Kind != ConnectionKind.Listen
        && c.RemoteAddress is not null
        && IPAddress.TryParse(c.LocalAddress, out var local) && local.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
        && IPAddress.TryParse(c.RemoteAddress, out var remote) && remote.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;

    public async Task<int> KillAsync(ActivityRow row)
    {
        int killed = 0;
        foreach (var c in KillableConnections(row))
        {
            bool ok = await RunAsync(() => _service.RequestAsync<bool>(Methods.ConnectionsKill,
                new KillConnectionRequest(c.Protocol, c.LocalAddress, c.LocalPort, c.RemoteAddress!, c.RemotePort)));
            if (ok)
                killed++;
        }
        return killed;
    }

    private async Task<bool> RunAsync(Func<Task> action)
    {
        try
        {
            await action();
            LastError = null;
            return true;
        }
        catch (Exception ex) when (ex is IpcRemoteException or IpcDisconnectedException)
        {
            LastError = ex.Message;
            return false;
        }
    }
}
