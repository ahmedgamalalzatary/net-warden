using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Formatting;
using NetWarden.Shared.Ipc;

namespace NetWarden.Client.ViewModels;

public sealed record LogRow(ConnectionLogEntry Entry)
{
    public string Time => Entry.Time.ToLocalTime().ToString("T");
    public string Event => Entry.Event.ToString();
    public string App => Entry.AppName;
    public int ProcessId => Entry.ProcessId;
    public string Protocol => Entry.Protocol.ToString().ToUpperInvariant();
    public string Local => $"{Entry.LocalAddress}:{Entry.LocalPort}";
    public string Remote => Entry.RemoteAddress is null ? "" : $"{Entry.RemoteAddress}:{Entry.RemotePort}";
    public string Host => Entry.RemoteHost ?? "";
    public bool IsBlocked => Entry.Event == ConnectionLogEvent.Blocked;

    public bool Matches(string search) =>
        App.Contains(search, StringComparison.OrdinalIgnoreCase) || Remote.Contains(search, StringComparison.OrdinalIgnoreCase)
        || Host.Contains(search, StringComparison.OrdinalIgnoreCase) || Event.Contains(search, StringComparison.OrdinalIgnoreCase);
}

/// <summary>The Log tab: follows the service's connection log, newest first.</summary>
public sealed partial class ConnectionLogViewModel(IServiceRequester service) : ObservableObject
{
    private const int MaxRows = 10_000;
    private readonly List<LogRow> _all = [];
    private long _lastId;

    /// <summary>The rows shown: newest first, narrowed by <see cref="Search"/>.</summary>
    public ObservableCollection<LogRow> Entries { get; } = [];

    [ObservableProperty]
    private bool _isRunning = true;

    [ObservableProperty]
    private string _search = "";

    [ObservableProperty]
    private string? _lastError;

    public string ToggleText => IsRunning ? "Stop" : "Start";

    partial void OnIsRunningChanged(bool value) => OnPropertyChanged(nameof(ToggleText));

    partial void OnSearchChanged(string value) => Rebuild();

    public async Task RefreshAsync()
    {
        try
        {
            if (await service.RequestAsync<ConnectionLogPage>(Methods.ConnectionLogGet, new ConnectionLogRequest(_lastId)) is not { } page)
                return;
            IsRunning = page.IsRunning;
            LastError = null;
            if (page.Entries.Count == 0)
                return;
            _lastId = page.Entries[^1].Id;
            _all.AddRange(page.Entries.Select(e => new LogRow(e)));
            if (_all.Count > MaxRows)
                _all.RemoveRange(0, _all.Count - MaxRows);
            Rebuild();
        }
        catch (Exception ex) when (ex is IpcRemoteException or IpcDisconnectedException)
        {
            LastError = ex.Message;
        }
    }

    [RelayCommand]
    private async Task ClearAsync()
    {
        await RunAsync(() => service.RequestAsync<bool>(Methods.ConnectionLogClear));
        _all.Clear();
        Rebuild();
    }

    [RelayCommand]
    private async Task ToggleRunningAsync()
    {
        await RunAsync(() => service.RequestAsync<bool>(Methods.ConnectionLogSetRunning, new ConnectionLogRunning(!IsRunning)));
        await RefreshAsync();
    }

    public string Csv()
    {
        var sb = new StringBuilder();
        sb.AppendLine(StatsViewModel.Csv("Time", "Event", "App", "Process id", "Protocol", "Local", "Remote", "Host"));
        foreach (var r in Entries.Reverse())
            sb.AppendLine(StatsViewModel.Csv(r.Entry.Time.ToString("yyyy-MM-ddTHH:mm:sszzz", CultureInfo.InvariantCulture), r.Event, r.App,
                r.ProcessId.ToString(CultureInfo.InvariantCulture), r.Protocol, r.Local, r.Remote, r.Host));
        return sb.ToString();
    }

    private void Rebuild()
    {
        Entries.Clear();
        foreach (var row in Enumerable.Reverse(_all))
            if (Search.Length == 0 || row.Matches(Search.Trim()))
                Entries.Add(row);
    }

    private async Task RunAsync(Func<Task> action)
    {
        try
        {
            await action();
            LastError = null;
        }
        catch (Exception ex) when (ex is IpcRemoteException or IpcDisconnectedException)
        {
            LastError = ex.Message;
        }
    }
}

public enum HistoryRange
{
    Day,
    Week,
    Month,
    All,
}

public sealed record HistoryRow(ConnectionHistoryRow Row)
{
    public string App => Row.AppName;
    public string Address => Row.Address;
    public string Host => Row.HostName ?? "";
    public string Port => Row.Port == 0 ? "" : Row.Port.ToString(CultureInfo.CurrentCulture);
    public string Protocol => Row.Protocol.ToString().ToUpperInvariant();
    public string In => ByteFormatter.Size(Row.In);
    public string Out => ByteFormatter.Size(Row.Out);
    public string First => Row.First.ToLocalTime().ToString("g");
    public string Last => Row.Last.ToLocalTime().ToString("g");

    public bool Matches(string search) =>
        App.Contains(search, StringComparison.OrdinalIgnoreCase) || Address.Contains(search, StringComparison.OrdinalIgnoreCase)
        || Host.Contains(search, StringComparison.OrdinalIgnoreCase) || Port.Contains(search, StringComparison.OrdinalIgnoreCase);
}

/// <summary>The History tab: who each app talked to, from the statistics.</summary>
public sealed partial class ConnectionHistoryViewModel(IServiceRequester service, Func<DateTimeOffset> now, ClientSettings? settings = null, Action? saveSettings = null) : ObservableObject
{
    private List<HistoryRow> _all = [];
    private AppInfo? _app;

    public IReadOnlyList<HistoryRange> Ranges { get; } = Enum.GetValues<HistoryRange>();
    public ObservableCollection<HistoryRow> Rows { get; } = [];

    [ObservableProperty]
    private HistoryRange _range = settings?.HistoryRange ?? HistoryRange.Week;

    [ObservableProperty]
    private string _search = "";

    [ObservableProperty]
    private string? _lastError;

    public bool HasApp => _app is not null;
    public string AppText => _app is null ? "" : $"App: {_app.DisplayName}";

    partial void OnRangeChanged(HistoryRange value)
    {
        if (settings is not null)
            settings.HistoryRange = value;
        saveSettings?.Invoke();
        _ = RefreshAsync();
    }

    partial void OnSearchChanged(string value) => Rebuild();

    public Task ShowAppAsync(AppInfo app)
    {
        _app = app;
        NotifyApp();
        return RefreshAsync();
    }

    [RelayCommand]
    private Task ClearAppAsync()
    {
        _app = null;
        NotifyApp();
        return RefreshAsync();
    }

    [RelayCommand]
    public async Task RefreshAsync()
    {
        DateTimeOffset to = now();
        DateTimeOffset? from = Range switch
        {
            HistoryRange.Day => to.AddDays(-1),
            HistoryRange.Week => to.AddDays(-7),
            HistoryRange.Month => to.AddDays(-30),
            _ => null,
        };
        try
        {
            // A minute in the future: the current minute's slot is still being written.
            var rows = await service.RequestAsync<List<ConnectionHistoryRow>>(Methods.StatsHistory,
                new ConnectionHistoryQuery(_app?.Id, from, to.AddMinutes(1)));
            _all = (rows ?? []).Select(r => new HistoryRow(r)).ToList();
            LastError = null;
            Rebuild();
        }
        catch (Exception ex) when (ex is IpcRemoteException or IpcDisconnectedException)
        {
            LastError = ex.Message;
        }
    }

    public string Csv()
    {
        var sb = new StringBuilder();
        sb.AppendLine(StatsViewModel.Csv("App", "Address", "Host", "Port", "Protocol", "Download bytes", "Upload bytes", "First transfer", "Last transfer"));
        foreach (var r in Rows)
            sb.AppendLine(StatsViewModel.Csv(r.App, r.Address, r.Host, r.Port, r.Protocol,
                r.Row.In.ToString(CultureInfo.InvariantCulture), r.Row.Out.ToString(CultureInfo.InvariantCulture),
                r.Row.First.ToString("yyyy-MM-ddTHH:mm:sszzz", CultureInfo.InvariantCulture), r.Row.Last.ToString("yyyy-MM-ddTHH:mm:sszzz", CultureInfo.InvariantCulture)));
        return sb.ToString();
    }

    private void NotifyApp()
    {
        OnPropertyChanged(nameof(HasApp));
        OnPropertyChanged(nameof(AppText));
    }

    private void Rebuild()
    {
        Rows.Clear();
        foreach (var row in _all)
            if (Search.Length == 0 || row.Matches(Search.Trim()))
                Rows.Add(row);
    }
}
