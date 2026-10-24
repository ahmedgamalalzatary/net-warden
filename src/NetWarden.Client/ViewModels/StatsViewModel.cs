using System.Globalization;
using System.IO;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetWarden.Client.Charts;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Formatting;
using NetWarden.Shared.Ipc;

namespace NetWarden.Client.ViewModels;

public enum StatsRange
{
    Hour,
    Today,
    Week,
    Month,
    Year,
    Custom,
}

/// <summary>A time range of the stats view in local time: [<see cref="From"/>, <see cref="To"/>).</summary>
public sealed record StatsWindow(DateTimeOffset From, DateTimeOffset To, StatsBucket Bucket, string Title);

/// <summary>One line of the stats breakdown; sortable by the raw byte counts of <see cref="Row"/>.</summary>
public sealed record StatsRowView(StatsRow Row, string Label, string? Detail, string In, string Out, string Total, double Share)
{
    public long TotalBytes => Row.In + Row.Out;
}

/// <summary>The Statistics tab: what was transferred over a time range, by app, host, port, country or user.</summary>
public sealed partial class StatsViewModel : ObservableObject
{
    private readonly IServiceRequester _service;
    private readonly ClientSettings _settings;
    private readonly Action _saveSettings;
    private readonly PortNames _ports;
    private readonly Func<ServiceSettings?> _serviceSettings;
    private readonly Func<Action<ServiceSettings>, Task> _updateSettings;
    private readonly TimeProvider _time;
    private int _version;

    public StatsViewModel(IServiceRequester service, ClientSettings settings, Action saveSettings, PortNames ports,
        Func<ServiceSettings?> serviceSettings, Func<Action<ServiceSettings>, Task> updateSettings, TimeProvider? time = null)
    {
        _service = service;
        _settings = settings;
        _saveSettings = saveSettings;
        _ports = ports;
        _serviceSettings = serviceSettings;
        _updateSettings = updateSettings;
        _time = time ?? TimeProvider.System;
        _range = settings.StatsRange;
        _groupBy = settings.StatsGroupBy;
        DateTime today = Now.Date;
        _customFrom = today.AddDays(-6);
        _customTo = today;
    }

    public IReadOnlyList<StatsRange> Ranges { get; } = Enum.GetValues<StatsRange>();
    public IReadOnlyList<StatsGroupBy> GroupBys { get; } = Enum.GetValues<StatsGroupBy>();
    public IReadOnlyList<string> Protocols { get; } = ["All", "TCP", "UDP"];

    /// <summary>Time zone the service buckets days and hours in; the client's own.</summary>
    public TimeZoneInfo TimeZone { get; set; } = TimeZoneInfo.Local;

    private DateTime Now => TimeZoneInfo.ConvertTime(_time.GetUtcNow(), TimeZone).DateTime;

    [ObservableProperty] private StatsRange _range;
    [ObservableProperty] private int _offset;
    [ObservableProperty] private DateTime _customFrom;
    [ObservableProperty] private DateTime _customTo;
    [ObservableProperty] private StatsGroupBy _groupBy;
    [ObservableProperty] private bool _showInternet = true;
    [ObservableProperty] private bool _showLocalNetwork = true;
    [ObservableProperty] private bool _showLoopback = true;
    [ObservableProperty] private string _protocol = "All";

    /// <summary>When set, everything is narrowed to this app (id and display name).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasAppFilter), nameof(AppFilterText))]
    private (string Id, string Name)? _appFilter;

    [ObservableProperty] private StatsResult? _result;
    [ObservableProperty] private IReadOnlyList<StatsBar> _bars = [];
    [ObservableProperty] private IReadOnlyList<StatsBar> _hourBars = [];
    [ObservableProperty] private IReadOnlyList<StatsRowView> _rows = [];
    [ObservableProperty] private string _rangeTitle = "";
    [ObservableProperty] private string _totalsText = "";
    [ObservableProperty] private string _footerText = "";
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private string? _lastError;

    public bool IsCustom => Range == StatsRange.Custom;
    public bool CanStep => Range != StatsRange.Custom;
    public bool CanGoForward => CanStep && Offset < 0;
    public bool HasAppFilter => AppFilter is not null;
    public string AppFilterText => AppFilter is { } app ? $"App: {app.Name}" : "";

    // Recording settings live in the service.
    public bool IsStatsEnabled { get => _serviceSettings()?.IsStatsEnabled ?? false; set => _ = _updateSettings(s => s.IsStatsEnabled = value); }
    public bool SaveInternet { get => Saves(s => s.SaveInternet); set => _ = _updateSettings(s => s.Stats.SaveInternet = value); }
    public bool SaveLocalNetwork { get => Saves(s => s.SaveLocalNetwork); set => _ = _updateSettings(s => s.Stats.SaveLocalNetwork = value); }
    public bool SaveLoopback { get => Saves(s => s.SaveLoopback); set => _ = _updateSettings(s => s.Stats.SaveLoopback = value); }

    private bool Saves(Func<StatsSettings, bool> get) => _serviceSettings() is { } s && get(s.Stats);

    public void RefreshSettings()
    {
        foreach (string name in new[] { nameof(IsStatsEnabled), nameof(SaveInternet), nameof(SaveLocalNetwork), nameof(SaveLoopback) })
            OnPropertyChanged(name);
    }

    /// <summary>True while the selected range contains the present, so new traffic can still change it.</summary>
    public bool IsLive
    {
        get
        {
            var window = Window(Range, Offset, Now, CustomFrom, CustomTo, TimeZone);
            var now = _time.GetUtcNow();
            return window.From <= now && now < window.To;
        }
    }

    partial void OnRangeChanged(StatsRange value)
    {
        _settings.StatsRange = value;
        _saveSettings();
        Offset = 0;
        OnPropertyChanged(nameof(IsCustom));
        OnPropertyChanged(nameof(CanStep));
        OnPropertyChanged(nameof(CanGoForward));
        _ = RefreshAsync();
    }

    partial void OnGroupByChanged(StatsGroupBy value)
    {
        _settings.StatsGroupBy = value;
        _saveSettings();
        _ = RefreshAsync();
    }

    partial void OnOffsetChanged(int value)
    {
        OnPropertyChanged(nameof(CanGoForward));
        _ = RefreshAsync();
    }

    partial void OnCustomFromChanged(DateTime value) => RefreshIfCustom();
    partial void OnCustomToChanged(DateTime value) => RefreshIfCustom();
    partial void OnShowInternetChanged(bool value) => _ = RefreshAsync();
    partial void OnShowLocalNetworkChanged(bool value) => _ = RefreshAsync();
    partial void OnShowLoopbackChanged(bool value) => _ = RefreshAsync();
    partial void OnProtocolChanged(string value) => _ = RefreshAsync();
    partial void OnAppFilterChanged((string Id, string Name)? value) => _ = RefreshAsync();

    private void RefreshIfCustom()
    {
        if (Range == StatsRange.Custom)
            _ = RefreshAsync();
    }

    [RelayCommand]
    private void Previous() => Offset--;

    [RelayCommand]
    private void Next()
    {
        if (Offset < 0)
            Offset++;
    }

    [RelayCommand]
    private void ClearAppFilter() => AppFilter = null;

    /// <summary>Narrows the view to the app of a breakdown row and lists its hosts.</summary>
    public void DrillInto(StatsRowView? row)
    {
        if (row is null || GroupBy != StatsGroupBy.App)
            return;
        AppFilter = (row.Row.Key, row.Row.Label);
        GroupBy = StatsGroupBy.Host;
    }

    public StatsQuery BuildQuery()
    {
        var window = Window(Range, Offset, Now, CustomFrom, CustomTo, TimeZone);
        var zones = new List<StatsZone>();
        if (ShowInternet)
            zones.Add(StatsZone.Internet);
        if (ShowLocalNetwork)
            zones.Add(StatsZone.LocalNetwork);
        if (ShowLoopback)
            zones.Add(StatsZone.Loopback);
        TransportProtocol? protocol = Protocol switch
        {
            "TCP" => TransportProtocol.Tcp,
            "UDP" => TransportProtocol.Udp,
            _ => null,
        };
        return new StatsQuery(window.From, window.To, window.Bucket, GroupBy, zones.Count == 3 ? null : zones, protocol,
            AppFilter?.Id, TimeZone.Id);
    }

    [RelayCommand]
    public async Task RefreshAsync()
    {
        int version = ++_version;
        var query = BuildQuery();
        RangeTitle = Window(Range, Offset, Now, CustomFrom, CustomTo, TimeZone).Title;
        IsLoading = true;
        try
        {
            var result = await _service.RequestAsync<StatsResult>(Methods.StatsQuery, query);
            if (version != _version)
                return; // a newer query was started meanwhile
            LastError = null;
            Show(result);
        }
        catch (Exception ex) when (ex is IpcRemoteException or IpcDisconnectedException or TimeoutException)
        {
            if (version == _version)
                LastError = ex is IpcRemoteException remote ? remote.RemoteMessage : ex.Message;
        }
        finally
        {
            if (version == _version)
                IsLoading = false;
        }
    }

    private void Show(StatsResult? result)
    {
        Result = result;
        if (result is null)
        {
            Bars = HourBars = [];
            Rows = [];
            TotalsText = FooterText = "";
            return;
        }
        Bars = result.Series.Select(p => new StatsBar(BarLabel(p.Time, result.Bucket, Range), BarTitle(p.Time, result.Bucket), p.In, p.Out)).ToList();
        HourBars = result.Hours.Select(h => new StatsBar(h.Hour.ToString("00", CultureInfo.CurrentCulture),
            $"{h.Hour:00}:00 - {h.Hour:00}:59", h.In, h.Out)).ToList();
        long total = Math.Max(1, result.Rows.Sum(r => r.In + r.Out));
        Rows = result.Rows.Select(r => new StatsRowView(r, RowLabel(r), r.Detail,
            ByteFormatter.Size(r.In), ByteFormatter.Size(r.Out), ByteFormatter.Size(r.In + r.Out), (double)(r.In + r.Out) / total)).ToList();
        TotalsText = $"↓ {ByteFormatter.Size(result.TotalIn)}   ↑ {ByteFormatter.Size(result.TotalOut)}   Σ {ByteFormatter.Size(result.TotalIn + result.TotalOut)}";
        FooterText = result.IsTruncated ? $"Showing the top {result.Rows.Count} entries." : $"{result.Rows.Count} entries";
    }

    private string RowLabel(StatsRow row) => GroupBy == StatsGroupBy.Port && int.TryParse(row.Label, out int port)
        && _ports.Get(port, row.Key.StartsWith("Udp", StringComparison.Ordinal) ? TransportProtocol.Udp : TransportProtocol.Tcp) is { } name
            ? $"{port} ({name})"
            : row.Label;

    /// <summary>The time range, bucket width and title for a range choice, stepped back by <paramref name="offset"/> periods.</summary>
    public static StatsWindow Window(StatsRange range, int offset, DateTime now, DateTime customFrom, DateTime customTo, TimeZoneInfo zone)
    {
        var culture = CultureInfo.CurrentCulture;
        DateTime start, end;
        StatsBucket bucket;
        string title;
        switch (range)
        {
            case StatsRange.Hour:
                end = new DateTime(now.Year, now.Month, now.Day, now.Hour, now.Minute, 0).AddMinutes(1 + 60 * offset);
                start = end.AddHours(-1);
                bucket = StatsBucket.Minute;
                title = offset == 0 ? "Last 60 minutes" : $"{start.ToString("g", culture)} - {end.ToString("t", culture)}";
                break;
            case StatsRange.Today:
                start = now.Date.AddDays(offset);
                end = start.AddDays(1);
                bucket = StatsBucket.Hour;
                title = (offset == 0 ? "Today, " : offset == -1 ? "Yesterday, " : "") + start.ToString("D", culture);
                break;
            case StatsRange.Week:
                int back = (7 + (int)now.DayOfWeek - (int)culture.DateTimeFormat.FirstDayOfWeek) % 7;
                start = now.Date.AddDays(-back + 7 * offset);
                end = start.AddDays(7);
                bucket = StatsBucket.Day;
                title = $"{start.ToString("d", culture)} - {end.AddDays(-1).ToString("d", culture)}";
                break;
            case StatsRange.Month:
                start = new DateTime(now.Year, now.Month, 1).AddMonths(offset);
                end = start.AddMonths(1);
                bucket = StatsBucket.Day;
                title = start.ToString("Y", culture);
                break;
            case StatsRange.Year:
                start = new DateTime(now.Year, 1, 1).AddYears(offset);
                end = start.AddYears(1);
                bucket = StatsBucket.Month;
                title = start.Year.ToString(culture);
                break;
            default:
                start = (customFrom <= customTo ? customFrom : customTo).Date;
                end = (customFrom <= customTo ? customTo : customFrom).Date.AddDays(1);
                double days = (end - start).TotalDays;
                bucket = days <= 2 ? StatsBucket.Hour : days <= 92 ? StatsBucket.Day : StatsBucket.Month;
                title = $"{start.ToString("d", culture)} - {end.AddDays(-1).ToString("d", culture)}";
                break;
        }
        return new StatsWindow(Local(start, zone), Local(end, zone), bucket, title);
    }

    private static DateTimeOffset Local(DateTime time, TimeZoneInfo zone)
    {
        // A time skipped by a DST change doesn't exist; move past the gap.
        while (zone.IsInvalidTime(time))
            time = time.AddMinutes(30);
        return new DateTimeOffset(DateTime.SpecifyKind(time, DateTimeKind.Unspecified), zone.GetUtcOffset(time));
    }

    internal static string BarLabel(DateTimeOffset time, StatsBucket bucket, StatsRange range) => bucket switch
    {
        StatsBucket.Minute => time.ToString("HH:mm", CultureInfo.CurrentCulture),
        StatsBucket.Hour => range == StatsRange.Custom ? time.ToString("d.M HH", CultureInfo.CurrentCulture) : time.ToString("HH", CultureInfo.CurrentCulture),
        StatsBucket.Day => range == StatsRange.Week ? time.ToString("ddd d", CultureInfo.CurrentCulture) : time.Day.ToString(CultureInfo.CurrentCulture),
        _ => time.ToString("MMM", CultureInfo.CurrentCulture),
    };

    internal static string BarTitle(DateTimeOffset time, StatsBucket bucket) => bucket switch
    {
        StatsBucket.Minute => time.ToString("g", CultureInfo.CurrentCulture),
        StatsBucket.Hour => $"{time.ToString("d", CultureInfo.CurrentCulture)} {time:HH}:00",
        StatsBucket.Day => time.ToString("D", CultureInfo.CurrentCulture),
        _ => time.ToString("Y", CultureInfo.CurrentCulture),
    };

    /// <summary>The breakdown as CSV (bytes, not formatted sizes, so spreadsheets can sum them).</summary>
    public string RowsCsv()
    {
        var sb = new StringBuilder();
        sb.AppendLine(Csv(GroupBy.ToString(), "Detail", "Key", "Download bytes", "Upload bytes", "Total bytes"));
        foreach (var r in Rows)
            sb.AppendLine(Csv(r.Label, r.Detail ?? "", r.Row.Key, Num(r.Row.In), Num(r.Row.Out), Num(r.TotalBytes)));
        return sb.ToString();
    }

    /// <summary>The time chart as CSV; times are ISO 8601 with their UTC offset.</summary>
    public string SeriesCsv()
    {
        var sb = new StringBuilder();
        sb.AppendLine(Csv("Time", "Download bytes", "Upload bytes"));
        foreach (var p in Result?.Series ?? [])
            sb.AppendLine(Csv(p.Time.ToString("yyyy-MM-ddTHH:mm:sszzz", CultureInfo.InvariantCulture), Num(p.In), Num(p.Out)));
        return sb.ToString();
    }

    public static void WriteCsv(string path, string csv) => File.WriteAllText(path, csv, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

    private static string Num(long value) => value.ToString(CultureInfo.InvariantCulture);

    internal static string Csv(params string[] fields) => string.Join(",", fields.Select(CsvField));

    private static string CsvField(string f)
    {
        // Text a spreadsheet would run as a formula (host names come from the network) gets a leading quote.
        if (f.Length > 0 && "=+-@".Contains(f[0]) && !long.TryParse(f, NumberStyles.Integer, CultureInfo.InvariantCulture, out _))
            f = "'" + f;
        return f.IndexOfAny([',', '"', '\n', '\r']) >= 0 || f.StartsWith(' ') || f.EndsWith(' ')
            ? "\"" + f.Replace("\"", "\"\"") + "\""
            : f;
    }

    /// <summary>A file name for exports, e.g. "NetWarden apps 2026-10-24.csv".</summary>
    public string ExportFileName(string what) =>
        $"NetWarden {what} {BuildQuery().From.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}.csv";
}
