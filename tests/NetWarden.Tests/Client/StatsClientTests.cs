using System.Globalization;
using Microsoft.Extensions.Time.Testing;
using NetWarden.Client;
using NetWarden.Client.ViewModels;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Formatting;
using NetWarden.Shared.Ipc;

namespace NetWarden.Tests.Client;

public sealed class StatsWindowTests : IDisposable
{
    private readonly CultureInfo _culture = CultureInfo.CurrentCulture;
    private static readonly TimeZoneInfo Utc = TimeZoneInfo.Utc;
    private static readonly DateTime Now = new(2026, 10, 22, 14, 37, 20); // a Thursday

    public StatsWindowTests() => CultureInfo.CurrentCulture = new CultureInfo("en-US"); // weeks start on Sunday

    public void Dispose() => CultureInfo.CurrentCulture = _culture;

    private static StatsWindow W(StatsRange range, int offset = 0, DateTime? from = null, DateTime? to = null, TimeZoneInfo? zone = null) =>
        StatsViewModel.Window(range, offset, Now, from ?? Now, to ?? Now, zone ?? Utc);

    private static DateTimeOffset U(int month, int day, int hour = 0, int minute = 0, int year = 2026) =>
        new(year, month, day, hour, minute, 0, TimeSpan.Zero);

    [Fact]
    public void Hour_is_the_last_60_minutes_including_the_current_one()
    {
        var w = W(StatsRange.Hour);
        Assert.Equal((U(10, 22, 13, 38), U(10, 22, 14, 38), StatsBucket.Minute), (w.From, w.To, w.Bucket));
        Assert.Equal("Last 60 minutes", w.Title);
        Assert.Equal(U(10, 22, 12, 38), W(StatsRange.Hour, -1).From);
    }

    [Fact]
    public void Today_and_yesterday()
    {
        Assert.Equal((U(10, 22), U(10, 23), StatsBucket.Hour), (W(StatsRange.Today).From, W(StatsRange.Today).To, W(StatsRange.Today).Bucket));
        Assert.StartsWith("Today, ", W(StatsRange.Today).Title);
        Assert.Equal(U(10, 21), W(StatsRange.Today, -1).From);
        Assert.StartsWith("Yesterday, ", W(StatsRange.Today, -1).Title);
    }

    [Fact]
    public void Week_starts_on_the_cultures_first_day()
    {
        Assert.Equal((U(10, 18), U(10, 25), StatsBucket.Day), (W(StatsRange.Week).From, W(StatsRange.Week).To, W(StatsRange.Week).Bucket));
        CultureInfo.CurrentCulture = new CultureInfo("de-DE"); // Monday
        Assert.Equal(U(10, 19), W(StatsRange.Week).From);
        Assert.Equal(U(10, 12), W(StatsRange.Week, -1).From);
    }

    [Fact]
    public void Month_and_year_are_calendar_periods()
    {
        Assert.Equal((U(10, 1), U(11, 1), StatsBucket.Day), (W(StatsRange.Month).From, W(StatsRange.Month).To, W(StatsRange.Month).Bucket));
        Assert.Equal("October 2026", W(StatsRange.Month).Title);
        Assert.Equal(U(12, 1, year: 2025), W(StatsRange.Month, -10).From);
        Assert.Equal((U(1, 1), U(1, 1, year: 2027), StatsBucket.Month), (W(StatsRange.Year).From, W(StatsRange.Year).To, W(StatsRange.Year).Bucket));
        Assert.Equal("2025", W(StatsRange.Year, -1).Title);
    }

    [Fact]
    public void Custom_covers_whole_days_and_picks_a_bucket()
    {
        var oneDay = W(StatsRange.Custom, from: new DateTime(2026, 10, 5, 13, 0, 0), to: new DateTime(2026, 10, 5));
        Assert.Equal((U(10, 5), U(10, 6), StatsBucket.Hour), (oneDay.From, oneDay.To, oneDay.Bucket));

        var swapped = W(StatsRange.Custom, from: new DateTime(2026, 10, 20), to: new DateTime(2026, 9, 1));
        Assert.Equal((U(9, 1), U(10, 21), StatsBucket.Day), (swapped.From, swapped.To, swapped.Bucket));

        Assert.Equal(StatsBucket.Month, W(StatsRange.Custom, from: new DateTime(2025, 1, 1), to: new DateTime(2026, 1, 1)).Bucket);
    }

    [Fact]
    public void Ranges_carry_the_local_offset()
    {
        var tokyo = TimeZoneInfo.FindSystemTimeZoneById("Tokyo Standard Time");
        var w = W(StatsRange.Today, zone: tokyo);
        Assert.Equal(new DateTimeOffset(2026, 10, 22, 0, 0, 0, TimeSpan.FromHours(9)), w.From);
    }
}

public sealed class StatsViewModelTests
{
    private readonly FakeService _service = new();
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 10, 22, 14, 37, 0, TimeSpan.Zero));
    private readonly ServiceSettings _serviceSettings = new();
    private readonly ClientSettings _clientSettings = new();
    private readonly List<StatsQuery> _queries = [];
    private StatsResult _result = Result();
    private readonly StatsViewModel _vm;

    public StatsViewModelTests()
    {
        _service.Handler = (method, payload) =>
        {
            if (method == Methods.StatsQuery)
            {
                _queries.Add((StatsQuery)payload!);
                return _result;
            }
            return null;
        };
        _vm = new StatsViewModel(_service, _clientSettings, () => { }, new PortNames(["https 443/tcp", "domain 53/udp"]),
            () => _serviceSettings, change => { change(_serviceSettings); return Task.CompletedTask; }, _time)
        { TimeZone = TimeZoneInfo.Utc };
    }

    private static StatsResult Result(params StatsRow[] rows) => new(
        DateTimeOffset.MinValue, DateTimeOffset.MinValue, StatsBucket.Hour, 3000, 300,
        [new StatsPoint(new DateTimeOffset(2026, 10, 22, 13, 0, 0, TimeSpan.Zero), 1000, 100),
         new StatsPoint(new DateTimeOffset(2026, 10, 22, 14, 0, 0, TimeSpan.Zero), 2000, 200)],
        Enumerable.Range(0, 24).Select(h => new StatsHour(h, h, 0)).ToList(),
        rows.Length > 0 ? rows : [new StatsRow("c:\\apps\\game.exe", "Game", "c:\\apps\\game.exe", 2000, 200),
                                  new StatsRow("c:\\apps\\browser.exe", "Browser", "c:\\apps\\browser.exe", 1000, 100)],
        IsTruncated: false);

    [Fact]
    public async Task Refresh_queries_the_range_and_shows_the_result()
    {
        await _vm.RefreshAsync();

        var q = Assert.Single(_queries);
        Assert.Equal((StatsGroupBy.App, StatsBucket.Hour, null, null, null), (q.GroupBy, q.Bucket, q.Zones, q.Protocol, q.AppId));
        Assert.Equal(new DateTimeOffset(2026, 10, 22, 0, 0, 0, TimeSpan.Zero), q.From);
        Assert.Equal("UTC", q.TimeZoneId);
        Assert.Equal(2, _vm.Bars.Count);
        Assert.Equal(("13", 1000L), (_vm.Bars[0].Label, _vm.Bars[0].In));
        Assert.Equal(24, _vm.HourBars.Count);
        Assert.Equal(["Game", "Browser"], _vm.Rows.Select(r => r.Label));
        Assert.Equal(2200.0 / 3300, _vm.Rows[0].Share, 3);
        Assert.Contains(ByteFormatter.Size(3000), _vm.TotalsText);
        Assert.Equal("2 entries", _vm.FooterText);
        Assert.True(_vm.IsLive);
    }

    [Fact]
    public async Task Filters_go_into_the_query()
    {
        _vm.ShowLoopback = false;
        _vm.Protocol = "UDP";
        _vm.GroupBy = StatsGroupBy.Country;
        await _vm.RefreshAsync();

        var q = _queries[^1];
        Assert.Equal([StatsZone.Internet, StatsZone.LocalNetwork], q.Zones);
        Assert.Equal(TransportProtocol.Udp, q.Protocol);
        Assert.Equal(StatsGroupBy.Country, q.GroupBy);
        Assert.Equal(StatsGroupBy.Country, _clientSettings.StatsGroupBy);
    }

    [Fact]
    public async Task Stepping_back_moves_the_range_and_ends_live_updates()
    {
        _vm.Range = StatsRange.Month;
        _vm.PreviousCommand.Execute(null);
        await _vm.RefreshAsync();

        Assert.Equal(new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero), _queries[^1].From);
        Assert.False(_vm.IsLive);
        Assert.True(_vm.CanGoForward);
        Assert.Equal(StatsRange.Month, _clientSettings.StatsRange);

        _vm.NextCommand.Execute(null);
        _vm.NextCommand.Execute(null); // can't go into the future
        Assert.Equal(0, _vm.Offset);
    }

    [Fact]
    public async Task Double_clicking_an_app_lists_its_hosts()
    {
        await _vm.RefreshAsync();

        _vm.DrillInto(_vm.Rows[0]);
        await _vm.RefreshAsync();

        Assert.Equal(("c:\\apps\\game.exe", StatsGroupBy.Host), (_queries[^1].AppId, _queries[^1].GroupBy));
        Assert.Equal("App: Game", _vm.AppFilterText);

        _vm.ClearAppFilterCommand.Execute(null);
        await _vm.RefreshAsync();
        Assert.Null(_queries[^1].AppId);
    }

    [Fact]
    public async Task Ports_get_service_names()
    {
        _result = Result(new StatsRow("Tcp/443", "443", "TCP", 10, 1), new StatsRow("Udp/53", "53", "UDP", 5, 1),
            new StatsRow("Tcp/50123", "50123", "TCP", 1, 1));
        _vm.GroupBy = StatsGroupBy.Port;
        await _vm.RefreshAsync();

        Assert.Equal(["443 (https)", "53 (domain)", "50123"], _vm.Rows.Select(r => r.Label));
    }

    [Fact]
    public async Task Errors_are_shown_and_cleared()
    {
        _service.Handler = (_, _) => new IpcRemoteException("stats.query", "The range is too long.");
        await _vm.RefreshAsync();
        Assert.Equal("The range is too long.", _vm.LastError);
        Assert.False(_vm.IsLoading);

        _service.Handler = (_, _) => _result;
        await _vm.RefreshAsync();
        Assert.Null(_vm.LastError);
    }

    [Fact]
    public void Recording_switches_change_the_service_settings()
    {
        _vm.IsStatsEnabled = false;
        _vm.SaveLoopback = true;
        _vm.SaveInternet = false;

        Assert.False(_serviceSettings.IsStatsEnabled);
        Assert.True(_serviceSettings.Stats.SaveLoopback);
        Assert.False(_serviceSettings.Stats.SaveInternet);
        Assert.True(_vm.SaveLoopback);
    }

    [Fact]
    public async Task Csv_exports_use_raw_bytes_and_escape_text()
    {
        _result = Result(new StatsRow("1.2.3.4", "=cmd|' /C calc'!A0", "1.2.3.4 · Spain", 1500, 20),
            new StatsRow("c:\\a,b.exe", "Say \"hi\"", null, 1, 2));
        _vm.GroupBy = StatsGroupBy.Host;
        await _vm.RefreshAsync();

        string[] rows = _vm.RowsCsv().TrimEnd().Split(Environment.NewLine);
        string[] series = _vm.SeriesCsv().TrimEnd().Split(Environment.NewLine);

        Assert.Equal("Host,Detail,Key,Download bytes,Upload bytes,Total bytes", rows[0]);
        Assert.Equal("'=cmd|' /C calc'!A0,1.2.3.4 · Spain,1.2.3.4,1500,20,1520", rows[1]);
        Assert.Equal("\"Say \"\"hi\"\"\",,\"c:\\a,b.exe\",1,2,3", rows[2]);
        Assert.Equal(["Time,Download bytes,Upload bytes", "2026-10-22T13:00:00+00:00,1000,100", "2026-10-22T14:00:00+00:00,2000,200"], series);
        Assert.Equal("NetWarden host 2026-10-22.csv", _vm.ExportFileName("host"));
    }

    [Fact]
    public void Csv_files_have_a_bom_for_excel()
    {
        using var dir = new TempDir();
        StatsViewModel.WriteCsv(dir.File("x.csv"), "a,b");

        Assert.Equal([0xEF, 0xBB, 0xBF, (byte)'a'], File.ReadAllBytes(dir.File("x.csv")).Take(4));
    }
}

public sealed class StatsManagerViewModelTests
{
    private readonly FakeService _service = new();
    private readonly List<(string Method, object? Payload)> _calls = [];
    private readonly StatsManagerViewModel _vm;
    private StatsInfo _info = new("c:\\data\\stats.db", 2 * 1024 * 1024, 1200, 2,
        new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2026, 10, 22, 0, 0, 0, TimeSpan.Zero), "2026-10");

    public StatsManagerViewModelTests()
    {
        _service.Handler = (method, payload) =>
        {
            _calls.Add((method, payload));
            return method switch
            {
                Methods.StatsInfo => _info,
                Methods.StatsQuery => new StatsResult(default, default, StatsBucket.Month, 0, 0, [], [],
                    [new StatsRow("game", "Game", null, 900, 100), new StatsRow("browser", "Browser", null, 10, 0)], false),
                Methods.StatsDelete => 42L,
                Methods.StatsCompact => _info = _info with { FileBytes = 1024 * 1024 },
                _ => null,
            };
        };
        _vm = new StatsManagerViewModel(_service, new FakeTimeProvider(new DateTimeOffset(2026, 10, 22, 12, 0, 0, TimeSpan.Zero)));
    }

    [Fact]
    public async Task Load_shows_the_database_and_its_apps()
    {
        await _vm.LoadAsync();

        Assert.Equal("2 MB", _vm.SizeText);
        Assert.Contains("1,200 records", _vm.RecordsText.Replace(CultureInfo.CurrentCulture.NumberFormat.NumberGroupSeparator, ","));
        Assert.Contains("DB-IP Lite 2026-10", _vm.GeoText);
        Assert.Equal(["Game", "Browser"], _vm.Apps.Select(a => a.Name));
        var query = (StatsQuery)_calls.Single(c => c.Method == Methods.StatsQuery).Payload!;
        Assert.Equal((_info.FirstRecord!.Value, StatsGroupBy.App), (query.From, query.GroupBy));
    }

    [Fact]
    public async Task Deleting_an_app_sends_its_id_and_reloads()
    {
        await _vm.LoadAsync();
        _vm.SelectedApp = _vm.Apps[0];

        await _vm.DeleteSelectedAppAsync();

        var request = (StatsDeleteRequest)_calls.Single(c => c.Method == Methods.StatsDelete).Payload!;
        Assert.Equal(new StatsDeleteRequest(AppId: "game"), request);
        Assert.StartsWith("Deleted 42 records of Game", _vm.Status);
        Assert.Equal(2, _calls.Count(c => c.Method == Methods.StatsInfo));
        Assert.Equal("game", _vm.SelectedApp?.Id);
    }

    [Fact]
    public async Task Deleting_old_records_uses_local_midnight()
    {
        _vm.DeleteBefore = new DateTime(2026, 7, 1);

        await _vm.DeleteOlderThanAsync();

        var request = (StatsDeleteRequest)_calls.Single(c => c.Method == Methods.StatsDelete).Payload!;
        Assert.Equal(new DateTime(2026, 7, 1), request.To!.Value.DateTime);
        Assert.Null(request.From);
        Assert.Null(request.AppId);
    }

    [Fact]
    public async Task Compact_reports_the_new_size()
    {
        await _vm.LoadAsync();

        await _vm.CompactAsync();

        Assert.Equal("Compacted: 2 MB → 1 MB.", _vm.Status);
        Assert.False(_vm.IsBusy);
    }

    [Fact]
    public async Task Errors_are_shown()
    {
        _service.Handler = (_, _) => new IpcDisconnectedException("Not connected.");

        await _vm.DeleteAllAsync();

        Assert.Equal("Not connected.", _vm.Error);
        Assert.True(_vm.IsIdle);
    }
}

public class StatsChartTests
{
    [Theory]
    [InlineData(500L, 500L)]
    [InlineData(1024L, 1024L)]
    [InlineData(1500L, 2048L)]
    [InlineData(200_000_000L, 200L * 1024 * 1024)]   // 190.7 MB -> 200 MB
    [InlineData(150L * 1024 * 1024, 200L * 1024 * 1024)]
    [InlineData(31L * 1024 * 1024, 40L * 1024 * 1024)]
    [InlineData(3L * 1024 * 1024 * 1024, 4L * 1024 * 1024 * 1024)]
    public void Axis_tops_are_round_binary_sizes(long max, long expected)
    {
        Assert.Equal(expected, NetWarden.Client.Charts.StatsChart.NiceSizeCeiling(max));
    }
}
