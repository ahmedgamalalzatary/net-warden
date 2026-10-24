using System.IO.Compression;
using System.Net;
using NetWarden.Core.Stats;
using NetWarden.Shared.Contracts;

namespace NetWarden.Tests.Stats;

internal static class StatsData
{
    public static readonly AppInfo Browser = App("c:\\apps\\browser.exe", "Browser");
    public static readonly AppInfo Game = App("c:\\apps\\game.exe", "Game");

    public static AppInfo App(string path, string name) => new(path, AppKind.Desktop, path, name, null, null, null, [], null);

    /// <summary>12:00 UTC on 2026-10-20 (a Tuesday).</summary>
    public static readonly DateTimeOffset Noon = new(2026, 10, 20, 12, 0, 0, TimeSpan.Zero);

    public static StatsRecord Record(DateTimeOffset time, AppInfo app, long bytesIn, long bytesOut = 0, string address = "8.8.8.8",
        string? host = null, int port = 443, TransportProtocol protocol = TransportProtocol.Tcp, StatsZone zone = StatsZone.Internet,
        string sid = "S-1-5-21-1", string? user = "PC\\alice")
    {
        long slot = time.ToUnixTimeSeconds();
        return new StatsRecord(slot - slot % 60, app, address, host, port, protocol, zone, sid, user, bytesIn, bytesOut);
    }
}

public sealed class StatsDatabaseTests : IDisposable
{
    private readonly TempDir _dir = new();
    private StatsDatabase _db;
    private static readonly CountryLookup Geo = CountryLookup.LoadDefault();
    private static readonly TimeZoneInfo Utc = TimeZoneInfo.Utc;
    private static readonly DateTimeOffset Noon = StatsData.Noon;

    public StatsDatabaseTests()
    {
        _db = new StatsDatabase(_dir.File("stats.db"));
    }

    public void Dispose()
    {
        _db.Dispose();
        _dir.Dispose();
    }

    private StatsResult Query(DateTimeOffset from, DateTimeOffset to, StatsBucket bucket = StatsBucket.Minute,
        StatsGroupBy groupBy = StatsGroupBy.App, IReadOnlyList<StatsZone>? zones = null, TransportProtocol? protocol = null,
        string? appId = null, TimeZoneInfo? zone = null) =>
        _db.Query(new StatsQuery(from, to, bucket, groupBy, zones, protocol, appId), Geo, zone ?? Utc);

    [Fact]
    public void Written_records_are_summed_into_totals_series_and_breakdown()
    {
        _db.Write([
            StatsData.Record(Noon, StatsData.Browser, 1000, 100),
            StatsData.Record(Noon.AddSeconds(30), StatsData.Game, 5000, 50, port: 27015, protocol: TransportProtocol.Udp),
            StatsData.Record(Noon.AddMinutes(2), StatsData.Browser, 3000, 300),
        ]);

        var result = Query(Noon, Noon.AddMinutes(5));

        Assert.Equal(9000, result.TotalIn);
        Assert.Equal(450, result.TotalOut);
        Assert.Equal(5, result.Series.Count);
        Assert.Equal([6000L, 0, 3000, 0, 0], result.Series.Select(p => p.In));
        Assert.Equal(Noon, result.Series[0].Time);
        Assert.Collection(result.Rows,
            r => Assert.Equal(("Game", 5000L, "c:\\apps\\game.exe"), (r.Label, r.In, r.Detail)),
            r => Assert.Equal(("Browser", 4000L), (r.Label, r.In)));
        Assert.False(result.IsTruncated);
    }

    [Fact]
    public void Writing_the_same_minute_again_adds_to_it()
    {
        _db.Write([StatsData.Record(Noon, StatsData.Browser, 1000, 10)]);
        _db.Write([StatsData.Record(Noon.AddSeconds(59), StatsData.Browser, 500, 5)]);

        var info = _db.Info(null);
        var result = Query(Noon, Noon.AddMinutes(1));

        Assert.Equal(1, info.Records);
        Assert.Equal(1500, result.TotalIn);
        Assert.Equal(15, result.TotalOut);
    }

    [Fact]
    public void Range_end_is_exclusive()
    {
        _db.Write([StatsData.Record(Noon, StatsData.Browser, 1), StatsData.Record(Noon.AddMinutes(1), StatsData.Browser, 2)]);

        Assert.Equal(1, Query(Noon, Noon.AddMinutes(1)).TotalIn);
    }

    [Fact]
    public void Breakdown_by_host_shows_domain_ip_and_country()
    {
        _db.Write([
            StatsData.Record(Noon, StatsData.Browser, 100, address: "8.8.8.8", host: "dns.google"),
            StatsData.Record(Noon, StatsData.Browser, 50, address: "192.168.1.1", zone: StatsZone.LocalNetwork),
            StatsData.Record(Noon, StatsData.Browser, 10, address: ""),
        ]);

        var rows = Query(Noon, Noon.AddMinutes(1), groupBy: StatsGroupBy.Host).Rows;

        Assert.Equal(3, rows.Count);
        Assert.Equal(("8.8.8.8", "dns.google", "8.8.8.8 · United States"), (rows[0].Key, rows[0].Label, rows[0].Detail));
        Assert.Equal(("192.168.1.1", null), (rows[1].Label, rows[1].Detail));
        Assert.Equal("(no remote address)", rows[2].Label);
    }

    [Fact]
    public void Host_names_are_kept_when_later_records_have_none()
    {
        _db.Write([StatsData.Record(Noon, StatsData.Browser, 100, host: "dns.google")]);
        _db.Write([StatsData.Record(Noon.AddMinutes(1), StatsData.Browser, 100, host: null)]);
        _db.Dispose();
        _db = new StatsDatabase(_dir.File("stats.db"));
        _db.Write([StatsData.Record(Noon.AddMinutes(2), StatsData.Browser, 100, host: null)]);

        var row = Assert.Single(Query(Noon, Noon.AddMinutes(3), groupBy: StatsGroupBy.Host).Rows);

        Assert.Equal("dns.google", row.Label);
        Assert.Equal(300, row.In);
    }

    [Fact]
    public void Breakdown_by_country_merges_hosts_of_one_country()
    {
        _db.Write([
            StatsData.Record(Noon, StatsData.Browser, 100, address: "8.8.8.8"),
            StatsData.Record(Noon, StatsData.Browser, 200, address: "2a03:2880:f003::1"),
            StatsData.Record(Noon, StatsData.Browser, 50, address: "10.0.0.2", zone: StatsZone.LocalNetwork),
        ]);

        var rows = Query(Noon, Noon.AddMinutes(1), groupBy: StatsGroupBy.Country).Rows;

        Assert.Collection(rows,
            r => Assert.Equal(("US", "United States", 300L), (r.Key, r.Label, r.In)),
            r => Assert.Equal(("", "Unknown / private", 50L), (r.Key, r.Label, r.In)));
    }

    [Fact]
    public void Breakdown_by_port_and_user()
    {
        _db.Write([
            StatsData.Record(Noon, StatsData.Browser, 100, port: 443),
            StatsData.Record(Noon, StatsData.Browser, 20, port: 53, protocol: TransportProtocol.Udp, sid: "S-1-5-18", user: null),
        ]);

        var ports = Query(Noon, Noon.AddMinutes(1), groupBy: StatsGroupBy.Port).Rows;
        var users = Query(Noon, Noon.AddMinutes(1), groupBy: StatsGroupBy.User).Rows;

        Assert.Equal([("Tcp/443", "443", "TCP"), ("Udp/53", "53", "UDP")], ports.Select(r => (r.Key, r.Label, r.Detail!)));
        Assert.Equal([("PC\\alice", "S-1-5-21-1"), ("S-1-5-18", null)], users.Select(r => (r.Label, r.Detail)));
    }

    [Fact]
    public void Queries_filter_by_zone_protocol_and_app()
    {
        _db.Write([
            StatsData.Record(Noon, StatsData.Browser, 1),
            StatsData.Record(Noon, StatsData.Browser, 2, address: "192.168.1.1", zone: StatsZone.LocalNetwork),
            StatsData.Record(Noon, StatsData.Game, 4, protocol: TransportProtocol.Udp),
            StatsData.Record(Noon, StatsData.Game, 8, address: "127.0.0.1", zone: StatsZone.Loopback),
        ]);
        var to = Noon.AddMinutes(1);

        Assert.Equal(15, Query(Noon, to).TotalIn);
        Assert.Equal(5, Query(Noon, to, zones: [StatsZone.Internet]).TotalIn);
        Assert.Equal(10, Query(Noon, to, zones: [StatsZone.LocalNetwork, StatsZone.Loopback]).TotalIn);
        Assert.Equal(0, Query(Noon, to, zones: []).TotalIn);
        Assert.Equal(4, Query(Noon, to, protocol: TransportProtocol.Udp).TotalIn);
        Assert.Equal(3, Query(Noon, to, appId: StatsData.Browser.Id).TotalIn);
        Assert.Equal(0, Query(Noon, to, appId: "c:\\never-seen.exe").TotalIn);
    }

    [Fact]
    public void Buckets_and_hours_follow_the_callers_time_zone()
    {
        var tokyo = TimeZoneInfo.FindSystemTimeZoneById("Tokyo Standard Time"); // UTC+9, no DST
        // 20:00 UTC on the 20th is 05:00 on the 21st in Tokyo.
        _db.Write([
            StatsData.Record(Noon, StatsData.Browser, 100),
            StatsData.Record(Noon.AddHours(8), StatsData.Browser, 10),
        ]);
        var from = new DateTimeOffset(2026, 10, 20, 0, 0, 0, TimeSpan.FromHours(9));

        var result = Query(from, from.AddDays(3), StatsBucket.Day, zone: tokyo);

        Assert.Equal(3, result.Series.Count);
        Assert.Equal([100L, 10, 0], result.Series.Select(p => p.In));
        Assert.Equal(TimeSpan.FromHours(9), result.Series[1].Time.Offset);
        Assert.Equal(21, result.Series[1].Time.Day);
        Assert.Equal(100, result.Hours[21].In); // 12:00 UTC = 21:00 Tokyo
        Assert.Equal(10, result.Hours[5].In);
        Assert.Equal(24, result.Hours.Count);
    }

    [Fact]
    public void Month_buckets_follow_calendar_months()
    {
        _db.Write([StatsData.Record(new DateTimeOffset(2026, 2, 28, 23, 59, 0, TimeSpan.Zero), StatsData.Browser, 7)]);
        var from = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        var result = Query(from, from.AddYears(1), StatsBucket.Month);

        Assert.Equal(12, result.Series.Count);
        Assert.Equal(7, result.Series[1].In);
        Assert.Equal(new DateTimeOffset(2026, 3, 1, 0, 0, 0, TimeSpan.Zero), result.Series[2].Time);
    }

    [Fact]
    public void Too_many_buckets_widen_the_bucket()
    {
        var result = Query(Noon, Noon.AddDays(30), StatsBucket.Minute);

        Assert.Equal(StatsBucket.Hour, result.Bucket);
        Assert.Equal(30 * 24, result.Series.Count);
    }

    [Fact]
    public void Breakdown_is_truncated_to_max_rows()
    {
        _db.Write(Enumerable.Range(1, 5).Select(i => StatsData.Record(Noon, StatsData.Browser, i, address: $"8.8.8.{i}")).ToList());

        var result = _db.Query(new StatsQuery(Noon, Noon.AddMinutes(1), StatsBucket.Minute, StatsGroupBy.Host, MaxRows: 2), Geo, Utc);

        Assert.Equal(["8.8.8.5", "8.8.8.4"], result.Rows.Select(r => r.Key));
        Assert.True(result.IsTruncated);
        Assert.Equal(15, result.TotalIn);
    }

    [Fact]
    public void Roll_up_merges_old_minutes_into_hours_and_keeps_recent_ones()
    {
        var old = Noon.AddDays(-5);
        _db.Write([
            StatsData.Record(old, StatsData.Browser, 1),
            StatsData.Record(old.AddMinutes(1), StatsData.Browser, 2),
            StatsData.Record(old.AddMinutes(59), StatsData.Browser, 4),
            StatsData.Record(old.AddMinutes(60), StatsData.Browser, 8),
            StatsData.Record(Noon.AddMinutes(-5), StatsData.Browser, 16),
            StatsData.Record(Noon.AddMinutes(-4), StatsData.Browser, 32),
        ]);

        long merged = _db.RollUp(Noon);
        var oldDay = Query(old.AddHours(-1), old.AddHours(2), StatsBucket.Hour);

        Assert.Equal(2, merged);
        Assert.Equal(4, _db.Info(null).Records);
        Assert.Equal([0L, 7, 8], oldDay.Series.Select(p => p.In));
        Assert.Equal(48, Query(Noon.AddHours(-1), Noon).TotalIn);
        Assert.Equal(0, _db.RollUp(Noon));
    }

    [Fact]
    public void Delete_by_app_and_time_range()
    {
        _db.Write([
            StatsData.Record(Noon, StatsData.Browser, 1),
            StatsData.Record(Noon.AddDays(1), StatsData.Browser, 2),
            StatsData.Record(Noon, StatsData.Game, 4),
            StatsData.Record(Noon.AddDays(1), StatsData.Game, 8),
        ]);
        var all = (Noon.AddYears(-1), Noon.AddYears(1));

        Assert.Equal(1, _db.Delete(new StatsDeleteRequest(To: Noon.AddHours(1), AppId: StatsData.Game.Id)));
        Assert.Equal(11, Query(all.Item1, all.Item2, StatsBucket.Month).TotalIn);
        Assert.Equal(2, _db.Delete(new StatsDeleteRequest(From: Noon.AddHours(1))));
        Assert.Equal(1, Query(all.Item1, all.Item2, StatsBucket.Month).TotalIn);
        Assert.Equal(1, _db.Delete(new StatsDeleteRequest()));
        Assert.Equal(0, _db.Info(null).Records);
    }

    [Fact]
    public void Compact_forgets_unused_apps_and_writing_continues()
    {
        _db.Write([StatsData.Record(Noon, StatsData.Browser, 1), StatsData.Record(Noon, StatsData.Game, 2)]);
        _db.Delete(new StatsDeleteRequest(AppId: StatsData.Game.Id));

        _db.Compact(Noon);
        _db.Write([StatsData.Record(Noon, StatsData.Game, 4), StatsData.Record(Noon, StatsData.Browser, 8)]);

        var rows = Query(Noon, Noon.AddMinutes(1)).Rows;
        Assert.Equal([("Browser", 9L), ("Game", 4L)], rows.Select(r => (r.Label, r.In)));
    }

    [Fact]
    public void Info_describes_the_database()
    {
        _db.Write([StatsData.Record(Noon, StatsData.Browser, 1), StatsData.Record(Noon.AddHours(3), StatsData.Game, 2)]);

        var info = _db.Info("2026-10");

        Assert.Equal(_dir.File("stats.db"), info.Path);
        Assert.True(info.FileBytes > 0);
        Assert.Equal(2, info.Records);
        Assert.Equal(2, info.Apps);
        Assert.Equal(Noon, info.FirstRecord);
        Assert.Equal(Noon.AddHours(3), info.LastRecord);
        Assert.Equal("2026-10", info.GeoDatabaseDate);
    }

    [Fact]
    public void Records_survive_reopening()
    {
        _db.Write([StatsData.Record(Noon, StatsData.Browser, 42)]);
        _db.Dispose();
        _db = new StatsDatabase(_dir.File("stats.db"));

        Assert.Equal(42, Query(Noon, Noon.AddMinutes(1)).TotalIn);
    }
}

public class CountryLookupTests
{
    private static readonly CountryLookup Geo = CountryLookup.LoadDefault();

    [Theory]
    [InlineData("8.8.8.8", "US")]
    [InlineData("::ffff:8.8.8.8", "US")]
    [InlineData("2a00:1450:4001::1", "DE")]
    [InlineData("1.0.0.1", "AU")]
    [InlineData("192.168.1.1", null)]
    [InlineData("127.0.0.1", null)]
    [InlineData("::1", null)]
    public void Looks_up_countries(string address, string? expected)
    {
        Assert.Equal(expected, Geo.Country(IPAddress.Parse(address)));
    }

    [Fact]
    public void Shipped_database_is_loaded()
    {
        Assert.True(Geo.RangeCount > 100_000);
        Assert.Matches(@"^\d{4}-\d{2}$", Geo.DatabaseDate);
    }

    [Fact]
    public void Country_names_come_from_windows()
    {
        Assert.Equal("Germany", CountryLookup.CountryName("DE"));
        Assert.Equal("Q1", CountryLookup.CountryName("Q1"));
    }

    [Fact]
    public void Rejects_other_files()
    {
        using var data = new MemoryStream();
        using (var gzip = new GZipStream(data, CompressionLevel.Fastest, leaveOpen: true))
            gzip.Write("NOTGEO"u8);
        data.Position = 0;

        Assert.Throws<InvalidDataException>(() => CountryLookup.Load(data));
    }

    [Fact]
    public void Rejects_truncated_files()
    {
        using var data = new MemoryStream();
        using (var gzip = new GZipStream(data, CompressionLevel.Fastest, leaveOpen: true))
        {
            gzip.Write("NWGEO1"u8);
            gzip.Write([0, 0, 0, 9, 1, 2, 3]); // claims 9 IPv4 ranges, has half of one
        }
        data.Position = 0;

        Assert.Throws<InvalidDataException>(() => CountryLookup.Load(data));
    }

    [Fact]
    public void Empty_lookup_knows_nothing()
    {
        Assert.Null(CountryLookup.Empty.Country(IPAddress.Parse("8.8.8.8")));
    }
}
