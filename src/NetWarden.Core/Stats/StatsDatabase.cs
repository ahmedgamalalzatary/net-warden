using System.Globalization;
using System.Net;
using System.Text;
using Microsoft.Data.Sqlite;
using NetWarden.Shared.Contracts;

namespace NetWarden.Core.Stats;

/// <summary>Bytes one (app, remote host, port, protocol, zone, user) moved in one minute.</summary>
public readonly record struct StatsRecord(
    long Slot,
    AppInfo App,
    string Address,
    string? HostName,
    int Port,
    TransportProtocol Protocol,
    StatsZone Zone,
    string UserSid,
    string? UserName,
    long In,
    long Out);

/// <summary>
/// The SQLite stats database. Traffic is stored per minute (<c>slot</c> = Unix seconds at the start
/// of the minute) and rolled up into hours once it is older than <see cref="MinuteRetention"/>.
/// Every method is thread-safe; calls are serialized on one connection.
/// </summary>
public sealed class StatsDatabase : IDisposable
{
    /// <summary>Minute records older than this are merged into hourly records.</summary>
    public static readonly TimeSpan MinuteRetention = TimeSpan.FromHours(48);

    /// <summary>A query never returns more time buckets than this; the bucket widens instead.</summary>
    public const int MaxBuckets = 5000;

    private const string Schema = """
        CREATE TABLE IF NOT EXISTS apps(id INTEGER PRIMARY KEY, app_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL, path TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS hosts(id INTEGER PRIMARY KEY, address TEXT NOT NULL UNIQUE, name TEXT);
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, sid TEXT NOT NULL UNIQUE, name TEXT);
        CREATE TABLE IF NOT EXISTS traffic(
            slot INTEGER NOT NULL,
            app INTEGER NOT NULL,
            host INTEGER NOT NULL,
            port INTEGER NOT NULL,
            protocol INTEGER NOT NULL,
            zone INTEGER NOT NULL,
            user INTEGER NOT NULL,
            bytes_in INTEGER NOT NULL,
            bytes_out INTEGER NOT NULL,
            PRIMARY KEY(slot, app, host, port, protocol, zone, user)) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS traffic_app ON traffic(app, slot);
        """;

    private readonly SqliteConnection _db;
    private readonly Lock _lock = new();
    private readonly Dictionary<string, (long Id, string? Name)> _apps = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (long Id, string? Name)> _hosts = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (long Id, string? Name)> _users = new(StringComparer.Ordinal);

    public StatsDatabase(string path)
    {
        FilePath = path;
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path))!);
        // No pooling: disposing must release the file (the stats manager reports its size, tests delete it).
        _db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false,
        }.ToString());
        _db.Open();
        Execute("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;");
        Execute(Schema);
        LoadIds();
    }

    public string FilePath { get; }

    public void Write(IReadOnlyCollection<StatsRecord> records)
    {
        if (records.Count == 0)
            return;
        lock (_lock)
        {
            try
            {
                WriteLocked(records);
            }
            catch
            {
                // Ids added during the rolled-back transaction don't exist.
                LoadIds();
                throw;
            }
        }
    }

    private void WriteLocked(IReadOnlyCollection<StatsRecord> records)
    {
        using var tx = _db.BeginTransaction();
        using var upsert = Command("""
            INSERT INTO traffic(slot, app, host, port, protocol, zone, user, bytes_in, bytes_out)
            VALUES($slot, $app, $host, $port, $protocol, $zone, $user, $in, $out)
            ON CONFLICT DO UPDATE SET bytes_in = bytes_in + excluded.bytes_in, bytes_out = bytes_out + excluded.bytes_out
            """, tx);
        var slot = upsert.Parameters.Add("$slot", SqliteType.Integer);
        var app = upsert.Parameters.Add("$app", SqliteType.Integer);
        var host = upsert.Parameters.Add("$host", SqliteType.Integer);
        var port = upsert.Parameters.Add("$port", SqliteType.Integer);
        var protocol = upsert.Parameters.Add("$protocol", SqliteType.Integer);
        var zone = upsert.Parameters.Add("$zone", SqliteType.Integer);
        var user = upsert.Parameters.Add("$user", SqliteType.Integer);
        var bytesIn = upsert.Parameters.Add("$in", SqliteType.Integer);
        var bytesOut = upsert.Parameters.Add("$out", SqliteType.Integer);
        upsert.Prepare();

        foreach (var r in records)
        {
            slot.Value = r.Slot;
            app.Value = Id(_apps, "apps", "app_id", r.App.Id, r.App.DisplayName, ("path", r.App.Path), tx);
            host.Value = Id(_hosts, "hosts", "address", r.Address, r.HostName, null, tx);
            user.Value = Id(_users, "users", "sid", r.UserSid, r.UserName, null, tx);
            port.Value = r.Port;
            protocol.Value = (int)r.Protocol;
            zone.Value = (int)r.Zone;
            bytesIn.Value = r.In;
            bytesOut.Value = r.Out;
            upsert.ExecuteNonQuery();
        }
        tx.Commit();
    }

    /// <summary>Totals, time series, 24-hour histogram and breakdown for a query.</summary>
    public StatsResult Query(StatsQuery query, CountryLookup geo, TimeZoneInfo zone)
    {
        lock (_lock)
        {
            using var series = Command("");
            string where = Where(query, series);
            series.CommandText = $"SELECT slot, SUM(bytes_in), SUM(bytes_out) FROM traffic t WHERE {where} GROUP BY slot";
            var slots = new List<(long Slot, long In, long Out)>();
            using (var reader = series.ExecuteReader())
                while (reader.Read())
                    slots.Add((reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2)));

            var (bucket, points) = Bucketize(slots, query.From, query.To, query.Bucket, zone);
            var hours = new long[24, 2];
            long totalIn = 0, totalOut = 0;
            foreach (var (slot, bytesIn, bytesOut) in slots)
            {
                int hour = TimeZoneInfo.ConvertTime(DateTimeOffset.FromUnixTimeSeconds(slot), zone).Hour;
                hours[hour, 0] += bytesIn;
                hours[hour, 1] += bytesOut;
                totalIn += bytesIn;
                totalOut += bytesOut;
            }

            var rows = Breakdown(query, geo);
            int max = Math.Clamp(query.MaxRows, 1, 100_000);
            return new StatsResult(query.From, query.To, bucket, totalIn, totalOut, points,
                Enumerable.Range(0, 24).Select(h => new StatsHour(h, hours[h, 0], hours[h, 1])).ToList(),
                rows.Take(max).ToList(), rows.Count > max);
        }
    }

    public StatsInfo Info(string? geoDate)
    {
        lock (_lock)
        {
            using var cmd = Command("SELECT COUNT(*), MIN(slot), MAX(slot), COUNT(DISTINCT app) FROM traffic");
            using var reader = cmd.ExecuteReader();
            reader.Read();
            DateTimeOffset? Time(int i) => reader.IsDBNull(i) ? null : DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(i));
            return new StatsInfo(FilePath, FileBytes(), reader.GetInt64(0), reader.GetInt32(3), Time(1), Time(2), geoDate);
        }
    }

    /// <summary>Deletes the records a request selects; returns how many there were.</summary>
    public long Delete(StatsDeleteRequest request)
    {
        lock (_lock)
        {
            using var cmd = Command("");
            var conditions = new List<string>();
            if (request.From is { } from)
            {
                conditions.Add("slot >= $from");
                cmd.Parameters.AddWithValue("$from", from.ToUnixTimeSeconds());
            }
            if (request.To is { } to)
            {
                conditions.Add("slot < $to");
                cmd.Parameters.AddWithValue("$to", to.ToUnixTimeSeconds());
            }
            if (request.AppId is { } appId)
            {
                conditions.Add("app = (SELECT id FROM apps WHERE app_id = $app)");
                cmd.Parameters.AddWithValue("$app", appId);
            }
            cmd.CommandText = "DELETE FROM traffic" + (conditions.Count > 0 ? " WHERE " + string.Join(" AND ", conditions) : "");
            return cmd.ExecuteNonQuery();
        }
    }

    /// <summary>Merges minute records older than <see cref="MinuteRetention"/> into hours; returns the records merged.</summary>
    public long RollUp(DateTimeOffset now)
    {
        long cutoff = (now - MinuteRetention).ToUnixTimeSeconds();
        cutoff -= cutoff % 3600;
        lock (_lock)
        {
            using var tx = _db.BeginTransaction();
            using var merge = Command("""
                INSERT INTO traffic(slot, app, host, port, protocol, zone, user, bytes_in, bytes_out)
                SELECT slot - slot % 3600, app, host, port, protocol, zone, user, SUM(bytes_in), SUM(bytes_out)
                FROM traffic WHERE slot < $cutoff AND slot % 3600 <> 0
                GROUP BY slot - slot % 3600, app, host, port, protocol, zone, user
                ON CONFLICT DO UPDATE SET bytes_in = bytes_in + excluded.bytes_in, bytes_out = bytes_out + excluded.bytes_out
                """, tx);
            merge.Parameters.AddWithValue("$cutoff", cutoff);
            merge.ExecuteNonQuery();
            using var delete = Command("DELETE FROM traffic WHERE slot < $cutoff AND slot % 3600 <> 0", tx);
            delete.Parameters.AddWithValue("$cutoff", cutoff);
            long merged = delete.ExecuteNonQuery();
            tx.Commit();
            return merged;
        }
    }

    /// <summary>Rolls up old minutes, forgets apps/hosts/users without records and shrinks the file.</summary>
    public void Compact(DateTimeOffset now)
    {
        RollUp(now);
        lock (_lock)
        {
            Execute("""
                DELETE FROM apps WHERE id NOT IN (SELECT DISTINCT app FROM traffic);
                DELETE FROM hosts WHERE id NOT IN (SELECT DISTINCT host FROM traffic);
                DELETE FROM users WHERE id NOT IN (SELECT DISTINCT user FROM traffic);
                """);
            LoadIds();
            Execute("VACUUM; PRAGMA wal_checkpoint(TRUNCATE);");
        }
    }

    public void Dispose()
    {
        lock (_lock)
            _db.Dispose();
    }

    private string Where(StatsQuery query, SqliteCommand cmd)
    {
        var sql = new StringBuilder("t.slot >= $from AND t.slot < $to");
        cmd.Parameters.AddWithValue("$from", query.From.ToUnixTimeSeconds());
        cmd.Parameters.AddWithValue("$to", query.To.ToUnixTimeSeconds());
        if (query.Zones is { } zones)
        {
            // Enum values only, so they can go into the SQL text.
            var ids = zones.Where(Enum.IsDefined).Select(z => ((int)z).ToString(CultureInfo.InvariantCulture)).Distinct().ToList();
            sql.Append(ids.Count == 0 ? " AND 0" : $" AND t.zone IN ({string.Join(",", ids)})");
        }
        if (query.Protocol is { } protocol)
        {
            sql.Append(" AND t.protocol = $protocol");
            cmd.Parameters.AddWithValue("$protocol", (int)protocol);
        }
        if (query.AppId is { } appId)
        {
            sql.Append(" AND t.app = (SELECT id FROM apps WHERE app_id = $app)");
            cmd.Parameters.AddWithValue("$app", appId);
        }
        return sql.ToString();
    }

    /// <summary>Breakdown rows, largest first.</summary>
    private List<StatsRow> Breakdown(StatsQuery query, CountryLookup geo)
    {
        using var cmd = Command("");
        string where = Where(query, cmd);
        const string sums = "SUM(t.bytes_in) AS i, SUM(t.bytes_out) AS o";
        cmd.CommandText = query.GroupBy switch
        {
            StatsGroupBy.App => $"SELECT a.app_id, a.name, a.path, {sums} FROM traffic t JOIN apps a ON a.id = t.app WHERE {where} GROUP BY t.app",
            StatsGroupBy.Port => $"SELECT t.protocol, t.port, NULL, {sums} FROM traffic t WHERE {where} GROUP BY t.protocol, t.port",
            StatsGroupBy.User => $"SELECT u.sid, u.name, NULL, {sums} FROM traffic t JOIN users u ON u.id = t.user WHERE {where} GROUP BY t.user",
            _ => $"SELECT h.address, h.name, NULL, {sums} FROM traffic t JOIN hosts h ON h.id = t.host WHERE {where} GROUP BY t.host",
        };

        var rows = new List<StatsRow>();
        var countries = new Dictionary<string, (long In, long Out)>(StringComparer.Ordinal);
        using (var reader = cmd.ExecuteReader())
        {
            while (reader.Read())
            {
                long bytesIn = reader.GetInt64(3), bytesOut = reader.GetInt64(4);
                string? text1 = reader.IsDBNull(1) ? null : reader.GetValue(1).ToString();
                switch (query.GroupBy)
                {
                    case StatsGroupBy.App:
                        rows.Add(new StatsRow(reader.GetString(0), text1 ?? reader.GetString(0), reader.GetString(2), bytesIn, bytesOut));
                        break;
                    case StatsGroupBy.Port:
                        var protocol = (TransportProtocol)reader.GetInt32(0);
                        int port = reader.GetInt32(1);
                        rows.Add(new StatsRow($"{protocol}/{port}", port.ToString(CultureInfo.InvariantCulture),
                            protocol.ToString().ToUpperInvariant(), bytesIn, bytesOut));
                        break;
                    case StatsGroupBy.User:
                        string sid = reader.GetString(0);
                        rows.Add(new StatsRow(sid, text1 ?? (sid.Length == 0 ? "Unknown" : sid), text1 is null ? null : sid, bytesIn, bytesOut));
                        break;
                    case StatsGroupBy.Country:
                        string code = CountryOf(reader.GetString(0), geo) ?? "";
                        var sum = countries.GetValueOrDefault(code);
                        countries[code] = (sum.In + bytesIn, sum.Out + bytesOut);
                        break;
                    default:
                        rows.Add(HostRow(reader.GetString(0), text1, geo, bytesIn, bytesOut));
                        break;
                }
            }
        }
        foreach (var (code, sum) in countries)
            rows.Add(new StatsRow(code, code.Length == 0 ? "Unknown / private" : CountryLookup.CountryName(code),
                code.Length == 0 ? null : code, sum.In, sum.Out));

        rows.Sort((a, b) =>
        {
            int c = (b.In + b.Out).CompareTo(a.In + a.Out);
            return c != 0 ? c : string.Compare(a.Label, b.Label, StringComparison.OrdinalIgnoreCase);
        });
        return rows;
    }

    private static StatsRow HostRow(string address, string? name, CountryLookup geo, long bytesIn, long bytesOut)
    {
        if (address.Length == 0)
            return new StatsRow("", "(no remote address)", null, bytesIn, bytesOut);
        string? country = CountryOf(address, geo) is { } code ? CountryLookup.CountryName(code) : null;
        string? detail = name is null ? country : country is null ? address : $"{address} · {country}";
        return new StatsRow(address, name ?? address, detail, bytesIn, bytesOut);
    }

    private static string? CountryOf(string address, CountryLookup geo) =>
        IPAddress.TryParse(address, out var ip) ? geo.Country(ip) : null;

    /// <summary>
    /// Sums slots into buckets of the caller's local time, from the bucket holding
    /// <paramref name="from"/> up to <paramref name="to"/>; empty buckets are zero.
    /// </summary>
    internal static (StatsBucket Bucket, List<StatsPoint> Points) Bucketize(
        IReadOnlyList<(long Slot, long In, long Out)> slots, DateTimeOffset from, DateTimeOffset to, StatsBucket bucket, TimeZoneInfo zone)
    {
        DateTime start = TimeZoneInfo.ConvertTime(from, zone).DateTime;
        DateTime end = TimeZoneInfo.ConvertTime(to, zone).DateTime;
        while (bucket < StatsBucket.Month && Count(start, end, bucket) > MaxBuckets)
            bucket++;

        var sums = new Dictionary<DateTime, (long In, long Out)>();
        foreach (var (slot, bytesIn, bytesOut) in slots)
        {
            DateTime key = Floor(TimeZoneInfo.ConvertTime(DateTimeOffset.FromUnixTimeSeconds(slot), zone).DateTime, bucket);
            var sum = sums.GetValueOrDefault(key);
            sums[key] = (sum.In + bytesIn, sum.Out + bytesOut);
        }

        var points = new List<StatsPoint>();
        for (DateTime t = Floor(start, bucket); t < end && points.Count < MaxBuckets; t = Next(t, bucket))
        {
            var sum = sums.GetValueOrDefault(t);
            points.Add(new StatsPoint(new DateTimeOffset(t, zone.GetUtcOffset(t)), sum.In, sum.Out));
        }
        return (bucket, points);
    }

    private static double Count(DateTime start, DateTime end, StatsBucket bucket) => bucket switch
    {
        StatsBucket.Minute => (end - start).TotalMinutes,
        StatsBucket.Hour => (end - start).TotalHours,
        StatsBucket.Day => (end - start).TotalDays,
        _ => (end - start).TotalDays / 28,
    };

    internal static DateTime Floor(DateTime t, StatsBucket bucket) => bucket switch
    {
        StatsBucket.Minute => new DateTime(t.Year, t.Month, t.Day, t.Hour, t.Minute, 0),
        StatsBucket.Hour => new DateTime(t.Year, t.Month, t.Day, t.Hour, 0, 0),
        StatsBucket.Day => t.Date,
        _ => new DateTime(t.Year, t.Month, 1),
    };

    private static DateTime Next(DateTime t, StatsBucket bucket) => bucket switch
    {
        StatsBucket.Minute => t.AddMinutes(1),
        StatsBucket.Hour => t.AddHours(1),
        StatsBucket.Day => t.AddDays(1),
        _ => t.AddMonths(1),
    };

    /// <summary>Id of a dimension row, inserting it (or updating its name) as needed.</summary>
    private long Id(Dictionary<string, (long Id, string? Name)> cache, string table, string keyColumn, string key, string? name,
        (string Column, string Value)? extra, SqliteTransaction tx)
    {
        if (cache.TryGetValue(key, out var known) && (name is null || name == known.Name))
            return known.Id;

        // Apps always have a name; hosts and users keep the last name that was known.
        string nameValue = table == "apps" ? "excluded.name" : "COALESCE(excluded.name, name)";
        string extraColumn = extra is { } e ? $", {e.Column}" : "";
        string extraValue = extra is not null ? ", $extra" : "";
        string extraSet = extra is { } x ? $", {x.Column} = excluded.{x.Column}" : "";
        using var cmd = Command($"""
            INSERT INTO {table}({keyColumn}, name{extraColumn}) VALUES($key, $name{extraValue})
            ON CONFLICT({keyColumn}) DO UPDATE SET name = {nameValue}{extraSet}
            RETURNING id, name
            """, tx);
        cmd.Parameters.AddWithValue("$key", key);
        cmd.Parameters.AddWithValue("$name", (object?)name ?? DBNull.Value);
        if (extra is { } ex)
            cmd.Parameters.AddWithValue("$extra", ex.Value);
        using var reader = cmd.ExecuteReader();
        reader.Read();
        var entry = (reader.GetInt64(0), reader.IsDBNull(1) ? null : reader.GetString(1));
        cache[key] = entry;
        return entry.Item1;
    }

    private void LoadIds()
    {
        Load(_apps, "SELECT app_id, id, name FROM apps");
        Load(_hosts, "SELECT address, id, name FROM hosts");
        Load(_users, "SELECT sid, id, name FROM users");

        void Load(Dictionary<string, (long, string?)> cache, string sql)
        {
            cache.Clear();
            using var cmd = Command(sql);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
                cache[reader.GetString(0)] = (reader.GetInt64(1), reader.IsDBNull(2) ? null : reader.GetString(2));
        }
    }

    private long FileBytes()
    {
        long size = 0;
        foreach (string suffix in new[] { "", "-wal" })
        {
            var file = new FileInfo(FilePath + suffix);
            if (file.Exists)
                size += file.Length;
        }
        return size;
    }

    private SqliteCommand Command(string sql, SqliteTransaction? tx = null)
    {
        var cmd = _db.CreateCommand();
        cmd.CommandText = sql;
        cmd.Transaction = tx;
        return cmd;
    }

    private void Execute(string sql)
    {
        using var cmd = Command(sql);
        cmd.ExecuteNonQuery();
    }
}
