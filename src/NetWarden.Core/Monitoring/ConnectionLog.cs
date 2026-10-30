using System.Net;
using NetWarden.Shared.Contracts;

namespace NetWarden.Core.Monitoring;

/// <summary>
/// The realtime connection log: compares activity snapshots to see connections come and go, and takes
/// the blocker's denials. Keeps the newest <c>capacity</c> entries in memory. While stopped it still
/// follows the snapshots, so starting again doesn't report everything that opened in between.
/// </summary>
public sealed class ConnectionLog(Func<IPAddress, string?> hostOf, int capacity = ConnectionLog.DefaultCapacity)
{
    public const int DefaultCapacity = 10_000;

    private readonly Lock _lock = new();
    private readonly Queue<ConnectionLogEntry> _entries = new();
    private Dictionary<string, (AppInfo App, ConnectionActivity Connection)>? _known;
    private long _nextId = 1;
    private bool _running = true;

    public void Update(ActivitySnapshot snapshot)
    {
        var current = new Dictionary<string, (AppInfo App, ConnectionActivity Connection)>(StringComparer.Ordinal);
        foreach (var app in snapshot.Apps)
            foreach (var connection in app.Connections)
                if (connection.State != "Closed")
                    current[connection.Key] = (app.App, connection);

        lock (_lock)
        {
            if (_known is { } known && _running)
            {
                foreach (var (key, (app, connection)) in current)
                    if (!known.ContainsKey(key))
                        Add(snapshot.Timestamp, EventOf(connection.Kind), app, connection);
                foreach (var (key, (app, connection)) in known)
                    if (!current.ContainsKey(key))
                        Add(snapshot.Timestamp, ConnectionLogEvent.Closed, app, connection);
            }
            _known = current;
        }
    }

    public void AddBlocked(BlockedConnection blocked)
    {
        lock (_lock)
        {
            if (_running)
                Append(id => new ConnectionLogEntry(id, blocked.Time, ConnectionLogEvent.Blocked, blocked.App.Id, blocked.App.DisplayName,
                    blocked.ProcessId, blocked.Protocol, blocked.LocalAddress, blocked.LocalPort, blocked.RemoteAddress, blocked.RemotePort, blocked.RemoteHost));
        }
    }

    public ConnectionLogPage Get(long afterId)
    {
        lock (_lock)
            return new ConnectionLogPage(_running, _entries.Where(e => e.Id > afterId).ToList());
    }

    public void SetRunning(bool running)
    {
        lock (_lock)
            _running = running;
    }

    public void Clear()
    {
        lock (_lock)
            _entries.Clear();
    }

    private static ConnectionLogEvent EventOf(ConnectionKind kind) => kind switch
    {
        ConnectionKind.Accept => ConnectionLogEvent.Accept,
        ConnectionKind.Listen => ConnectionLogEvent.Listen,
        _ => ConnectionLogEvent.Connect,
    };

    private void Add(DateTimeOffset time, ConnectionLogEvent e, AppInfo app, ConnectionActivity c)
    {
        string? host = IPAddress.TryParse(c.RemoteAddress, out var remote) ? hostOf(remote) : null;
        Append(id => new ConnectionLogEntry(id, time, e, app.Id, app.DisplayName, c.ProcessId, c.Protocol,
            c.LocalAddress, c.LocalPort, c.RemoteAddress, c.RemotePort, host));
    }

    private void Append(Func<long, ConnectionLogEntry> entry)
    {
        _entries.Enqueue(entry(_nextId++));
        while (_entries.Count > capacity)
            _entries.Dequeue();
    }
}
