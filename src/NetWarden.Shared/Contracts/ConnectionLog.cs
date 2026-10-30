namespace NetWarden.Shared.Contracts;

public enum ConnectionLogEvent
{
    Connect,
    Accept,
    Listen,
    Closed,
    Blocked,
}

/// <summary>One line of the realtime connection log. <see cref="Id"/> only ever grows.</summary>
public sealed record ConnectionLogEntry(
    long Id,
    DateTimeOffset Time,
    ConnectionLogEvent Event,
    string AppId,
    string AppName,
    int ProcessId,
    TransportProtocol Protocol,
    string LocalAddress,
    int LocalPort,
    string? RemoteAddress,
    int RemotePort,
    string? RemoteHost);

/// <summary>A connection attempt the blocker denied.</summary>
public sealed record BlockedConnection(
    AppInfo App,
    int ProcessId,
    TransportProtocol Protocol,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    string? RemoteHost,
    DateTimeOffset Time);

public sealed record ConnectionLogRequest(long AfterId);
public sealed record ConnectionLogRunning(bool IsRunning);
public sealed record ConnectionLogPage(bool IsRunning, IReadOnlyList<ConnectionLogEntry> Entries);

/// <summary>Connection history from the statistics; null <see cref="AppId"/> = every app, null <see cref="From"/> = from the beginning.</summary>
public sealed record ConnectionHistoryQuery(string? AppId, DateTimeOffset? From, DateTimeOffset To, int MaxRows = 5000);

/// <summary>What an app exchanged with one host, port and protocol.</summary>
public sealed record ConnectionHistoryRow(
    string AppId,
    string AppName,
    string Address,
    string? HostName,
    int Port,
    TransportProtocol Protocol,
    long In,
    long Out,
    DateTimeOffset First,
    DateTimeOffset Last);
