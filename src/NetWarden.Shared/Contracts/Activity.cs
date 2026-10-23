namespace NetWarden.Shared.Contracts;

public enum TransportProtocol
{
    Tcp,
    Udp,
}

/// <summary>How a socket came to exist, as NetLimiter shows it.</summary>
public enum ConnectionKind
{
    /// <summary>Outgoing: this machine initiated the connection.</summary>
    Connect,
    /// <summary>Incoming: accepted on a listening socket.</summary>
    Accept,
    /// <summary>A listening TCP socket or a bound UDP socket.</summary>
    Listen,
}

/// <summary>Byte rates are per second; totals are since the service started or totals were reset.</summary>
public sealed record ConnectionActivity(
    string Key,
    int ProcessId,
    TransportProtocol Protocol,
    ConnectionKind Kind,
    string State,
    string LocalAddress,
    int LocalPort,
    string? RemoteAddress,
    int RemotePort,
    long RateIn,
    long RateOut,
    long TotalIn,
    long TotalOut);

public sealed record AppActivity(
    AppInfo App,
    bool IsOnline,
    IReadOnlyList<int> ProcessIds,
    long RateIn,
    long RateOut,
    long TotalIn,
    long TotalOut,
    IReadOnlyList<ConnectionActivity> Connections);

public sealed record ActivitySnapshot(
    DateTimeOffset Timestamp,
    long RateIn,
    long RateOut,
    long TotalIn,
    long TotalOut,
    IReadOnlyList<AppActivity> Apps);

public sealed record KillConnectionRequest(
    TransportProtocol Protocol,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort);

public sealed record ReverseDnsRequest(string Address);
