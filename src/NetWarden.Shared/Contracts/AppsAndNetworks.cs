namespace NetWarden.Shared.Contracts;

/// <summary>A program NetWarden has seen online, with the tags the user gave it.</summary>
public sealed record KnownApp(
    string Id,
    AppKind Kind,
    string Path,
    string DisplayName,
    string? CompanyName,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    IReadOnlyList<string> Tags);

public sealed record KnownAppView(KnownApp App, bool IsInstalled);

public sealed class AppsDocument
{
    public List<KnownApp> Apps { get; set; } = [];
}

public sealed record SetAppTagsRequest(string AppId, IReadOnlyList<string> Tags);
public sealed record DeleteAppsRequest(IReadOnlyList<string> AppIds, bool DeleteStats);

/// <summary>A network this computer has been on, identified by SSID and gateway rather than by adapter.</summary>
public sealed record KnownNetwork(
    string Id,
    string Name,
    string InterfaceName,
    string InterfaceDescription,
    bool IsWifi,
    string? Ssid,
    string? GatewayMac,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen);

public sealed record NetworkView(KnownNetwork Network, bool IsActive);

public sealed class NetworksDocument
{
    public List<KnownNetwork> Networks { get; set; } = [];
}

public sealed record DeleteNetworkRequest(string Id);

/// <summary>A filter to find or create, e.g. for a tag or a network.</summary>
public sealed record EnsureFilterRequest(string Name, IReadOnlyList<FilterFunction> Functions);

public sealed record AddressRequest(string Address);

/// <summary>Country of an address: ISO code and English name.</summary>
public sealed record GeoInfo(string Code, string Name);
