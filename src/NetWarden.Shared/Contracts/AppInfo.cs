namespace NetWarden.Shared.Contracts;

public enum AppKind
{
    /// <summary>A normal executable.</summary>
    Desktop,
    /// <summary>A process hosting one or more Windows services (e.g. svchost).</summary>
    Service,
    /// <summary>A packaged (Microsoft Store / MSIX) app.</summary>
    Store,
    /// <summary>The kernel (PID 4) and other pseudo-processes.</summary>
    System,
}

public sealed record ServiceEntry(string Name, string DisplayName);

/// <summary>
/// Identity of the program behind a process. <see cref="Id"/> is stable across
/// restarts of the same program, so rules and stats can be keyed by it.
/// </summary>
public sealed record AppInfo(
    string Id,
    AppKind Kind,
    string Path,
    string DisplayName,
    string? CompanyName,
    string? ProductName,
    string? FileVersion,
    IReadOnlyList<ServiceEntry> Services,
    string? PackageFamilyName);

public sealed record ResolveAppRequest(int ProcessId);
