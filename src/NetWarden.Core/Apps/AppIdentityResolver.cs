using System.Collections.Concurrent;
using System.Diagnostics;
using NetWarden.Shared.Contracts;

namespace NetWarden.Core.Apps;

/// <summary>
/// Turns a process id into an <see cref="AppInfo"/>. Results are cached per
/// (pid, creation time) so a reused pid never returns a stale identity.
/// </summary>
public sealed class AppIdentityResolver
{
    public const int SystemIdleProcessId = 0;
    public const int SystemProcessId = 4;
    public const string SystemAppId = "system";

    private static readonly TimeSpan ServiceMapMaxAge = TimeSpan.FromSeconds(2);
    private const int MaxCacheEntries = 8192;

    private readonly Func<int, ProcessFacts?> _inspect;
    private readonly Func<Dictionary<int, List<ServiceEntry>>> _getServices;
    private readonly TimeProvider _time;
    private readonly ConcurrentDictionary<(int Pid, long Created), AppInfo> _cache = new();
    private readonly Lock _servicesLock = new();
    private Dictionary<int, List<ServiceEntry>> _services = [];
    private DateTimeOffset _servicesLoadedAt = DateTimeOffset.MinValue;

    public AppIdentityResolver()
        : this(ProcessInspector.TryInspect, ProcessInspector.GetRunningServices, TimeProvider.System)
    {
    }

    public AppIdentityResolver(
        Func<int, ProcessFacts?> inspect,
        Func<Dictionary<int, List<ServiceEntry>>> getServices,
        TimeProvider time)
    {
        _inspect = inspect;
        _getServices = getServices;
        _time = time;
    }

    public static AppInfo SystemApp { get; } =
        new(SystemAppId, AppKind.System, "System", "System", "Microsoft Corporation", null, null, [], null);

    public AppInfo? Resolve(int processId)
    {
        if (processId is SystemIdleProcessId or SystemProcessId)
            return SystemApp;

        ProcessFacts? facts = _inspect(processId);
        if (facts is null)
            return null;

        if (_cache.TryGetValue((processId, facts.CreationTime), out AppInfo? cached))
            return cached;

        AppInfo info = Build(facts, GetServices(processId));
        if (_cache.Count >= MaxCacheEntries)
            _cache.Clear();
        _cache[(processId, facts.CreationTime)] = info;
        return info;
    }

    private IReadOnlyList<ServiceEntry> GetServices(int processId)
    {
        lock (_servicesLock)
        {
            if (_time.GetUtcNow() - _servicesLoadedAt > ServiceMapMaxAge)
            {
                _services = _getServices();
                _servicesLoadedAt = _time.GetUtcNow();
            }
            return _services.TryGetValue(processId, out var list) ? list : [];
        }
    }

    internal static AppInfo Build(ProcessFacts facts, IReadOnlyList<ServiceEntry> services)
    {
        FileVersionInfo? version = TryGetVersionInfo(facts.ImagePath);
        string? description = NullIfBlank(version?.FileDescription);
        string fileName = Path.GetFileName(facts.ImagePath);
        string normalizedPath = facts.ImagePath.ToLowerInvariant();

        AppKind kind;
        string id;
        string displayName;

        if (facts.PackageFamilyName is { } family)
        {
            kind = AppKind.Store;
            id = "pkg:" + family.ToLowerInvariant();
            displayName = description ?? family;
        }
        else if (services.Count == 1)
        {
            kind = AppKind.Service;
            id = "svc:" + services[0].Name.ToLowerInvariant();
            displayName = services[0].DisplayName;
        }
        else if (services.Count > 1)
        {
            // A shared host (svchost -k netsvcs). Traffic cannot be split per service from user mode.
            kind = AppKind.Service;
            id = normalizedPath;
            displayName = $"{description ?? fileName} ({services.Count} services)";
        }
        else
        {
            kind = AppKind.Desktop;
            id = normalizedPath;
            displayName = description ?? fileName;
        }

        return new AppInfo(
            id, kind, facts.ImagePath, displayName,
            NullIfBlank(version?.CompanyName), NullIfBlank(version?.ProductName), NullIfBlank(version?.FileVersion),
            services, facts.PackageFamilyName);
    }

    private static FileVersionInfo? TryGetVersionInfo(string path)
    {
        try
        {
            return File.Exists(path) ? FileVersionInfo.GetVersionInfo(path) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static string? NullIfBlank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
