using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Storage;

namespace NetWarden.Core.Apps;

/// <summary>Every app seen online, with its tags. Persisted in apps.json; a deleted app that runs again comes back, without its tags.</summary>
public sealed class AppRegistry
{
    private readonly JsonFileStore<AppsDocument> _store;
    private readonly TimeProvider _time;
    private readonly Func<string, bool> _fileExists;
    private readonly ILogger _logger;
    private readonly Lock _lock = new();
    private readonly Dictionary<string, KnownApp> _apps;
    private bool _dirty;

    public AppRegistry(JsonFileStore<AppsDocument> store, TimeProvider time, Func<string, bool>? fileExists = null, ILogger? logger = null)
    {
        _store = store;
        _time = time;
        _fileExists = fileExists ?? File.Exists;
        _logger = logger ?? NullLogger.Instance;
        _apps = store.Load().Apps.ToDictionary(a => a.Id, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Raised outside the lock after tags changed; flows must then be evaluated again.</summary>
    public event Action? TagsChanged;

    public void Observe(ActivitySnapshot snapshot)
    {
        DateTimeOffset now = _time.GetUtcNow();
        lock (_lock)
        {
            foreach (var activity in snapshot.Apps)
            {
                if (!activity.IsOnline)
                    continue;
                AppInfo app = activity.App;
                _apps[app.Id] = _apps.TryGetValue(app.Id, out var known)
                    ? known with { Kind = app.Kind, Path = app.Path, DisplayName = app.DisplayName, CompanyName = app.CompanyName, LastSeen = now }
                    : new KnownApp(app.Id, app.Kind, app.Path, app.DisplayName, app.CompanyName, now, now, []);
                _dirty = true;
            }
        }
    }

    public IReadOnlyList<KnownAppView> List()
    {
        lock (_lock)
            return _apps.Values.Select(a => new KnownAppView(a, a.Kind == AppKind.System || _fileExists(a.Path))).ToList();
    }

    public IReadOnlyCollection<string> TagsOf(string appId)
    {
        lock (_lock)
            return _apps.TryGetValue(appId, out var app) ? app.Tags : [];
    }

    public IReadOnlyList<string> AllTags()
    {
        lock (_lock)
            return _apps.Values.SelectMany(a => a.Tags).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public void SetTags(string appId, IReadOnlyList<string> tags)
    {
        lock (_lock)
        {
            if (!_apps.TryGetValue(appId, out var app))
                throw new ArgumentException($"App {appId} not found.");
            _apps[appId] = app with { Tags = tags.Select(t => t.Trim()).Where(t => t.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList() };
            _dirty = true;
            Save();
        }
        TagsChanged?.Invoke();
    }

    public void Delete(IReadOnlyList<string> appIds)
    {
        lock (_lock)
        {
            foreach (string id in appIds)
                _apps.Remove(id);
            _dirty = true;
            Save();
        }
        TagsChanged?.Invoke();
    }

    /// <summary>Writes the list if it changed. A failure is logged and retried on the next save.</summary>
    public void Save()
    {
        lock (_lock)
        {
            if (!_dirty)
                return;
            try
            {
                _store.Save(new AppsDocument { Apps = [.. _apps.Values] });
                _dirty = false;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _logger.LogError(ex, "Could not save the apps list.");
            }
        }
    }
}
