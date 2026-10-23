using NetWarden.Shared.Contracts;
using NetWarden.Shared.Storage;

namespace NetWarden.Core;

/// <summary>The live service settings; components read <see cref="Current"/> on every use.</summary>
public sealed class SettingsService
{
    private readonly JsonFileStore<ServiceSettings> _store;
    private readonly Lock _lock = new();
    private ServiceSettings _current;

    public SettingsService(JsonFileStore<ServiceSettings> store)
    {
        _store = store;
        _current = store.Load();
    }

    public event Action<ServiceSettings>? Changed;

    public ServiceSettings Current => Volatile.Read(ref _current);

    public ServiceSettings Update(ServiceSettings settings)
    {
        lock (_lock)
        {
            settings.SchemaVersion = ServiceSettings.CurrentSchemaVersion;
            _store.Save(settings);
            Volatile.Write(ref _current, settings);
        }
        Changed?.Invoke(settings);
        return settings;
    }
}
