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
        Normalize(_current);
    }

    public event Action<ServiceSettings>? Changed;

    public ServiceSettings Current => Volatile.Read(ref _current);

    public ServiceSettings Update(ServiceSettings settings)
    {
        lock (_lock)
        {
            settings.SchemaVersion = ServiceSettings.CurrentSchemaVersion;
            Normalize(settings);
            _store.Save(settings);
            Volatile.Write(ref _current, settings);
        }
        Changed?.Invoke(settings);
        return settings;
    }

    /// <summary>Puts out-of-range values back in range rather than rejecting the whole update.</summary>
    public static void Normalize(ServiceSettings settings)
    {
        var p = settings.Priorities ??= new PrioritySettings();
        if (!Enum.IsDefined(p.ReactionSpeed))
            p.ReactionSpeed = ReactionSpeed.Normal;
        p.ReactionMillis = Math.Clamp(p.ReactionMillis, PrioritySettings.MinReactionMillis, PrioritySettings.MaxReactionMillis);
        p.CriticalPercent = Math.Clamp(p.CriticalPercent, 0, 95);
        p.HighPercent = Math.Clamp(p.HighPercent, 0, 95);
        p.NormalPercent = Math.Clamp(p.NormalPercent, 0, 95);
        p.HeadroomPercent = Math.Clamp(p.HeadroomPercent, 0, 200);
        p.MinDownloadBytesPerSecond = Math.Max(0, p.MinDownloadBytesPerSecond);
        p.MaxDownloadBytesPerSecond = Math.Max(0, p.MaxDownloadBytesPerSecond);
        p.MinUploadBytesPerSecond = Math.Max(0, p.MinUploadBytesPerSecond);
        p.MaxUploadBytesPerSecond = Math.Max(0, p.MaxUploadBytesPerSecond);
        if (p.MaxDownloadBytesPerSecond > 0 && p.MinDownloadBytesPerSecond > p.MaxDownloadBytesPerSecond)
            p.MinDownloadBytesPerSecond = p.MaxDownloadBytesPerSecond;
        if (p.MaxUploadBytesPerSecond > 0 && p.MinUploadBytesPerSecond > p.MaxUploadBytesPerSecond)
            p.MinUploadBytesPerSecond = p.MaxUploadBytesPerSecond;
    }
}
