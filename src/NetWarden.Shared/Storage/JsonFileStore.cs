using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace NetWarden.Shared.Storage;

/// <summary>
/// Persists one object as JSON. Writes go to a temp file that atomically replaces
/// the target, keeping the previous good file as a backup. Loading falls back to
/// the backup, then to defaults, so a corrupt file never stops the service.
/// </summary>
public sealed class JsonFileStore<T> where T : class, new()
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    private readonly ILogger _logger;
    private readonly Lock _lock = new();

    public JsonFileStore(string path, ILogger? logger = null)
    {
        FilePath = path;
        _logger = logger ?? NullLogger.Instance;
    }

    public string FilePath { get; }
    public string BackupPath => FilePath + ".bak";

    public T Load()
    {
        lock (_lock)
        {
            if (TryRead(FilePath, out T? value))
                return value;
            if (TryRead(BackupPath, out value))
            {
                _logger.LogWarning("Settings file {Path} was unreadable; loaded the backup.", FilePath);
                return value;
            }
            return new T();
        }
    }

    public void Save(T value)
    {
        lock (_lock)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(FilePath))!);
            string temp = FilePath + ".tmp";
            File.WriteAllBytes(temp, JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions));

            // Only keep the current file as backup if it is valid; never back up a corrupt file over a good one.
            if (File.Exists(FilePath) && TryRead(FilePath, out _))
                File.Replace(temp, FilePath, BackupPath, ignoreMetadataErrors: true);
            else
                File.Move(temp, FilePath, overwrite: true);
        }
    }

    private bool TryRead(string path, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out T? value)
    {
        value = null;
        if (!File.Exists(path))
            return false;
        try
        {
            value = JsonSerializer.Deserialize<T>(File.ReadAllBytes(path), JsonOptions);
            return value is not null;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "Failed to read {Path}.", path);
            return false;
        }
    }
}
