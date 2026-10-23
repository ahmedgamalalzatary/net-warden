using NetWarden.Shared.Storage;
using NetWarden.Shared.Contracts;

namespace NetWarden.Tests.Settings;

public sealed class JsonFileStoreTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private JsonFileStore<ServiceSettings> NewStore() => new(_dir.File("sub/settings.json"));

    [Fact]
    public void Missing_file_loads_defaults()
    {
        var settings = NewStore().Load();

        Assert.Equal(ServiceSettings.CurrentSchemaVersion, settings.SchemaVersion);
        Assert.True(settings.IsBlockerEnabled);
    }

    [Fact]
    public void Save_then_load_round_trips_and_creates_directory()
    {
        var store = NewStore();
        store.Save(new ServiceSettings { IsLimiterEnabled = false, IsStatsEnabled = false });

        var loaded = NewStore().Load();

        Assert.False(loaded.IsLimiterEnabled);
        Assert.False(loaded.IsStatsEnabled);
        Assert.True(loaded.IsBlockerEnabled);
    }

    [Fact]
    public void Second_save_keeps_previous_file_as_backup()
    {
        var store = NewStore();
        store.Save(new ServiceSettings { IsLimiterEnabled = false });
        store.Save(new ServiceSettings { IsLimiterEnabled = true });

        Assert.True(File.Exists(store.BackupPath));
        Assert.False(new JsonFileStore<ServiceSettings>(store.BackupPath).Load().IsLimiterEnabled);
        Assert.False(File.Exists(store.FilePath + ".tmp"));
    }

    [Fact]
    public void Corrupt_file_falls_back_to_backup()
    {
        var store = NewStore();
        store.Save(new ServiceSettings { IsBlockerEnabled = false });
        store.Save(new ServiceSettings { IsBlockerEnabled = false, IsPriorityEnabled = false });
        File.WriteAllText(store.FilePath, "{ not json");

        var loaded = store.Load();

        Assert.False(loaded.IsBlockerEnabled);
    }

    [Fact]
    public void Corrupt_file_without_backup_loads_defaults()
    {
        var store = NewStore();
        Directory.CreateDirectory(Path.GetDirectoryName(store.FilePath)!);
        File.WriteAllText(store.FilePath, "garbage");

        Assert.True(store.Load().IsBlockerEnabled);
    }

    [Fact]
    public void Saving_over_corrupt_file_does_not_overwrite_good_backup()
    {
        var store = NewStore();
        store.Save(new ServiceSettings { IsStatsEnabled = false });
        store.Save(new ServiceSettings { IsStatsEnabled = false, IsLimiterEnabled = false });
        File.WriteAllText(store.FilePath, "garbage");

        store.Save(new ServiceSettings());

        Assert.True(store.Load().IsStatsEnabled);
        Assert.False(new JsonFileStore<ServiceSettings>(store.BackupPath).Load().IsStatsEnabled);
    }

    [Fact]
    public void Unknown_properties_are_ignored_for_forward_compatibility()
    {
        var store = NewStore();
        Directory.CreateDirectory(Path.GetDirectoryName(store.FilePath)!);
        File.WriteAllText(store.FilePath, """{ "schemaVersion": 1, "isLimiterEnabled": false, "someFutureSetting": 5 }""");

        Assert.False(store.Load().IsLimiterEnabled);
    }
}
