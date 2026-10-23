using NetWarden.Shared.Storage;
using NetWarden.Core;
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

public class PrioritySettingsTests
{
    [Fact]
    public void Defaults_are_sensible()
    {
        var p = new ServiceSettings().Priorities;

        Assert.True(p.Adaptive);
        Assert.Equal(TimeSpan.FromMilliseconds(250), p.ReactionTime);
        Assert.Equal(70, p.ReservedPercent(PriorityLevel.Critical));
        Assert.Equal(0, p.ReservedPercent(PriorityLevel.Low));
    }

    [Theory]
    [InlineData(ReactionSpeed.Low, 1000)]
    [InlineData(ReactionSpeed.Fast, 100)]
    [InlineData(ReactionSpeed.Custom, 50)]
    public void Reaction_speed_maps_to_a_time(ReactionSpeed speed, int millis)
    {
        var p = new PrioritySettings { ReactionSpeed = speed, ReactionMillis = 10 };
        Assert.Equal(TimeSpan.FromMilliseconds(millis), p.ReactionTime);
    }

    [Fact]
    public void Normalize_puts_values_in_range()
    {
        var s = new ServiceSettings
        {
            Priorities = new PrioritySettings
            {
                CriticalPercent = 150, HighPercent = -5, HeadroomPercent = 999, ReactionMillis = 1,
                ReactionSpeed = (ReactionSpeed)9, MinDownloadBytesPerSecond = 5000, MaxDownloadBytesPerSecond = 1000,
                MinUploadBytesPerSecond = -1,
            },
        };

        SettingsService.Normalize(s);

        var p = s.Priorities;
        Assert.Equal(95, p.CriticalPercent);
        Assert.Equal(0, p.HighPercent);
        Assert.Equal(200, p.HeadroomPercent);
        Assert.Equal(PrioritySettings.MinReactionMillis, p.ReactionMillis);
        Assert.Equal(ReactionSpeed.Normal, p.ReactionSpeed);
        Assert.Equal(1000, p.MinDownloadBytesPerSecond);
        Assert.Equal(0, p.MinUploadBytesPerSecond);
    }

    [Fact]
    public void Missing_priority_section_gets_defaults()
    {
        var s = new ServiceSettings { Priorities = null! };
        SettingsService.Normalize(s);
        Assert.NotNull(s.Priorities);
    }
}
