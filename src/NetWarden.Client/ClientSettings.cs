using System.IO;
using NetWarden.Shared.Formatting;

namespace NetWarden.Client;

public enum ActivityFilter
{
    Online,
    Offline,
    All,
    Hidden,
}

/// <summary>Per-user UI preferences, stored in %LocalAppData%\NetWarden\client.json.</summary>
public sealed class ClientSettings
{
    public static string DefaultPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetWarden", "client.json");

    public UnitMode Units { get; set; } = UnitMode.Bytes;
    public ActivityFilter Filter { get; set; } = ActivityFilter.Online;
    public HashSet<string> HiddenAppIds { get; set; } = new(StringComparer.Ordinal);

    /// <summary>Column id to visibility; ids missing from the map are visible.</summary>
    public Dictionary<string, bool> Columns { get; set; } = [];

    public int ChartWindowSeconds { get; set; } = 60;
    public bool ShowInfoPane { get; set; } = true;
    public bool ShowChart { get; set; } = true;
}
