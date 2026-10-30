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

    public int ChartWindowSeconds { get; set; } = 60;
    public bool ShowInfoPane { get; set; } = true;
    public bool ShowChart { get; set; } = true;
    public NetWarden.Client.Services.AppTheme Theme { get; set; } = NetWarden.Client.Services.AppTheme.System;

    public NetWarden.Client.ViewModels.StatsRange StatsRange { get; set; } = NetWarden.Client.ViewModels.StatsRange.Today;
    public NetWarden.Shared.Contracts.StatsGroupBy StatsGroupBy { get; set; } = NetWarden.Shared.Contracts.StatsGroupBy.App;

    /// <summary>The page that was open.</summary>
    public string Page { get; set; } = "Activity";
    public double WindowLeft { get; set; } = double.NaN;
    public double WindowTop { get; set; } = double.NaN;
    public double WindowWidth { get; set; } = 1360;
    public double WindowHeight { get; set; } = 820;
    public bool WindowMaximized { get; set; }
    public double InfoPaneWidth { get; set; } = 320;

    public NetWarden.Client.ViewModels.ActivitySortColumn ActivitySort { get; set; } = NetWarden.Client.ViewModels.ActivitySortColumn.Name;
    public bool ActivitySortDescending { get; set; }
    public NetWarden.Client.ViewModels.RuleKindFilter RuleKinds { get; set; } = NetWarden.Client.ViewModels.RuleKindFilter.All;
    public NetWarden.Client.ViewModels.HistoryRange HistoryRange { get; set; } = NetWarden.Client.ViewModels.HistoryRange.Week;
    public NetWarden.Client.ViewModels.AppAvailability AppAvailability { get; set; } = NetWarden.Client.ViewModels.AppAvailability.All;

    /// <summary>Sort, column widths, order and visibility per grid.</summary>
    public Dictionary<string, NetWarden.Client.Services.GridLayout> Grids { get; set; } = [];
    public Dictionary<string, NetWarden.Client.Services.LayoutProfile> LayoutProfiles { get; set; } = [];

    public NetWarden.Client.Charts.ChartStyle ChartStyle { get; set; } = NetWarden.Client.Charts.ChartStyle.Line;
    public NetWarden.Client.Services.AccentColor Accent { get; set; } = NetWarden.Client.Services.AccentColor.Harbour;
    public string Language { get; set; } = "en";
    public bool MinimizeToTray { get; set; }
    public bool CloseToTray { get; set; }
    public bool RunOnStartup { get; set; }
    public bool Notifications { get; set; } = true;
    public List<NetWarden.Client.Services.HotkeyBinding> Hotkeys { get; set; } = [];

    /// <summary>VirusTotal API key, encrypted for this Windows user.</summary>
    public string? VirusTotalKey { get; set; }
    public string LastRemoteHost { get; set; } = "";
    public int LastRemotePort { get; set; } = 5317;

    /// <summary>"host:port" to the certificate seen the first time.</summary>
    public Dictionary<string, string> KnownHosts { get; set; } = [];
}
