namespace NetWarden.Core;

public static class AppPaths
{
    /// <summary>%ProgramData%\NetWarden, shared by the service and every user.</summary>
    public static string DataDirectory { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "NetWarden");

    public static string SettingsFile => Path.Combine(DataDirectory, "settings.json");
    public static string LogsDirectory => Path.Combine(DataDirectory, "logs");
}
