namespace NetWarden.Shared.Ipc;

/// <summary>Method names understood by the service.</summary>
public static class Methods
{
    public const string ServiceInfo = "service.info";
    public const string SettingsGet = "settings.get";
    public const string AppsResolve = "apps.resolve";

    public const string ActivityGet = "activity.get";
    public const string ActivityResetTotals = "activity.resetTotals";
    public const string ConnectionsKill = "connections.kill";
    public const string DnsReverse = "dns.reverse";
}

/// <summary>Event names pushed by the service to every client.</summary>
public static class Events
{
    /// <summary>Payload: <see cref="Contracts.ActivitySnapshot"/>, once per second.</summary>
    public const string ActivitySnapshot = "activity.snapshot";
}
