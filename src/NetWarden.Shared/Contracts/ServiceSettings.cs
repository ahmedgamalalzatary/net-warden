namespace NetWarden.Shared.Contracts;

/// <summary>Settings persisted by the service.</summary>
public sealed class ServiceSettings
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; set; } = CurrentSchemaVersion;
    public bool IsBlockerEnabled { get; set; } = true;
    public bool IsLimiterEnabled { get; set; } = true;
    public bool IsPriorityEnabled { get; set; } = true;
    public bool IsStatsEnabled { get; set; } = true;

    /// <summary>Blocker action for incoming connections no rule matches.</summary>
    public FirewallAction DefaultFirewallIn { get; set; } = FirewallAction.Allow;

    /// <summary>Blocker action for outgoing connections no rule matches.</summary>
    public FirewallAction DefaultFirewallOut { get; set; } = FirewallAction.Allow;
}
