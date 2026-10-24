namespace NetWarden.Shared.Ipc;

/// <summary>Method names understood by the service.</summary>
public static class Methods
{
    public const string ServiceInfo = "service.info";
    public const string SettingsGet = "settings.get";
    public const string SettingsUpdate = "settings.update";
    public const string AppsResolve = "apps.resolve";

    public const string ActivityGet = "activity.get";
    public const string ActivityResetTotals = "activity.resetTotals";
    public const string ConnectionsKill = "connections.kill";
    public const string DnsReverse = "dns.reverse";

    public const string RulesGet = "rules.get";
    public const string RulesSave = "rules.save";
    public const string RulesDelete = "rules.delete";
    public const string RulesSetEnabled = "rules.setEnabled";
    public const string RulesReorder = "rules.reorder";
    public const string RulesEvaluate = "rules.evaluate";
    public const string FiltersSave = "filters.save";
    public const string FiltersDelete = "filters.delete";
    public const string FiltersEnsureForApp = "filters.ensureForApp";

    public const string FilterStatus = "packetfilter.status";
    public const string BlockerPending = "blocker.pending";
    public const string BlockerAnswer = "blocker.answer";

    public const string StatsQuery = "stats.query";
    public const string StatsInfo = "stats.info";
    public const string StatsDelete = "stats.delete";
    public const string StatsCompact = "stats.compact";
}

/// <summary>Event names pushed by the service to every client.</summary>
public static class Events
{
    /// <summary>Payload: <see cref="Contracts.ActivitySnapshot"/>, once per second.</summary>
    public const string ActivitySnapshot = "activity.snapshot";

    /// <summary>Payload: the new rules generation (long). Clients reload with rules.get.</summary>
    public const string RulesChanged = "rules.changed";

    /// <summary>Payload: <see cref="Contracts.ServiceSettings"/>.</summary>
    public const string SettingsChanged = "settings.changed";

    /// <summary>Payload: <see cref="Contracts.BlockerRequest"/>, when a connection waits for an answer.</summary>
    public const string BlockerRequest = "blocker.request";

    /// <summary>Payload: <see cref="Contracts.BlockerResolved"/>.</summary>
    public const string BlockerResolved = "blocker.resolved";

    /// <summary>Payload: <see cref="Contracts.PacketFilterStatus"/>, when filtering starts, stops or fails.</summary>
    public const string FilterStatus = "packetfilter.status";
}
