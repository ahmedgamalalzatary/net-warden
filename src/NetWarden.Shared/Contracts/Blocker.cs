namespace NetWarden.Shared.Contracts;

/// <summary>A connection waiting for the user to allow or deny it (Ask mode).</summary>
public sealed record BlockerRequest(
    Guid Id,
    AppInfo App,
    int ProcessId,
    TransportProtocol Protocol,
    ConnectionKind Kind,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    string? RemoteHost,
    DateTimeOffset Created,
    DateTimeOffset Deadline,
    Guid? SourceRuleId);

public enum RememberMode
{
    /// <summary>Only the waiting connection(s).</summary>
    Once,
    /// <summary>Create a rule that is deleted after a while.</summary>
    Temporary,
    /// <summary>Create a permanent rule.</summary>
    Always,
}

public enum RuleScope
{
    App,
    AppAndRemoteAddress,
    AppAndRemotePort,
}

public sealed record BlockerAnswer(
    Guid RequestId,
    bool Allow,
    RememberMode Remember = RememberMode.Once,
    RuleScope Scope = RuleScope.App,
    int TemporaryMinutes = 30);

public sealed record BlockerResolved(Guid RequestId, bool Allowed, bool TimedOut);

/// <summary>Whether packet filtering is running and why not.</summary>
public sealed record PacketFilterStatus(bool IsRunning, bool IsNeeded, string? Error, long PacketsSeen, long PacketsDropped);
