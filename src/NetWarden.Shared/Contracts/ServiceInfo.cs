namespace NetWarden.Shared.Contracts;

public sealed record ServiceInfo(
    string Version,
    int ProcessId,
    DateTimeOffset StartedAt,
    bool IsElevated,
    bool IsWindowsService,
    string MachineName);
