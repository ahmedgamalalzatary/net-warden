namespace NetWarden.Shared.Contracts;

/// <summary>What is saved about remote administration. Never sent to clients.</summary>
public sealed class RemoteConfig
{
    public bool IsEnabled { get; set; }
    public int Port { get; set; } = 5317;
    public string? PasswordHash { get; set; }
    public string? PasswordSalt { get; set; }
    public int Iterations { get; set; }
}

public sealed record RemoteStatus(bool IsEnabled, int Port, bool HasPassword, bool IsListening, string? Thumbprint, string? Error);

/// <summary><see cref="NewPassword"/> null or empty keeps the current password.</summary>
public sealed record RemoteConfigureRequest(bool IsEnabled, int Port, string? NewPassword);

public sealed record RemoteAuthRequest(string Password);

/// <summary>A user or group allowed or denied the service. <see cref="Account"/> is a SID, or a name when setting.</summary>
public sealed record AccessEntry(string Account, string? Name, bool IsAllowed);

public sealed class AccessDocument
{
    public List<AccessEntry> Entries { get; set; } = [];
}

public sealed record AccessSetRequest(IReadOnlyList<AccessEntry> Entries);
