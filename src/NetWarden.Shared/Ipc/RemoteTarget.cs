namespace NetWarden.Shared.Ipc;

/// <summary>
/// A service on another computer. With <see cref="PinnedThumbprint"/> set, any other certificate is refused before
/// the password is sent; without it the certificate is accepted and reported through <see cref="OnThumbprint"/>.
/// </summary>
public sealed record RemoteTarget(string Host, int Port, string Password, string? PinnedThumbprint = null, Action<string>? OnThumbprint = null);
