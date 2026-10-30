namespace NetWarden.Shared.Ipc;

/// <summary>The service handled the request but returned an error.</summary>
public sealed class IpcRemoteException(string method, string message)
    : Exception($"{method}: {message}")
{
    public string Method { get; } = method;
    public string RemoteMessage { get; } = message;
}

/// <summary>The pipe to the service closed before a response arrived.</summary>
public sealed class IpcDisconnectedException(string message, Exception? inner = null)
    : Exception(message, inner);

/// <summary>The service refused the password; trying again with the same one is pointless.</summary>
public sealed class IpcAuthFailedException(string message) : Exception(message);
