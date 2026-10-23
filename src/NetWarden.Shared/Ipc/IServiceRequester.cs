namespace NetWarden.Shared.Ipc;

/// <summary>What view models need from the service connection; faked in tests.</summary>
public interface IServiceRequester
{
    Task<T?> RequestAsync<T>(string method, object? payload = null, CancellationToken ct = default);
}
