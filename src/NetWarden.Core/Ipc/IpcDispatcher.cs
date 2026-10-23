using System.Text.Json;
using NetWarden.Shared.Ipc;

namespace NetWarden.Core.Ipc;

public sealed class IpcMethodNotFoundException(string method)
    : Exception($"Unknown method '{method}'.");

/// <summary>Routes request methods to registered handlers.</summary>
public sealed class IpcDispatcher
{
    private readonly Dictionary<string, Func<JsonElement?, CancellationToken, Task<object?>>> _handlers =
        new(StringComparer.Ordinal);

    public IpcDispatcher Register<TRequest, TResponse>(
        string method, Func<TRequest?, CancellationToken, Task<TResponse>> handler)
    {
        _handlers.Add(method, async (payload, ct) => await handler(IpcJson.FromElement<TRequest>(payload), ct));
        return this;
    }

    public IpcDispatcher Register<TResponse>(string method, Func<CancellationToken, Task<TResponse>> handler)
    {
        _handlers.Add(method, async (_, ct) => await handler(ct));
        return this;
    }

    public Task<object?> DispatchAsync(string method, JsonElement? payload, CancellationToken ct) =>
        _handlers.TryGetValue(method, out var handler)
            ? handler(payload, ct)
            : throw new IpcMethodNotFoundException(method);
}
