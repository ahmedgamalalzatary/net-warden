using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace NetWarden.Core.Monitoring;

/// <summary>Reverse DNS with caching (including negative results) and a timeout.</summary>
public sealed class HostNameCache(Func<IPAddress, Task<string?>>? lookup = null)
{
    public static readonly TimeSpan LookupTimeout = TimeSpan.FromSeconds(3);

    private readonly Func<IPAddress, Task<string?>> _lookup = lookup ?? DefaultLookupAsync;
    private readonly ConcurrentDictionary<IPAddress, Task<string?>> _cache = new();

    public Task<string?> GetAsync(IPAddress address) =>
        _cache.GetOrAdd(Endpoints.Normalize(address), LookupWithTimeoutAsync);

    private async Task<string?> LookupWithTimeoutAsync(IPAddress address)
    {
        try
        {
            return await _lookup(address).WaitAsync(LookupTimeout).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or TimeoutException or ArgumentException)
        {
            return null;
        }
    }

    private static async Task<string?> DefaultLookupAsync(IPAddress address)
    {
        IPHostEntry entry = await Dns.GetHostEntryAsync(address).ConfigureAwait(false);
        return string.IsNullOrEmpty(entry.HostName) || entry.HostName == address.ToString() ? null : entry.HostName;
    }
}
