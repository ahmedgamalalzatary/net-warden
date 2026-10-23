using System.Net;
using System.Net.Sockets;
using NetWarden.Core.Monitoring;

namespace NetWarden.Tests.Monitoring;

public class HostNameCacheTests
{
    [Fact]
    public async Task Caches_results_per_address()
    {
        int calls = 0;
        var cache = new HostNameCache(_ => { Interlocked.Increment(ref calls); return Task.FromResult<string?>("host.example"); });

        Assert.Equal("host.example", await cache.GetAsync(IPAddress.Parse("1.2.3.4")));
        Assert.Equal("host.example", await cache.GetAsync(IPAddress.Parse("1.2.3.4")));
        // Mapped form is the same address.
        Assert.Equal("host.example", await cache.GetAsync(IPAddress.Parse("1.2.3.4").MapToIPv6()));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Lookup_failure_returns_null_and_is_cached()
    {
        int calls = 0;
        var cache = new HostNameCache(_ => { calls++; throw new SocketException(11001); });

        Assert.Null(await cache.GetAsync(IPAddress.Parse("10.0.0.1")));
        Assert.Null(await cache.GetAsync(IPAddress.Parse("10.0.0.1")));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Slow_lookup_times_out_to_null()
    {
        var cache = new HostNameCache(async _ => { await Task.Delay(TimeSpan.FromSeconds(30)); return "late"; });

        var started = DateTime.UtcNow;
        Assert.Null(await cache.GetAsync(IPAddress.Parse("10.0.0.2")));
        Assert.True(DateTime.UtcNow - started < HostNameCache.LookupTimeout + TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task Real_lookup_of_loopback_does_not_throw()
    {
        await new HostNameCache().GetAsync(IPAddress.Loopback);
    }
}
