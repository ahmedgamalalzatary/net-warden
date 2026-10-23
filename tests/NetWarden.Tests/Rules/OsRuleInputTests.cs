using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using NetWarden.Core.Apps;
using NetWarden.Core.Monitoring;
using NetWarden.Tests.Monitoring;

namespace NetWarden.Tests.Rules;

public partial class ProcessUsersTests
{
    [Fact]
    public void Resolves_current_process_user()
    {
        using var me = WindowsIdentity.GetCurrent();

        var user = new ProcessUsers().Get(Environment.ProcessId);

        Assert.NotNull(user);
        Assert.Equal(me.User!.Value, user.Sid);
        Assert.Equal(me.Name, user.Name, ignoreCase: true);
    }

    [Fact]
    public void System_pids_are_local_system_and_dead_pids_are_null()
    {
        Assert.Equal("S-1-5-18", new ProcessUsers().Get(4)!.Sid);
        Assert.Null(new ProcessUsers().Get(int.MaxValue - 2));
    }
}

public partial class EtwDnsSourceTests
{
    [LibraryImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCacheEntry_W", StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DnsFlushResolverCacheEntry(string name);

    [AdminFact]
    public async Task Records_names_resolved_by_this_machine()
    {
        var map = new DnsMap();
        using var source = new EtwDnsSource(map, NullLogger<EtwDnsSource>.Instance, $"NetWarden-Test-Dns-{Guid.NewGuid():N}");
        source.Start();
        await Task.Delay(1500);

        IPAddress[] addresses = [];
        string? hit = null;
        foreach (string name in new[] { "example.com", "example.org", "www.iana.org" })
        {
            // Force a real query rather than a cache hit, which logs no completion event.
            DnsFlushResolverCacheEntry(name);
            try
            {
                addresses = await Dns.GetHostAddressesAsync(name);
            }
            catch (System.Net.Sockets.SocketException)
            {
                continue;
            }
            var deadline = DateTime.UtcNow.AddSeconds(5);
            while (DateTime.UtcNow < deadline && hit is null)
            {
                hit = addresses.Select(map.Lookup).FirstOrDefault(n => n is not null);
                await Task.Delay(100);
            }
            if (hit is not null)
            {
                Assert.Equal(name, hit, ignoreCase: true);
                return;
            }
        }
        Assert.Fail($"No DNS completion was recorded (map has {map.Count} entries).");
    }
}
