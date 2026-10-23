using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using NetWarden.Core.Monitoring;
using NetWarden.Shared.Contracts;

namespace NetWarden.Tests.Monitoring;

/// <summary>Skips when the test process is not elevated (ETW kernel sessions need admin).</summary>
public sealed class AdminFactAttribute : FactAttribute
{
    public AdminFactAttribute()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            Skip = "Requires an elevated test run.";
    }
}

/// <summary>A connected loopback TCP pair owned by this process.</summary>
internal sealed class LoopbackPair : IDisposable
{
    public TcpListener Listener { get; }
    public TcpClient Client { get; }
    public TcpClient Server { get; }

    private LoopbackPair(TcpListener listener, TcpClient client, TcpClient server)
    {
        Listener = listener;
        Client = client;
        Server = server;
    }

    public static async Task<LoopbackPair> CreateAsync()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var client = new TcpClient();
        var accept = listener.AcceptTcpClientAsync();
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        return new LoopbackPair(listener, client, await accept);
    }

    public int ListenPort => ((IPEndPoint)Listener.LocalEndpoint).Port;
    public int ClientPort => ((IPEndPoint)Client.Client.LocalEndPoint!).Port;

    public void Dispose()
    {
        Client.Dispose();
        Server.Dispose();
        Listener.Stop();
    }
}

public class SocketTableTests
{
    [Fact]
    public async Task Lists_own_listening_and_established_sockets()
    {
        using var pair = await LoopbackPair.CreateAsync();
        int pid = Environment.ProcessId;

        var rows = new SocketTable().Snapshot().Where(r => r.ProcessId == pid).ToList();

        Assert.Contains(rows, r => r.Protocol == TransportProtocol.Tcp && r.State == TcpState.Listen && r.LocalPort == pair.ListenPort);
        Assert.Contains(rows, r => r.State == TcpState.Established && r.LocalPort == pair.ClientPort && r.RemotePort == pair.ListenPort
                                   && r.RemoteAddress!.Equals(IPAddress.Loopback));
        Assert.Contains(rows, r => r.State == TcpState.Established && r.LocalPort == pair.ListenPort && r.RemotePort == pair.ClientPort);
    }

    [Fact]
    public void Lists_ipv6_and_udp_sockets()
    {
        using var udp = new UdpClient(new IPEndPoint(IPAddress.IPv6Loopback, 0));
        int port = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;

        var rows = new SocketTable().Snapshot();

        Assert.Contains(rows, r => r.Protocol == TransportProtocol.Udp && r.LocalPort == port
                                   && r.ProcessId == Environment.ProcessId && r.LocalAddress.Equals(IPAddress.IPv6Loopback));
    }
}

public class ConnectionKillerTests
{
    [AdminFact]
    public async Task Kills_an_ipv4_tcp_connection()
    {
        using var pair = await LoopbackPair.CreateAsync();

        uint rc = ConnectionKiller.KillTcp(IPAddress.Loopback, pair.ClientPort, IPAddress.Loopback, pair.ListenPort);

        Assert.Equal(0u, rc);
        var buffer = new byte[1];
        await Assert.ThrowsAnyAsync<IOException>(async () =>
        {
            // A reset connection fails on read (or returns 0 then fails on write).
            int n = await pair.Client.GetStream().ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
            if (n == 0)
                await pair.Client.GetStream().WriteAsync(new byte[1]);
            throw new IOException("closed");
        });
    }

    [Fact]
    public void Ipv6_is_rejected()
    {
        Assert.Throws<NotSupportedException>(() =>
            ConnectionKiller.KillTcp(IPAddress.IPv6Loopback, 1, IPAddress.IPv6Loopback, 2));
    }
}

public class EtwTrafficSourceTests
{
    [AdminFact]
    public async Task Reports_loopback_tcp_traffic_of_this_process()
    {
        long received = 0, sent = 0;
        using var source = new EtwTrafficSource(NullLogger<EtwTrafficSource>.Instance, $"NetWarden-Test-{Guid.NewGuid():N}");
        int pid = Environment.ProcessId;
        using var pair = await LoopbackPair.CreateAsync();
        source.Traffic += e =>
        {
            if (e.ProcessId != pid || e.Protocol != TransportProtocol.Tcp || e.RemotePort != pair.ListenPort)
                return;
            Interlocked.Add(ref e.Direction == TrafficDirection.Out ? ref sent : ref received, e.Bytes);
        };
        source.Start();
        await Task.Delay(1500); // ETW sessions take a moment to start delivering.

        var payload = new byte[200_000];
        var read = Task.Run(async () =>
        {
            var buf = new byte[65536];
            int total = 0;
            while (total < payload.Length)
                total += await pair.Server.GetStream().ReadAsync(buf);
        });
        await pair.Client.GetStream().WriteAsync(payload);
        await read;

        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (Interlocked.Read(ref sent) < payload.Length && DateTime.UtcNow < deadline)
            await Task.Delay(100);

        Assert.True(Interlocked.Read(ref sent) >= payload.Length, $"Saw {sent} bytes sent, expected >= {payload.Length}.");
    }
}
