using Microsoft.Extensions.Hosting;
using NetWarden.Service;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;
using NetWarden.Shared.Storage;
using NetWarden.Tests.Monitoring;

namespace NetWarden.Tests.Stats;

/// <summary>Real ETW traffic through the whole pipeline: monitor, recorder, SQLite, stats.query.</summary>
public sealed class StatsLiveTests
{
    [AdminFact]
    public async Task Loopback_traffic_of_this_process_shows_up_in_stats()
    {
        using var dir = new TempDir();
        new JsonFileStore<ServiceSettings>(dir.File("settings.json")).Save(new ServiceSettings
        {
            Stats = new StatsSettings { SaveLoopback = true },
        });
        string pipe = TestPipes.NewName();
        using var host = ServiceHost.Build([], new Dictionary<string, string?>
        {
            ["NetWarden:PipeName"] = pipe,
            ["NetWarden:RestrictPipeToAdmins"] = "false",
            ["NetWarden:DataDirectory"] = dir.Path,
            ["NetWarden:EnablePacketFilter"] = "false",
            ["NetWarden:TrafficSessionName"] = $"NetWarden-Test-{Guid.NewGuid():N}",
            ["NetWarden:DnsSessionName"] = $"NetWarden-TestDns-{Guid.NewGuid():N}",
        });
        await host.StartAsync();
        try
        {
            await using var client = new ServiceClient(pipe);
            await client.ConnectAsync(TimeSpan.FromSeconds(5));
            await Task.Delay(1500); // ETW sessions take a moment to start delivering.
            var started = DateTimeOffset.UtcNow;

            using var pair = await LoopbackPair.CreateAsync();
            var payload = new byte[500_000];
            var read = Task.Run(async () =>
            {
                var buf = new byte[65536];
                int total = 0;
                while (total < payload.Length)
                    total += await pair.Server.GetStream().ReadAsync(buf);
            });
            await pair.Client.GetStream().WriteAsync(payload);
            await read;

            var query = new StatsQuery(started.AddMinutes(-2), DateTimeOffset.UtcNow.AddMinutes(2), StatsBucket.Minute,
                StatsGroupBy.Port, Zones: [StatsZone.Loopback]);
            long seen = 0;
            for (var deadline = DateTime.UtcNow.AddSeconds(15); DateTime.UtcNow < deadline; await Task.Delay(500))
            {
                // Each port row holds both directions of that connection.
                var result = await client.RequestAsync<StatsResult>(Methods.StatsQuery, query);
                seen = result!.Rows.Where(r => r.Key == $"Tcp/{pair.ListenPort}").Sum(r => r.Out);
                if (seen >= payload.Length)
                    break;
            }

            Assert.True(seen >= payload.Length, $"Stats show {seen} bytes sent to port {pair.ListenPort}, expected >= {payload.Length}.");
        }
        finally
        {
            await host.StopAsync();
        }
    }
}
