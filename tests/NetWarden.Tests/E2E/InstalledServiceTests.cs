using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;

namespace NetWarden.Tests.E2E;

/// <summary>Runs only when NETWARDEN_E2E=1 and the real service is installed (scripts\install-service.ps1).</summary>
public sealed class InstalledServiceFactAttribute : FactAttribute
{
    public InstalledServiceFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("NETWARDEN_E2E") != "1")
            Skip = "Set NETWARDEN_E2E=1 with the NetWarden service installed and running.";
    }
}

public class InstalledServiceTests
{
    [InstalledServiceFact]
    public async Task Installed_service_answers_on_default_pipe()
    {
        await using var client = new ServiceClient();
        await client.ConnectAsync(TimeSpan.FromSeconds(5));

        var info = await client.RequestAsync<ServiceInfo>(Methods.ServiceInfo);

        Assert.NotNull(info);
        Assert.True(info.IsWindowsService);
        Assert.True(info.IsElevated);
        Assert.NotEqual(Environment.ProcessId, info.ProcessId);
    }

    [InstalledServiceFact]
    public async Task Installed_service_resolves_svchost_services()
    {
        await using var client = new ServiceClient();
        await client.ConnectAsync(TimeSpan.FromSeconds(5));
        int dnsPid = ProcessIdOfService("Dnscache");

        var app = await client.RequestAsync<AppInfo>(Methods.AppsResolve, new ResolveAppRequest(dnsPid));

        Assert.NotNull(app);
        Assert.Equal(AppKind.Service, app.Kind);
        Assert.Contains(app.Services, s => s.Name.Equals("Dnscache", StringComparison.OrdinalIgnoreCase));
    }

    [InstalledServiceFact]
    public async Task Installed_service_counts_traffic_of_this_process()
    {
        await using var client = new ServiceClient();
        await client.ConnectAsync(TimeSpan.FromSeconds(5));
        using var pair = await Monitoring.LoopbackPair.CreateAsync();
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

        long sent = 0;
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (sent < payload.Length && DateTime.UtcNow < deadline)
        {
            await Task.Delay(500);
            var snapshot = await client.RequestAsync<ActivitySnapshot>(Methods.ActivityGet);
            sent = snapshot!.Apps
                .SelectMany(a => a.Connections)
                .Where(c => c.ProcessId == Environment.ProcessId && c.RemotePort == pair.ListenPort)
                .Sum(c => c.TotalOut);
        }

        Assert.True(sent >= payload.Length, $"Service counted {sent} bytes, expected >= {payload.Length}.");
    }

    [InstalledServiceFact]
    public async Task Installed_service_blocks_and_unblocks_a_targeted_connection()
    {
        await using var client = new ServiceClient();
        await client.ConnectAsync(TimeSpan.FromSeconds(5));
        var target = System.Net.IPAddress.Parse("1.1.1.1");
        if (!await CanConnect(System.Net.IPAddress.Parse("1.0.0.1")))
            return; // no Internet

        var filter = (await client.RequestAsync<FilterDefinition>(Methods.FiltersSave, new FilterDefinition(Guid.Empty,
            $"E2E block {Guid.NewGuid():N}", FilterType.Filter, FilterPerType.None,
            [
                new FilterFunction(FilterFunctionKind.RemoteAddressInRange, true, ["1.1.1.1"]),
                new FilterFunction(FilterFunctionKind.RemotePortInRange, true, ["80"]),
                new FilterFunction(FilterFunctionKind.ProcessId, true, [Environment.ProcessId.ToString()]),
            ], [])))!;
        try
        {
            await client.RequestAsync<RuleDefinition>(Methods.RulesSave, new RuleDefinition(Guid.Empty, filter.Id,
                RuleKind.Firewall, RuleDirection.Out, Action: FirewallAction.Deny));
            var status = await WaitForStatus(client, running: true);
            Assert.True(status.IsRunning, $"Filter not running: {status.Error}");

            Assert.False(await CanConnect(target), "Connection was not blocked.");
        }
        finally
        {
            await client.RequestAsync<bool>(Methods.FiltersDelete, new DeleteRequest(filter.Id));
        }

        Assert.True(await CanConnect(target), "Connection still blocked after the rule was removed.");
    }

    private static async Task<PacketFilterStatus> WaitForStatus(ServiceClient client, bool running)
    {
        PacketFilterStatus status = null!;
        for (int i = 0; i < 50; i++)
        {
            status = (await client.RequestAsync<PacketFilterStatus>(Methods.FilterStatus))!;
            if (status.IsRunning == running)
                break;
            await Task.Delay(100);
        }
        return status;
    }

    private static async Task<bool> CanConnect(System.Net.IPAddress address)
    {
        using var tcp = new System.Net.Sockets.TcpClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        try
        {
            await tcp.ConnectAsync(address, 80, cts.Token);
            return true;
        }
        catch (Exception ex) when (ex is OperationCanceledException or System.Net.Sockets.SocketException)
        {
            return false;
        }
    }

    private static int ProcessIdOfService(string name) =>
        NetWarden.Core.Apps.ProcessInspector.GetRunningServices()
            .Single(kv => kv.Value.Any(s => s.Name.Equals(name, StringComparison.OrdinalIgnoreCase))).Key;
}
