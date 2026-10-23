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

    private static int ProcessIdOfService(string name) =>
        NetWarden.Core.Apps.ProcessInspector.GetRunningServices()
            .Single(kv => kv.Value.Any(s => s.Name.Equals(name, StringComparison.OrdinalIgnoreCase))).Key;
}
