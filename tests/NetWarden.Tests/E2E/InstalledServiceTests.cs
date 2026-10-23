using System.Net.Http;
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

    [InstalledServiceFact]
    public async Task Installed_service_limits_download_speed()
    {
        await using var client = new ServiceClient();
        await client.ConnectAsync(TimeSpan.FromSeconds(5));
        const string Url = "https://speed.cloudflare.com/__down?bytes=400000";
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        try
        {
            await http.GetByteArrayAsync("https://speed.cloudflare.com/__down?bytes=1000");
        }
        catch (HttpRequestException)
        {
            return; // no Internet
        }

        var filter = (await client.RequestAsync<FilterDefinition>(Methods.FiltersSave, new FilterDefinition(Guid.Empty,
            $"E2E limit {Guid.NewGuid():N}", FilterType.Filter, FilterPerType.None,
            [new FilterFunction(FilterFunctionKind.ProcessId, true, [Environment.ProcessId.ToString()])], [])))!;
        try
        {
            await client.RequestAsync<RuleDefinition>(Methods.RulesSave, new RuleDefinition(Guid.Empty, filter.Id,
                RuleKind.Limit, RuleDirection.In, LimitBytesPerSecond: 100 * 1024));
            for (int i = 0; i < 50 && (await client.RequestAsync<PacketFilterStatus>(Methods.FilterStatus))!.Limiter?.IsRunning != true; i++)
                await Task.Delay(100);

            var watch = System.Diagnostics.Stopwatch.StartNew();
            byte[] body = await http.GetByteArrayAsync(Url);
            double rate = body.Length / watch.Elapsed.TotalSeconds;

            Assert.Equal(400_000, body.Length);
            Assert.InRange(rate, 50 * 1024, 115 * 1024);
        }
        finally
        {
            await client.RequestAsync<bool>(Methods.FiltersDelete, new DeleteRequest(filter.Id));
        }
    }

    [InstalledServiceFact]
    public async Task Installed_service_gives_critical_traffic_priority_over_normal()
    {
        string curl = Path.Combine(Environment.SystemDirectory, "curl.exe");
        if (!File.Exists(curl))
            return;
        string dir = Path.Combine(Path.GetTempPath(), "netwarden-e2e-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        // Two copies are two apps: one gets Critical, the other stays Normal.
        string critical = Path.Combine(dir, "nw-critical-curl.exe");
        string normal = Path.Combine(dir, "nw-normal-curl.exe");
        File.Copy(curl, critical);
        File.Copy(curl, normal);

        await using var client = new ServiceClient();
        await client.ConnectAsync(TimeSpan.FromSeconds(5));
        var original = (await client.RequestAsync<ServiceSettings>(Methods.SettingsGet))!;
        var filter = (await client.RequestAsync<FilterDefinition>(Methods.FiltersSave, new FilterDefinition(Guid.Empty,
            $"E2E priority {Guid.NewGuid():N}", FilterType.Filter, FilterPerType.None,
            [new FilterFunction(FilterFunctionKind.PathContains, true, ["nw-critical-curl"])], [])))!;
        try
        {
            if (await Download(normal, seconds: 4) is not { } alone || alone < 800 * 1024)
                return; // the line is too slow to tell a 300 KB/s stream from the rest
            // Tell the service the line speed (a little under what it just measured, at most 2000 KB/s).
            long line = (long)Math.Min(2000 * 1024, alone * 0.8);

            var settings = IpcJson.FromElement<ServiceSettings>(IpcJson.ToElement(original))!;
            settings.IsPriorityEnabled = true;
            settings.Priorities.MinDownloadBytesPerSecond = settings.Priorities.MaxDownloadBytesPerSecond = line;
            await client.RequestAsync<ServiceSettings>(Methods.SettingsUpdate, settings);
            await client.RequestAsync<RuleDefinition>(Methods.RulesSave, new RuleDefinition(Guid.Empty, filter.Id,
                RuleKind.Priority, RuleDirection.Both, Priority: PriorityLevel.Critical));
            for (int i = 0; i < 50 && (await client.RequestAsync<PacketFilterStatus>(Methods.FilterStatus))!.Limiter?.IsRunning != true; i++)
                await Task.Delay(100);

            // A steady 300 KB/s Critical stream, and a greedy Normal download next to it.
            var stream = Download(critical, seconds: 9, limit: "300k");
            await Task.Delay(1500);
            double? squeezedOrNull = await Download(normal, seconds: 6);
            double? streamedOrNull = await stream;

            double? releasedOrNull = await Download(normal, seconds: 4);
            if (squeezedOrNull is not { } squeezed || streamedOrNull is not { } streamed || releasedOrNull is not { } released)
                return; // the speed test server stopped answering (rate limit)

            // Critical reserves 70% of the line (more than the stream needs), so Normal gets the
            // other 30%; curl's own --limit-rate runs a little over 300 KB/s.
            double expected = line - Math.Max(0.7 * line, 1.2 * 300 * 1024);
            string measured = $"alone {alone / 1024:0}, line {line / 1024}, expected {expected / 1024:0}, squeezed {squeezed / 1024:0}, " +
                $"critical {streamed / 1024:0}, released {released / 1024:0} KB/s";
            // Real lines vary from run to run: observed 0.94x - 1.42x of the expected share.
            Assert.True(squeezed > expected * 0.5 && squeezed < expected * 1.6, measured);
            Assert.True(streamed is > 250 * 1024 and < 380 * 1024, measured);
            Assert.True(released > expected * 1.5, measured);
        }
        finally
        {
            await client.RequestAsync<bool>(Methods.FiltersDelete, new DeleteRequest(filter.Id));
            await client.RequestAsync<ServiceSettings>(Methods.SettingsUpdate, original);
            try { Directory.Delete(dir, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    /// <summary>Downloads with a copy of curl for <paramref name="seconds"/>; returns curl's average bytes/s, or null if the server refused.</summary>
    private static async Task<double?> Download(string curl, int seconds, string? limit = null)
    {
        var start = new System.Diagnostics.ProcessStartInfo(curl)
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (string arg in new[] { "-s", "-o", "NUL", "--max-time", seconds.ToString(), "-w", "%{speed_download} %{http_code}" })
            start.ArgumentList.Add(arg);
        if (limit is not null)
        {
            start.ArgumentList.Add("--limit-rate");
            start.ArgumentList.Add(limit);
        }
        // Hetzner's public test file: Cloudflare's speed test answers 429 to repeated large downloads.
        start.ArgumentList.Add("https://fsn1-speed.hetzner.com/100MB.bin");
        using var process = System.Diagnostics.Process.Start(start)!;
        string output = await process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync();
        // curl reports 0 B/s when the server refuses (e.g. 429 after many runs); that says nothing about NetWarden.
        string[] parts = output.Trim().Split(' ');
        return parts is [var speed, "200"] ? double.Parse(speed, System.Globalization.CultureInfo.InvariantCulture) : null;
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
