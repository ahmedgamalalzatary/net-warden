using NetWarden.Service;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace NetWarden.Tests.Service;

/// <summary>Starts the real service host in-process and talks to it over the pipe.</summary>
public sealed class ServiceHostTests : IAsyncLifetime
{
    private readonly string _pipeName = TestPipes.NewName();
    private readonly TempDir _dir = new();
    private IHost _host = null!;
    private ServiceClient _client = null!;

    public async Task InitializeAsync()
    {
        _host = ServiceHost.Build([], new Dictionary<string, string?>
        {
            ["NetWarden:PipeName"] = _pipeName,
            ["NetWarden:RestrictPipeToAdmins"] = "false",
            ["NetWarden:DataDirectory"] = _dir.Path,
            ["NetWarden:EnableTrafficSource"] = "false",
            ["NetWarden:EnablePacketFilter"] = "false",
        });
        await _host.StartAsync();
        _client = new ServiceClient(_pipeName);
        await _client.ConnectAsync(TimeSpan.FromSeconds(5));
    }

    public async Task DisposeAsync()
    {
        await _client.DisposeAsync();
        await _host.StopAsync();
        _host.Dispose();
        _dir.Dispose();
    }

    [Fact]
    public async Task Service_info_describes_the_running_host()
    {
        var info = await _client.RequestAsync<ServiceInfo>(Methods.ServiceInfo);

        Assert.NotNull(info);
        Assert.Equal(Environment.ProcessId, info.ProcessId);
        Assert.Equal("0.6.0", info.Version);
        Assert.False(info.IsWindowsService);
        Assert.Equal(Environment.MachineName, info.MachineName);
        Assert.True(info.StartedAt <= DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task Settings_get_returns_defaults_when_no_file()
    {
        var settings = await _client.RequestAsync<ServiceSettings>(Methods.SettingsGet);

        Assert.NotNull(settings);
        Assert.True(settings.IsLimiterEnabled);
    }

    [Fact]
    public async Task Apps_resolve_identifies_a_process()
    {
        var app = await _client.RequestAsync<AppInfo>(Methods.AppsResolve, new ResolveAppRequest(Environment.ProcessId));

        Assert.NotNull(app);
        Assert.Equal(AppKind.Desktop, app.Kind);
    }

    [Fact]
    public async Task Apps_resolve_returns_null_for_dead_pid()
    {
        Assert.Null(await _client.RequestAsync<AppInfo>(Methods.AppsResolve, new ResolveAppRequest(int.MaxValue - 2)));
    }

    [Fact]
    public async Task Activity_snapshot_lists_this_process_and_its_sockets()
    {
        using var pair = await Monitoring.LoopbackPair.CreateAsync();

        var snapshot = await _client.RequestAsync<ActivitySnapshot>(Methods.ActivityGet);
        // activity.get may return the startup snapshot; wait for a tick that sees the new sockets.
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!HasListener(snapshot, pair.ListenPort) && DateTime.UtcNow < deadline)
        {
            await Task.Delay(200);
            snapshot = await _client.RequestAsync<ActivitySnapshot>(Methods.ActivityGet);
        }

        Assert.True(HasListener(snapshot, pair.ListenPort), "Own listening socket not in snapshot.");
        var me = snapshot!.Apps.Single(a => a.ProcessIds.Contains(Environment.ProcessId));
        Assert.True(me.IsOnline);
        Assert.Contains(me.Connections, c => c.Kind == ConnectionKind.Connect && c.RemotePort == pair.ListenPort);
        Assert.Contains(me.Connections, c => c.Kind == ConnectionKind.Accept && c.LocalPort == pair.ListenPort);
    }

    private static bool HasListener(ActivitySnapshot? snapshot, int port) =>
        snapshot?.Apps.Any(a => a.Connections.Any(c => c.Kind == ConnectionKind.Listen && c.LocalPort == port)) == true;

    [Fact]
    public async Task Snapshot_events_are_pushed_to_clients()
    {
        var received = new TaskCompletionSource<ActivitySnapshot?>();
        _client.EventReceived += (method, payload) =>
        {
            if (method == Events.ActivitySnapshot)
                received.TrySetResult(IpcJson.FromElement<ActivitySnapshot>(payload));
        };

        var snapshot = await received.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.NotNull(snapshot);
        Assert.NotEmpty(snapshot.Apps);
    }

    [Fact]
    public async Task Reset_totals_succeeds()
    {
        Assert.True(await _client.RequestAsync<bool>(Methods.ActivityResetTotals));
    }

    [Monitoring.AdminFact]
    public async Task Kill_connection_resets_a_tcp_connection()
    {
        using var pair = await Monitoring.LoopbackPair.CreateAsync();

        bool ok = await _client.RequestAsync<bool>(Methods.ConnectionsKill, new KillConnectionRequest(
            TransportProtocol.Tcp, "127.0.0.1", pair.ClientPort, "127.0.0.1", pair.ListenPort));

        Assert.True(ok);
    }

    [Fact]
    public async Task Kill_udp_is_rejected_with_a_clear_error()
    {
        var ex = await Assert.ThrowsAsync<IpcRemoteException>(() => _client.RequestAsync<bool>(Methods.ConnectionsKill,
            new KillConnectionRequest(TransportProtocol.Udp, "127.0.0.1", 1, "127.0.0.1", 2)));
        Assert.Contains("Only TCP", ex.RemoteMessage);
    }

    [Fact]
    public async Task Reverse_dns_rejects_invalid_address()
    {
        await Assert.ThrowsAsync<IpcRemoteException>(() =>
            _client.RequestAsync<string>(Methods.DnsReverse, new ReverseDnsRequest("not-an-ip")));
    }

    [Fact]
    public async Task Rules_round_trip_over_ipc_and_changes_are_broadcast()
    {
        var changed = new TaskCompletionSource<long>();
        _client.EventReceived += (method, payload) =>
        {
            if (method == Events.RulesChanged)
                changed.TrySetResult(payload!.Value.GetInt64());
        };

        var initial = await _client.RequestAsync<RulesSnapshot>(Methods.RulesGet);
        Assert.Equal(PredefinedFilters.All.Count, initial!.Filters.Count);

        var filter = await _client.RequestAsync<FilterDefinition>(Methods.FiltersEnsureForApp,
            new EnsureAppFilterRequest(@"c:\apps\game.exe", "Game"));
        var rule = await _client.RequestAsync<RuleDefinition>(Methods.RulesSave,
            new RuleDefinition(Guid.Empty, filter!.Id, RuleKind.Firewall, RuleDirection.Out, Action: FirewallAction.Deny));

        long generation = await changed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(generation > initial.Generation);

        var decision = await _client.RequestAsync<FlowDecision>(Methods.RulesEvaluate, new EvaluateRequest(
            @"c:\apps\game.exe", @"c:\apps\game.exe", 1, TransportProtocol.Tcp, ConnectionKind.Connect,
            "192.168.1.2", 50000, "8.8.8.8", 443));
        Assert.Equal(FirewallAction.Deny, decision!.Firewall);
        Assert.Equal(rule!.Id, decision.FirewallRuleId);

        Assert.True(await _client.RequestAsync<bool>(Methods.RulesSetEnabled, new SetRuleEnabledRequest(rule.Id, false)));
        Assert.True(await _client.RequestAsync<bool>(Methods.RulesDelete, new DeleteRequest(rule.Id)));
        Assert.True(await _client.RequestAsync<bool>(Methods.FiltersDelete, new DeleteRequest(filter.Id)));
        Assert.True(File.Exists(_dir.File("rules.json")));
    }

    [Fact]
    public async Task Invalid_rule_is_rejected_with_reason()
    {
        var ex = await Assert.ThrowsAsync<IpcRemoteException>(() => _client.RequestAsync<RuleDefinition>(Methods.RulesSave,
            new RuleDefinition(Guid.Empty, PredefinedFilters.Internet, RuleKind.Limit, RuleDirection.In, LimitBytesPerSecond: 0)));
        Assert.Contains("greater than zero", ex.RemoteMessage);
    }

    [Fact]
    public async Task Settings_update_persists_and_is_broadcast()
    {
        var changed = new TaskCompletionSource<ServiceSettings?>();
        _client.EventReceived += (method, payload) =>
        {
            if (method == Events.SettingsChanged)
                changed.TrySetResult(IpcJson.FromElement<ServiceSettings>(payload));
        };
        var settings = (await _client.RequestAsync<ServiceSettings>(Methods.SettingsGet))!;
        settings.DefaultFirewallOut = FirewallAction.Ask;

        await _client.RequestAsync<ServiceSettings>(Methods.SettingsUpdate, settings);

        Assert.Equal(FirewallAction.Ask, (await changed.Task.WaitAsync(TimeSpan.FromSeconds(5)))!.DefaultFirewallOut);
        Assert.Equal(FirewallAction.Ask, (await _client.RequestAsync<ServiceSettings>(Methods.SettingsGet))!.DefaultFirewallOut);
        Assert.True(File.Exists(_dir.File("settings.json")));
    }

    [Fact]
    public async Task Stopping_host_disconnects_client()
    {
        var disconnected = new TaskCompletionSource();
        _client.Disconnected += _ => disconnected.TrySetResult();

        await _host.StopAsync();

        await disconnected.Task.WaitAsync(TimeSpan.FromSeconds(5));
    }

    private void RecordTraffic(long bytesIn, DateTimeOffset time)
    {
        var recorder = _host.Services.GetRequiredService<NetWarden.Core.Stats.StatsRecorder>();
        var app = new AppInfo(@"c:\apps\game.exe", AppKind.Desktop, @"c:\apps\game.exe", "Game", null, null, null, [], null);
        recorder.Add([new NetWarden.Core.Monitoring.FlowTraffic(app, Environment.ProcessId, TransportProtocol.Tcp, ConnectionKind.Connect,
            System.Net.IPAddress.Parse("192.168.1.2"), 50000, System.Net.IPAddress.Parse("8.8.8.8"), 443, bytesIn, 10, time)]);
    }

    [Fact]
    public async Task Stats_round_trip_over_ipc()
    {
        var now = DateTimeOffset.UtcNow;
        RecordTraffic(1234, now);
        var query = new StatsQuery(now.AddHours(-1), now.AddMinutes(1), StatsBucket.Minute, StatsGroupBy.Country,
            TimeZoneId: TimeZoneInfo.Local.Id);

        // Collected traffic is written before the query runs.
        var result = await _client.RequestAsync<StatsResult>(Methods.StatsQuery, query);
        Assert.Equal(1234, result!.TotalIn);
        Assert.Equal(10, result.TotalOut);
        Assert.Equal(("US", 1234L), (result.Rows[0].Key, result.Rows[0].In));
        Assert.Equal(1234, result.Series.Sum(p => p.In));

        var info = await _client.RequestAsync<StatsInfo>(Methods.StatsInfo);
        Assert.Equal((1L, 1), (info!.Records, info.Apps));
        Assert.Equal(_dir.File("stats.db"), info.Path);
        Assert.NotNull(info.GeoDatabaseDate);

        Assert.Equal(1, await _client.RequestAsync<long>(Methods.StatsDelete, new StatsDeleteRequest(AppId: @"c:\apps\game.exe")));
        var compacted = await _client.RequestAsync<StatsInfo>(Methods.StatsCompact);
        Assert.Equal((0L, 0), (compacted!.Records, compacted.Apps));
    }

    [Fact]
    public async Task Stats_query_rejects_an_empty_range()
    {
        var now = DateTimeOffset.UtcNow;
        var ex = await Assert.ThrowsAsync<IpcRemoteException>(() => _client.RequestAsync<StatsResult>(Methods.StatsQuery,
            new StatsQuery(now, now, StatsBucket.Hour, StatsGroupBy.App)));
        Assert.Contains("after its start", ex.RemoteMessage);
    }

    [Fact]
    public async Task Collected_stats_are_written_when_the_service_stops()
    {
        var now = DateTimeOffset.UtcNow;
        RecordTraffic(77, now);

        await _host.StopAsync();
        _host.Services.GetRequiredService<NetWarden.Core.Stats.StatsDatabase>().Dispose();

        using var db = new NetWarden.Core.Stats.StatsDatabase(_dir.File("stats.db"));
        Assert.Equal(1, db.Info(null).Records);
    }
}
