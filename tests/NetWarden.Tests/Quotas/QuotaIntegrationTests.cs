using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NetWarden.Core.Apps;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Packets;
using NetWarden.Core.Quotas;
using NetWarden.Core.Rules;
using NetWarden.Core.Stats;
using NetWarden.Service;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;
using NetWarden.Shared.Storage;
using NetWarden.Tests.Stats;

namespace NetWarden.Tests.Quotas;

public sealed class StatsFlowsTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly StatsDatabase _db;

    public StatsFlowsTests() => _db = new StatsDatabase(_dir.File("stats.db"));

    public void Dispose()
    {
        _db.Dispose();
        _dir.Dispose();
    }

    [Fact]
    public void Flows_sums_a_range_per_app_and_host()
    {
        var noon = StatsData.Noon;
        _db.Write(
        [
            StatsData.Record(noon.AddHours(-2), StatsData.Browser, 1000, 1000),
            StatsData.Record(noon, StatsData.Browser, 100, 10, host: "dns.google"),
            StatsData.Record(noon.AddMinutes(1), StatsData.Browser, 200, 20),
            StatsData.Record(noon, StatsData.Game, 5, 6, address: "1.1.1.1", port: 53, protocol: TransportProtocol.Udp),
        ]);

        var rows = _db.Flows(noon, noon.AddHours(1)).OrderBy(r => r.AppId).ToList();

        Assert.Equal(2, rows.Count);
        var browser = rows[0];
        Assert.Equal((StatsData.Browser.Id, StatsData.Browser.Path, "8.8.8.8", "dns.google", 443), (browser.AppId, browser.AppPath, browser.Address, browser.HostName, browser.Port));
        Assert.Equal((300L, 30L), (browser.In, browser.Out));
        Assert.Equal(("S-1-5-21-1", TransportProtocol.Tcp), (browser.UserSid, browser.Protocol));
        Assert.Equal((TransportProtocol.Udp, 53, 5L, 6L), (rows[1].Protocol, rows[1].Port, rows[1].In, rows[1].Out));
    }

    [Fact]
    public void Flows_without_a_start_reads_from_the_beginning()
    {
        _db.Write([StatsData.Record(StatsData.Noon.AddYears(-3), StatsData.Browser, 100)]);

        Assert.Equal(100, Assert.Single(_db.Flows(null, StatsData.Noon)).In);
    }
}

public sealed class QuotaConnectionFinderTests : IDisposable
{
    private static readonly AppInfo Browser = StatsData.Browser;
    private static readonly AppInfo Game = StatsData.Game;
    private readonly TempDir _dir = new();
    private readonly RuleRepository _rules;
    private readonly FlowContextFactory _flows;

    public QuotaConnectionFinderTests()
    {
        _rules = new RuleRepository(new JsonFileStore<RulesDocument>(_dir.File("rules.json")), new ZoneClassifier([]), TimeProvider.System);
        var apps = new Dictionary<int, AppInfo> { [100] = Browser, [200] = Game };
        _flows = new FlowContextFactory(pid => apps.GetValueOrDefault(pid), _ => null, new DnsMap());
    }

    public void Dispose() => _dir.Dispose();

    private static SocketEntry Tcp(int pid, string remote = "8.8.8.8", TcpState state = TcpState.Established) =>
        new(TransportProtocol.Tcp, IPAddress.Parse("192.168.1.14"), 50000, IPAddress.Parse(remote), 443, state, pid);

    [Fact]
    public void Finds_established_ipv4_tcp_connections_of_the_filter_only()
    {
        var filter = _rules.EnsureAppFilter(Browser.Id, "Browser");
        var match = Tcp(100);
        SocketEntry[] sockets =
        [
            match,
            Tcp(200),
            Tcp(100, state: TcpState.TimeWait),
            Tcp(100, "2001:4860:4860::8888"),
            Tcp(100, "127.0.0.1"),
            new(TransportProtocol.Udp, IPAddress.Any, 5353, null, 0, default, 100),
        ];

        var found = BlockedConnectionSweeper.FindMatching(sockets, _rules.Current, filter.Id, _flows);

        Assert.Equal([match], found);
    }
}

/// <summary>The real service host, with quotas driven over the pipe.</summary>
public sealed class QuotaServiceTests : IAsyncLifetime
{
    private readonly string _pipe = TestPipes.NewName();
    private readonly TempDir _dir = new();
    private IHost _host = null!;
    private ServiceClient _client = null!;

    public async Task InitializeAsync()
    {
        _host = ServiceHost.Build([], new Dictionary<string, string?>
        {
            ["NetWarden:PipeName"] = _pipe,
            ["NetWarden:RestrictPipeToAdmins"] = "false",
            ["NetWarden:DataDirectory"] = _dir.Path,
            ["NetWarden:EnableTrafficSource"] = "false",
            ["NetWarden:EnablePacketFilter"] = "false",
        });
        await _host.StartAsync();
        _client = new ServiceClient(_pipe);
        await _client.ConnectAsync(TimeSpan.FromSeconds(5));
    }

    public async Task DisposeAsync()
    {
        await _client.DisposeAsync();
        await _host.StopAsync();
        _host.Dispose();
        _dir.Dispose();
    }

    private async Task<(RuleDefinition Quota, AppInfo App)> CreateQuotaAsync(long bytes, bool alert = false)
    {
        var app = (await _client.RequestAsync<AppInfo>(Methods.AppsResolve, new ResolveAppRequest(Environment.ProcessId)))!;
        var filter = (await _client.RequestAsync<FilterDefinition>(Methods.FiltersEnsureForApp, new EnsureAppFilterRequest(app.Id, app.DisplayName)))!;
        var quota = (await _client.RequestAsync<RuleDefinition>(Methods.RulesSave,
            new RuleDefinition(Guid.Empty, filter.Id, RuleKind.Quota, RuleDirection.Both, QuotaBytes: bytes, OverflowAlert: alert)))!;
        return (quota, app);
    }

    private void Traffic(AppInfo app, long bytes) =>
        _host.Services.GetRequiredService<QuotaTracker>().Add(
        [
            new FlowTraffic(app, Environment.ProcessId, TransportProtocol.Tcp, ConnectionKind.Connect, IPAddress.Parse("192.168.1.14"), 50000,
                IPAddress.Parse("8.8.8.8"), 443, bytes, 0, DateTimeOffset.UtcNow),
        ]);

    private async Task<QuotaStatus> StatusAsync(Guid id) =>
        (await _client.RequestAsync<List<QuotaStatus>>(Methods.QuotasStatus))!.Single(s => s.RuleId == id);

    [Fact]
    public async Task Status_and_reset_work_over_the_pipe()
    {
        var (quota, app) = await CreateQuotaAsync(1000);
        Traffic(app, 400);

        Assert.Equal(400, (await StatusAsync(quota.Id)).Used);

        Assert.True(await _client.RequestAsync<bool>(Methods.QuotasReset, new QuotaRequest(quota.Id)));
        Assert.Equal(0, (await StatusAsync(quota.Id)).Used);
    }

    [Fact]
    public async Task Exceeding_a_quota_with_an_alert_notifies_clients()
    {
        var got = new TaskCompletionSource<QuotaAlert?>(TaskCreationOptions.RunContinuationsAsynchronously);
        _client.EventReceived += (method, payload) =>
        {
            if (method == Events.QuotaAlert)
                got.TrySetResult(IpcJson.FromElement<QuotaAlert>(payload));
        };
        var (quota, app) = await CreateQuotaAsync(1000, alert: true);

        Traffic(app, 1000);

        var alert = await got.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal((quota.Id, 1000L), (alert!.RuleId, alert.Limit));
    }

    [Fact]
    public async Task Exceeding_a_quota_without_an_alert_stays_silent()
    {
        bool alerted = false;
        _client.EventReceived += (method, _) => alerted |= method == Events.QuotaAlert;
        var (quota, app) = await CreateQuotaAsync(1000);

        Traffic(app, 1000);
        for (int i = 0; i < 100 && (await StatusAsync(quota.Id)).OverflowedAt is null; i++)
            await Task.Delay(50);

        Assert.NotNull((await StatusAsync(quota.Id)).OverflowedAt);
        Assert.False(alerted);
    }

    [Fact]
    public async Task Init_from_stats_reads_the_stats_database()
    {
        var (quota, app) = await CreateQuotaAsync(100_000);
        _host.Services.GetRequiredService<StatsDatabase>().Write(
            [StatsData.Record(DateTimeOffset.UtcNow.AddMinutes(-5), app, 700, 50)]);

        Assert.True(await _client.RequestAsync<bool>(Methods.QuotasInitFromStats, new QuotaRequest(quota.Id)));

        Assert.Equal(750, (await StatusAsync(quota.Id)).Used);
    }

    [Fact]
    public async Task Counters_are_saved_when_the_service_stops()
    {
        var (quota, app) = await CreateQuotaAsync(1000);
        Traffic(app, 400);

        await _host.StopAsync();

        string json = await File.ReadAllTextAsync(Path.Combine(_dir.Path, "quotas.json"));
        Assert.Contains(quota.Id.ToString(), json);
        Assert.Contains("400", json);
    }
}
