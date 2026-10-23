using Microsoft.Extensions.Time.Testing;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Packets;
using NetWarden.Core.Rules;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Storage;

namespace NetWarden.Tests.Packets;

public sealed class LimiterTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 10, 23, 12, 0, 0, TimeSpan.Zero));
    private readonly RuleRepository _rules;
    private readonly Dictionary<FlowId, int> _owners = [];
    private readonly Limiter _limiter;

    private static readonly AppInfo Browser = new(@"c:\apps\browser.exe", AppKind.Desktop, @"c:\apps\browser.exe", "Browser", null, null, null, [], null);
    private static readonly AppInfo Game = new(@"c:\apps\game.exe", AppKind.Desktop, @"c:\apps\game.exe", "Game", null, null, null, [], null);

    private sealed class Owners(Dictionary<FlowId, int> map) : IFlowOwnerLookup
    {
        public int Lookups;
        public int? FindOwner(in PacketInfo packet)
        {
            Lookups++;
            return map.TryGetValue(packet.Flow, out int pid) ? pid : null;
        }
    }

    private readonly Owners _lookup;

    public LimiterTests()
    {
        _rules = new RuleRepository(new JsonFileStore<RulesDocument>(_dir.File("rules.json")), new ZoneClassifier([]), _time);
        var contexts = new FlowContextFactory(pid => pid switch { 100 => Browser, 200 => Game, _ => null }, _ => null, new DnsMap());
        _lookup = new Owners(_owners);
        _limiter = new Limiter(() => _rules.Current, _lookup, contexts, _time);
    }

    public void Dispose() => _dir.Dispose();

    private PacketVerdict Send(byte[] raw, bool outbound = true, int? owner = 100)
    {
        var info = PacketParser.Parse(raw, outbound)!.Value;
        if (owner is { } pid)
            _owners[info.Flow] = pid;
        return _limiter.Process(info, raw, Raw.Address(outbound));
    }

    /// <summary>An outbound TCP packet carrying <paramref name="size"/> payload bytes (what limits count).</summary>
    private static byte[] Up(int size, int localPort = 50000, string remote = "1.1.1.1") =>
        Raw.Tcp4("192.168.1.14", localPort, remote, 443, flags: 0x18, payload: size);

    /// <summary>An inbound TCP packet carrying <paramref name="size"/> payload bytes.</summary>
    private static byte[] Down(int size, int localPort = 50000) =>
        Raw.Tcp4("1.1.1.1", 443, "192.168.1.14", localPort, flags: 0x18, payload: size);

    private static int Payload(HeldPacket p) => p.Data.Length - 40;

    private RuleDefinition Limit(long bytesPerSecond, RuleDirection dir, AppInfo? app = null, FilterPerType per = FilterPerType.None)
    {
        app ??= Browser;
        Guid filterId = per == FilterPerType.None
            ? _rules.EnsureAppFilter(app.Id, app.DisplayName).Id
            : _rules.SaveFilter(new FilterDefinition(Guid.Empty, $"{app.DisplayName} per {per}", FilterType.Filter, per,
                [new FilterFunction(FilterFunctionKind.AppId, true, [app.Id])], [])).Id;
        return _rules.SaveRule(new RuleDefinition(Guid.Empty, filterId, RuleKind.Limit, dir, LimitBytesPerSecond: bytesPerSecond));
    }

    [Fact]
    public void Unlimited_traffic_passes()
    {
        Assert.Equal(PacketVerdict.Pass, Send(Up(1500)));
        Assert.Equal(PacketVerdict.Pass, Send(Down(1500), outbound: false));
        Assert.Equal(PacketVerdict.Pass, Send(Up(1500), owner: null));
    }

    [Fact]
    public void Packets_over_the_burst_wait_until_tokens_refill()
    {
        Limit(10_000, RuleDirection.Out);

        Assert.Equal(PacketVerdict.Pass, Send(Up(1000)));  // burst is 1514 bytes
        Assert.Equal(PacketVerdict.Hold, Send(Up(1000)));  // 486 bytes short: 48.6 ms

        Assert.Empty(_limiter.TakeDue(out var wait));
        Assert.InRange(wait!.Value.TotalMilliseconds, 48, 50);
        _time.Advance(TimeSpan.FromMilliseconds(49));
        Assert.Single(_limiter.TakeDue(out wait));
        Assert.Null(wait);
        Assert.Equal(1, _limiter.Delayed);
    }

    [Fact]
    public void Limit_applies_only_to_its_direction()
    {
        Limit(1_000, RuleDirection.In);

        for (int i = 0; i < 5; i++)
            Assert.Equal(PacketVerdict.Pass, Send(Up(1500)));
        Assert.Equal(PacketVerdict.Pass, Send(Down(1500), outbound: false));
        Assert.Equal(PacketVerdict.Hold, Send(Down(1500), outbound: false));
    }

    [Fact]
    public void Packets_without_payload_are_free()
    {
        Limit(1_000, RuleDirection.Out);

        for (int i = 0; i < 50; i++)
            Assert.Equal(PacketVerdict.Pass, Send(Up(0)));
    }

    [Fact]
    public void Backlog_longer_than_the_queue_limit_drops()
    {
        Limit(10_000, RuleDirection.Out);

        // 500 ms of backlog at 10 KB/s is 5000 bytes.
        var verdicts = Enumerable.Range(0, 10).Select(_ => Send(Up(1000))).ToList();

        Assert.Equal(PacketVerdict.Pass, verdicts[0]);
        Assert.All(verdicts.Skip(1).Take(5), v => Assert.Equal(PacketVerdict.Hold, v));
        Assert.All(verdicts.Skip(7), v => Assert.Equal(PacketVerdict.Drop, v));
        Assert.True(_limiter.Dropped >= 3);
    }

    [Theory]
    [InlineData(10_000)]
    [InlineData(100_000)]
    [InlineData(1_000_000)]
    public void Sustained_throughput_matches_the_limit(long rate)
    {
        Limit(rate, RuleDirection.Out);
        long sent = 0;
        int localPort = 50000;
        // A greedy sender: one 1500-byte packet every 0.5 ms (3 MB/s offered), for 10 s.
        for (int tick = 0; tick < 20_000; tick++)
        {
            if (Send(Up(1500, localPort)) == PacketVerdict.Pass)
                sent += 1500;
            _time.Advance(TimeSpan.FromMilliseconds(0.5));
            sent += _limiter.TakeDue(out _).Sum(Payload);
        }

        double perSecond = sent / 10.0;
        Assert.InRange(perSecond, rate * 0.97, rate * 1.03 + 1514 / 10.0);
    }

    [Fact]
    public void Flows_of_one_app_share_a_bucket()
    {
        Limit(10_000, RuleDirection.Out);

        Assert.Equal(PacketVerdict.Pass, Send(Up(1000, 50000)));
        Assert.Equal(PacketVerdict.Hold, Send(Up(1000, 50001)));
    }

    [Fact]
    public void Per_connection_limits_give_each_flow_its_own_bucket()
    {
        Limit(10_000, RuleDirection.Out, per: FilterPerType.PerConnection);

        Assert.Equal(PacketVerdict.Pass, Send(Up(1000, 50000)));
        Assert.Equal(PacketVerdict.Pass, Send(Up(1000, 50001)));
        Assert.Equal(PacketVerdict.Hold, Send(Up(1000, 50000)));
    }

    [Fact]
    public void Per_app_limits_give_each_app_its_own_bucket()
    {
        var filter = _rules.SaveFilter(new FilterDefinition(Guid.Empty, "Every app", FilterType.Filter, FilterPerType.PerApp, [], []));
        _rules.SaveRule(new RuleDefinition(Guid.Empty, filter.Id, RuleKind.Limit, RuleDirection.Out, LimitBytesPerSecond: 10_000));

        Assert.Equal(PacketVerdict.Pass, Send(Up(1000, 50000), owner: 100));
        Assert.Equal(PacketVerdict.Pass, Send(Up(1000, 50001), owner: 200));
        Assert.Equal(PacketVerdict.Hold, Send(Up(1000, 50002), owner: 100));
    }

    [Fact]
    public void Every_matching_limit_applies_and_the_tightest_wins()
    {
        Limit(1_000_000, RuleDirection.Out);
        var all = _rules.SaveFilter(new FilterDefinition(Guid.Empty, "All", FilterType.Filter, FilterPerType.None, [], []));
        _rules.SaveRule(new RuleDefinition(Guid.Empty, all.Id, RuleKind.Limit, RuleDirection.Out, LimitBytesPerSecond: 10_000));

        Assert.Equal(PacketVerdict.Pass, Send(Up(1000)));
        Assert.Equal(PacketVerdict.Hold, Send(Up(1000)));
    }

    [Fact]
    public void Local_network_is_not_limited_by_default_ignore_rules()
    {
        var all = _rules.SaveFilter(new FilterDefinition(Guid.Empty, "All", FilterType.Filter, FilterPerType.None, [], []));
        _rules.SaveRule(new RuleDefinition(Guid.Empty, all.Id, RuleKind.Limit, RuleDirection.Out, LimitBytesPerSecond: 1_000));

        for (int i = 0; i < 5; i++)
            Assert.Equal(PacketVerdict.Pass, Send(Up(1500, remote: "192.168.1.1")));
        Assert.Equal(PacketVerdict.Pass, Send(Up(1500, remote: "1.1.1.1")));
        Assert.Equal(PacketVerdict.Hold, Send(Up(1500, remote: "1.1.1.1")));
    }

    [Fact]
    public void Ignore_rule_with_higher_weight_lifts_a_limit()
    {
        Limit(1_000, RuleDirection.Both);
        var app = _rules.EnsureAppFilter(Browser.Id, "Browser");
        _rules.SaveRule(new RuleDefinition(Guid.Empty, app.Id, RuleKind.Ignore, RuleDirection.Out, Weight: 10, IgnoreLimit: true));

        for (int i = 0; i < 5; i++)
            Assert.Equal(PacketVerdict.Pass, Send(Up(1500)));
        Assert.Equal(PacketVerdict.Pass, Send(Down(1500), outbound: false));
        Assert.Equal(PacketVerdict.Hold, Send(Down(1500), outbound: false));
    }

    [Fact]
    public void Undelayed_packet_waits_behind_its_own_flow_but_not_others()
    {
        Limit(10_000, RuleDirection.Out, per: FilterPerType.PerConnection);
        Send(Up(1514, 50000));
        Assert.Equal(PacketVerdict.Hold, Send(Up(1000, 50000)));

        _time.Advance(TimeSpan.FromSeconds(1)); // bucket full again, packet above still queued
        Assert.Equal(PacketVerdict.Hold, Send(Up(100, 50000)));
        Assert.Equal(PacketVerdict.Pass, Send(Up(100, 50001)));

        var due = _limiter.TakeDue(out _);
        Assert.Equal([1000, 100], due.Select(Payload));
    }

    [Fact]
    public void Rule_changes_take_effect_on_existing_flows()
    {
        var rule = Limit(1_000, RuleDirection.Out);
        Send(Up(1500));
        Assert.Equal(PacketVerdict.Hold, Send(Up(1500)));

        _rules.DeleteRule(rule.Id);

        Assert.Equal(PacketVerdict.Pass, Send(Up(1500)));
    }

    [Fact]
    public void Owner_is_looked_up_once_per_flow()
    {
        Limit(1_000_000, RuleDirection.Out);
        for (int i = 0; i < 20; i++)
            Send(Up(100));

        Assert.Equal(1, _lookup.Lookups);
    }

    [Fact]
    public void Reset_returns_queued_packets_in_order()
    {
        Limit(10_000, RuleDirection.Out);
        Send(Up(1000));
        Send(Up(1001));
        Send(Up(1002));

        var rest = _limiter.Reset();

        Assert.Equal([1001, 1002], rest.Select(Payload));
        Assert.Equal(0, _limiter.QueuedBytes);
    }

    [Fact]
    public void Pump_sends_due_packets_on_its_own()
    {
        var limiter = new Limiter(() => _rules.Current, _lookup, new FlowContextFactory(_ => Browser, _ => null, new DnsMap()), TimeProvider.System);
        Limit(10_000, RuleDirection.Out);
        var sent = new System.Collections.Concurrent.ConcurrentQueue<HeldPacket>();
        using (var pump = new LimiterPump(limiter, ps => { foreach (var p in ps) sent.Enqueue(p); }))
        {
            var raw = Up(1500);
            var info = PacketParser.Parse(raw, true)!.Value;
            _owners[info.Flow] = 100;
            for (int i = 0; i < 4; i++)
                limiter.Process(info, raw, Raw.Address(true));

            var deadline = DateTime.UtcNow.AddSeconds(2);
            while (sent.Count < 3 && DateTime.UtcNow < deadline)
                Thread.Sleep(5);
            Assert.Equal(3, sent.Count); // the first one passed straight through; three waited
        }
    }
}
