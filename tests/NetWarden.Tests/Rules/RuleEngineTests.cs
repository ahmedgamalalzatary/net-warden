using System.Net;
using Microsoft.Extensions.Time.Testing;
using NetWarden.Core.Rules;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Storage;

namespace NetWarden.Tests.Rules;

internal static class Flows
{
    public static FlowContext Make(
        string appId = "c:\\apps\\browser.exe", string remote = "8.8.8.8", int remotePort = 443,
        ConnectionKind kind = ConnectionKind.Connect, TransportProtocol protocol = TransportProtocol.Tcp,
        string local = "192.168.1.14", int localPort = 50000, int pid = 100, string? host = null,
        string? userSid = null, string? userName = null) =>
        new(appId, appId, pid, protocol, kind, IPAddress.Parse(local), localPort, IPAddress.Parse(remote), remotePort,
            host, userSid, userName);
}

public class FilterFunctionTests
{
    private static readonly ZoneClassifier Zones = new([]);

    private static bool Eval(FilterFunction f, FlowContext flow) => FilterCompiler.Compile(f, Zones)(flow);

    [Theory]
    [InlineData(FilterFunctionKind.AppId, "C:\\APPS\\BROWSER.EXE", true)]
    [InlineData(FilterFunctionKind.AppId, "c:\\apps\\other.exe", false)]
    [InlineData(FilterFunctionKind.PathEquals, "*\\browser.exe", true)]
    [InlineData(FilterFunctionKind.PathContains, "\\APPS\\", true)]
    [InlineData(FilterFunctionKind.RemoteAddressInRange, "8.0.0.0/8", true)]
    [InlineData(FilterFunctionKind.LocalAddressInRange, "192.168.1.0/24", true)]
    [InlineData(FilterFunctionKind.RemotePortInRange, "400-500", true)]
    [InlineData(FilterFunctionKind.LocalPortInRange, "1-1000", false)]
    [InlineData(FilterFunctionKind.Protocol, "tcp", true)]
    [InlineData(FilterFunctionKind.Protocol, "UDP", false)]
    [InlineData(FilterFunctionKind.ProcessId, "100", true)]
    [InlineData(FilterFunctionKind.DomainName, "*.google.com", true)]
    [InlineData(FilterFunctionKind.User, "S-1-5-21-1", true)]
    [InlineData(FilterFunctionKind.User, "pc\\alice", true)]
    public void Function_kinds_match_their_field(FilterFunctionKind kind, string value, bool expected)
    {
        var flow = Flows.Make(host: "dns.google.com", userSid: "S-1-5-21-1", userName: "PC\\alice");

        Assert.Equal(expected, Eval(new FilterFunction(kind, true, [value]), flow));
        Assert.Equal(!expected, Eval(new FilterFunction(kind, false, [value]), flow));
    }

    [Fact]
    public void Any_value_matches()
    {
        var f = new FilterFunction(FilterFunctionKind.RemotePortInRange, true, ["80", "443"]);
        Assert.True(Eval(f, Flows.Make(remotePort: 443)));
        Assert.False(Eval(f, Flows.Make(remotePort: 8080)));
    }

    [Fact]
    public void Domain_filter_does_not_match_unknown_host()
    {
        Assert.False(Eval(new FilterFunction(FilterFunctionKind.DomainName, true, ["*"]), Flows.Make(host: null)));
    }

    [Theory]
    [InlineData("8.8.8.8", FilterFunctionKind.IsInternet)]
    [InlineData("192.168.1.1", FilterFunctionKind.IsLocalNetwork)]
    [InlineData("127.0.0.1", FilterFunctionKind.IsLoopback)]
    public void Zone_functions(string remote, FilterFunctionKind zone)
    {
        foreach (var kind in new[] { FilterFunctionKind.IsInternet, FilterFunctionKind.IsLocalNetwork, FilterFunctionKind.IsLoopback })
            Assert.Equal(kind == zone, Eval(new FilterFunction(kind), Flows.Make(remote: remote)));
    }
}

public sealed class RuleRepositoryTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 10, 23, 12, 0, 0, TimeSpan.Zero));
    private RuleRepository _repo;

    public RuleRepositoryTests()
    {
        _repo = NewRepo();
    }

    public void Dispose() => _dir.Dispose();

    private RuleRepository NewRepo() =>
        new(new JsonFileStore<RulesDocument>(_dir.File("rules.json")), new ZoneClassifier([]), _time);

    private FlowDecision Eval(FlowContext flow, FirewallAction defaultIn = FirewallAction.Allow, FirewallAction defaultOut = FirewallAction.Allow) =>
        _repo.Current.Evaluate(flow, defaultIn, defaultOut, _time.GetUtcNow());

    private FilterDefinition AppFilter(string appId = "c:\\apps\\browser.exe", FilterPerType perType = FilterPerType.None)
    {
        var f = _repo.EnsureAppFilter(appId, Path.GetFileNameWithoutExtension(appId));
        return perType == FilterPerType.None ? f : _repo.SaveFilter(f with { PerType = perType });
    }

    private RuleDefinition Limit(Guid filter, long bps, RuleDirection dir = RuleDirection.In, int weight = 0) =>
        _repo.SaveRule(new RuleDefinition(Guid.Empty, filter, RuleKind.Limit, dir, LimitBytesPerSecond: bps, Weight: weight));

    private RuleDefinition Block(Guid filter, FirewallAction action, RuleDirection dir = RuleDirection.Both, int weight = 0) =>
        _repo.SaveRule(new RuleDefinition(Guid.Empty, filter, RuleKind.Firewall, dir, Action: action, Weight: weight));

    [Fact]
    public void First_run_creates_predefined_filters_and_default_ignore_rules()
    {
        var snapshot = _repo.Snapshot();

        Assert.Equal(PredefinedFilters.All.Select(f => f.Id), snapshot.Filters.Select(f => f.Id));
        Assert.Equal(2, snapshot.Rules.Count);
        Assert.All(snapshot.Rules, r => Assert.True(r.Rule.IgnoreLimit));
        Assert.True(File.Exists(_dir.File("rules.json")));
    }

    [Fact]
    public void Changes_persist_and_reload()
    {
        var filter = AppFilter();
        var rule = Limit(filter.Id, 1000);

        _repo = NewRepo();

        var snapshot = _repo.Snapshot();
        Assert.Contains(snapshot.Filters, f => f.Id == filter.Id);
        Assert.Contains(snapshot.Rules, r => r.Rule.Id == rule.Id && r.Rule.LimitBytesPerSecond == 1000);
        Assert.Equal(PredefinedFilters.DefaultRules.Count + 1, snapshot.Rules.Count);
    }

    [Fact]
    public void Deleted_default_rules_are_not_recreated_on_restart()
    {
        foreach (var r in _repo.Snapshot().Rules.ToList())
            _repo.DeleteRule(r.Rule.Id);

        _repo = NewRepo();

        Assert.Empty(_repo.Snapshot().Rules);
    }

    [Fact]
    public void Ensure_app_filter_is_idempotent_and_disambiguates_names()
    {
        var a = _repo.EnsureAppFilter("c:\\a\\tool.exe", "Tool");
        var again = _repo.EnsureAppFilter("C:\\A\\TOOL.EXE", "Tool");
        var b = _repo.EnsureAppFilter("c:\\b\\tool.exe", "Tool");

        Assert.Equal(a.Id, again.Id);
        Assert.Equal("Tool", a.Name);
        Assert.Equal("Tool (2)", b.Name);
    }

    [Fact]
    public void No_rules_means_default_actions_and_no_limits()
    {
        var decision = Eval(Flows.Make(), defaultOut: FirewallAction.Ask);

        Assert.Equal(FirewallAction.Ask, decision.Firewall);
        Assert.Null(decision.FirewallRuleId);
        Assert.Empty(decision.DownloadLimits);
    }

    [Fact]
    public void Default_in_applies_to_accepted_and_listening_sockets()
    {
        Assert.Equal(FirewallAction.Deny, Eval(Flows.Make(kind: ConnectionKind.Accept), defaultIn: FirewallAction.Deny).Firewall);
        Assert.Equal(FirewallAction.Deny, Eval(Flows.Make(kind: ConnectionKind.Listen), defaultIn: FirewallAction.Deny).Firewall);
        Assert.Equal(FirewallAction.Allow, Eval(Flows.Make(kind: ConnectionKind.Connect), defaultIn: FirewallAction.Deny).Firewall);
    }

    [Fact]
    public void More_specific_filter_beats_zone_beats_whole_computer()
    {
        Block(PredefinedFilters.AnyTraffic, FirewallAction.Deny);
        Assert.Equal(FirewallAction.Deny, Eval(Flows.Make()).Firewall);

        Block(PredefinedFilters.Internet, FirewallAction.Allow);
        Assert.Equal(FirewallAction.Allow, Eval(Flows.Make()).Firewall);
        Assert.Equal(FirewallAction.Deny, Eval(Flows.Make(remote: "192.168.1.1")).Firewall);

        var app = Block(AppFilter().Id, FirewallAction.Deny);
        var decision = Eval(Flows.Make());
        Assert.Equal(FirewallAction.Deny, decision.Firewall);
        Assert.Equal(app.Id, decision.FirewallRuleId);
    }

    [Fact]
    public void Explicit_weight_overrides_default_and_list_order_breaks_ties()
    {
        var filter = AppFilter();
        var allow = Block(filter.Id, FirewallAction.Allow);
        var deny = Block(filter.Id, FirewallAction.Deny);
        Assert.Equal(allow.Id, Eval(Flows.Make()).FirewallRuleId);

        _repo.Reorder([deny.Id, allow.Id]);
        Assert.Equal(deny.Id, Eval(Flows.Make()).FirewallRuleId);

        var zoneOverride = Block(PredefinedFilters.Internet, FirewallAction.Ask, weight: 10);
        Assert.Equal(zoneOverride.Id, Eval(Flows.Make()).FirewallRuleId);
    }

    [Fact]
    public void Blocker_direction_is_connection_direction()
    {
        var filter = AppFilter();
        Block(filter.Id, FirewallAction.Deny, RuleDirection.In);

        Assert.Equal(FirewallAction.Allow, Eval(Flows.Make(kind: ConnectionKind.Connect)).Firewall);
        Assert.Equal(FirewallAction.Deny, Eval(Flows.Make(kind: ConnectionKind.Accept)).Firewall);
    }

    [Fact]
    public void Disabled_and_expired_rules_do_not_apply_and_expired_are_removed()
    {
        var filter = AppFilter();
        var disabled = Block(filter.Id, FirewallAction.Deny);
        _repo.SetEnabled(disabled.Id, false);
        var temp = _repo.SaveRule(new RuleDefinition(Guid.Empty, filter.Id, RuleKind.Firewall, RuleDirection.Both,
            Action: FirewallAction.Deny, ExpiresAt: _time.GetUtcNow().AddMinutes(5)));

        Assert.Equal(temp.Id, Eval(Flows.Make()).FirewallRuleId);
        Assert.Equal(RuleState.Disabled, _repo.Snapshot().Rules.Single(r => r.Rule.Id == disabled.Id).State);

        _time.Advance(TimeSpan.FromMinutes(6));
        Assert.Null(Eval(Flows.Make()).FirewallRuleId);
        Assert.Equal(RuleState.Inactive, _repo.Snapshot().Rules.Single(r => r.Rule.Id == temp.Id).State);

        Assert.Equal(1, _repo.RemoveExpired());
        Assert.DoesNotContain(_repo.Snapshot().Rules, r => r.Rule.Id == temp.Id);
    }

    [Fact]
    public void All_matching_limits_apply_per_direction()
    {
        var app = Limit(AppFilter().Id, 1000, RuleDirection.In);
        var all = Limit(PredefinedFilters.AnyTraffic, 5000, RuleDirection.Both);

        var decision = Eval(Flows.Make());

        Assert.Equal([app.Id, all.Id], decision.DownloadLimits.Select(l => l.RuleId));
        Assert.Equal([all.Id], decision.UploadLimits.Select(l => l.RuleId));
        Assert.Equal(5000, decision.UploadLimits[0].BytesPerSecond);
    }

    [Fact]
    public void Default_ignore_rules_exempt_lan_from_whole_computer_limit_but_not_app_limits()
    {
        Limit(PredefinedFilters.AnyTraffic, 5000, RuleDirection.Both);
        var app = Limit(AppFilter().Id, 1000, RuleDirection.In);

        var lan = Eval(Flows.Make(remote: "192.168.1.20"));
        Assert.Equal([app.Id], lan.DownloadLimits.Select(l => l.RuleId));
        Assert.Empty(lan.UploadLimits);

        Assert.Equal(2, Eval(Flows.Make(remote: "8.8.8.8")).DownloadLimits.Count);
    }

    [Fact]
    public void Ignore_data_is_reported()
    {
        _repo.SaveRule(new RuleDefinition(Guid.Empty, PredefinedFilters.Loopback, RuleKind.Ignore, RuleDirection.Both, IgnoreData: true));

        Assert.True(Eval(Flows.Make(remote: "127.0.0.1", local: "127.0.0.1")).IgnoreData);
        Assert.False(Eval(Flows.Make()).IgnoreData);
    }

    [Fact]
    public void Per_type_controls_bucket_keys()
    {
        var shared = Limit(AppFilter("c:\\a.exe").Id, 1000);
        var perProcess = Limit(AppFilter("c:\\b.exe", FilterPerType.PerProcess).Id, 1000);
        var perConnection = Limit(AppFilter("c:\\c.exe", FilterPerType.PerConnection).Id, 1000);

        string Bucket(string app, int pid, int port) =>
            Eval(Flows.Make(appId: app, pid: pid, localPort: port)).DownloadLimits.Single().BucketKey;

        Assert.Equal(Bucket("c:\\a.exe", 1, 1), Bucket("c:\\a.exe", 2, 2));
        Assert.NotEqual(Bucket("c:\\b.exe", 1, 1), Bucket("c:\\b.exe", 2, 1));
        Assert.Equal(Bucket("c:\\b.exe", 1, 1), Bucket("c:\\b.exe", 1, 2));
        Assert.NotEqual(Bucket("c:\\c.exe", 1, 1), Bucket("c:\\c.exe", 1, 2));
        Assert.Contains(shared.Id.ToString("N"), Bucket("c:\\a.exe", 1, 1));
        _ = perProcess;
        _ = perConnection;
    }

    [Fact]
    public void Composite_filter_requires_a_base_match_and_its_own_functions()
    {
        var browser = AppFilter("c:\\browser.exe");
        var game = AppFilter("c:\\game.exe");
        var composite = _repo.SaveFilter(new FilterDefinition(Guid.Empty, "Apps on port 443", FilterType.Composite, FilterPerType.None,
            [new FilterFunction(FilterFunctionKind.RemotePortInRange, true, ["443"])], [browser.Id, game.Id]));
        Block(composite.Id, FirewallAction.Deny);

        Assert.Equal(FirewallAction.Deny, Eval(Flows.Make(appId: "c:\\game.exe")).Firewall);
        Assert.Equal(FirewallAction.Allow, Eval(Flows.Make(appId: "c:\\game.exe", remotePort: 80)).Firewall);
        Assert.Equal(FirewallAction.Allow, Eval(Flows.Make(appId: "c:\\other.exe")).Firewall);
    }

    [Fact]
    public void Deleting_a_filter_removes_its_rules_but_base_filters_in_use_are_protected()
    {
        var browser = AppFilter("c:\\browser.exe");
        var rule = Limit(browser.Id, 10);
        var composite = _repo.SaveFilter(new FilterDefinition(Guid.Empty, "C", FilterType.Composite, FilterPerType.None, [], [browser.Id]));

        Assert.Throws<RuleValidationException>(() => _repo.DeleteFilter(browser.Id));
        _repo.DeleteFilter(composite.Id);
        _repo.DeleteFilter(browser.Id);

        Assert.DoesNotContain(_repo.Snapshot().Rules, r => r.Rule.Id == rule.Id);
    }

    [Fact]
    public void Predefined_filters_are_read_only()
    {
        var internet = _repo.Snapshot().Filters.Single(f => f.Id == PredefinedFilters.Internet);

        Assert.Throws<RuleValidationException>(() => _repo.SaveFilter(internet with { Name = "Web" }));
        Assert.Throws<RuleValidationException>(() => _repo.DeleteFilter(PredefinedFilters.Internet));
    }

    [Fact]
    public void Every_change_bumps_generation_and_raises_changed()
    {
        long before = _repo.Current.Generation;
        var events = new List<long>();
        _repo.Changed += events.Add;

        var f = AppFilter();
        Limit(f.Id, 1);

        Assert.Equal(2, events.Count);
        Assert.True(_repo.Current.Generation > before);
        Assert.Equal(_repo.Current.Generation, events[^1]);
    }

    [Fact]
    public void Corrupt_rules_file_with_orphan_rules_is_repaired()
    {
        var doc = new RulesDocument
        {
            Rules = [new RuleDefinition(Guid.NewGuid(), Guid.NewGuid(), RuleKind.Limit, RuleDirection.In, LimitBytesPerSecond: 5)],
        };
        new JsonFileStore<RulesDocument>(_dir.File("rules.json")).Save(doc);

        _repo = NewRepo();

        Assert.Empty(_repo.Snapshot().Rules);
        Assert.Equal(PredefinedFilters.All.Count, _repo.Snapshot().Filters.Count);
    }
}

public class RuleValidatorTests
{
    private static readonly IReadOnlyList<FilterDefinition> Base = PredefinedFilters.All;

    private static FilterDefinition F(string name, params FilterFunction[] functions) =>
        new(Guid.NewGuid(), name, FilterType.Filter, FilterPerType.None, functions, []);

    [Theory]
    [InlineData(FilterFunctionKind.RemoteAddressInRange, "999.1.1.1")]
    [InlineData(FilterFunctionKind.LocalPortInRange, "abc")]
    [InlineData(FilterFunctionKind.Protocol, "ICMP")]
    [InlineData(FilterFunctionKind.ProcessId, "-3")]
    [InlineData(FilterFunctionKind.AppId, " ")]
    public void Invalid_values_are_rejected(FilterFunctionKind kind, string value)
    {
        var ex = Assert.Throws<RuleValidationException>(() =>
            RuleValidator.ValidateFilter(F("x", new FilterFunction(kind, true, [value])), Base));
        Assert.NotEmpty(ex.Message);
    }

    [Fact]
    public void Names_must_be_present_short_and_unique()
    {
        Assert.Throws<RuleValidationException>(() => RuleValidator.ValidateFilter(F(" "), Base));
        Assert.Throws<RuleValidationException>(() => RuleValidator.ValidateFilter(F(new string('x', 101)), Base));
        Assert.Throws<RuleValidationException>(() => RuleValidator.ValidateFilter(F("internet"), Base));
    }

    [Fact]
    public void Zone_functions_take_no_values()
    {
        Assert.Throws<RuleValidationException>(() =>
            RuleValidator.ValidateFilter(F("z", new FilterFunction(FilterFunctionKind.IsInternet, true, ["x"])), Base));
        RuleValidator.ValidateFilter(F("z", new FilterFunction(FilterFunctionKind.IsInternet)), Base);
    }

    [Fact]
    public void Composite_rules()
    {
        var comp = new FilterDefinition(Guid.NewGuid(), "c", FilterType.Composite, FilterPerType.None, [], [PredefinedFilters.Internet]);
        RuleValidator.ValidateFilter(comp, [.. Base, comp]);

        Assert.Throws<RuleValidationException>(() => RuleValidator.ValidateFilter(comp with { BaseFilterIds = [] }, Base));
        Assert.Throws<RuleValidationException>(() => RuleValidator.ValidateFilter(comp with { BaseFilterIds = [Guid.NewGuid()] }, Base));
        var nested = comp with { Id = Guid.NewGuid(), Name = "n", BaseFilterIds = [comp.Id] };
        Assert.Throws<RuleValidationException>(() => RuleValidator.ValidateFilter(nested, [.. Base, comp, nested]));
        Assert.Throws<RuleValidationException>(() => RuleValidator.ValidateFilter(F("plain") with { BaseFilterIds = [PredefinedFilters.Internet] }, Base));
    }

    [Theory]
    [InlineData(RuleKind.Limit)]
    [InlineData(RuleKind.Firewall)]
    [InlineData(RuleKind.Ignore)]
    public void Rules_need_their_kind_specific_value(RuleKind kind)
    {
        var rule = new RuleDefinition(Guid.NewGuid(), PredefinedFilters.Internet, kind, RuleDirection.In);
        Assert.Throws<RuleValidationException>(() => RuleValidator.ValidateRule(rule, Base));
    }

    [Fact]
    public void Rules_need_an_existing_filter_and_sane_values()
    {
        Assert.Throws<RuleValidationException>(() => RuleValidator.ValidateRule(
            new RuleDefinition(Guid.NewGuid(), Guid.NewGuid(), RuleKind.Firewall, RuleDirection.In, Action: FirewallAction.Deny), Base));
        Assert.Throws<RuleValidationException>(() => RuleValidator.ValidateRule(
            new RuleDefinition(Guid.NewGuid(), PredefinedFilters.Internet, RuleKind.Limit, RuleDirection.In, LimitBytesPerSecond: -1), Base));
        Assert.Throws<RuleValidationException>(() => RuleValidator.ValidateRule(
            new RuleDefinition(Guid.NewGuid(), PredefinedFilters.Internet, RuleKind.Firewall, RuleDirection.In, Action: FirewallAction.Deny, Weight: -1), Base));
    }
}
