using NetWarden.Client.ViewModels;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;

namespace NetWarden.Tests.Client;

public class QuickBlockTests
{
    private static readonly Guid Filter = Guid.NewGuid();

    private static RulesSnapshot With(params RuleDefinition[] rules) =>
        new(1, PredefinedFilters.All, rules.Select(r => new RuleView(r, RuleState.Active, 3, "f")).ToList());

    private static RuleDefinition Deny(RuleDirection dir, bool enabled = true, DateTimeOffset? expires = null) =>
        new(Guid.NewGuid(), Filter, RuleKind.Firewall, dir, IsEnabled: enabled, Action: FirewallAction.Deny, ExpiresAt: expires);

    [Fact]
    public void Only_enabled_permanent_deny_rules_count_as_blocked()
    {
        Assert.True(QuickBlock.IsBlocked(With(Deny(RuleDirection.Both)), Filter, RuleDirection.In));
        Assert.True(QuickBlock.IsBlocked(With(Deny(RuleDirection.Out)), Filter, RuleDirection.Out));
        Assert.False(QuickBlock.IsBlocked(With(Deny(RuleDirection.Out)), Filter, RuleDirection.In));
        Assert.False(QuickBlock.IsBlocked(With(Deny(RuleDirection.In, enabled: false)), Filter, RuleDirection.In));
        Assert.False(QuickBlock.IsBlocked(With(Deny(RuleDirection.In, expires: DateTimeOffset.UtcNow.AddHours(1))), Filter, RuleDirection.In));
        Assert.False(QuickBlock.IsBlocked(With(Deny(RuleDirection.In)), null, RuleDirection.In));
    }

    [Fact]
    public void Blocking_adds_one_deny_rule_unless_already_blocked()
    {
        var plan = QuickBlock.Plan(With(), Filter, RuleDirection.Out, block: true);
        var rule = Assert.Single(plan.Save);
        Assert.Equal((RuleKind.Firewall, RuleDirection.Out, FirewallAction.Deny), (rule.Kind, rule.Direction, rule.Action!.Value));

        Assert.True(QuickBlock.Plan(With(Deny(RuleDirection.Both)), Filter, RuleDirection.Out, true).IsEmpty);
    }

    [Fact]
    public void Unblocking_deletes_single_direction_rules_and_narrows_both()
    {
        var outRule = Deny(RuleDirection.Out);
        var both = Deny(RuleDirection.Both);

        var plan = QuickBlock.Plan(With(outRule, both), Filter, RuleDirection.Out, block: false);

        Assert.Equal([outRule.Id], plan.Delete);
        var narrowed = Assert.Single(plan.Save);
        Assert.Equal(both.Id, narrowed.Id);
        Assert.Equal(RuleDirection.In, narrowed.Direction);
    }

    [Fact]
    public void Finds_the_app_filter()
    {
        var app = new FilterDefinition(Guid.NewGuid(), "App", FilterType.Filter, FilterPerType.None,
            [new FilterFunction(FilterFunctionKind.AppId, true, [@"c:\a.exe"])], []);
        var snapshot = new RulesSnapshot(1, [.. PredefinedFilters.All, app], []);

        Assert.Equal(app.Id, QuickBlock.AppFilterId(snapshot, @"C:\A.EXE"));
        Assert.Null(QuickBlock.AppFilterId(snapshot, @"c:\b.exe"));
    }
}

public class BlockerViewModelTests
{
    private readonly FakeService _service = new();
    private readonly RulesViewModel _rules;
    private readonly BlockerViewModel _vm;

    private static BlockerRequest Request(string remote = "1.1.1.1") =>
        new(Guid.NewGuid(), Snapshots.App("b", "Browser"), 100, TransportProtocol.Tcp, ConnectionKind.Connect,
            "192.168.1.14", 50000, remote, 443, "one.one.one.one", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(1), null);

    public BlockerViewModelTests()
    {
        _rules = new RulesViewModel(_service);
        _vm = new BlockerViewModel(_service, _rules);
    }

    [Fact]
    public void Requests_arrive_once_and_leave_when_resolved()
    {
        var arrived = new List<BlockerRequest>();
        _vm.RequestArrived += arrived.Add;
        var r = Request();

        _vm.OnRequest(r);
        _vm.OnRequest(r);
        Assert.Single(_vm.Pending);
        Assert.Single(arrived);

        _vm.OnResolved(new BlockerResolved(r.Id, false, true));
        Assert.Empty(_vm.Pending);
    }

    [Fact]
    public async Task Answer_sends_choice_and_removes_request()
    {
        var r = Request();
        _vm.OnRequest(r);

        Assert.True(await _vm.AnswerAsync(r, true, RememberMode.Temporary, RuleScope.AppAndRemotePort, 15));

        var answer = (BlockerAnswer)_service.Calls.Single(c => c.Method == Methods.BlockerAnswer).Payload!;
        Assert.Equal(new BlockerAnswer(r.Id, true, RememberMode.Temporary, RuleScope.AppAndRemotePort, 15), answer);
        Assert.Empty(_vm.Pending);
    }

    [Fact]
    public async Task Load_reads_pending_and_status()
    {
        _service.Handler = (method, _) => method switch
        {
            Methods.BlockerPending => new List<BlockerRequest> { Request() },
            Methods.FilterStatus => new PacketFilterStatus(true, true, null, 1234, 5),
            _ => null,
        };

        await _vm.LoadAsync();

        Assert.Single(_vm.Pending);
        Assert.Contains("1,234", _vm.StatusText.Replace("\u00a0", ","));
    }

    [Theory]
    [InlineData(true, true, null, "Filtering")]
    [InlineData(false, false, null, "Idle")]
    [InlineData(false, true, "driver blocked", "error: driver blocked")]
    public void Status_text(bool running, bool needed, string? error, string expected)
    {
        _vm.Status = new PacketFilterStatus(running, needed, error, 0, 0);
        Assert.Contains(expected, _vm.StatusText);
    }

    [Fact]
    public async Task Blocking_an_app_creates_its_filter_then_a_deny_rule()
    {
        var filter = new FilterDefinition(Guid.NewGuid(), "Browser", FilterType.Filter, FilterPerType.None,
            [new FilterFunction(FilterFunctionKind.AppId, true, ["b"])], []);
        _service.Handler = (method, _) => method switch
        {
            Methods.FiltersEnsureForApp => filter,
            Methods.RulesGet => new RulesSnapshot(1, [.. PredefinedFilters.All, filter], []),
            Methods.RulesSave => new RuleDefinition(Guid.NewGuid(), filter.Id, RuleKind.Firewall, RuleDirection.Out),
            _ => true,
        };

        Assert.True(await _vm.SetBlockedAsync(null, Snapshots.App("b", "Browser"), RuleDirection.Out, block: true));

        var saved = (RuleDefinition)_service.Calls.Single(c => c.Method == Methods.RulesSave).Payload!;
        Assert.Equal(filter.Id, saved.FilterId);
        Assert.Equal(FirewallAction.Deny, saved.Action);
    }
}

public class BlockerPromptViewModelTests
{
    private readonly FakeService _service = new();
    private readonly BlockerViewModel _blocker;

    public BlockerPromptViewModelTests()
    {
        _blocker = new BlockerViewModel(_service, new RulesViewModel(_service));
    }

    private static BlockerRequest Request(string remote, string? host = null, ConnectionKind kind = ConnectionKind.Connect) =>
        new(Guid.NewGuid(), Snapshots.App("b", "Browser"), 100, TransportProtocol.Udp, kind,
            "192.168.1.14", 5000, remote, 53, host, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(1), null);

    [Fact]
    public async Task Shows_oldest_request_advances_after_answers_and_finishes()
    {
        var first = Request("8.8.8.8", "dns.google");
        var second = Request("1.1.1.1", kind: ConnectionKind.Accept);
        _blocker.OnRequest(first);
        _blocker.OnRequest(second);
        var vm = new BlockerPromptViewModel(_blocker);
        bool finished = false;
        vm.Finished += () => finished = true;

        Assert.Equal("Browser wants to connect to", vm.Headline);
        Assert.Equal("dns.google : 53 (UDP)", vm.Target);
        Assert.Equal("1 more waiting", vm.MoreText);

        vm.Remember = RememberMode.Always;
        vm.Scope = RuleScope.AppAndRemoteAddress;
        await vm.AllowCommand.ExecuteAsync(null);

        var answer = (BlockerAnswer)_service.Calls.Single().Payload!;
        Assert.Equal((first.Id, true, RememberMode.Always, RuleScope.AppAndRemoteAddress),
            (answer.RequestId, answer.Allow, answer.Remember, answer.Scope));
        Assert.Same(second, vm.Current);
        Assert.Equal("Browser is receiving a connection from", vm.Headline);
        Assert.Equal(RememberMode.Once, vm.Remember);

        await vm.DenyCommand.ExecuteAsync(null);
        Assert.True(finished);
        Assert.Null(vm.Current);
    }

    [Fact]
    public void Request_resolved_elsewhere_moves_prompt_on()
    {
        var first = Request("8.8.8.8");
        _blocker.OnRequest(first);
        var vm = new BlockerPromptViewModel(_blocker);
        bool finished = false;
        vm.Finished += () => finished = true;

        _blocker.OnResolved(new BlockerResolved(first.Id, false, TimedOut: true));

        Assert.True(finished);
    }
}
