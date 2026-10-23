using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using NetWarden.Core.Apps;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Packets;
using NetWarden.Core.Rules;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Storage;
using NetWarden.Tests.Monitoring;

namespace NetWarden.Tests.Packets;

/// <summary>
/// Real WinDivert against the real network. Rules only target two specific Internet
/// addresses on port 80, so nothing else on the machine is affected.
/// </summary>
[Collection(LiveNetworkCollection.Name)]
public sealed class WinDivertLiveTests : IDisposable
{
    private static readonly IPAddress Target = IPAddress.Parse("1.1.1.1");
    private static readonly IPAddress Control = IPAddress.Parse("1.0.0.1");

    private readonly TempDir _dir = new();
    private readonly RuleRepository _rules;
    private readonly Blocker _blocker;

    public WinDivertLiveTests()
    {
        _rules = new RuleRepository(new JsonFileStore<RulesDocument>(_dir.File("rules.json")), new ZoneClassifier(), TimeProvider.System);
        var contexts = new FlowContextFactory(new AppIdentityResolver().Resolve, new ProcessUsers().Get, new DnsMap());
        _blocker = new Blocker(() => _rules.Current, () => new ServiceSettings(),
            new SocketOwnerLookup(new SocketTable(), TimeProvider.System), contexts, TimeProvider.System);
    }

    public void Dispose() => _dir.Dispose();

    private void TargetRule(FirewallAction action)
    {
        var filter = _rules.SaveFilter(new FilterDefinition(Guid.Empty, "test target", FilterType.Filter, FilterPerType.None,
        [
            new FilterFunction(FilterFunctionKind.RemoteAddressInRange, true, [Target.ToString()]),
            new FilterFunction(FilterFunctionKind.RemotePortInRange, true, ["80"]),
            new FilterFunction(FilterFunctionKind.ProcessId, true, [Environment.ProcessId.ToString()]),
        ], []));
        _rules.SaveRule(new RuleDefinition(Guid.Empty, filter.Id, RuleKind.Firewall, RuleDirection.Out, Action: action));
    }

    private static async Task<bool> CanConnect(IPAddress address, TimeSpan timeout)
    {
        using var client = new TcpClient();
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            await client.ConnectAsync(address, 80, cts.Token);
            return true;
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException)
        {
            return false;
        }
    }

    private PacketFilter StartFilter() =>
        new(new WinDivertDevice(PacketFilter.BlockerFilter), _blocker, NullLogger.Instance);

    [AdminFact]
    public void Driver_opens_and_closes()
    {
        using var device = new WinDivertDevice("false");
    }

    [AdminFact]
    public async Task Deny_rule_blocks_only_the_targeted_connection()
    {
        if (!await CanConnect(Control, TimeSpan.FromSeconds(5)))
            return; // no Internet here; nothing to prove

        TargetRule(FirewallAction.Deny);
        using (StartFilter())
        {
            Assert.False(await CanConnect(Target, TimeSpan.FromSeconds(3)), "Blocked connection succeeded.");
            Assert.True(await CanConnect(Control, TimeSpan.FromSeconds(5)), "Unrelated connection was affected.");
            Assert.True(_blocker.Dropped > 0);
        }

        // Closing the filter restores normal traffic.
        Assert.True(await CanConnect(Target, TimeSpan.FromSeconds(5)));
    }

    [AdminFact]
    public async Task Ask_holds_connection_until_allowed()
    {
        if (!await CanConnect(Control, TimeSpan.FromSeconds(5)))
            return;

        TargetRule(FirewallAction.Ask);
        var asked = new TaskCompletionSource<BlockerRequest>();
        _blocker.RequestCreated += r => asked.TrySetResult(r);
        using var filter = StartFilter();

        var connect = CanConnect(Target, TimeSpan.FromSeconds(10));
        var request = await asked.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(Environment.ProcessId, request.ProcessId);
        Assert.Equal(80, request.RemotePort);
        await Task.Delay(500);
        Assert.False(connect.IsCompleted, "Connection completed before it was allowed.");

        filter.Inject(_blocker.Resolve(request.Id, allow: true));

        Assert.True(await connect, "Allowed connection did not complete.");
    }
}

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class LiveNetworkCollection
{
    public const string Name = "Live network";
}
