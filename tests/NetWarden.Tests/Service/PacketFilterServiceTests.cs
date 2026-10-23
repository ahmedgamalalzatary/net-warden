using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NetWarden.Core.Packets;
using NetWarden.Service;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;
using NetWarden.Tests.Packets;

namespace NetWarden.Tests.Service;

/// <summary>A packet device fed by the test; records what the filter re-injects.</summary>
internal sealed class FakePacketDevice : IPacketDevice
{
    private readonly BlockingCollection<(byte[] Data, WinDivertAddress Address)> _inbound = new();

    public ConcurrentQueue<byte[]> Sent { get; } = new();
    public string? Filter { get; init; }
    public bool Disposed { get; private set; }

    public void Push(byte[] data, bool outbound) => _inbound.Add((data, Raw.Address(outbound)));

    public bool Receive(byte[] buffer, out int length, out WinDivertAddress address)
    {
        try
        {
            var (data, addr) = _inbound.Take();
            data.CopyTo(buffer, 0);
            length = data.Length;
            address = addr;
            return true;
        }
        catch (InvalidOperationException)
        {
            length = 0;
            address = default;
            return false;
        }
    }

    public void Send(ReadOnlySpan<byte> packet, in WinDivertAddress address) => Sent.Enqueue(packet.ToArray());

    public void Shutdown() => _inbound.CompleteAdding();

    public void Dispose() => Disposed = true;
}

public sealed class PacketFilterServiceTests : IAsyncLifetime
{
    private readonly string _pipeName = TestPipes.NewName();
    private readonly TempDir _dir = new();
    private readonly ConcurrentQueue<FakePacketDevice> _devices = new();
    private IHost _host = null!;
    private ServiceClient _client = null!;
    private readonly ConcurrentQueue<(string Method, System.Text.Json.JsonElement? Payload)> _events = new();

    public async Task InitializeAsync()
    {
        _host = ServiceHost.Build([], new Dictionary<string, string?>
        {
            ["NetWarden:PipeName"] = _pipeName,
            ["NetWarden:RestrictPipeToAdmins"] = "false",
            ["NetWarden:DataDirectory"] = _dir.Path,
            ["NetWarden:EnableTrafficSource"] = "false",
        }, services => services.AddSingleton<PacketDeviceFactory>(_ => filter =>
        {
            var device = new FakePacketDevice { Filter = filter };
            _devices.Enqueue(device);
            return device;
        }));
        await _host.StartAsync();
        _client = new ServiceClient(_pipeName);
        _client.EventReceived += (m, p) => _events.Enqueue((m, p));
        await _client.ConnectAsync(TimeSpan.FromSeconds(5));
    }

    public async Task DisposeAsync()
    {
        await _client.DisposeAsync();
        await _host.StopAsync();
        _host.Dispose();
        _dir.Dispose();
    }

    private async Task<T> Eventually<T>(Func<Task<T?>> probe, string what)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            if (await probe() is { } value)
                return value;
            await Task.Delay(50);
        }
        throw new Xunit.Sdk.XunitException($"Timed out waiting for {what}.");
    }

    private Task SetDefaultOut(FirewallAction action) => Task.Run(async () =>
    {
        var s = (await _client.RequestAsync<ServiceSettings>(Methods.SettingsGet))!;
        s.DefaultFirewallOut = action;
        await _client.RequestAsync<ServiceSettings>(Methods.SettingsUpdate, s);
    });

    [Fact]
    public async Task Filter_runs_only_while_needed()
    {
        var status = await _client.RequestAsync<PacketFilterStatus>(Methods.FilterStatus);
        Assert.False(status!.IsRunning);
        Assert.False(status.IsNeeded);
        Assert.Empty(_devices);

        await SetDefaultOut(FirewallAction.Deny);
        await Eventually(async () => (await _client.RequestAsync<PacketFilterStatus>(Methods.FilterStatus))!.IsRunning ? (bool?)true : null, "filter start");
        var device = Assert.Single(_devices);
        Assert.Equal(PacketFilter.BlockerFilter, device.Filter);

        await SetDefaultOut(FirewallAction.Allow);
        await Eventually(async () => (await _client.RequestAsync<PacketFilterStatus>(Methods.FilterStatus))!.IsRunning ? null : (bool?)true, "filter stop");
        Assert.True(device.Disposed);
    }

    [Fact]
    public async Task Ask_request_is_broadcast_and_remembered_answer_creates_rule_and_reinjects()
    {
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
        int port = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
        await SetDefaultOut(FirewallAction.Ask);
        var device = await Eventually(() => Task.FromResult(_devices.TryPeek(out var d) ? d : null), "device");

        byte[] packet = Raw.Udp4("192.168.1.14", port, "203.0.113.7", 53);
        device.Push(packet, outbound: true);

        var request = await Eventually(async () => (await _client.RequestAsync<List<BlockerRequest>>(Methods.BlockerPending))!.FirstOrDefault(), "request");
        Assert.Equal(Environment.ProcessId, request.ProcessId);
        Assert.Equal("203.0.113.7", request.RemoteAddress);
        Assert.Contains(_events, e => e.Method == Events.BlockerRequest);
        Assert.Empty(device.Sent);

        Assert.True(await _client.RequestAsync<bool>(Methods.BlockerAnswer,
            new BlockerAnswer(request.Id, Allow: true, RememberMode.Always, RuleScope.AppAndRemotePort)));

        Assert.Equal(packet, Assert.Single(device.Sent));
        Assert.Empty((await _client.RequestAsync<List<BlockerRequest>>(Methods.BlockerPending))!);
        var rules = (await _client.RequestAsync<RulesSnapshot>(Methods.RulesGet))!;
        var rule = Assert.Single(rules.Rules, r => r.Rule.Kind == RuleKind.Firewall);
        Assert.Equal(FirewallAction.Allow, rule.Rule.Action);
        Assert.Equal(RuleDirection.Out, rule.Rule.Direction);
        Assert.Contains("UDP 53", rule.FilterName);

        // A new flow from the same app to the same port is now allowed without asking.
        byte[] next = Raw.Udp4("192.168.1.14", port, "198.51.100.1", 53);
        device.Push(next, outbound: true);
        await Eventually(() => Task.FromResult(device.Sent.Count == 2 ? (bool?)true : null), "second packet passed");
        Assert.Empty((await _client.RequestAsync<List<BlockerRequest>>(Methods.BlockerPending))!);
    }

    [Fact]
    public async Task Temporary_deny_creates_expiring_rule()
    {
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
        int port = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
        await SetDefaultOut(FirewallAction.Ask);
        var device = await Eventually(() => Task.FromResult(_devices.TryPeek(out var d) ? d : null), "device");
        device.Push(Raw.Udp4("192.168.1.14", port, "203.0.113.9", 123), outbound: true);
        var request = await Eventually(async () => (await _client.RequestAsync<List<BlockerRequest>>(Methods.BlockerPending))!.FirstOrDefault(), "request");

        await _client.RequestAsync<bool>(Methods.BlockerAnswer, new BlockerAnswer(request.Id, false, RememberMode.Temporary, RuleScope.App, 15));

        Assert.Empty(device.Sent);
        var rule = (await _client.RequestAsync<RulesSnapshot>(Methods.RulesGet))!.Rules.Single(r => r.Rule.Kind == RuleKind.Firewall).Rule;
        Assert.Equal(FirewallAction.Deny, rule.Action);
        Assert.InRange(rule.ExpiresAt!.Value - DateTimeOffset.UtcNow, TimeSpan.FromMinutes(14), TimeSpan.FromMinutes(16));
    }

    [Fact]
    public async Task Answering_unknown_request_returns_false()
    {
        Assert.False(await _client.RequestAsync<bool>(Methods.BlockerAnswer, new BlockerAnswer(Guid.NewGuid(), true)));
    }

    [Fact]
    public void Need_requires_blocker_enabled_and_some_blocking_configuration()
    {
        var empty = NetWarden.Core.Rules.CompiledRuleSet.Empty;
        Assert.False(PacketFilterService.IsNeeded(new ServiceSettings(), empty));
        Assert.True(PacketFilterService.IsNeeded(new ServiceSettings { DefaultFirewallIn = FirewallAction.Deny }, empty));
        Assert.False(PacketFilterService.IsNeeded(new ServiceSettings { DefaultFirewallIn = FirewallAction.Deny, IsBlockerEnabled = false }, empty));
    }
}
