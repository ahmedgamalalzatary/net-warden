using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using NetWarden.Core.Ipc;
using NetWarden.Shared.Ipc;

namespace NetWarden.Tests.Ipc;

public sealed class IpcServerClientTests : IAsyncLifetime
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(5);

    private readonly string _pipeName = TestPipes.NewName();
    private readonly IpcDispatcher _dispatcher = new();
    private IpcServer _server = null!;

    public sealed record EchoRequest(string Text);
    public sealed record EchoResponse(string Text, int Length);

    public Task InitializeAsync()
    {
        _dispatcher
            .Register<EchoRequest, EchoResponse>("echo", (r, _) => Task.FromResult(new EchoResponse(r!.Text, r.Text.Length)))
            .Register<EchoRequest, EchoResponse>("slow-echo", async (r, ct) =>
            {
                await Task.Delay(int.Parse(r!.Text), ct);
                return new EchoResponse(r.Text, r.Text.Length);
            })
            .Register<string>("fail", _ => throw new InvalidOperationException("boom"))
            .Register<string?>("null", _ => Task.FromResult<string?>(null));

        _server = new IpcServer(_pipeName, _dispatcher, NullLogger.Instance);
        _server.Start();
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await _server.DisposeAsync();

    private async Task<ServiceClient> ConnectAsync()
    {
        var client = new ServiceClient(_pipeName);
        await client.ConnectAsync(ConnectTimeout);
        return client;
    }

    [Fact]
    public async Task Request_gets_typed_response()
    {
        await using var client = await ConnectAsync();

        var response = await client.RequestAsync<EchoResponse>("echo", new EchoRequest("hello"));

        Assert.Equal(new EchoResponse("hello", 5), response);
    }

    [Fact]
    public async Task Null_result_is_returned_as_null()
    {
        await using var client = await ConnectAsync();
        Assert.Null(await client.RequestAsync<string>("null"));
    }

    [Fact]
    public async Task Unknown_method_raises_remote_exception()
    {
        await using var client = await ConnectAsync();

        var ex = await Assert.ThrowsAsync<IpcRemoteException>(() => client.RequestAsync<string>("nope"));
        Assert.Contains("Unknown method", ex.RemoteMessage);
    }

    [Fact]
    public async Task Handler_exception_is_reported_and_connection_survives()
    {
        await using var client = await ConnectAsync();

        var ex = await Assert.ThrowsAsync<IpcRemoteException>(() => client.RequestAsync<string>("fail"));
        Assert.Equal("boom", ex.RemoteMessage);

        var after = await client.RequestAsync<EchoResponse>("echo", new EchoRequest("still ok"));
        Assert.Equal("still ok", after!.Text);
    }

    [Fact]
    public async Task Concurrent_requests_are_matched_to_their_own_responses()
    {
        await using var client = await ConnectAsync();

        // Slow requests first so responses come back out of order.
        var tasks = Enumerable.Range(0, 50)
            .Select(i => client.RequestAsync<EchoResponse>("slow-echo", new EchoRequest(((50 - i) % 7 * 5).ToString("D" + (i + 1)))))
            .ToArray();
        var results = await Task.WhenAll(tasks);

        for (int i = 0; i < 50; i++)
            Assert.Equal(i + 1, results[i]!.Text.Length);
    }

    [Fact]
    public async Task Multiple_clients_are_served_independently()
    {
        await using var a = await ConnectAsync();
        await using var b = await ConnectAsync();
        await using var c = await ConnectAsync();

        var results = await Task.WhenAll(
            a.RequestAsync<EchoResponse>("echo", new EchoRequest("a")),
            b.RequestAsync<EchoResponse>("echo", new EchoRequest("bb")),
            c.RequestAsync<EchoResponse>("echo", new EchoRequest("ccc")));

        Assert.Equal(["a", "bb", "ccc"], results.Select(r => r!.Text));
        await WaitUntil(() => _server.ClientCount == 3);
    }

    [Fact]
    public async Task Server_tracks_client_disconnects()
    {
        var client = await ConnectAsync();
        await client.RequestAsync<EchoResponse>("echo", new EchoRequest("x"));
        await WaitUntil(() => _server.ClientCount == 1);

        await client.DisposeAsync();

        await WaitUntil(() => _server.ClientCount == 0);
    }

    [Fact]
    public async Task Broadcast_reaches_all_clients()
    {
        await using var a = await ConnectAsync();
        await using var b = await ConnectAsync();
        await WaitUntil(() => _server.ClientCount == 2);

        var gotA = new TaskCompletionSource<JsonElement?>();
        var gotB = new TaskCompletionSource<JsonElement?>();
        a.EventReceived += (m, p) => { if (m == "tick") gotA.TrySetResult(p); };
        b.EventReceived += (m, p) => { if (m == "tick") gotB.TrySetResult(p); };

        await _server.BroadcastAsync("tick", new { N = 3 });

        Assert.Equal(3, (await gotA.Task.WaitAsync(ConnectTimeout))!.Value.GetProperty("n").GetInt32());
        Assert.Equal(3, (await gotB.Task.WaitAsync(ConnectTimeout))!.Value.GetProperty("n").GetInt32());
    }

    [Fact]
    public async Task Server_shutdown_fails_pending_requests_and_raises_disconnected()
    {
        var client = await ConnectAsync();
        var disconnected = new TaskCompletionSource();
        client.Disconnected += _ => disconnected.TrySetResult();

        var pending = client.RequestAsync<EchoResponse>("slow-echo", new EchoRequest("5000"));
        await WaitUntil(() => _server.ClientCount == 1);
        await _server.DisposeAsync();

        await Assert.ThrowsAsync<IpcDisconnectedException>(() => pending.WaitAsync(ConnectTimeout));
        await disconnected.Task.WaitAsync(ConnectTimeout);
        Assert.False(client.IsConnected);
        await Assert.ThrowsAsync<IpcDisconnectedException>(() => client.RequestAsync<EchoResponse>("echo", new EchoRequest("x")));
        await client.DisposeAsync();
    }

    [Fact]
    public async Task Dispose_is_idempotent()
    {
        await _server.DisposeAsync();
        await _server.DisposeAsync();
    }

    [Fact]
    public async Task Request_can_be_cancelled_by_caller()
    {
        await using var client = await ConnectAsync();
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => client.RequestAsync<EchoResponse>("slow-echo", new EchoRequest("3000"), cts.Token));

        // The connection is still usable after a cancelled request.
        Assert.Equal("ok", (await client.RequestAsync<EchoResponse>("echo", new EchoRequest("ok")))!.Text);
    }

    [Fact]
    public async Task Connect_times_out_when_no_server()
    {
        await using var client = new ServiceClient(TestPipes.NewName());
        await Assert.ThrowsAsync<TimeoutException>(() => client.ConnectAsync(TimeSpan.FromMilliseconds(200)));
    }

    [Fact]
    public async Task Garbage_from_client_drops_only_that_session()
    {
        await using (var raw = new System.IO.Pipes.NamedPipeClientStream(".", _pipeName, System.IO.Pipes.PipeDirection.InOut))
        {
            await raw.ConnectAsync(5000);
            await raw.WriteAsync(new byte[] { 0xFF, 0xFF, 0xFF, 0x7F });
            await raw.FlushAsync();
        }

        await using var client = await ConnectAsync();
        Assert.Equal("fine", (await client.RequestAsync<EchoResponse>("echo", new EchoRequest("fine")))!.Text);
    }

    private static async Task WaitUntil(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
                Assert.Fail("Condition was not met within 5 seconds.");
            await Task.Delay(20);
        }
    }
}
