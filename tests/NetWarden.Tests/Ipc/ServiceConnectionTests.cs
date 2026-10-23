using Microsoft.Extensions.Logging.Abstractions;
using NetWarden.Core.Ipc;
using NetWarden.Shared.Ipc;

namespace NetWarden.Tests.Ipc;

public class ServiceConnectionTests
{
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(5);

    private static IpcServer StartServer(string pipeName)
    {
        var server = new IpcServer(pipeName, new IpcDispatcher().Register("ping", _ => Task.FromResult("pong")), NullLogger.Instance);
        server.Start();
        return server;
    }

    private static ServiceConnection NewConnection(string pipeName) =>
        new(pipeName, connectTimeout: TimeSpan.FromMilliseconds(200), retryDelay: TimeSpan.FromMilliseconds(50));

    private static async Task WaitForState(ServiceConnection connection, ConnectionState state)
    {
        var deadline = DateTime.UtcNow + Wait;
        while (connection.State != state)
        {
            if (DateTime.UtcNow > deadline)
                Assert.Fail($"State stayed {connection.State}, expected {state}.");
            await Task.Delay(20);
        }
    }

    [Fact]
    public async Task Connects_once_server_appears_later()
    {
        string pipe = TestPipes.NewName();
        await using var connection = NewConnection(pipe);
        connection.Start();

        // The initial state is already Disconnected, so wait for a failed attempt instead.
        var deadline = DateTime.UtcNow + Wait;
        while (connection.LastError is null && DateTime.UtcNow < deadline)
            await Task.Delay(20);
        Assert.Equal("The NetWarden service is not running.", connection.LastError);
        await Assert.ThrowsAsync<IpcDisconnectedException>(() => connection.RequestAsync<string>("ping"));

        await using var server = StartServer(pipe);
        await WaitForState(connection, ConnectionState.Connected);

        Assert.Equal("pong", await connection.RequestAsync<string>("ping"));
        Assert.Null(connection.LastError);
    }

    [Fact]
    public async Task Reconnects_after_server_restart()
    {
        string pipe = TestPipes.NewName();
        var server = StartServer(pipe);
        await using var connection = NewConnection(pipe);
        var states = new List<ConnectionState>();
        connection.StateChanged += s => { lock (states) states.Add(s); };
        connection.Start();
        await WaitForState(connection, ConnectionState.Connected);

        await server.DisposeAsync();
        await WaitForState(connection, ConnectionState.Disconnected);

        await using var restarted = StartServer(pipe);
        await WaitForState(connection, ConnectionState.Connected);
        Assert.Equal("pong", await connection.RequestAsync<string>("ping"));

        lock (states)
            Assert.Equal(2, states.Count(s => s == ConnectionState.Connected));
    }

    [Fact]
    public async Task Dispose_stops_the_loop()
    {
        string pipe = TestPipes.NewName();
        await using var server = StartServer(pipe);
        var connection = NewConnection(pipe);
        connection.Start();
        await WaitForState(connection, ConnectionState.Connected);

        await connection.DisposeAsync().AsTask().WaitAsync(Wait);
    }
}
