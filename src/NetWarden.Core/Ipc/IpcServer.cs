using System.IO.Pipes;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using NetWarden.Shared.Ipc;

namespace NetWarden.Core.Ipc;

/// <summary>
/// Accepts any number of clients on a named pipe. Each request is dispatched
/// concurrently and answered with a response carrying the same id.
/// </summary>
public sealed class IpcServer : IAsyncDisposable
{
    private readonly string _pipeName;
    private readonly IpcDispatcher _dispatcher;
    private readonly ILogger _logger;
    private readonly PipeSecurity? _security;
    private readonly List<Session> _sessions = [];
    private readonly Lock _sessionsLock = new();
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;
    private int _disposed;

    public IpcServer(string pipeName, IpcDispatcher dispatcher, ILogger logger, PipeSecurity? security = null)
    {
        _pipeName = pipeName;
        _dispatcher = dispatcher;
        _logger = logger;
        _security = security;
    }

    public int ClientCount
    {
        get { lock (_sessionsLock) return _sessions.Count; }
    }

    public void Start()
    {
        if (_cts is not null)
            throw new InvalidOperationException("Server already started.");
        _cts = new CancellationTokenSource();
        // Create the first instance synchronously so clients can connect as soon as Start returns.
        NamedPipeServerStream first = CreatePipe();
        _acceptLoop = Task.Run(() => AcceptLoopAsync(first, _cts.Token));
    }

    /// <summary>Pushes an event to every connected client.</summary>
    public async Task BroadcastAsync(string method, object? payload)
    {
        var message = new IpcMessage(MessageKind.Event, 0, method, IpcJson.ToElement(payload));
        Session[] sessions;
        lock (_sessionsLock) sessions = [.. _sessions];
        foreach (var session in sessions)
        {
            try
            {
                await session.SendAsync(message, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                // The session read loop will notice the broken pipe and remove it.
            }
        }
    }

    private NamedPipeServerStream CreatePipe() =>
        _security is null
            ? new NamedPipeServerStream(_pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous)
            : NamedPipeServerStreamAcl.Create(_pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, _security);

    private async Task AcceptLoopAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (IOException ex)
            {
                // A client connected and vanished before we accepted it.
                _logger.LogDebug(ex, "Pipe connection failed before accept.");
                await pipe.DisposeAsync().ConfigureAwait(false);
                pipe = CreatePipe();
                continue;
            }

            var session = new Session(pipe);
            lock (_sessionsLock) _sessions.Add(session);
            session.Run = Task.Run(() => RunSessionAsync(session, ct));

            pipe = CreatePipe();
        }
        await pipe.DisposeAsync().ConfigureAwait(false);
    }

    private async Task RunSessionAsync(Session session, CancellationToken ct)
    {
        _logger.LogInformation("Client connected ({Count} total).", ClientCount);
        try
        {
            while (!ct.IsCancellationRequested)
            {
                IpcMessage? message = await MessageFraming.ReadAsync(session.Pipe, ct).ConfigureAwait(false);
                if (message is null)
                    break;
                if (message.Kind != MessageKind.Request)
                    continue;

                _ = HandleRequestAsync(session, message, ct);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or ObjectDisposedException or JsonException)
        {
            _logger.LogWarning(ex, "Client session ended with an error.");
        }
        finally
        {
            lock (_sessionsLock) _sessions.Remove(session);
            await session.Pipe.DisposeAsync().ConfigureAwait(false);
            _logger.LogInformation("Client disconnected ({Count} remaining).", ClientCount);
        }
    }

    private async Task HandleRequestAsync(Session session, IpcMessage request, CancellationToken ct)
    {
        IpcMessage response;
        try
        {
            object? result = await _dispatcher.DispatchAsync(request.Method, request.Payload, ct).ConfigureAwait(false);
            response = new IpcMessage(MessageKind.Response, request.Id, request.Method, IpcJson.ToElement(result));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            if (ex is not IpcMethodNotFoundException)
                _logger.LogError(ex, "Request {Method} failed.", request.Method);
            response = new IpcMessage(MessageKind.Response, request.Id, request.Method, Error: ex.Message);
        }

        try
        {
            await session.SendAsync(response, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException)
        {
            // Client went away; nothing to answer.
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_cts is null || Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        _cts.Cancel();
        if (_acceptLoop is not null)
            await _acceptLoop.ConfigureAwait(false);

        Session[] sessions;
        lock (_sessionsLock) sessions = [.. _sessions];
        foreach (var session in sessions)
        {
            await session.Pipe.DisposeAsync().ConfigureAwait(false);
            if (session.Run is not null)
                await session.Run.ConfigureAwait(false);
        }
        _cts.Dispose();
    }

    private sealed class Session(NamedPipeServerStream pipe)
    {
        private readonly SemaphoreSlim _writeLock = new(1, 1);

        public NamedPipeServerStream Pipe { get; } = pipe;
        public Task? Run { get; set; }

        public async Task SendAsync(IpcMessage message, CancellationToken ct)
        {
            await _writeLock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await MessageFraming.WriteAsync(Pipe, message, ct).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }
        }
    }
}
