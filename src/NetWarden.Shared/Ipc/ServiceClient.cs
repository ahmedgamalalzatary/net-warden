using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using NetWarden.Shared.Contracts;

namespace NetWarden.Shared.Ipc;

/// <summary>
/// Client end of the service pipe. Requests may be issued concurrently; responses
/// are matched to requests by id. Events pushed by the service raise <see cref="EventReceived"/>.
/// </summary>
public sealed class ServiceClient : IAsyncDisposable
{
    private readonly Func<TimeSpan, CancellationToken, Task<Stream>> _connect;
    private readonly ConcurrentDictionary<long, TaskCompletionSource<IpcMessage>> _pending = new();
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly CancellationTokenSource _cts = new();
    private Stream? _stream;
    private Task? _readLoop;
    private long _nextId;
    private int _disconnected;

    public ServiceClient(string pipeName = PipeNames.Default)
    {
        _connect = async (timeout, ct) =>
        {
            var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            try
            {
                await pipe.ConnectAsync((int)timeout.TotalMilliseconds, ct).ConfigureAwait(false);
            }
            catch
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                throw;
            }
            return pipe;
        };
    }

    private ServiceClient(Func<TimeSpan, CancellationToken, Task<Stream>> connect) => _connect = connect;

    /// <summary>A client over any stream the connector opens.</summary>
    public static ServiceClient FromConnector(Func<TimeSpan, CancellationToken, Task<Stream>> connect) => new(connect);

    /// <summary>A client of a service on another computer: TLS, certificate check, then the password.</summary>
    public static ServiceClient ForRemote(RemoteTarget target) => new(async (timeout, ct) =>
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        var tcp = new TcpClient();
        SslStream? tls = null;
        try
        {
            await tcp.ConnectAsync(target.Host, target.Port, deadline.Token).ConfigureAwait(false);
            string? seen = null;
            tls = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (_, certificate, _, _) =>
            {
                seen = certificate?.GetCertHashString(HashAlgorithmName.SHA256);
                return seen is not null && (target.PinnedThumbprint is null || string.Equals(seen, target.PinnedThumbprint, StringComparison.OrdinalIgnoreCase));
            });
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "netwarden" }, deadline.Token).ConfigureAwait(false);
            target.OnThumbprint?.Invoke(seen!);

            await MessageFraming.WriteAsync(tls, new IpcMessage(MessageKind.Request, 0, Methods.RemoteAuth,
                IpcJson.ToElement(new RemoteAuthRequest(target.Password))), deadline.Token).ConfigureAwait(false);
            var answer = await MessageFraming.ReadAsync(tls, deadline.Token).ConfigureAwait(false);
            if (answer is null)
                throw new IpcAuthFailedException("The computer closed the connection.");
            if (answer.Error is { } refusal)
                throw new IpcAuthFailedException(refusal);
            return tls;
        }
        catch
        {
            if (tls is not null)
                await tls.DisposeAsync().ConfigureAwait(false);
            tcp.Dispose();
            throw;
        }
    });

    public event Action<string, JsonElement?>? EventReceived;

    /// <summary>Raised once when the connection ends, with the error if it ended abnormally.</summary>
    public event Action<Exception?>? Disconnected;

    public bool IsConnected => _stream is not null && _stream is not NamedPipeClientStream { IsConnected: false } && Volatile.Read(ref _disconnected) == 0;

    public async Task ConnectAsync(TimeSpan timeout, CancellationToken ct = default)
    {
        if (_stream is not null)
            throw new InvalidOperationException("Already connected; create a new client to reconnect.");

        Stream stream = await _connect(timeout, ct).ConfigureAwait(false);
        _stream = stream;
        _readLoop = Task.Run(() => ReadLoopAsync(stream, _cts.Token));
    }

    public async Task<TResult?> RequestAsync<TResult>(string method, object? payload = null, CancellationToken ct = default)
    {
        IpcMessage response = await SendRequestAsync(method, payload, ct).ConfigureAwait(false);
        return IpcJson.FromElement<TResult>(response.Payload);
    }

    public Task RequestAsync(string method, object? payload = null, CancellationToken ct = default) =>
        SendRequestAsync(method, payload, ct);

    private async Task<IpcMessage> SendRequestAsync(string method, object? payload, CancellationToken ct)
    {
        Stream stream = _stream ?? throw new InvalidOperationException("Not connected.");
        if (Volatile.Read(ref _disconnected) != 0)
            throw new IpcDisconnectedException("The connection to the service is closed.");

        long id = Interlocked.Increment(ref _nextId);
        var tcs = new TaskCompletionSource<IpcMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = tcs;
        try
        {
            var request = new IpcMessage(MessageKind.Request, id, method, IpcJson.ToElement(payload));
            await _writeLock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await MessageFraming.WriteAsync(stream, request, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                throw new IpcDisconnectedException("The connection to the service is closed.", ex);
            }
            finally
            {
                _writeLock.Release();
            }

            // The read loop may have failed between registering and writing.
            if (Volatile.Read(ref _disconnected) != 0)
                tcs.TrySetException(new IpcDisconnectedException("The connection to the service is closed."));

            IpcMessage response = await tcs.Task.WaitAsync(ct).ConfigureAwait(false);
            if (response.Error is not null)
                throw new IpcRemoteException(method, response.Error);
            return response;
        }
        finally
        {
            _pending.TryRemove(id, out _);
        }
    }

    private async Task ReadLoopAsync(Stream stream, CancellationToken ct)
    {
        Exception? error = null;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                IpcMessage? message = await MessageFraming.ReadAsync(stream, ct).ConfigureAwait(false);
                if (message is null)
                    break;

                switch (message.Kind)
                {
                    case MessageKind.Response when _pending.TryGetValue(message.Id, out var tcs):
                        tcs.TrySetResult(message);
                        break;
                    case MessageKind.Event:
                        EventReceived?.Invoke(message.Method, message.Payload);
                        break;
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            error = ex;
        }
        finally
        {
            MarkDisconnected(error);
        }
    }

    private void MarkDisconnected(Exception? error)
    {
        if (Interlocked.Exchange(ref _disconnected, 1) != 0)
            return;

        foreach (var tcs in _pending.Values)
            tcs.TrySetException(new IpcDisconnectedException("The connection to the service was lost.", error));

        Disconnected?.Invoke(error);
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        if (_stream is not null)
            await _stream.DisposeAsync().ConfigureAwait(false);
        if (_readLoop is not null)
            await _readLoop.ConfigureAwait(false);
        MarkDisconnected(null);
        _cts.Dispose();
        // _writeLock stays undisposed: that would strand requests waiting for it. It holds no OS handle.
    }
}
