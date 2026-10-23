using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text.Json;

namespace NetWarden.Shared.Ipc;

/// <summary>
/// Client end of the service pipe. Requests may be issued concurrently; responses
/// are matched to requests by id. Events pushed by the service raise <see cref="EventReceived"/>.
/// </summary>
public sealed class ServiceClient : IAsyncDisposable
{
    private readonly string _pipeName;
    private readonly ConcurrentDictionary<long, TaskCompletionSource<IpcMessage>> _pending = new();
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly CancellationTokenSource _cts = new();
    private NamedPipeClientStream? _pipe;
    private Task? _readLoop;
    private long _nextId;
    private int _disconnected;

    public ServiceClient(string pipeName = PipeNames.Default)
    {
        _pipeName = pipeName;
    }

    public event Action<string, JsonElement?>? EventReceived;

    /// <summary>Raised once when the connection ends, with the error if it ended abnormally.</summary>
    public event Action<Exception?>? Disconnected;

    public bool IsConnected => _pipe is { IsConnected: true } && Volatile.Read(ref _disconnected) == 0;

    public async Task ConnectAsync(TimeSpan timeout, CancellationToken ct = default)
    {
        if (_pipe is not null)
            throw new InvalidOperationException("Already connected; create a new client to reconnect.");

        var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await pipe.ConnectAsync((int)timeout.TotalMilliseconds, ct).ConfigureAwait(false);
        }
        catch
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        _pipe = pipe;
        _readLoop = Task.Run(() => ReadLoopAsync(pipe, _cts.Token));
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
        NamedPipeClientStream pipe = _pipe ?? throw new InvalidOperationException("Not connected.");
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
                await MessageFraming.WriteAsync(pipe, request, ct).ConfigureAwait(false);
            }
            catch (IOException ex)
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

    private async Task ReadLoopAsync(NamedPipeClientStream pipe, CancellationToken ct)
    {
        Exception? error = null;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                IpcMessage? message = await MessageFraming.ReadAsync(pipe, ct).ConfigureAwait(false);
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
        if (_pipe is not null)
            await _pipe.DisposeAsync().ConfigureAwait(false);
        if (_readLoop is not null)
            await _readLoop.ConfigureAwait(false);
        MarkDisconnected(null);
        _cts.Dispose();
        _writeLock.Dispose();
    }
}
