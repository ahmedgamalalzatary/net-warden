using System.Text.Json;

namespace NetWarden.Shared.Ipc;

public enum ConnectionState
{
    Disconnected,
    Connecting,
    Connected,
}

/// <summary>
/// Keeps a <see cref="ServiceClient"/> connected, reconnecting after the service
/// restarts or before it has started. Used by the UI, which should never have to
/// handle reconnection itself.
/// </summary>
public sealed class ServiceConnection : IAsyncDisposable
{
    private readonly string _pipeName;
    private readonly TimeSpan _connectTimeout;
    private readonly TimeSpan _retryDelay;
    private readonly CancellationTokenSource _cts = new();
    private ServiceClient? _client;
    private Task? _loop;

    public ServiceConnection(string pipeName = PipeNames.Default, TimeSpan? connectTimeout = null, TimeSpan? retryDelay = null)
    {
        _pipeName = pipeName;
        _connectTimeout = connectTimeout ?? TimeSpan.FromSeconds(2);
        _retryDelay = retryDelay ?? TimeSpan.FromSeconds(2);
    }

    public ConnectionState State { get; private set; } = ConnectionState.Disconnected;

    /// <summary>Why the last attempt failed, in words a user can act on.</summary>
    public string? LastError { get; private set; }

    public event Action<ConnectionState>? StateChanged;
    public event Action<string, JsonElement?>? EventReceived;

    public void Start()
    {
        if (_loop is not null)
            throw new InvalidOperationException("Already started.");
        _loop = Task.Run(() => RunAsync(_cts.Token));
    }

    public Task<T?> RequestAsync<T>(string method, object? payload = null, CancellationToken ct = default)
    {
        ServiceClient client = Volatile.Read(ref _client) is { IsConnected: true } c
            ? c
            : throw new IpcDisconnectedException("Not connected to the service.");
        return client.RequestAsync<T>(method, payload, ct);
    }

    private async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            SetState(ConnectionState.Connecting);
            var client = new ServiceClient(_pipeName);
            var lost = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            client.Disconnected += _ => lost.TrySetResult();
            client.EventReceived += (m, p) => EventReceived?.Invoke(m, p);

            try
            {
                await client.ConnectAsync(_connectTimeout, ct).ConfigureAwait(false);
                LastError = null;
                Volatile.Write(ref _client, client);
                SetState(ConnectionState.Connected);
                await lost.Task.WaitAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
            }
            catch (TimeoutException)
            {
                LastError = "The NetWarden service is not running.";
            }
            catch (UnauthorizedAccessException)
            {
                LastError = "Access denied. Run NetWarden as administrator.";
            }
            catch (IOException ex)
            {
                LastError = ex.Message;
            }

            Volatile.Write(ref _client, null);
            await client.DisposeAsync().ConfigureAwait(false);
            SetState(ConnectionState.Disconnected);

            try
            {
                await Task.Delay(_retryDelay, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private void SetState(ConnectionState state)
    {
        if (State == state)
            return;
        State = state;
        StateChanged?.Invoke(state);
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        if (_loop is not null)
            await _loop.ConfigureAwait(false);
        _cts.Dispose();
    }
}
