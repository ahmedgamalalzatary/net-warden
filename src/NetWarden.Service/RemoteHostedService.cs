using NetWarden.Core.Ipc;

namespace NetWarden.Service;

/// <summary>Opens remote administration, if it is on, once the pipe server runs; closes it on stop.</summary>
public sealed class RemoteHostedService(RemoteAdmin remote) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        _ = remote.Status();
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken) => await remote.DisposeAsync();
}
