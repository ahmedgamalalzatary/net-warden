using NetWarden.Core.Ipc;

namespace NetWarden.Service;

/// <summary>Runs the pipe server for the lifetime of the host.</summary>
public sealed class IpcHostedService(IpcServer server, ILogger<IpcHostedService> logger) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        server.Start();
        logger.LogInformation("Pipe server started.");
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken) => await server.DisposeAsync();
}
