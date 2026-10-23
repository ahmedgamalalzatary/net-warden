using Microsoft.Extensions.Options;
using NetWarden.Core.Ipc;

namespace NetWarden.Service;

/// <summary>Runs the pipe server for the lifetime of the host.</summary>
public sealed class IpcHostedService(
    IpcDispatcher dispatcher,
    IOptions<ServiceOptions> options,
    ILogger<IpcServer> logger) : IHostedService, IAsyncDisposable
{
    private IpcServer? _server;

    public IpcServer? Server => _server;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        ServiceOptions o = options.Value;
        _server = new IpcServer(o.PipeName, dispatcher, logger,
            o.RestrictPipeToAdmins ? PipeSecurityFactory.AdminsAndSystem() : null);
        _server.Start();
        logger.LogInformation("Listening on pipe {PipeName}.", o.PipeName);
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_server is not null)
            await _server.DisposeAsync();
        _server = null;
    }

    public async ValueTask DisposeAsync()
    {
        if (_server is not null)
            await _server.DisposeAsync();
    }
}
