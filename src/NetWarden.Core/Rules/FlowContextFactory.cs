using System.Net;
using NetWarden.Core.Apps;
using NetWarden.Core.Monitoring;
using NetWarden.Shared.Contracts;

namespace NetWarden.Core.Rules;

/// <summary>Builds a <see cref="FlowContext"/> for a socket from process, user and DNS knowledge.</summary>
public sealed class FlowContextFactory(Func<int, AppInfo?> resolveApp, Func<int, ProcessUser?> resolveUser, DnsMap dns)
{
    public AppInfo? ResolveApp(int processId) => resolveApp(processId);

    public FlowContext? Create(int processId, TransportProtocol protocol, ConnectionKind kind,
        IPAddress local, int localPort, IPAddress remote, int remotePort)
    {
        AppInfo? app = resolveApp(processId);
        if (app is null)
            return null;
        ProcessUser? user = resolveUser(processId);
        return new FlowContext(app.Id, app.Path, processId, protocol, kind,
            Endpoints.Normalize(local), localPort, Endpoints.Normalize(remote), remotePort,
            dns.Lookup(remote), user?.Sid, user?.Name);
    }
}
