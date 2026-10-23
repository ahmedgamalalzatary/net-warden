using System.Net;
using System.Net.Sockets;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Rules;
using NetWarden.Shared.Contracts;

namespace NetWarden.Core.Packets;

/// <summary>
/// After rules change, the packet filter only sees new connections. This finds
/// established connections the new rules deny so they can be reset.
/// </summary>
public static class BlockedConnectionSweeper
{
    public static IReadOnlyList<SocketEntry> FindDenied(
        IReadOnlyList<SocketEntry> sockets, CompiledRuleSet rules, ServiceSettings settings,
        FlowContextFactory contexts, DateTimeOffset now)
    {
        var listening = sockets
            .Where(s => s.Protocol == TransportProtocol.Tcp && s.State == TcpState.Listen)
            .Select(s => (s.ProcessId, s.LocalPort))
            .ToHashSet();

        var denied = new List<SocketEntry>();
        foreach (var s in sockets)
        {
            if (s.Protocol != TransportProtocol.Tcp || s.State != TcpState.Established || s.ProcessId == 0 || s.RemoteAddress is null)
                continue;
            // Loopback is never filtered, and Windows can only reset IPv4 connections.
            if (IPAddress.IsLoopback(s.RemoteAddress) || Endpoints.Normalize(s.RemoteAddress).AddressFamily != AddressFamily.InterNetwork)
                continue;
            var kind = listening.Contains((s.ProcessId, s.LocalPort)) ? ConnectionKind.Accept : ConnectionKind.Connect;
            var flow = contexts.Create(s.ProcessId, s.Protocol, kind, s.LocalAddress, s.LocalPort, s.RemoteAddress, s.RemotePort);
            if (flow is null)
                continue;
            if (rules.Evaluate(flow, settings.DefaultFirewallIn, settings.DefaultFirewallOut, now).Firewall == FirewallAction.Deny)
                denied.Add(s);
        }
        return denied;
    }
}
