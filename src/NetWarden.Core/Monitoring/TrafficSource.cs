using System.Net;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;
using NetWarden.Shared.Contracts;

namespace NetWarden.Core.Monitoring;

public enum TrafficDirection
{
    In,
    Out,
}

/// <summary>Payload bytes sent or received by a process on one socket.</summary>
public readonly record struct TrafficEvent(
    int ProcessId,
    TransportProtocol Protocol,
    TrafficDirection Direction,
    int Bytes,
    IPAddress LocalAddress,
    int LocalPort,
    IPAddress RemoteAddress,
    int RemotePort);

public interface ITrafficSource : IDisposable
{
    event Action<TrafficEvent>? Traffic;
    void Start();
}

/// <summary>
/// Kernel TCP/IP events via ETW. In these events saddr/sport are always the local
/// end and daddr/dport the remote end, for both send and receive.
/// </summary>
public sealed class EtwTrafficSource(ILogger<EtwTrafficSource> logger, string sessionName = EtwTrafficSource.DefaultSessionName) : ITrafficSource
{
    public const string DefaultSessionName = "NetWarden-Traffic";

    private TraceEventSession? _session;
    private Thread? _thread;

    public event Action<TrafficEvent>? Traffic;

    public void Start()
    {
        if (_session is not null)
            throw new InvalidOperationException("Already started.");

        // Creating a session with an existing name stops the stale one (e.g. after a crash).
        _session = new TraceEventSession(sessionName) { StopOnDispose = true };
        _session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);

        var kernel = _session.Source.Kernel;
        kernel.TcpIpSend += e => Emit(TransportProtocol.Tcp, TrafficDirection.Out, e.ProcessID, e.size, e.saddr, e.sport, e.daddr, e.dport);
        kernel.TcpIpRecv += e => Emit(TransportProtocol.Tcp, TrafficDirection.In, e.ProcessID, e.size, e.saddr, e.sport, e.daddr, e.dport);
        kernel.TcpIpSendIPV6 += e => Emit(TransportProtocol.Tcp, TrafficDirection.Out, e.ProcessID, e.size, e.saddr, e.sport, e.daddr, e.dport);
        kernel.TcpIpRecvIPV6 += e => Emit(TransportProtocol.Tcp, TrafficDirection.In, e.ProcessID, e.size, e.saddr, e.sport, e.daddr, e.dport);
        kernel.UdpIpSend += e => Emit(TransportProtocol.Udp, TrafficDirection.Out, e.ProcessID, e.size, e.saddr, e.sport, e.daddr, e.dport);
        kernel.UdpIpRecv += e => Emit(TransportProtocol.Udp, TrafficDirection.In, e.ProcessID, e.size, e.saddr, e.sport, e.daddr, e.dport);
        kernel.UdpIpSendIPV6 += e => Emit(TransportProtocol.Udp, TrafficDirection.Out, e.ProcessID, e.size, e.saddr, e.sport, e.daddr, e.dport);
        kernel.UdpIpRecvIPV6 += e => Emit(TransportProtocol.Udp, TrafficDirection.In, e.ProcessID, e.size, e.saddr, e.sport, e.daddr, e.dport);

        var session = _session;
        _thread = new Thread(() =>
        {
            try
            {
                session.Source.Process();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "ETW processing stopped.");
            }
        })
        {
            IsBackground = true,
            Name = "NetWarden ETW",
        };
        _thread.Start();
        logger.LogInformation("ETW traffic session {Session} started.", sessionName);
    }

    private void Emit(TransportProtocol protocol, TrafficDirection direction, int pid, int size,
        IPAddress local, int localPort, IPAddress remote, int remotePort)
    {
        if (size <= 0)
            return;
        Traffic?.Invoke(new TrafficEvent(pid, protocol, direction, size, local, localPort, remote, remotePort));
    }

    public void Dispose()
    {
        _session?.Dispose();
        _thread?.Join(TimeSpan.FromSeconds(5));
        _session = null;
    }
}

/// <summary>Produces no traffic; used when ETW is disabled (tests).</summary>
public sealed class NullTrafficSource : ITrafficSource
{
    public event Action<TrafficEvent>? Traffic { add { } remove { } }
    public void Start() { }
    public void Dispose() { }
}
