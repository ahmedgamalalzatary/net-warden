using System.Net;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;

namespace NetWarden.Core.Monitoring;

/// <summary>
/// Remembers which domain name each IP address was last resolved from, so filters
/// can match "domain name is *.example.com" for a connection to that IP.
/// </summary>
public sealed class DnsMap(int capacity = 50_000)
{
    private readonly Dictionary<IPAddress, string> _names = [];
    private readonly Queue<IPAddress> _order = new();
    private readonly Lock _lock = new();

    public int Count
    {
        get { lock (_lock) return _names.Count; }
    }

    public void Record(string name, IEnumerable<IPAddress> addresses)
    {
        name = name.TrimEnd('.');
        if (name.Length == 0)
            return;
        lock (_lock)
        {
            foreach (var raw in addresses)
            {
                var address = Endpoints.Normalize(raw);
                if (!_names.ContainsKey(address))
                    _order.Enqueue(address);
                _names[address] = name;
            }
            while (_names.Count > capacity && _order.TryDequeue(out var oldest))
                _names.Remove(oldest);
        }
    }

    public string? Lookup(IPAddress address)
    {
        lock (_lock)
            return _names.GetValueOrDefault(Endpoints.Normalize(address));
    }

    /// <summary>
    /// Parses the DNS-Client "QueryResults" field, e.g. "type:  5 cdn.example.net;::ffff:93.184.216.34;".
    /// CNAME entries ("type: 5 name") are skipped; only addresses are returned.
    /// </summary>
    public static IEnumerable<IPAddress> ParseQueryResults(string? results)
    {
        if (string.IsNullOrWhiteSpace(results))
            yield break;
        foreach (string part in results.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.StartsWith("type:", StringComparison.OrdinalIgnoreCase))
                continue;
            if (IPAddress.TryParse(part, out var address))
                yield return address;
        }
    }
}

/// <summary>Feeds <see cref="DnsMap"/> from the Microsoft-Windows-DNS-Client ETW provider.</summary>
public sealed class EtwDnsSource(DnsMap map, ILogger<EtwDnsSource> logger, string sessionName = EtwDnsSource.DefaultSessionName) : IDisposable
{
    public const string DefaultSessionName = "NetWarden-Dns";
    private const string ProviderName = "Microsoft-Windows-DNS-Client";
    private const int QueryCompletedEventId = 3008;

    private TraceEventSession? _session;
    private Thread? _thread;

    public void Start()
    {
        _session = new TraceEventSession(sessionName) { StopOnDispose = true };
        _session.EnableProvider(ProviderName, TraceEventLevel.Informational);
        _session.Source.Dynamic.All += OnEvent;
        var session = _session;
        _thread = new Thread(() =>
        {
            try
            {
                session.Source.Process();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "DNS ETW processing stopped.");
            }
        })
        {
            IsBackground = true,
            Name = "NetWarden DNS ETW",
        };
        _thread.Start();
        logger.LogInformation("ETW DNS session {Session} started.", sessionName);
    }

    private void OnEvent(TraceEvent e)
    {
        if ((int)e.ID != QueryCompletedEventId)
            return;
        if (e.PayloadByName("QueryName") is string name && e.PayloadByName("QueryResults") is string results)
            map.Record(name, DnsMap.ParseQueryResults(results));
    }

    public void Dispose()
    {
        _session?.Dispose();
        _thread?.Join(TimeSpan.FromSeconds(5));
        _session = null;
    }
}
