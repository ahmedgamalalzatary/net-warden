using System.Net;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Rules;
using NetWarden.Shared.Contracts;

namespace NetWarden.Core.Stats;

/// <summary>
/// Collects the traffic of every monitor tick into per-minute records until they are drained
/// into the database. Skips zones the settings don't save and flows an "ignore data" rule matches.
/// </summary>
public sealed class StatsRecorder(
    Func<CompiledRuleSet> rules,
    Func<ServiceSettings> settings,
    FlowContextFactory flows,
    ZoneClassifier zones)
{
    /// <summary>What is known about a flow is looked up again after this long (DNS names arrive late).</summary>
    public static readonly TimeSpan FactsLifetime = TimeSpan.FromSeconds(60);

    private readonly Lock _lock = new();
    private Dictionary<Key, (long In, long Out)> _pending = [];
    private readonly Dictionary<string, AppInfo> _apps = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string?> _hostNames = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string?> _userNames = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Facts> _facts = new(StringComparer.Ordinal);

    /// <summary>Number of records waiting to be drained.</summary>
    public int PendingCount
    {
        get
        {
            lock (_lock)
                return _pending.Count;
        }
    }

    public void Add(IReadOnlyList<FlowTraffic> traffic)
    {
        ServiceSettings s = settings();
        if (!s.IsStatsEnabled || traffic.Count == 0)
            return;
        CompiledRuleSet ruleSet = rules();
        lock (_lock)
        {
            foreach (var t in traffic)
            {
                if (t.In == 0 && t.Out == 0)
                    continue;
                Facts facts = FactsFor(t, ruleSet);
                if (facts.IgnoreData || !s.Stats.Saves(facts.Zone))
                    continue;
                long slot = t.Time.ToUnixTimeSeconds();
                slot -= slot % 60;
                var key = new Key(slot, t.App.Id, facts.Address, facts.Port, t.Protocol, facts.Zone, facts.UserSid);
                var sum = _pending.GetValueOrDefault(key);
                _pending[key] = (sum.In + t.In, sum.Out + t.Out);
                _apps[t.App.Id] = t.App;
                if (facts.HostName is not null || !_hostNames.ContainsKey(facts.Address))
                    _hostNames[facts.Address] = facts.HostName;
                if (facts.UserName is not null || !_userNames.ContainsKey(facts.UserSid))
                    _userNames[facts.UserSid] = facts.UserName;
            }
        }
    }

    /// <summary>Takes every collected record, leaving the recorder empty.</summary>
    public List<StatsRecord> Drain()
    {
        lock (_lock)
        {
            var records = new List<StatsRecord>(_pending.Count);
            foreach (var (k, sum) in _pending)
                records.Add(new StatsRecord(k.Slot, _apps[k.AppId], k.Address, _hostNames.GetValueOrDefault(k.Address), k.Port,
                    k.Protocol, k.Zone, k.UserSid, _userNames.GetValueOrDefault(k.UserSid), sum.In, sum.Out));
            _pending = [];
            _apps.Clear();
            _hostNames.Clear();
            _userNames.Clear();
            return records;
        }
    }

    /// <summary>
    /// The service port: the remote port of outgoing TCP, the local port of incoming TCP, and the
    /// lower of the two for UDP (well-known ports are low; the other side is usually ephemeral).
    /// </summary>
    internal static int ServicePort(FlowTraffic t)
    {
        if (t.Protocol == TransportProtocol.Tcp)
            return t.Kind == ConnectionKind.Connect ? t.RemotePort : t.LocalPort;
        return t.RemoteAddress is null || t.RemotePort == 0 ? t.LocalPort
            : t.LocalPort == 0 ? t.RemotePort
            : Math.Min(t.LocalPort, t.RemotePort);
    }

    internal StatsZone ZoneOf(FlowTraffic t)
    {
        if (t.RemoteAddress is not { } remote || Endpoints.IsUnspecified(remote))
            return IPAddress.IsLoopback(Endpoints.Normalize(t.LocalAddress)) ? StatsZone.Loopback : StatsZone.Internet;
        return ZoneClassifier.IsLoopback(remote, t.LocalAddress) ? StatsZone.Loopback
            : zones.IsLocalNetwork(remote, t.LocalAddress) ? StatsZone.LocalNetwork
            : StatsZone.Internet;
    }

    private Facts FactsFor(FlowTraffic t, CompiledRuleSet ruleSet)
    {
        string id = $"{t.ProcessId}|{t.Protocol}|{t.LocalAddress}|{t.LocalPort}|{t.RemoteAddress}|{t.RemotePort}";
        if (_facts.TryGetValue(id, out var known) && known.Generation == ruleSet.Generation && t.Time - known.Created < FactsLifetime)
            return known;

        if (_facts.Count > 20_000)
            _facts.Clear();
        IPAddress? remote = t.RemoteAddress is { } r && !Endpoints.IsUnspecified(r) ? Endpoints.Normalize(r) : null;
        FlowContext? flow = flows.Create(t.ProcessId, t.Protocol, t.Kind, t.LocalAddress, t.LocalPort,
            remote ?? IPAddress.Any, t.RemotePort);
        bool ignore = flow is not null
            && ruleSet.Evaluate(flow, FirewallAction.Allow, FirewallAction.Allow, t.Time).IgnoreData;
        var facts = new Facts(
            remote?.ToString() ?? "",
            remote is null ? null : flow?.RemoteHost,
            ServicePort(t),
            ZoneOf(t),
            flow?.UserSid ?? "",
            flow?.UserName,
            ignore,
            ruleSet.Generation,
            t.Time);
        _facts[id] = facts;
        return facts;
    }

    private readonly record struct Key(long Slot, string AppId, string Address, int Port, TransportProtocol Protocol, StatsZone Zone, string UserSid);

    private sealed record Facts(string Address, string? HostName, int Port, StatsZone Zone, string UserSid, string? UserName,
        bool IgnoreData, long Generation, DateTimeOffset Created);
}
