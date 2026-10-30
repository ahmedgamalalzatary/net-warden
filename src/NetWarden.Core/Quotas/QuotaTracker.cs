using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Rules;
using NetWarden.Core.Stats;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Storage;

namespace NetWarden.Core.Quotas;

/// <summary>
/// Counts the traffic of quota rules and applies their overflow actions. A quota counts all traffic of
/// its filter together. <see cref="Tick"/> handles period resets and overflow changes; state is saved on
/// every such change and whenever <see cref="Save"/> is called, so a crash loses at most the latest counts.
/// </summary>
public sealed class QuotaTracker
{
    private readonly RuleRepository _rules;
    private readonly FlowContextFactory _flows;
    private readonly JsonFileStore<QuotaDocument> _store;
    private readonly TimeProvider _time;
    private readonly TimeZoneInfo _zone;
    private readonly ILogger _logger;
    private readonly Lock _lock = new();
    private readonly Dictionary<Guid, QuotaState> _states;
    private readonly Dictionary<string, Facts> _facts = new(StringComparer.Ordinal);
    private bool _dirty;

    public QuotaTracker(RuleRepository rules, FlowContextFactory flows, JsonFileStore<QuotaDocument> store,
        TimeProvider time, TimeZoneInfo zone, ILogger? logger = null)
    {
        _rules = rules;
        _flows = flows;
        _store = store;
        _time = time;
        _zone = zone;
        _logger = logger ?? NullLogger.Instance;
        _states = store.Load().Quotas.ToDictionary(q => q.RuleId);
    }

    /// <summary>Raised when a quota overflows, after its rules were enabled. Outside the tracker's lock.</summary>
    public event Action<RuleDefinition, QuotaAlert>? Exceeded;

    public void Add(IReadOnlyList<FlowTraffic> traffic)
    {
        CompiledRuleSet ruleSet = _rules.Current;
        if (ruleSet.QuotaRules.Count == 0 || traffic.Count == 0)
            return;
        lock (_lock)
        {
            foreach (var t in traffic)
            {
                if (t.In == 0 && t.Out == 0)
                    continue;
                foreach (var quota in FactsFor(t, ruleSet).Quotas)
                {
                    long bytes = quota.Direction switch
                    {
                        RuleDirection.In => t.In,
                        RuleDirection.Out => t.Out,
                        _ => t.In + t.Out,
                    };
                    if (bytes == 0)
                        continue;
                    StateOf(quota).Used += bytes;
                    _dirty = true;
                }
            }
        }
    }

    /// <summary>Applies period resets and starts or ends overflows.</summary>
    public void Tick()
    {
        var exceeded = new List<(RuleDefinition, QuotaAlert)>();
        lock (_lock)
        {
            DateTimeOffset now = _time.GetUtcNow();
            bool changed = false;
            IReadOnlyList<RuleDefinition> quotas = _rules.Current.QuotaRules;

            foreach (var gone in _states.Values.Where(s => quotas.All(q => q.Id != s.RuleId)).ToList())
            {
                Release(gone);
                _states.Remove(gone.RuleId);
                changed = true;
            }

            foreach (var quota in quotas)
            {
                QuotaState state = StateOf(quota);
                DateTimeOffset? last = quota.QuotaReset is { } reset ? TimeSchedules.Last(reset, now, _zone) : null;
                if (last != state.LastReset)
                {
                    // A later moment passed: new period. Otherwise the schedule was edited or the clock
                    // went back, which must not throw the count away.
                    if (last > (state.LastReset ?? DateTimeOffset.MinValue))
                        state.Used = 0;
                    state.LastReset = last;
                    changed = true;
                }

                bool over = quota.IsEnabled && state.Used >= quota.QuotaBytes;
                if (over && state.OverflowedAt is null)
                {
                    state.OverflowedAt = now;
                    Enable(quota, state);
                    exceeded.Add((quota, new QuotaAlert(quota.Id, FilterName(quota), state.Used, quota.QuotaBytes ?? 0, now)));
                    changed = true;
                }
                else if (!over && state.OverflowedAt is not null)
                {
                    Release(state);
                    changed = true;
                }
            }

            if (changed)
            {
                _dirty = true;
                Save();
            }
        }
        foreach (var (rule, alert) in exceeded)
            Exceeded?.Invoke(rule, alert);
    }

    /// <summary>Writes the counters if they changed. A failure is logged and retried on the next save.</summary>
    public void Save()
    {
        lock (_lock)
        {
            if (!_dirty)
                return;
            try
            {
                _store.Save(new QuotaDocument { Quotas = [.. _states.Values] });
                _dirty = false;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _logger.LogError(ex, "Could not save the quota counters.");
            }
        }
    }

    public IReadOnlyList<QuotaStatus> Status()
    {
        lock (_lock)
        {
            DateTimeOffset now = _time.GetUtcNow();
            return _rules.Current.QuotaRules.Select(q =>
            {
                _states.TryGetValue(q.Id, out var state);
                return new QuotaStatus(q.Id, q.FilterId, FilterName(q), q.Direction, q.IsEnabled, state?.Used ?? 0, q.QuotaBytes ?? 0,
                    q.QuotaReset, q.QuotaReset is { } reset ? TimeSchedules.Next(reset, now, _zone) : null, state?.OverflowedAt);
            }).ToList();
        }
    }

    /// <summary>Puts a quota's counter back to zero and ends its overflow.</summary>
    public void Reset(Guid ruleId)
    {
        lock (_lock)
        {
            QuotaState state = StateOf(Require(ruleId));
            state.Used = 0;
            Release(state);
            _dirty = true;
            Save();
        }
    }

    /// <summary>When the current period of a quota started (null = no reset yet), for reading its usage from the statistics.</summary>
    public DateTimeOffset? PeriodStart(Guid ruleId) =>
        Require(ruleId).QuotaReset is { } reset ? TimeSchedules.Last(reset, _time.GetUtcNow(), _zone) : null;

    /// <summary>
    /// Sets a quota's counter from statistics of its current period. Stats know no process or local endpoint,
    /// so filters testing those see pid 0, an unspecified local address and the service port as remote port.
    /// </summary>
    public void InitFromStats(Guid ruleId, IReadOnlyList<StatsFlowSummary> rows)
    {
        var quota = Require(ruleId);
        CompiledRuleSet ruleSet = _rules.Current;
        long used = 0;
        foreach (var row in rows)
        {
            var remote = IPAddress.TryParse(row.Address, out var address) ? address : IPAddress.Any;
            var flow = new FlowContext(row.AppId, row.AppPath, 0, row.Protocol, ConnectionKind.Connect, IPAddress.Any, 0,
                remote, row.Port, row.HostName, row.UserSid);
            if (!ruleSet.Matches(quota.FilterId, flow))
                continue;
            used += quota.Direction switch
            {
                RuleDirection.In => row.In,
                RuleDirection.Out => row.Out,
                _ => row.In + row.Out,
            };
        }
        lock (_lock)
        {
            StateOf(quota).Used = used;
            _dirty = true;
            Save();
        }
    }

    private RuleDefinition Require(Guid ruleId) =>
        _rules.Current.QuotaRules.FirstOrDefault(q => q.Id == ruleId)
            ?? throw new RuleValidationException($"Quota {ruleId} not found.");

    private QuotaState StateOf(RuleDefinition quota)
    {
        if (!_states.TryGetValue(quota.Id, out var state))
        {
            state = new QuotaState
            {
                RuleId = quota.Id,
                LastReset = quota.QuotaReset is { } reset ? TimeSchedules.Last(reset, _time.GetUtcNow(), _zone) : null,
            };
            _states[quota.Id] = state;
            _dirty = true;
        }
        return state;
    }

    private void Enable(RuleDefinition quota, QuotaState state)
    {
        var all = _rules.Snapshot().Rules;
        foreach (Guid id in quota.OverflowRuleIds ?? [])
        {
            if (all.FirstOrDefault(r => r.Rule.Id == id) is not { Rule.IsEnabled: false })
                continue;
            _rules.SetEnabled(id, true);
            state.EnabledRuleIds.Add(id);
        }
    }

    private void Release(QuotaState state)
    {
        state.OverflowedAt = null;
        var all = _rules.Snapshot().Rules;
        foreach (Guid id in state.EnabledRuleIds)
            if (all.Any(r => r.Rule.Id == id))
                _rules.SetEnabled(id, false);
        state.EnabledRuleIds.Clear();
    }

    private string FilterName(RuleDefinition quota) =>
        _rules.Snapshot().Filters.FirstOrDefault(f => f.Id == quota.FilterId)?.Name ?? "";

    private Facts FactsFor(FlowTraffic t, CompiledRuleSet ruleSet)
    {
        string id = $"{t.ProcessId}|{t.Protocol}|{t.LocalAddress}|{t.LocalPort}|{t.RemoteAddress}|{t.RemotePort}";
        if (_facts.TryGetValue(id, out var known) && known.Generation == ruleSet.Generation && t.Time - known.Created < StatsRecorder.FactsLifetime)
            return known;

        if (_facts.Count > 20_000)
            _facts.Clear();
        IPAddress remote = t.RemoteAddress is { } r && !Endpoints.IsUnspecified(r) ? r : IPAddress.Any;
        FlowContext? flow = _flows.Create(t.ProcessId, t.Protocol, t.Kind, t.LocalAddress, t.LocalPort, remote, t.RemotePort);
        IReadOnlyList<RuleDefinition> quotas = flow is null
            || ruleSet.Evaluate(flow, FirewallAction.Allow, FirewallAction.Allow, t.Time).IgnoreData
            ? [] : ruleSet.MatchingQuotas(flow, t.Time);
        return _facts[id] = new Facts(quotas, ruleSet.Generation, t.Time);
    }

    private sealed record Facts(IReadOnlyList<RuleDefinition> Quotas, long Generation, DateTimeOffset Created);
}
