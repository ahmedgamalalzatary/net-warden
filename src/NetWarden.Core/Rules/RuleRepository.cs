using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Storage;

namespace NetWarden.Core.Rules;

/// <summary>
/// Owns the filter and rule configuration: validates changes, persists them and
/// publishes a freshly compiled <see cref="CompiledRuleSet"/> after each one.
/// </summary>
public sealed class RuleRepository
{
    public const int WholeComputerWeight = 1;
    public const int ZoneWeight = 2;
    public const int FilterWeight = 3;

    private readonly JsonFileStore<RulesDocument> _store;
    private readonly ZoneClassifier _zones;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly Lock _lock = new();
    private RulesDocument _document;
    private CompiledRuleSet _compiled = CompiledRuleSet.Empty;
    private long _generation;

    public RuleRepository(JsonFileStore<RulesDocument> store, ZoneClassifier zones, TimeProvider time, ILogger? logger = null)
    {
        _store = store;
        _zones = zones;
        _time = time;
        _logger = logger ?? NullLogger.Instance;
        _document = store.Load();
        bool firstRun = !File.Exists(store.FilePath) && !File.Exists(store.BackupPath);
        EnsurePredefined(_document, firstRun);
        Recompile();
    }

    /// <summary>Raised after every successful change, with the new generation.</summary>
    public event Action<long>? Changed;

    public CompiledRuleSet Current => Volatile.Read(ref _compiled);

    public RulesSnapshot Snapshot()
    {
        lock (_lock)
        {
            DateTimeOffset now = _time.GetUtcNow();
            var filters = _document.Filters.ToList();
            var views = _document.Rules.Select(r =>
            {
                var filter = filters.First(f => f.Id == r.FilterId);
                return new RuleView(r, StateOf(r, now), EffectiveWeight(r, filter), filter.Name);
            }).ToList();
            return new RulesSnapshot(_generation, filters, views);
        }
    }

    public FilterDefinition SaveFilter(FilterDefinition filter)
    {
        lock (_lock)
        {
            DateTimeOffset now = _time.GetUtcNow();
            int index = _document.Filters.FindIndex(f => f.Id == filter.Id);
            if (index >= 0 && _document.Filters[index].IsPredefined)
                throw new RuleValidationException("Predefined filters can't be changed.");

            var saved = filter with
            {
                Id = filter.Id == Guid.Empty ? Guid.NewGuid() : filter.Id,
                Name = filter.Name.Trim(),
                IsPredefined = false,
                Created = index >= 0 ? _document.Filters[index].Created : now,
                Updated = now,
            };
            var candidate = _document.Filters.Where(f => f.Id != saved.Id).Append(saved).ToList();
            RuleValidator.ValidateFilter(saved, candidate);

            var next = Clone();
            if (index >= 0)
                next.Filters[index] = saved;
            else
                next.Filters.Add(saved);
            Commit(next);
            return saved;
        }
    }

    public void DeleteFilter(Guid id)
    {
        lock (_lock)
        {
            var filter = _document.Filters.FirstOrDefault(f => f.Id == id)
                ?? throw new RuleValidationException($"Filter {id} not found.");
            if (filter.IsPredefined)
                throw new RuleValidationException("Predefined filters can't be deleted.");
            if (_document.Filters.FirstOrDefault(f => f.BaseFilterIds.Contains(id)) is { } user)
                throw new RuleValidationException($"Filter '{filter.Name}' is a base filter of '{user.Name}'.");

            var next = Clone();
            next.Filters.RemoveAll(f => f.Id == id);
            // Rules belong to their filter and go with it, as in NetLimiter.
            next.Rules.RemoveAll(r => r.FilterId == id);
            Commit(next);
        }
    }

    /// <summary>Returns the filter matching exactly this app, creating it if needed.</summary>
    public FilterDefinition EnsureAppFilter(string appId, string displayName)
    {
        lock (_lock)
        {
            var existing = _document.Filters.FirstOrDefault(f =>
                f.Type == FilterType.Filter && f.Functions.Count == 1
                && f.Functions[0] is { Kind: FilterFunctionKind.AppId, Match: true, Values: [var v] }
                && string.Equals(v, appId, StringComparison.OrdinalIgnoreCase));
            if (existing is not null)
                return existing;

            // Names are unique; disambiguate apps that share a display name.
            string name = displayName.Trim();
            for (int n = 2; _document.Filters.Any(f => string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase)); n++)
                name = $"{displayName.Trim()} ({n})";
            if (name.Length > RuleValidator.MaxNameLength)
                name = name[..RuleValidator.MaxNameLength];

            return SaveFilter(new FilterDefinition(Guid.Empty, name, FilterType.Filter, FilterPerType.None,
                [new FilterFunction(FilterFunctionKind.AppId, true, [appId])], []));
        }
    }

    public RuleDefinition SaveRule(RuleDefinition rule)
    {
        lock (_lock)
        {
            DateTimeOffset now = _time.GetUtcNow();
            int index = _document.Rules.FindIndex(r => r.Id == rule.Id);
            var saved = rule with
            {
                Id = rule.Id == Guid.Empty ? Guid.NewGuid() : rule.Id,
                Created = index >= 0 ? _document.Rules[index].Created : now,
                Updated = now,
            };
            RuleValidator.ValidateRule(saved, _document.Filters);

            var next = Clone();
            if (index >= 0)
                next.Rules[index] = saved;
            else
                next.Rules.Add(saved);
            Commit(next);
            return saved;
        }
    }

    public void DeleteRule(Guid id)
    {
        lock (_lock)
        {
            if (_document.Rules.All(r => r.Id != id))
                throw new RuleValidationException($"Rule {id} not found.");
            var next = Clone();
            next.Rules.RemoveAll(r => r.Id == id);
            Commit(next);
        }
    }

    public void SetEnabled(Guid id, bool enabled)
    {
        lock (_lock)
        {
            var rule = _document.Rules.FirstOrDefault(r => r.Id == id)
                ?? throw new RuleValidationException($"Rule {id} not found.");
            if (rule.IsEnabled == enabled)
                return;
            SaveRule(rule with { IsEnabled = enabled });
        }
    }

    /// <summary>Reorders rules; ids not listed keep their relative order after the listed ones.</summary>
    public void Reorder(IReadOnlyList<Guid> ids)
    {
        lock (_lock)
        {
            var next = Clone();
            var byId = next.Rules.ToDictionary(r => r.Id);
            if (ids.Any(id => !byId.ContainsKey(id)) || ids.Distinct().Count() != ids.Count)
                throw new RuleValidationException("Rule order contains unknown or duplicate ids.");
            next.Rules = ids.Select(id => byId[id]).Concat(next.Rules.Where(r => !ids.Contains(r.Id))).ToList();
            Commit(next);
        }
    }

    /// <summary>Deletes rules whose expiry passed (temporary blocker answers). Returns how many.</summary>
    public int RemoveExpired()
    {
        lock (_lock)
        {
            DateTimeOffset now = _time.GetUtcNow();
            if (!_document.Rules.Any(r => r.ExpiresAt <= now))
                return 0;
            var next = Clone();
            int removed = next.Rules.RemoveAll(r => r.ExpiresAt <= now);
            Commit(next);
            return removed;
        }
    }

    public static int EffectiveWeight(RuleDefinition rule, FilterDefinition filter) =>
        rule.Weight != 0 ? rule.Weight
        : filter.Type == FilterType.Zone ? ZoneWeight
        : filter.Type == FilterType.Filter && filter.Functions.Count == 0 ? WholeComputerWeight
        : FilterWeight;

    public static RuleState StateOf(RuleDefinition rule, DateTimeOffset now) =>
        !rule.IsEnabled ? RuleState.Disabled
        : rule.ExpiresAt is { } expires && expires <= now ? RuleState.Inactive
        : RuleState.Active;

    private void Commit(RulesDocument next)
    {
        _store.Save(next);
        _document = next;
        Recompile();
        Changed?.Invoke(_generation);
    }

    private void Recompile()
    {
        _generation++;
        var filters = _document.Filters.ToDictionary(f => f.Id, f => new CompiledFilter(f, _zones));
        var rules = _document.Rules
            .Where(r => filters.ContainsKey(r.FilterId))
            .Select(r => new CompiledRule(r, EffectiveWeight(r, filters[r.FilterId].Definition)))
            .ToList();
        Volatile.Write(ref _compiled, new CompiledRuleSet(_generation, filters, rules));
    }

    private RulesDocument Clone() => new()
    {
        SchemaVersion = RulesDocument.CurrentSchemaVersion,
        Filters = [.. _document.Filters],
        Rules = [.. _document.Rules],
    };

    private void EnsurePredefined(RulesDocument document, bool firstRun)
    {
        bool changed = false;
        foreach (var predefined in PredefinedFilters.All)
        {
            int index = document.Filters.FindIndex(f => f.Id == predefined.Id);
            if (index < 0)
            {
                document.Filters.Insert(Math.Min(PredefinedFilters.All.ToList().IndexOf(predefined), document.Filters.Count), predefined);
                changed = true;
            }
            else if (!document.Filters[index].IsPredefined || document.Filters[index].Functions.Count != predefined.Functions.Count)
            {
                // Someone edited the file by hand; predefined filters are not user data.
                document.Filters[index] = predefined;
                changed = true;
            }
        }
        if (firstRun)
        {
            document.Rules.AddRange(PredefinedFilters.DefaultRules.Where(d => document.Rules.All(r => r.Id != d.Id)));
            changed = true;
        }
        // Drop rules pointing at filters that no longer exist (hand-edited or corrupt files).
        int orphans = document.Rules.RemoveAll(r => document.Filters.All(f => f.Id != r.FilterId));
        if (orphans > 0)
            _logger.LogWarning("Removed {Count} rules whose filters no longer exist.", orphans);
        if (changed || orphans > 0)
        {
            try
            {
                _store.Save(document);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _logger.LogError(ex, "Could not save the initial rules file.");
            }
        }
    }
}
