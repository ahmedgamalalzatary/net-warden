using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Storage;

namespace NetWarden.Core.Rules;

/// <summary>
/// Carries out the time conditions of rules. Every moment between the previous tick and now fires once, so
/// moments missed while the service was stopped apply on start, oldest first, and a manual change made
/// after a moment stays. The last run is saved; a crash at worst repeats the actions since the last save.
/// </summary>
public sealed class RuleScheduler(
    RuleRepository rules,
    JsonFileStore<SchedulerState> store,
    TimeProvider time,
    TimeZoneInfo zone,
    Action<Guid> resetQuota,
    ILogger? logger = null)
{
    private readonly ILogger _logger = logger ?? NullLogger.Instance;
    private DateTimeOffset? _lastRun = store.Load().LastRun;

    public void Tick()
    {
        DateTimeOffset now = time.GetUtcNow();
        if (_lastRun is not { } last || now <= last)
        {
            // First run ever, or the clock went back: nothing has newly passed.
            _lastRun = now;
            return;
        }
        _lastRun = now;

        bool acted = false;
        foreach (var rule in rules.Snapshot().Rules.Select(r => r.Rule).Where(r => r.Schedule is { Count: > 0 }))
        {
            var due = rule.Schedule!
                .Where(c => c.IsEnabled)
                .Select(c => (Condition: c, Moment: TimeSchedules.Last(c.When, now, zone)))
                .Where(d => d.Moment > last)
                .OrderBy(d => d.Moment)
                .ToList();
            foreach (var (condition, _) in due)
            {
                acted = true;
                if (!Apply(rule.Id, condition.Action))
                    break;
            }
        }
        if (acted)
            Save();
    }

    /// <summary>Remembers the last run. A failure is logged; the next save tries again.</summary>
    public void Save()
    {
        try
        {
            store.Save(new SchedulerState { LastRun = _lastRun });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogError(ex, "Could not save the scheduler state.");
        }
    }

    /// <summary>Returns false when the rule is gone afterwards.</summary>
    private bool Apply(Guid ruleId, ScheduleAction action)
    {
        try
        {
            switch (action)
            {
                case ScheduleAction.Start:
                    rules.SetEnabled(ruleId, true);
                    return true;
                case ScheduleAction.Stop:
                    rules.SetEnabled(ruleId, false);
                    return true;
                case ScheduleAction.Reset:
                    resetQuota(ruleId);
                    return true;
                default:
                    rules.DeleteRule(ruleId);
                    return false;
            }
        }
        catch (RuleValidationException ex)
        {
            // The rule changed or went away under us; the other rules still get their turn.
            _logger.LogWarning(ex, "Scheduled {Action} of rule {Rule} failed.", action, ruleId);
            return false;
        }
    }
}
