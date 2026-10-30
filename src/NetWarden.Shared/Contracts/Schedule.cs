namespace NetWarden.Shared.Contracts;

public enum ScheduleRepeat
{
    Once,
    EveryDay,
    Days,
    DayOfMonth,
}

/// <summary>
/// Moments in the service computer's time zone, always at <see cref="MinuteOfDay"/>: one <see cref="Date"/>,
/// every day, on <see cref="Days"/>, or on <see cref="DayOfMonth"/> (1-31, clamped to the month's length).
/// </summary>
public sealed record TimeSchedule(
    ScheduleRepeat Repeat,
    int MinuteOfDay = 0,
    DateOnly? Date = null,
    IReadOnlyList<DayOfWeek>? Days = null,
    int DayOfMonth = 1);

public enum ScheduleAction
{
    /// <summary>Enables the rule.</summary>
    Start,
    /// <summary>Disables the rule.</summary>
    Stop,
    /// <summary>Resets the counter of a quota rule.</summary>
    Reset,
    /// <summary>Deletes the rule.</summary>
    Delete,
}

/// <summary>A time condition of a rule: do <see cref="Action"/> at the moments of <see cref="When"/>.</summary>
public sealed record ScheduleCondition(ScheduleAction Action, TimeSchedule When, bool IsEnabled = true);

/// <summary>The persisted scheduler position; moments up to <see cref="LastRun"/> have been handled.</summary>
public sealed class SchedulerState
{
    public DateTimeOffset? LastRun { get; set; }
}
