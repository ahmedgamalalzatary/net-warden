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
