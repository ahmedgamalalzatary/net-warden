using NetWarden.Shared.Contracts;

namespace NetWarden.Core.Rules;

/// <summary>Finds the moments of a <see cref="TimeSchedule"/> around a point in time.</summary>
public static class TimeSchedules
{
    /// <summary>Long enough to reach any repeating schedule's neighbouring moment (next day of month, clamped).</summary>
    private const int SearchDays = 63;

    /// <summary>The latest moment at or before <paramref name="now"/>, or null if there is none yet.</summary>
    public static DateTimeOffset? Last(TimeSchedule schedule, DateTimeOffset now, TimeZoneInfo zone)
    {
        if (schedule.Repeat == ScheduleRepeat.Once)
            return OnceMoment(schedule, zone) is { } once && once <= now ? once : null;
        DateTime today = TimeZoneInfo.ConvertTime(now, zone).Date;
        for (int i = 0; i <= SearchDays; i++)
        {
            DateTime day = today.AddDays(-i);
            if (Occurs(schedule, day) && At(day, schedule, zone) is var moment && moment <= now)
                return moment;
        }
        return null;
    }

    /// <summary>The first moment after <paramref name="now"/>, or null if there is none.</summary>
    public static DateTimeOffset? Next(TimeSchedule schedule, DateTimeOffset now, TimeZoneInfo zone)
    {
        if (schedule.Repeat == ScheduleRepeat.Once)
            return OnceMoment(schedule, zone) is { } once && once > now ? once : null;
        DateTime today = TimeZoneInfo.ConvertTime(now, zone).Date;
        for (int i = 0; i <= SearchDays; i++)
        {
            DateTime day = today.AddDays(i);
            if (Occurs(schedule, day) && At(day, schedule, zone) is var moment && moment > now)
                return moment;
        }
        return null;
    }

    private static DateTimeOffset? OnceMoment(TimeSchedule schedule, TimeZoneInfo zone) =>
        schedule.Date is { } date ? At(date.ToDateTime(TimeOnly.MinValue), schedule, zone) : null;

    private static bool Occurs(TimeSchedule schedule, DateTime day) => schedule.Repeat switch
    {
        ScheduleRepeat.EveryDay => true,
        ScheduleRepeat.Days => schedule.Days?.Contains(day.DayOfWeek) == true,
        ScheduleRepeat.DayOfMonth => day.Day == Math.Min(schedule.DayOfMonth, DateTime.DaysInMonth(day.Year, day.Month)),
        _ => false,
    };

    private static DateTimeOffset At(DateTime day, TimeSchedule schedule, TimeZoneInfo zone)
    {
        DateTime wall = DateTime.SpecifyKind(day.AddMinutes(schedule.MinuteOfDay), DateTimeKind.Unspecified);
        return new DateTimeOffset(wall, zone.GetUtcOffset(wall));
    }
}
