using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetWarden.Shared.Contracts;

namespace NetWarden.Client.ViewModels;

public sealed partial class FunctionItem : ObservableObject
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TakesValues), nameof(Hint))]
    private FilterFunctionKind _kind = FilterFunctionKind.RemoteAddressInRange;

    /// <summary>False means "is not".</summary>
    [ObservableProperty]
    private bool _match = true;

    /// <summary>Values separated by new lines or commas.</summary>
    [ObservableProperty]
    private string _valuesText = "";

    public bool TakesValues => RuleText.TakesValues(Kind);
    public string Hint => RuleText.ValueHint(Kind);

    public static FunctionItem From(FilterFunction f) =>
        new() { Kind = f.Kind, Match = f.Match, ValuesText = string.Join(Environment.NewLine, f.Values ?? []) };

    public FilterFunction ToFunction()
    {
        // Addresses, ports, protocols and pids never contain commas, so commas separate them too;
        // paths, users and domains can, so only new lines separate those.
        char[] separators = Kind is FilterFunctionKind.RemoteAddressInRange or FilterFunctionKind.LocalAddressInRange
            or FilterFunctionKind.RemotePortInRange or FilterFunctionKind.LocalPortInRange
            or FilterFunctionKind.Protocol or FilterFunctionKind.ProcessId
            ? ['\r', '\n', ',']
            : ['\r', '\n'];
        var values = TakesValues
            ? ValuesText.Split(separators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : [];
        return new FilterFunction(Kind, Match, values.Length == 0 ? null : values);
    }
}

public sealed partial class BaseFilterChoice(FilterDefinition filter, bool selected) : ObservableObject
{
    public FilterDefinition Filter { get; } = filter;
    public string Name => Filter.Name;

    [ObservableProperty]
    private bool _isSelected = selected;
}

/// <summary>Create or edit one filter. Validation is authoritative on the service; this only catches the obvious.</summary>
public sealed partial class FilterEditorViewModel : ObservableObject
{
    private readonly FilterDefinition? _original;

    public FilterEditorViewModel(FilterDefinition? original, IReadOnlyList<FilterDefinition> allFilters)
    {
        _original = original;
        _name = original?.Name ?? "";
        _type = original?.Type ?? FilterType.Filter;
        _perType = original?.PerType ?? FilterPerType.None;
        _notes = original?.Notes ?? "";
        foreach (var f in original?.Functions ?? [])
            Functions.Add(FunctionItem.From(f));
        foreach (var f in allFilters.Where(f => f.Type != FilterType.Composite && f.Id != original?.Id))
            BaseFilters.Add(new BaseFilterChoice(f, original?.BaseFilterIds.Contains(f.Id) == true));
    }

    public string Title => _original is null ? "New filter" : $"Edit filter · {_original.Name}";

    [ObservableProperty]
    private string _name;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsComposite))]
    private FilterType _type;

    [ObservableProperty]
    private FilterPerType _perType;

    [ObservableProperty]
    private string _notes;

    [ObservableProperty]
    private FunctionItem? _selectedFunction;

    [ObservableProperty]
    private string? _error;

    public bool IsComposite => Type == FilterType.Composite;

    public ObservableCollection<FunctionItem> Functions { get; } = [];
    public ObservableCollection<BaseFilterChoice> BaseFilters { get; } = [];

    public IReadOnlyList<FilterType> Types { get; } = [FilterType.Filter, FilterType.Composite];
    public IReadOnlyList<FilterPerType> PerTypes { get; } = Enum.GetValues<FilterPerType>();
    public IReadOnlyList<FilterFunctionKind> FunctionKinds { get; } = Enum.GetValues<FilterFunctionKind>();

    [RelayCommand]
    private void AddFunction()
    {
        var item = new FunctionItem();
        Functions.Add(item);
        SelectedFunction = item;
    }

    [RelayCommand]
    private void RemoveFunction(FunctionItem? item)
    {
        if (item is not null)
            Functions.Remove(item);
    }

    /// <summary>Builds the definition, or returns null and sets <see cref="Error"/>.</summary>
    public FilterDefinition? Build()
    {
        Error = null;
        if (string.IsNullOrWhiteSpace(Name))
        {
            Error = "Enter a filter name.";
            return null;
        }
        var functions = Functions.Select(f => f.ToFunction()).ToList();
        if (functions.FirstOrDefault(f => RuleText.TakesValues(f.Kind) && (f.Values?.Count ?? 0) == 0) is { } empty)
        {
            Error = $"{RuleText.FunctionName(empty.Kind)}: enter at least one value.";
            return null;
        }
        var bases = IsComposite ? BaseFilters.Where(b => b.IsSelected).Select(b => b.Filter.Id).ToList() : [];
        if (IsComposite && bases.Count == 0)
        {
            Error = "Select at least one base filter.";
            return null;
        }
        return new FilterDefinition(_original?.Id ?? Guid.Empty, Name.Trim(), Type, PerType, functions, bases,
            Notes: string.IsNullOrWhiteSpace(Notes) ? null : Notes.Trim());
    }
}

public enum QuotaUnit
{
    Bytes,
    Kilobytes,
    Megabytes,
    Gigabytes,
    Bits,
    Kilobits,
    Megabits,
    Gigabits,
}

/// <summary>What the editor offers for a quota's reset; everything but Never maps to a <see cref="ScheduleRepeat"/>.</summary>
public enum QuotaResetRepeat
{
    Never,
    Once,
    EveryDay,
    Days,
    DayOfMonth,
}

public sealed partial class DayChoice(DayOfWeek day, bool selected) : ObservableObject
{
    public DayOfWeek Day { get; } = day;
    public string Name => Day.ToString()[..3];

    [ObservableProperty]
    private bool _isSelected = selected;
}

public sealed partial class RuleChoice(RuleDefinition rule, string text, bool selected) : ObservableObject
{
    public RuleDefinition Rule { get; } = rule;
    public string Text { get; } = text;

    [ObservableProperty]
    private bool _isSelected = selected;
}

public sealed partial class RuleEditorViewModel : ObservableObject
{
    private readonly RuleDefinition? _original;

    public RuleEditorViewModel(RuleDefinition? original, IReadOnlyList<FilterDefinition> filters, Guid? filterId = null, RuleKind? kind = null,
        IReadOnlyList<RuleView>? rules = null)
    {
        _original = original;
        Filters = filters;
        _filter = filters.FirstOrDefault(f => f.Id == (original?.FilterId ?? filterId)) ?? filters.FirstOrDefault();
        _kind = original?.Kind ?? kind ?? RuleKind.Limit;
        _direction = original?.Direction ?? RuleDirection.In;
        _isEnabled = original?.IsEnabled ?? true;
        _weight = original?.Weight ?? 0;
        _notes = original?.Notes ?? "";
        _limitKilobytes = original?.LimitBytesPerSecond is { } bps ? bps / 1024.0 : 100;
        _action = original?.Action ?? FirewallAction.Deny;
        _ignoreLimit = original?.IgnoreLimit ?? true;
        _ignoreData = original?.IgnoreData ?? false;
        _priority = original?.Priority ?? PriorityLevel.High;
        if (original is null && _kind == RuleKind.Firewall)
            _direction = RuleDirection.Both;

        (_quotaAmount, _quotaUnit) = AmountOf(original?.QuotaBytes ?? 1024L * 1024 * 1024);
        var reset = original?.QuotaReset;
        _resetRepeat = reset is null ? QuotaResetRepeat.Never : (QuotaResetRepeat)Enum.Parse(typeof(QuotaResetRepeat), reset.Repeat.ToString());
        _resetTime = TimeOnly.FromTimeSpan(TimeSpan.FromMinutes(reset?.MinuteOfDay ?? 0)).ToString("HH:mm");
        _resetDate = reset?.Date?.ToDateTime(TimeOnly.MinValue);
        _resetDayOfMonth = reset?.DayOfMonth ?? 1;
        ResetDays = [.. new[] { DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday, DayOfWeek.Saturday, DayOfWeek.Sunday }
            .Select(d => new DayChoice(d, reset?.Days?.Contains(d) == true))];
        _overflowAlert = original?.OverflowAlert ?? true;
        _overflowKillConnections = original?.OverflowKillConnections ?? false;
        foreach (var view in rules ?? [])
            if (view.Rule.Id != original?.Id)
                OverflowChoices.Add(new RuleChoice(view.Rule, ChoiceText(view.Rule, view.FilterName), original?.OverflowRuleIds?.Contains(view.Rule.Id) == true));
    }

    /// <summary>Saves a rule right away, for the overflow rule buttons; set by the window's owner.</summary>
    public Func<RuleDefinition, Task<RuleDefinition?>>? CreateRule { get; set; }

    public IReadOnlyList<QuotaUnit> QuotaUnits { get; } = Enum.GetValues<QuotaUnit>();
    public IReadOnlyList<QuotaResetRepeat> ResetRepeats { get; } = Enum.GetValues<QuotaResetRepeat>();
    public IReadOnlyList<int> DaysOfMonth { get; } = Enumerable.Range(1, 31).ToList();
    public IReadOnlyList<DayChoice> ResetDays { get; }
    public ObservableCollection<RuleChoice> OverflowChoices { get; } = [];

    [ObservableProperty]
    private double _quotaAmount;

    [ObservableProperty]
    private QuotaUnit _quotaUnit;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasResetTime), nameof(IsResetOnce), nameof(IsResetDays), nameof(IsResetDayOfMonth))]
    private QuotaResetRepeat _resetRepeat;

    /// <summary>Time of day as HH:mm.</summary>
    [ObservableProperty]
    private string _resetTime;

    [ObservableProperty]
    private DateTime? _resetDate;

    [ObservableProperty]
    private int _resetDayOfMonth;

    [ObservableProperty]
    private bool _overflowAlert;

    [ObservableProperty]
    private bool _overflowKillConnections;

    [ObservableProperty]
    private double _overflowLimitKilobytes = 100;

    public bool IsQuota => Kind == RuleKind.Quota;
    public bool HasResetTime => ResetRepeat != QuotaResetRepeat.Never;
    public bool IsResetOnce => ResetRepeat == QuotaResetRepeat.Once;
    public bool IsResetDays => ResetRepeat == QuotaResetRepeat.Days;
    public bool IsResetDayOfMonth => ResetRepeat == QuotaResetRepeat.DayOfMonth;

    private static string ChoiceText(RuleDefinition rule, string filterName) =>
        $"{RuleText.Kind(rule.Kind)} {rule.Direction}: {RuleText.Value(rule)} for {filterName}";

    private static double UnitBytes(QuotaUnit unit) => unit switch
    {
        QuotaUnit.Bytes => 1,
        QuotaUnit.Kilobytes => 1024,
        QuotaUnit.Megabytes => 1024 * 1024,
        QuotaUnit.Gigabytes => 1024 * 1024 * 1024,
        QuotaUnit.Bits => 1.0 / 8,
        QuotaUnit.Kilobits => 1024.0 / 8,
        QuotaUnit.Megabits => 1024.0 * 1024 / 8,
        _ => 1024.0 * 1024 * 1024 / 8,
    };

    private static (double, QuotaUnit) AmountOf(long bytes)
    {
        foreach (var unit in new[] { QuotaUnit.Gigabytes, QuotaUnit.Megabytes, QuotaUnit.Kilobytes })
            if (bytes >= UnitBytes(unit))
                return (bytes / UnitBytes(unit), unit);
        return (bytes, QuotaUnit.Bytes);
    }

    [RelayCommand]
    private Task AddBlockRuleAsync() => AddOverflowRuleAsync(new RuleDefinition(Guid.Empty, Filter?.Id ?? Guid.Empty, RuleKind.Firewall, RuleDirection.Both,
        IsEnabled: false, Action: FirewallAction.Deny, Notes: "Turned on by a quota"));

    [RelayCommand]
    private Task AddLimitRuleAsync()
    {
        if (!(OverflowLimitKilobytes > 0))
        {
            Error = "Enter a limit greater than zero.";
            return Task.CompletedTask;
        }
        return AddOverflowRuleAsync(new RuleDefinition(Guid.Empty, Filter?.Id ?? Guid.Empty, RuleKind.Limit, Direction,
            IsEnabled: false, LimitBytesPerSecond: (long)Math.Round(OverflowLimitKilobytes * 1024), Notes: "Turned on by a quota"));
    }

    private async Task AddOverflowRuleAsync(RuleDefinition rule)
    {
        if (CreateRule is null || Filter is null)
            return;
        if (await CreateRule(rule) is { } saved)
            OverflowChoices.Add(new RuleChoice(saved, ChoiceText(saved, Filter.Name), true));
    }

    /// <summary>The reset schedule the fields describe. False (with <see cref="Error"/>) when they are incomplete.</summary>
    private bool TryBuildReset(out TimeSchedule? schedule)
    {
        schedule = null;
        if (ResetRepeat == QuotaResetRepeat.Never)
            return true;
        if (!TimeOnly.TryParseExact(ResetTime.Trim(), ["H:mm", "HH:mm"], System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None, out TimeOnly time))
        {
            Error = "Enter the reset time as HH:mm.";
            return false;
        }
        int minute = time.Hour * 60 + time.Minute;
        switch (ResetRepeat)
        {
            case QuotaResetRepeat.Once when ResetDate is null:
                Error = "Choose the reset date.";
                return false;
            case QuotaResetRepeat.Once:
                schedule = new TimeSchedule(ScheduleRepeat.Once, minute, DateOnly.FromDateTime(ResetDate.Value));
                return true;
            case QuotaResetRepeat.Days when !ResetDays.Any(d => d.IsSelected):
                Error = "Choose at least one reset day.";
                return false;
            case QuotaResetRepeat.Days:
                schedule = new TimeSchedule(ScheduleRepeat.Days, minute, Days: ResetDays.Where(d => d.IsSelected).Select(d => d.Day).ToList());
                return true;
            case QuotaResetRepeat.DayOfMonth:
                schedule = new TimeSchedule(ScheduleRepeat.DayOfMonth, minute, DayOfMonth: ResetDayOfMonth);
                return true;
            default:
                schedule = new TimeSchedule(ScheduleRepeat.EveryDay, minute);
                return true;
        }
    }

    public string Title => _original is null ? "New rule" : "Edit rule";

    public IReadOnlyList<FilterDefinition> Filters { get; }
    public IReadOnlyList<RuleKind> Kinds { get; } = Enum.GetValues<RuleKind>();
    public IReadOnlyList<RuleDirection> Directions { get; } = Enum.GetValues<RuleDirection>();
    public IReadOnlyList<FirewallAction> Actions { get; } = Enum.GetValues<FirewallAction>();
    public IReadOnlyList<PriorityLevel> PriorityLevels { get; } = QuickPriority.Levels;

    [ObservableProperty]
    private FilterDefinition? _filter;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsLimit), nameof(IsFirewall), nameof(IsIgnore), nameof(IsPriority), nameof(IsQuota))]
    private RuleKind _kind;

    [ObservableProperty]
    private RuleDirection _direction;

    [ObservableProperty]
    private bool _isEnabled;

    /// <summary>0 = default weight for the filter.</summary>
    [ObservableProperty]
    private int _weight;

    [ObservableProperty]
    private string _notes;

    [ObservableProperty]
    private double _limitKilobytes;

    [ObservableProperty]
    private FirewallAction _action;

    [ObservableProperty]
    private bool _ignoreLimit;

    [ObservableProperty]
    private bool _ignoreData;

    [ObservableProperty]
    private PriorityLevel _priority;

    [ObservableProperty]
    private string? _error;

    public bool IsLimit => Kind == RuleKind.Limit;
    public bool IsFirewall => Kind == RuleKind.Firewall;
    public bool IsIgnore => Kind == RuleKind.Ignore;
    public bool IsPriority => Kind == RuleKind.Priority;

    public RuleDefinition? Build()
    {
        Error = null;
        if (Filter is null)
        {
            Error = "Choose a filter.";
            return null;
        }
        if (IsLimit && !(LimitKilobytes > 0))
        {
            Error = "Enter a limit greater than zero.";
            return null;
        }
        if (IsIgnore && !IgnoreLimit && !IgnoreData)
        {
            Error = "Choose what to ignore.";
            return null;
        }
        if (Weight < 0)
        {
            Error = "Weight can't be negative.";
            return null;
        }
        TimeSchedule? reset = null;
        if (IsQuota)
        {
            if (!(QuotaAmount > 0))
            {
                Error = "Enter a quota greater than zero.";
                return null;
            }
            if (!TryBuildReset(out reset))
                return null;
        }
        return new RuleDefinition(
            _original?.Id ?? Guid.Empty, Filter.Id, Kind, Direction, IsEnabled, Weight,
            string.IsNullOrWhiteSpace(Notes) ? null : Notes.Trim(),
            LimitBytesPerSecond: IsLimit ? (long)Math.Round(LimitKilobytes * 1024) : null,
            Action: IsFirewall ? Action : null,
            IgnoreLimit: IsIgnore && IgnoreLimit,
            IgnoreData: IsIgnore && IgnoreData,
            ExpiresAt: _original?.ExpiresAt,
            Priority: IsPriority ? Priority : null,
            QuotaBytes: IsQuota ? (long)Math.Round(QuotaAmount * UnitBytes(QuotaUnit)) : null,
            QuotaReset: reset,
            OverflowRuleIds: IsQuota ? OverflowChoices.Where(c => c.IsSelected).Select(c => c.Rule.Id).ToList() : null,
            OverflowAlert: IsQuota && OverflowAlert,
            OverflowKillConnections: IsQuota && OverflowKillConnections);
    }
}
