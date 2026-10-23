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

public sealed partial class RuleEditorViewModel : ObservableObject
{
    private readonly RuleDefinition? _original;

    public RuleEditorViewModel(RuleDefinition? original, IReadOnlyList<FilterDefinition> filters, Guid? filterId = null, RuleKind? kind = null)
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
        if (original is null && _kind == RuleKind.Firewall)
            _direction = RuleDirection.Both;
    }

    public string Title => _original is null ? "New rule" : "Edit rule";

    public IReadOnlyList<FilterDefinition> Filters { get; }
    public IReadOnlyList<RuleKind> Kinds { get; } = Enum.GetValues<RuleKind>();
    public IReadOnlyList<RuleDirection> Directions { get; } = Enum.GetValues<RuleDirection>();
    public IReadOnlyList<FirewallAction> Actions { get; } = Enum.GetValues<FirewallAction>();

    [ObservableProperty]
    private FilterDefinition? _filter;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsLimit), nameof(IsFirewall), nameof(IsIgnore))]
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
    private string? _error;

    public bool IsLimit => Kind == RuleKind.Limit;
    public bool IsFirewall => Kind == RuleKind.Firewall;
    public bool IsIgnore => Kind == RuleKind.Ignore;

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
        return new RuleDefinition(
            _original?.Id ?? Guid.Empty, Filter.Id, Kind, Direction, IsEnabled, Weight,
            string.IsNullOrWhiteSpace(Notes) ? null : Notes.Trim(),
            LimitBytesPerSecond: IsLimit ? (long)Math.Round(LimitKilobytes * 1024) : null,
            Action: IsFirewall ? Action : null,
            IgnoreLimit: IsIgnore && IgnoreLimit,
            IgnoreData: IsIgnore && IgnoreData,
            ExpiresAt: _original?.ExpiresAt);
    }
}
