using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;

namespace NetWarden.Client.ViewModels;

public sealed record FilterItem(FilterDefinition Filter, int RuleCount)
{
    public string Name => Filter.Name;
    public string Type => Filter.Type.ToString();
    public string PerType => Filter.PerType == FilterPerType.None ? "" : Filter.PerType.ToString();
    public string Definition => RuleText.Describe(Filter);
    public bool IsPredefined => Filter.IsPredefined;
}

public sealed partial class RuleItem(RuleView view) : ObservableObject
{
    public RuleView View { get; } = view;
    public RuleDefinition Rule => View.Rule;
    public bool IsEnabled => Rule.IsEnabled;
    public string Kind => RuleText.Kind(Rule.Kind);
    public string For => View.FilterName;
    public string Direction => Rule.Direction.ToString();
    public string Value => RuleText.Value(Rule);
    public int Weight => View.EffectiveWeight;
    public string State => View.State.ToString();
    public string Expires => Rule.ExpiresAt?.ToLocalTime().ToString("g") ?? "";
    public string Schedule => RuleText.Schedule(Rule);
    public string Notes => Rule.Notes ?? "";
}

public enum RuleKindFilter
{
    All,
    Limits,
    Blocks,
    Priorities,
    Quotas,
    Ignore,
}

/// <summary>The Filters and Rules pages, kept in sync with the service.</summary>
public sealed partial class RulesViewModel(IServiceRequester service, ClientSettings? settings = null, Action? saveSettings = null) : ObservableObject
{
    private long _generation = -1;
    private RuleKindFilter _kindFilter = settings?.RuleKinds ?? RuleKindFilter.All;

    /// <summary>The rules the Rules page shows: those of the chosen type.</summary>
    public ObservableCollection<RuleItem> VisibleRules { get; } = [];

    public IReadOnlyList<RuleKindFilter> KindFilters { get; } = Enum.GetValues<RuleKindFilter>();

    public RuleKindFilter KindFilter
    {
        get => _kindFilter;
        set
        {
            if (!SetProperty(ref _kindFilter, value))
                return;
            if (settings is not null)
                settings.RuleKinds = value;
            saveSettings?.Invoke();
            ShowVisibleRules();
        }
    }

    private void ShowVisibleRules()
    {
        VisibleRules.Clear();
        foreach (var rule in Rules)
            if (KindFilter == RuleKindFilter.All || KindFilter == Group(rule.Rule.Kind))
                VisibleRules.Add(rule);
    }

    private static RuleKindFilter Group(RuleKind kind) => kind switch
    {
        RuleKind.Limit => RuleKindFilter.Limits,
        RuleKind.Firewall => RuleKindFilter.Blocks,
        RuleKind.Priority => RuleKindFilter.Priorities,
        RuleKind.Quota => RuleKindFilter.Quotas,
        _ => RuleKindFilter.Ignore,
    };

    /// <summary>Flips a rule on or off, for hotkeys.</summary>
    public async Task ToggleByIdAsync(Guid id)
    {
        if (Rules.FirstOrDefault(r => r.Rule.Id == id) is { } item)
            await ToggleEnabledAsync(item);
    }

    public ObservableCollection<FilterItem> Filters { get; } = [];
    public ObservableCollection<RuleItem> Rules { get; } = [];

    public RulesSnapshot? Snapshot { get; private set; }

    [ObservableProperty]
    private string? _lastError;

    [ObservableProperty]
    private RuleItem? _selectedRule;

    [ObservableProperty]
    private FilterItem? _selectedFilter;

    public event Action? Reloaded;

    /// <summary>Reloads unless the service generation is already shown.</summary>
    public async Task ReloadAsync(long? knownGeneration = null)
    {
        if (knownGeneration is { } g && g == _generation)
            return;
        var snapshot = await RunAsync(() => service.RequestAsync<RulesSnapshot>(Methods.RulesGet));
        if (snapshot is not null)
            Apply(snapshot);
    }

    public void Apply(RulesSnapshot snapshot)
    {
        Snapshot = snapshot;
        _generation = snapshot.Generation;
        Guid? selectedRule = SelectedRule?.Rule.Id;
        Guid? selectedFilter = SelectedFilter?.Filter.Id;

        Filters.Clear();
        foreach (var f in snapshot.Filters.OrderBy(f => !f.IsPredefined).ThenBy(f => f.Name, StringComparer.CurrentCultureIgnoreCase))
            Filters.Add(new FilterItem(f, snapshot.Rules.Count(r => r.Rule.FilterId == f.Id)));
        Rules.Clear();
        foreach (var r in snapshot.Rules)
            Rules.Add(new RuleItem(r));
        ShowVisibleRules();

        SelectedRule = Rules.FirstOrDefault(r => r.Rule.Id == selectedRule);
        SelectedFilter = Filters.FirstOrDefault(f => f.Filter.Id == selectedFilter);
        Reloaded?.Invoke();
    }

    public IEnumerable<RuleView> RulesFor(Guid filterId) =>
        Snapshot?.Rules.Where(r => r.Rule.FilterId == filterId) ?? [];

    public async Task<bool> SaveFilterAsync(FilterDefinition filter) =>
        await RunAsync(() => service.RequestAsync<FilterDefinition>(Methods.FiltersSave, filter)) is not null && await Refresh();

    public async Task<bool> SaveRuleAsync(RuleDefinition rule) =>
        await RunAsync(() => service.RequestAsync<RuleDefinition>(Methods.RulesSave, rule)) is not null && await Refresh();

    /// <summary>Saves a new rule and returns it with its id.</summary>
    public async Task<RuleDefinition?> CreateRuleAsync(RuleDefinition rule)
    {
        var saved = await RunAsync(() => service.RequestAsync<RuleDefinition>(Methods.RulesSave, rule));
        if (saved is not null)
            await Refresh();
        return saved;
    }

    /// <summary>Finds or creates the filter with exactly these functions.</summary>
    public async Task<FilterDefinition?> EnsureFilterAsync(string name, IReadOnlyList<FilterFunction> functions)
    {
        var filter = await RunAsync(() => service.RequestAsync<FilterDefinition>(Methods.FiltersEnsure, new EnsureFilterRequest(name, functions)));
        if (filter is not null)
            await Refresh();
        return filter;
    }

    public async Task<FilterDefinition?> EnsureAppFilterAsync(AppInfo app)
    {
        var filter = await RunAsync(() => service.RequestAsync<FilterDefinition>(Methods.FiltersEnsureForApp,
            new EnsureAppFilterRequest(app.Id, app.DisplayName)));
        if (filter is not null)
            await Refresh();
        return filter;
    }

    public async Task<bool> DeleteFilterAsync(FilterItem item) =>
        await RunAsync(() => service.RequestAsync<bool>(Methods.FiltersDelete, new DeleteRequest(item.Filter.Id))) && await Refresh();

    public async Task<bool> DeleteRuleAsync(RuleItem item) =>
        await RunAsync(() => service.RequestAsync<bool>(Methods.RulesDelete, new DeleteRequest(item.Rule.Id))) && await Refresh();

    [RelayCommand]
    private async Task ToggleEnabledAsync(RuleItem? item)
    {
        if (item is null)
            return;
        if (await RunAsync(() => service.RequestAsync<bool>(Methods.RulesSetEnabled, new SetRuleEnabledRequest(item.Rule.Id, !item.IsEnabled))))
            await Refresh();
    }

    [RelayCommand]
    private Task MoveUpAsync(RuleItem? item) => MoveAsync(item, -1);

    [RelayCommand]
    private Task MoveDownAsync(RuleItem? item) => MoveAsync(item, +1);

    private async Task MoveAsync(RuleItem? item, int delta)
    {
        if (item is null)
            return;
        var ids = Rules.Select(r => r.Rule.Id).ToList();
        int index = ids.IndexOf(item.Rule.Id);
        int target = index + delta;
        if (index < 0 || target < 0 || target >= ids.Count)
            return;
        (ids[index], ids[target]) = (ids[target], ids[index]);
        if (await RunAsync(() => service.RequestAsync<bool>(Methods.RulesReorder, new ReorderRulesRequest(ids))))
            await Refresh();
    }

    private async Task<bool> Refresh()
    {
        await ReloadAsync();
        return true;
    }

    private async Task<T?> RunAsync<T>(Func<Task<T?>> action)
    {
        try
        {
            T? result = await action();
            LastError = null;
            return result;
        }
        catch (Exception ex) when (ex is IpcRemoteException or IpcDisconnectedException)
        {
            LastError = ex is IpcRemoteException remote ? remote.RemoteMessage : ex.Message;
            return default;
        }
    }
}
