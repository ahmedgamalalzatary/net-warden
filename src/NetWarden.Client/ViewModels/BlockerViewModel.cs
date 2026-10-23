using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;

namespace NetWarden.Client.ViewModels;

/// <summary>The rule changes behind a "quick block" checkbox.</summary>
public sealed record QuickBlockPlan(IReadOnlyList<RuleDefinition> Save, IReadOnlyList<Guid> Delete)
{
    public bool IsEmpty => Save.Count == 0 && Delete.Count == 0;
}

public static class QuickBlock
{
    /// <summary>A permanent, enabled Deny rule on this filter covers the direction.</summary>
    public static bool IsBlocked(RulesSnapshot? rules, Guid? filterId, RuleDirection direction) =>
        filterId is { } id && rules is not null && rules.Rules.Any(r => Covers(r.Rule, id, direction));

    public static QuickBlockPlan Plan(RulesSnapshot rules, Guid filterId, RuleDirection direction, bool block)
    {
        if (block)
        {
            return IsBlocked(rules, filterId, direction)
                ? new QuickBlockPlan([], [])
                : new QuickBlockPlan([new RuleDefinition(Guid.Empty, filterId, RuleKind.Firewall, direction,
                    Action: FirewallAction.Deny, Notes: "Quick block")], []);
        }

        var save = new List<RuleDefinition>();
        var delete = new List<Guid>();
        foreach (var rule in rules.Rules.Select(r => r.Rule).Where(r => Covers(r, filterId, direction)))
        {
            if (rule.Direction == RuleDirection.Both)
                save.Add(rule with { Direction = direction == RuleDirection.In ? RuleDirection.Out : RuleDirection.In });
            else
                delete.Add(rule.Id);
        }
        return new QuickBlockPlan(save, delete);
    }

    /// <summary>The filter that matches exactly this app (as created by filters.ensureForApp).</summary>
    public static Guid? AppFilterId(RulesSnapshot? rules, string appId) =>
        rules?.Filters.FirstOrDefault(f => f.Type == FilterType.Filter && f.Functions.Count == 1
            && f.Functions[0] is { Kind: FilterFunctionKind.AppId, Match: true, Values: [var v] }
            && string.Equals(v, appId, StringComparison.OrdinalIgnoreCase))?.Id;

    private static bool Covers(RuleDefinition r, Guid filterId, RuleDirection direction) =>
        r.FilterId == filterId && r.Kind == RuleKind.Firewall && r.IsEnabled && r.Action == FirewallAction.Deny
        && r.ExpiresAt is null && (r.Direction == direction || r.Direction == RuleDirection.Both);
}

/// <summary>The Blocker tab, the prompt window and the quick-block checkboxes.</summary>
public sealed partial class BlockerViewModel(IServiceRequester service, RulesViewModel rules) : ObservableObject
{
    public ObservableCollection<BlockerRequest> Pending { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusText))]
    private PacketFilterStatus? _status;

    [ObservableProperty]
    private string? _lastError;

    public IReadOnlyList<FirewallAction> Actions { get; } = Enum.GetValues<FirewallAction>();

    public string StatusText => Status switch
    {
        null => "",
        { Error: { } error } => "Packet filter error: " + error,
        { IsRunning: true } s => $"Filtering connections · {s.PacketsSeen:N0} packets inspected · {s.PacketsDropped:N0} dropped",
        { IsNeeded: false } => "Idle: no blocker rules and default actions allow everything",
        _ => "Starting...",
    };

    /// <summary>Raised when a new request arrives, so the window can show the prompt.</summary>
    public event Action<BlockerRequest>? RequestArrived;

    public async Task LoadAsync()
    {
        try
        {
            var pending = await service.RequestAsync<List<BlockerRequest>>(Methods.BlockerPending) ?? [];
            Pending.Clear();
            foreach (var r in pending)
                Pending.Add(r);
            Status = await service.RequestAsync<PacketFilterStatus>(Methods.FilterStatus);
        }
        catch (Exception ex) when (ex is IpcRemoteException or IpcDisconnectedException)
        {
            LastError = ex.Message;
        }
    }

    public void OnRequest(BlockerRequest request)
    {
        if (Pending.Any(p => p.Id == request.Id))
            return;
        Pending.Add(request);
        RequestArrived?.Invoke(request);
    }

    public void OnResolved(BlockerResolved resolved)
    {
        if (Pending.FirstOrDefault(p => p.Id == resolved.RequestId) is { } request)
            Pending.Remove(request);
    }

    public async Task<bool> AnswerAsync(BlockerRequest request, bool allow, RememberMode remember, RuleScope scope, int minutes)
    {
        try
        {
            await service.RequestAsync<bool>(Methods.BlockerAnswer, new BlockerAnswer(request.Id, allow, remember, scope, minutes));
            Pending.Remove(request);
            LastError = null;
            return true;
        }
        catch (Exception ex) when (ex is IpcRemoteException or IpcDisconnectedException)
        {
            LastError = ex.Message;
            return false;
        }
    }

    /// <summary>Blocks or unblocks an app or a predefined zone in one direction.</summary>
    public async Task<bool> SetBlockedAsync(Guid? filterId, AppInfo? app, RuleDirection direction, bool block)
    {
        if (filterId is null && app is not null)
            filterId = block ? (await rules.EnsureAppFilterAsync(app))?.Id : QuickBlock.AppFilterId(rules.Snapshot, app.Id);
        if (filterId is not { } id || rules.Snapshot is not { } snapshot)
            return !block;

        var plan = QuickBlock.Plan(snapshot, id, direction, block);
        bool ok = true;
        foreach (var rule in plan.Save)
            ok &= await rules.SaveRuleAsync(rule);
        foreach (var ruleId in plan.Delete)
        {
            var item = rules.Rules.FirstOrDefault(r => r.Rule.Id == ruleId);
            if (item is not null)
                ok &= await rules.DeleteRuleAsync(item);
        }
        LastError = ok ? null : rules.LastError;
        return ok;
    }
}
