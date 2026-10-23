using CommunityToolkit.Mvvm.ComponentModel;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Formatting;

namespace NetWarden.Client.ViewModels;

/// <summary>
/// The rule behind the Priority cell of the activity grid: one permanent priority rule
/// (both directions) on the app's filter. Normal is the default, so choosing it deletes the rule.
/// </summary>
public static class QuickPriority
{
    public static IReadOnlyList<PriorityLevel> Levels { get; } = [PriorityLevel.Critical, PriorityLevel.High, PriorityLevel.Normal, PriorityLevel.Low];

    public static RuleDefinition? Find(RulesSnapshot? rules, Guid? filterId) =>
        filterId is { } id && rules is not null
            ? rules.Rules.Select(r => r.Rule).FirstOrDefault(r => r.FilterId == id && r.Kind == RuleKind.Priority
                && r.Direction == RuleDirection.Both && r.ExpiresAt is null && r.Priority is not null)
            : null;

    public static PriorityLevel Level(RuleDefinition? rule) =>
        rule is { IsEnabled: true, Priority: { } level } ? level : PriorityLevel.Normal;

    /// <summary>The rule to save (or the id of the rule to delete) to give the app this level; both null when nothing changes.</summary>
    public static (RuleDefinition? Save, Guid? Delete) Plan(RuleDefinition? existing, Guid filterId, PriorityLevel level)
    {
        if (level == PriorityLevel.Normal)
            return (null, existing?.Id);
        if (existing is null)
            return (new RuleDefinition(Guid.Empty, filterId, RuleKind.Priority, RuleDirection.Both, Priority: level, Notes: "Quick priority"), null);
        return existing is { IsEnabled: true } && existing.Priority == level
            ? (null, null)
            : (existing with { IsEnabled = true, Priority = level }, null);
    }
}

/// <summary>One priority level in the Priorities tab status table.</summary>
public sealed record PriorityLevelRow(PriorityLevel Level, string Reserved, string DownloadRate, string DownloadCap,
    string UploadRate, string UploadCap, bool IsActive);

/// <summary>The Priorities tab: how levels share the line, and what the scheduler is doing now.</summary>
public sealed partial class PrioritiesViewModel(Func<ServiceSettings?> settings, Func<Action<ServiceSettings>, Task> update) : ObservableObject
{
    public IReadOnlyList<ReactionSpeed> ReactionSpeeds { get; } = Enum.GetValues<ReactionSpeed>();

    private PrioritySettings P => settings()?.Priorities ?? new PrioritySettings();

    private void Set(Action<PrioritySettings> change) => _ = update(s => change(s.Priorities));

    public ReactionSpeed ReactionSpeed { get => P.ReactionSpeed; set => Set(p => p.ReactionSpeed = value); }
    public int ReactionMillis { get => P.ReactionMillis; set => Set(p => p.ReactionMillis = value); }
    public bool IsCustomReaction => P.ReactionSpeed == ReactionSpeed.Custom;
    public bool Adaptive { get => P.Adaptive; set => Set(p => p.Adaptive = value); }
    public int CriticalPercent { get => P.CriticalPercent; set => Set(p => p.CriticalPercent = value); }
    public int HighPercent { get => P.HighPercent; set => Set(p => p.HighPercent = value); }
    public int NormalPercent { get => P.NormalPercent; set => Set(p => p.NormalPercent = value); }
    public int HeadroomPercent { get => P.HeadroomPercent; set => Set(p => p.HeadroomPercent = value); }

    // Line bounds in KB/s as text; empty or 0 = automatic.
    public string MinDownload { get => Kb(P.MinDownloadBytesPerSecond); set => SetBytes(value, (p, v) => p.MinDownloadBytesPerSecond = v); }
    public string MaxDownload { get => Kb(P.MaxDownloadBytesPerSecond); set => SetBytes(value, (p, v) => p.MaxDownloadBytesPerSecond = v); }
    public string MinUpload { get => Kb(P.MinUploadBytesPerSecond); set => SetBytes(value, (p, v) => p.MinUploadBytesPerSecond = v); }
    public string MaxUpload { get => Kb(P.MaxUploadBytesPerSecond); set => SetBytes(value, (p, v) => p.MaxUploadBytesPerSecond = v); }

    [ObservableProperty]
    private string? _inputError;

    [ObservableProperty]
    private IReadOnlyList<PriorityLevelRow> _levels = [];

    [ObservableProperty]
    private string _capacityText = "";

    [ObservableProperty]
    private string _stateText = "";

    /// <summary>Re-reads every setting after the service saved (or rejected) a change.</summary>
    public void RefreshSettings()
    {
        foreach (string name in new[] { nameof(ReactionSpeed), nameof(ReactionMillis), nameof(IsCustomReaction), nameof(Adaptive),
                     nameof(CriticalPercent), nameof(HighPercent), nameof(NormalPercent), nameof(HeadroomPercent),
                     nameof(MinDownload), nameof(MaxDownload), nameof(MinUpload), nameof(MaxUpload) })
            OnPropertyChanged(name);
        ShowStatus(_lastStatus, _lastEnabled);
    }

    private LimiterStatus? _lastStatus;
    private bool _lastEnabled;

    public void ShowStatus(LimiterStatus? limiter, bool hasPriorityRules)
    {
        _lastStatus = limiter;
        _lastEnabled = hasPriorityRules;
        var status = limiter?.IsRunning == true ? limiter.Priorities : null;
        var p = P;
        Levels = QuickPriority.Levels.Select(level =>
        {
            var down = status?.Download.Levels.FirstOrDefault(l => l.Level == level);
            var up = status?.Upload.Levels.FirstOrDefault(l => l.Level == level);
            return new PriorityLevelRow(level,
                level == PriorityLevel.Low ? "-" : $"{p.ReservedPercent(level)} %",
                Rate(down?.BytesPerSecond), Cap(down), Rate(up?.BytesPerSecond), Cap(up),
                down?.IsActive == true || up?.IsActive == true);
        }).ToList();

        CapacityText = status is null ? "" :
            $"Estimated line: {ByteFormatter.Rate(status.Download.CapacityBytesPerSecond, UnitMode.Bytes)} down · " +
            $"{ByteFormatter.Rate(status.Upload.CapacityBytesPerSecond, UnitMode.Bytes)} up";
        StateText = settings() is { IsPriorityEnabled: false } ? "Priorities are off."
            : !hasPriorityRules ? "No priority rules: every app is Normal. Pick a priority per app in the Activity tab."
            : status is null ? "Waiting for the limiter's packet filter..."
            : status.IsActive ? "Restricting lower priorities now."
            : "Watching traffic; nothing needs restricting.";
    }

    private static string Rate(long? bps) => bps is > 0 ? ByteFormatter.Rate(bps.Value, UnitMode.Bytes) : "";

    private static string Cap(PriorityLevelStatus? level) => level?.CapBytesPerSecond is { } cap ? ByteFormatter.Rate(cap, UnitMode.Bytes) : "";

    private static string Kb(long bytes) => bytes > 0 ? QuickLimit.Format(bytes / 1024.0) : "";

    private void SetBytes(string? text, Action<PrioritySettings, long> apply)
    {
        long bytes;
        if (string.IsNullOrWhiteSpace(text) || text.Trim() == "0")
            bytes = 0;
        else if (QuickLimit.Parse(text) is { } kb)
            bytes = (long)Math.Round(kb * 1024);
        else
        {
            InputError = $"'{text}' is not a speed in KB/s.";
            RefreshSettings();
            return;
        }
        InputError = null;
        Set(p => apply(p, bytes));
    }
}
