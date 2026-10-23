using System.Collections.Specialized;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetWarden.Shared.Contracts;

namespace NetWarden.Client.ViewModels;

public sealed record ScopeChoice(RuleScope Scope, string Text);

/// <summary>The prompt shown for pending blocker requests, oldest first.</summary>
public sealed partial class BlockerPromptViewModel : ObservableObject
{
    private readonly BlockerViewModel _blocker;

    public BlockerPromptViewModel(BlockerViewModel blocker)
    {
        _blocker = blocker;
        blocker.Pending.CollectionChanged += OnPendingChanged;
        Current = blocker.Pending.FirstOrDefault();
    }

    /// <summary>Raised when nothing is left to answer.</summary>
    public event Action? Finished;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Headline), nameof(Target), nameof(Details), nameof(MoreText))]
    private BlockerRequest? _current;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsTemporary))]
    private RememberMode _remember = RememberMode.Once;

    [ObservableProperty]
    private RuleScope _scope = RuleScope.App;

    [ObservableProperty]
    private int _minutes = 30;

    [ObservableProperty]
    private string? _error;

    public bool IsTemporary => Remember == RememberMode.Temporary;

    public IReadOnlyList<int> MinuteChoices { get; } = [5, 15, 30, 60, 240, 1440];

    // A record, not a tuple: WPF bindings only see properties, and tuple members are fields.
    public IReadOnlyList<ScopeChoice> ScopeChoices { get; } =
    [
        new(RuleScope.App, "this application"),
        new(RuleScope.AppAndRemoteAddress, "this application and remote address"),
        new(RuleScope.AppAndRemotePort, "this application and remote port"),
    ];

    public string Headline => Current is { } r
        ? $"{r.App.DisplayName} {(r.Kind == ConnectionKind.Connect ? "wants to connect to" : "is receiving a connection from")}"
        : "";

    public string Target => Current is { } r
        ? $"{r.RemoteHost ?? r.RemoteAddress} : {r.RemotePort} ({r.Protocol.ToString().ToUpperInvariant()})"
        : "";

    public string Details => Current is { } r
        ? $"{r.App.Path}\nProcess {r.ProcessId} · local {r.LocalAddress}:{r.LocalPort}"
          + (r.RemoteHost is null ? "" : $" · remote {r.RemoteAddress}")
        : "";

    public string MoreText => _blocker.Pending.Count > 1 ? $"{_blocker.Pending.Count - 1} more waiting" : "";

    private void OnPendingChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (Current is null || !_blocker.Pending.Contains(Current))
            Current = _blocker.Pending.FirstOrDefault();
        OnPropertyChanged(nameof(MoreText));
        if (Current is null)
            Finished?.Invoke();
    }

    [RelayCommand]
    private Task AllowAsync() => AnswerAsync(true);

    [RelayCommand]
    private Task DenyAsync() => AnswerAsync(false);

    private async Task AnswerAsync(bool allow)
    {
        if (Current is not { } request)
            return;
        Error = await _blocker.AnswerAsync(request, allow, Remember, Scope, Minutes) ? null : _blocker.LastError;
        if (Error is null)
            Remember = RememberMode.Once;
    }

    public void Detach() => _blocker.Pending.CollectionChanged -= OnPendingChanged;
}
