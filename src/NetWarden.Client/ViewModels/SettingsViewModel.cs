using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetWarden.Client.Charts;
using NetWarden.Client.Services;
using NetWarden.Shared.Contracts;

namespace NetWarden.Client.ViewModels;

public sealed record HotkeyTargetChoice(string Id, string Name);

/// <summary>Names what a saved hotkey does; the list of targets lives in the running settings page.</summary>
public sealed class HotkeyTargetNameConverter : System.Windows.Data.IValueConverter
{
    public static SettingsViewModel? Settings { get; set; }

    public object? Convert(object? value, Type targetType, object? parameter, System.Globalization.CultureInfo culture) =>
        value is string id ? Settings?.TargetName(id) ?? id : "";

    public object ConvertBack(object? value, Type targetType, object? parameter, System.Globalization.CultureInfo culture) =>
        throw new NotSupportedException();
}

public sealed record LanguageChoice(string Code, string Name);

/// <summary>The Settings page: everything that is about the app rather than about traffic.</summary>
public sealed partial class SettingsViewModel : ObservableObject
{
    private readonly ClientSettings _settings;
    private readonly Action _save;
    private readonly StartupTask _startup;
    private readonly LayoutProfiles _profiles;

    public SettingsViewModel(ClientSettings settings, Action save, StartupTask startup)
    {
        _settings = settings;
        _save = save;
        _startup = startup;
        _profiles = new LayoutProfiles(settings, save);
        _newHotkeyTarget = HotkeyTargets[0];
        foreach (var binding in settings.Hotkeys)
            Hotkeys.Add(binding);
        foreach (string name in settings.LayoutProfiles.Keys.Order())
            ProfileNames.Add(name);
    }

    /// <summary>Raised when hotkeys changed and must be registered again.</summary>
    public event Action? HotkeysChanged;

    /// <summary>Raised when a look setting changed, for the window to apply.</summary>
    public event Action? AppearanceChanged;

    /// <summary>Raised after a layout profile was put back into the settings.</summary>
    public event Action? ProfileApplied;

    public IReadOnlyList<ChartStyle> ChartStyles { get; } = Enum.GetValues<ChartStyle>();
    public IReadOnlyList<AccentColor> Accents { get; } = Enum.GetValues<AccentColor>();
    public IReadOnlyList<LanguageChoice> Languages { get; } = [new("en", "English"), new("ar", "العربية")];

    public ObservableCollection<HotkeyBinding> Hotkeys { get; } = [];
    public ObservableCollection<string> ProfileNames { get; } = [];
    public ObservableCollection<HotkeyTargetChoice> HotkeyTargetChoices { get; } = [];

    /// <summary>The global targets, then one per rule once rules are known.</summary>
    public IReadOnlyList<HotkeyTargetChoice> HotkeyTargets { get; private set; } =
    [
        new(Services.HotkeyTargets.Limiter, "Turn the limiter on or off"),
        new(Services.HotkeyTargets.Blocker, "Turn the blocker on or off"),
        new(Services.HotkeyTargets.Priorities, "Turn priorities on or off"),
        new(Services.HotkeyTargets.ShowWindow, "Show or hide this window"),
    ];

    public void SetRules(IEnumerable<RuleView> rules)
    {
        string? selected = NewHotkeyTarget?.Id;
        HotkeyTargets = [.. HotkeyTargets.Where(t => !t.Id.StartsWith(Services.HotkeyTargets.RulePrefix, StringComparison.Ordinal)),
            .. rules.Select(r => new HotkeyTargetChoice(Services.HotkeyTargets.RulePrefix + r.Rule.Id, $"Rule: {RuleText.Kind(r.Rule.Kind)} {RuleText.Value(r.Rule)} for {r.FilterName}"))];
        OnPropertyChanged(nameof(HotkeyTargets));
        NewHotkeyTarget = HotkeyTargets.FirstOrDefault(t => t.Id == selected) ?? HotkeyTargets[0];
    }

    public ChartStyle ChartStyle
    {
        get => _settings.ChartStyle;
        set { _settings.ChartStyle = value; Changed(); }
    }

    public AccentColor Accent
    {
        get => _settings.Accent;
        set { _settings.Accent = value; Changed(); }
    }

    /// <summary>Takes effect at the next start, which <see cref="LanguageNote"/> says.</summary>
    public LanguageChoice Language
    {
        get => Languages.FirstOrDefault(l => l.Code == _settings.Language) ?? Languages[0];
        set
        {
            _settings.Language = value.Code;
            _save();
            OnPropertyChanged();
            OnPropertyChanged(nameof(LanguageNote));
        }
    }

    public string LanguageNote => _settings.Language == Loc.Current.Language ? "" : "The new language shows after you restart NetWarden.";

    public bool MinimizeToTray
    {
        get => _settings.MinimizeToTray;
        set { _settings.MinimizeToTray = value; Changed(); }
    }

    public bool CloseToTray
    {
        get => _settings.CloseToTray;
        set { _settings.CloseToTray = value; Changed(); }
    }

    public bool Notifications
    {
        get => _settings.Notifications;
        set { _settings.Notifications = value; Changed(); }
    }

    public bool RunOnStartup
    {
        get => _settings.RunOnStartup;
        set
        {
            if (_startup.Set(value))
            {
                _settings.RunOnStartup = value;
                StartupError = null;
                _save();
            }
            else
            {
                StartupError = "Windows refused to change the startup task. Open Task Scheduler to check it.";
            }
            OnPropertyChanged();
        }
    }

    [ObservableProperty]
    private string? _startupError;

    [ObservableProperty]
    private string _newHotkeyText = "";

    [ObservableProperty]
    private HotkeyTargetChoice? _newHotkeyTarget;

    [ObservableProperty]
    private string? _hotkeyError;

    [ObservableProperty]
    private string _newProfileName = "";

    [ObservableProperty]
    private string? _selectedProfile;

    public string TargetName(string id) => HotkeyTargets.FirstOrDefault(t => t.Id == id)?.Name ?? id;

    public void ShowRefusedHotkeys(IReadOnlyList<string> refused) =>
        HotkeyError = refused.Count == 0 ? null : $"Another program already uses {string.Join(", ", refused)}. Choose a different combination.";

    [RelayCommand]
    private void AddHotkey()
    {
        if (!HotkeyGesture.TryParse(NewHotkeyText, out var gesture))
        {
            HotkeyError = "Press a key with Ctrl, Alt, Shift or Win, for example Ctrl+Alt+L.";
            return;
        }
        if (Hotkeys.Any(h => HotkeyGesture.TryParse(h.Gesture, out var other) && other == gesture))
        {
            HotkeyError = $"{NewHotkeyText} is already in the list.";
            return;
        }
        if (NewHotkeyTarget is not { } target)
            return;
        HotkeyError = null;
        var binding = new HotkeyBinding { Gesture = NewHotkeyText.Trim(), Target = target.Id };
        Hotkeys.Add(binding);
        _settings.Hotkeys.Add(binding);
        NewHotkeyText = "";
        _save();
        HotkeysChanged?.Invoke();
    }

    [RelayCommand]
    private void RemoveHotkey(HotkeyBinding? binding)
    {
        if (binding is null)
            return;
        Hotkeys.Remove(binding);
        _settings.Hotkeys.Remove(binding);
        _save();
        HotkeysChanged?.Invoke();
    }

    [RelayCommand]
    private void SaveProfile()
    {
        string name = NewProfileName.Trim();
        if (name.Length == 0)
            return;
        _profiles.Save(name);
        if (!ProfileNames.Contains(name))
            ProfileNames.Add(name);
        NewProfileName = "";
        SelectedProfile = name;
    }

    [RelayCommand]
    private void ApplyProfile()
    {
        if (SelectedProfile is { } name && _profiles.Apply(name))
            ProfileApplied?.Invoke();
    }

    [RelayCommand]
    private void DeleteProfile()
    {
        if (SelectedProfile is not { } name)
            return;
        _profiles.Delete(name);
        ProfileNames.Remove(name);
        SelectedProfile = null;
    }

    private void Changed([System.Runtime.CompilerServices.CallerMemberName] string? name = null)
    {
        _save();
        OnPropertyChanged(name);
        AppearanceChanged?.Invoke();
    }
}

/// <summary>What the Rules column of the activity grid says about an app.</summary>
public static class RuleStatus
{
    public static string Describe(bool blockedIn, bool blockedOut, bool limitedIn, string limitIn, bool limitedOut, string limitOut, PriorityLevel priority)
    {
        var parts = new List<string>();
        if (blockedIn && blockedOut)
            parts.Add("Blocked");
        else if (blockedIn)
            parts.Add("Blocked in");
        else if (blockedOut)
            parts.Add("Blocked out");
        if (limitedIn)
            parts.Add($"down limit {limitIn} KB/s");
        if (limitedOut)
            parts.Add($"up limit {limitOut} KB/s");
        if (priority != PriorityLevel.Normal)
            parts.Add($"{priority} priority");
        string text = string.Join(", ", parts);
        return text.Length == 0 ? "" : char.ToUpperInvariant(text[0]) + text[1..];
    }
}
