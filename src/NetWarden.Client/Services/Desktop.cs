using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows.Interop;

namespace NetWarden.Client.Services;

public static class TrayPolicy
{
    public static bool HideOnClose(bool closeToTray, bool exiting) => closeToTray && !exiting;
}

/// <summary>A key combination for RegisterHotKey.</summary>
public readonly record struct HotkeyGesture(uint Modifiers, uint VirtualKey)
{
    public const uint Alt = 1, Ctrl = 2, Shift = 4, Win = 8;

    /// <summary>Needs at least one modifier and exactly one key: a letter, a digit or F1-F24.</summary>
    public static bool TryParse(string text, out HotkeyGesture gesture)
    {
        gesture = default;
        uint modifiers = 0;
        uint? key = null;
        foreach (string raw in text.Split('+'))
        {
            string part = raw.Trim().ToUpperInvariant();
            switch (part)
            {
                case "CTRL" or "CONTROL":
                    modifiers |= Ctrl;
                    break;
                case "ALT":
                    modifiers |= Alt;
                    break;
                case "SHIFT":
                    modifiers |= Shift;
                    break;
                case "WIN" or "WINDOWS":
                    modifiers |= Win;
                    break;
                default:
                    if (key is not null || KeyOf(part) is not { } parsed)
                        return false;
                    key = parsed;
                    break;
            }
        }
        if (modifiers == 0 || key is null)
            return false;
        gesture = new HotkeyGesture(modifiers, key.Value);
        return true;
    }

    private static uint? KeyOf(string part)
    {
        if (part.Length == 1 && char.IsAsciiLetterOrDigit(part[0]))
            return part[0];
        if (part.Length >= 2 && part[0] == 'F' && int.TryParse(part[1..], out int f) && f is >= 1 and <= 24)
            return (uint)(0x70 + f - 1);
        return null;
    }
}

/// <summary>What a hotkey does: a global switch, showing the window, or "rule:&lt;id&gt;".</summary>
public static class HotkeyTargets
{
    public const string Limiter = "limiter";
    public const string Blocker = "blocker";
    public const string Priorities = "priorities";
    public const string ShowWindow = "show";
    public const string RulePrefix = "rule:";
}

public sealed class HotkeyBinding
{
    public string Gesture { get; set; } = "";
    public string Target { get; set; } = "";
}

/// <summary>Registers system-wide hotkeys on a window and calls back when one is pressed.</summary>
public sealed partial class HotkeyManager(IntPtr window, Action<string> run) : IDisposable
{
    private const int WmHotkey = 0x0312;
    private const uint NoRepeat = 0x4000;

    private readonly List<string> _targets = [];
    private HwndSource? _source;

    /// <summary>Replaces every registered hotkey. Returns the gestures Windows refused (taken by another program).</summary>
    public IReadOnlyList<string> Register(IEnumerable<HotkeyBinding> bindings)
    {
        if (_source is null)
        {
            _source = HwndSource.FromHwnd(window);
            _source?.AddHook(Hook);
        }
        Clear();
        var refused = new List<string>();
        foreach (var binding in bindings)
        {
            if (!HotkeyGesture.TryParse(binding.Gesture, out var gesture))
                continue;
            if (RegisterHotKey(window, _targets.Count, gesture.Modifiers | NoRepeat, gesture.VirtualKey))
                _targets.Add(binding.Target);
            else
                refused.Add(binding.Gesture);
        }
        return refused;
    }

    private IntPtr Hook(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WmHotkey && (int)wParam is var id && id >= 0 && id < _targets.Count)
        {
            run(_targets[id]);
            handled = true;
        }
        return IntPtr.Zero;
    }

    private void Clear()
    {
        for (int i = 0; i < _targets.Count; i++)
            UnregisterHotKey(window, i);
        _targets.Clear();
    }

    public void Dispose()
    {
        Clear();
        _source?.RemoveHook(Hook);
    }

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool RegisterHotKey(IntPtr hWnd, int id, uint modifiers, uint key);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool UnregisterHotKey(IntPtr hWnd, int id);
}

/// <summary>
/// Starts the client at logon. It needs elevation, which the Run registry key can't give without a UAC
/// prompt, so this is a scheduled task with the highest run level.
/// </summary>
public sealed class StartupTask(string exePath, Func<string, int>? runSchtasks = null)
{
    public const string TaskName = "NetWarden Client";

    private readonly Func<string, int> _run = runSchtasks ?? RunSchtasks;

    public bool Set(bool enabled) => _run(enabled
        ? $"/Create /F /TN \"{TaskName}\" /SC ONLOGON /RL HIGHEST /TR \"\\\"{exePath}\\\" --tray\""
        : $"/Delete /F /TN \"{TaskName}\"") == 0;

    public bool IsSet() => _run($"/Query /TN \"{TaskName}\"") == 0;

    private static int RunSchtasks(string args)
    {
        using var process = Process.Start(new ProcessStartInfo("schtasks.exe", args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });
        if (process is null)
            return -1;
        process.WaitForExit(10_000);
        return process.HasExited ? process.ExitCode : -1;
    }
}

/// <summary>
/// Translations, keyed by the English text. English needs no file, and any text without a translation
/// shows in English. Files are Assets/Lang/&lt;code&gt;.json; the language applies at the next start.
/// </summary>
public sealed class Loc
{
    private static readonly string[] RightToLeft = ["ar", "he", "fa", "ur"];

    private readonly Dictionary<string, string> _texts = [];

    public Loc(string language)
    {
        Language = language;
        IsRightToLeft = RightToLeft.Contains(language);
        using var stream = typeof(Loc).Assembly.GetManifestResourceStream($"NetWarden.Client.Assets.Lang.{language}.json");
        if (stream is not null)
            _texts = JsonSerializer.Deserialize<Dictionary<string, string>>(stream) ?? [];
    }

    /// <summary>The language the UI runs in; set once when the app starts.</summary>
    public static Loc Current { get; set; } = new("en");

    public string Language { get; }
    public bool IsRightToLeft { get; }
    public string this[string text] => _texts.GetValueOrDefault(text, text);
}

/// <summary><c>{svc:T Activity}</c> in XAML.</summary>
[System.Windows.Markup.MarkupExtensionReturnType(typeof(string))]
public sealed class TExtension(string text) : System.Windows.Markup.MarkupExtension
{
    public override object ProvideValue(IServiceProvider serviceProvider) => Loc.Current[text];
}

/// <summary>Translates a bound page name.</summary>
public sealed class TranslateConverter : System.Windows.Data.IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, System.Globalization.CultureInfo culture) =>
        value is string s ? Loc.Current[s] : value;

    public object ConvertBack(object? value, Type targetType, object? parameter, System.Globalization.CultureInfo culture) =>
        throw new NotSupportedException();
}
