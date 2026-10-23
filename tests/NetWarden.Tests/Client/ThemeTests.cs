using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using NetWarden.Client.Dialogs;
using NetWarden.Client.Services;
using NetWarden.Client.ViewModels;
using NetWarden.Shared.Contracts;

namespace NetWarden.Tests.Client;

public class ThemeResolveTests
{
    [Theory]
    [InlineData(AppTheme.Dark, false, true)]
    [InlineData(AppTheme.Light, true, false)]
    [InlineData(AppTheme.System, true, true)]
    [InlineData(AppTheme.System, false, false)]
    public void Choice_resolves_against_windows_setting(AppTheme theme, bool systemDark, bool expectDark)
    {
        Assert.Equal(expectDark, ThemeManager.Resolve(theme, systemDark));
    }
}

[Collection(WpfCollection.Name)]
public sealed class ThemeTests(WpfHarness wpf)
{
    private static Color Brush(string key) => ((SolidColorBrush)Application.Current.FindResource(key)).Color;

    [Fact]
    public void Switching_swaps_our_colors_without_stacking_dictionaries()
    {
        var (dark, light, count) = wpf.Run(() =>
        {
            try
            {
                wpf.Themes.Apply(AppTheme.Dark);
                wpf.Themes.Apply(AppTheme.Dark);
                var d = Brush("PanelBackground");
                int ours = Application.Current.Resources.MergedDictionaries
                    .Count(x => x.Source?.OriginalString.Contains("NetWarden.Client;component/Themes/") == true);
                wpf.Themes.Apply(AppTheme.Light);
                return (d, Brush("PanelBackground"), ours);
            }
            finally
            {
                wpf.Themes.Apply(AppTheme.Light);
            }
        });

        Assert.Equal(Color.FromRgb(0x26, 0x26, 0x28), dark);
        Assert.Equal(Colors.White, light);
        Assert.Equal(1, count);
    }

    [Theory]
    [InlineData(AppTheme.Light)]
    [InlineData(AppTheme.Dark)]
    public async Task Dialogs_open_and_render_in_both_themes(AppTheme theme)
    {
        // Set NETWARDEN_SHOTS to a folder to get PNGs of each window for a visual check.
        string? shots = Environment.GetEnvironmentVariable("NETWARDEN_SHOTS");
        await wpf.RunAsync(async () =>
        {
            wpf.Themes.Apply(theme);
            try
            {
                var service = new FakeService();
                var blocker = new BlockerViewModel(service, new RulesViewModel(service));
                blocker.OnRequest(new BlockerRequest(Guid.NewGuid(), Snapshots.App("b", "Browser"), 100, TransportProtocol.Tcp,
                    ConnectionKind.Connect, "192.168.1.14", 50000, "1.1.1.1", 443, "one.one.one.one",
                    DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(1), null));
                var filterVm = new FilterEditorViewModel(null, PredefinedFilters.All) { Name = "Browser" };
                filterVm.AddFunctionCommand.Execute(null);
                Window[] windows =
                [
                    new FilterEditorWindow(filterVm, _ => Task.FromResult<string?>(null)),
                    new RuleEditorWindow(new RuleEditorViewModel(null, PredefinedFilters.All, PredefinedFilters.Internet), _ => Task.FromResult<string?>(null)),
                    new RuleEditorWindow(new RuleEditorViewModel(null, PredefinedFilters.All, PredefinedFilters.Internet, RuleKind.Priority), _ => Task.FromResult<string?>(null)),
                    new BlockerPromptWindow(new BlockerPromptViewModel(blocker)),
                ];
                foreach (var window in windows)
                {
                    window.Show();
                    await WpfHarness.Settle();
                    if (shots is not null)
                        Save(window, Path.Combine(shots, $"{window.GetType().Name}-{theme}.png"));
                    window.Close();
                }
            }
            finally
            {
                wpf.Themes.Apply(AppTheme.Light);
            }
        });
    }

    internal static void Save(Window window, string path)
    {
        // The window's own visual: its client area at its real size (the title bar is drawn by Windows).
        var bitmap = new RenderTargetBitmap((int)window.ActualWidth, (int)window.ActualHeight, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(window);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        using var file = File.Create(path);
        encoder.Save(file);
    }
}
