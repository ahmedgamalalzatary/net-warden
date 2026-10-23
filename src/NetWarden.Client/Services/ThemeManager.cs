using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using Microsoft.Win32;

namespace NetWarden.Client.Services;

public enum AppTheme
{
    /// <summary>Follow the Windows "app mode" setting, live.</summary>
    System,
    Light,
    Dark,
}

/// <summary>
/// Switches the whole client between light and dark: WPF's Fluent theme styles the
/// standard controls (and the title bar), and Themes/Light|Dark.xaml supply our own
/// brushes, which every view uses through DynamicResource.
/// </summary>
public sealed class ThemeManager
{
    private const string ColorsPath = "NetWarden.Client;component/Themes/";
    private const string PersonalizeKey = @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";

    private readonly Application _app;
    private bool _listening;

    public ThemeManager(Application app) => _app = app;

    public AppTheme Theme { get; private set; } = AppTheme.System;

    /// <summary>The theme actually shown: <see cref="AppTheme.System"/> resolved to Light or Dark.</summary>
    public bool IsDark { get; private set; }

    public event Action? Changed;

    public void Apply(AppTheme theme)
    {
        Theme = theme;
        if (theme == AppTheme.System && !_listening)
        {
            SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
            _listening = true;
        }
        else if (theme != AppTheme.System && _listening)
        {
            SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
            _listening = false;
        }
        Show(Resolve(theme, SystemUsesDarkMode()));
    }

    /// <summary>Light or dark for a choice, given what Windows uses.</summary>
    public static bool Resolve(AppTheme theme, bool systemIsDark) => theme switch
    {
        AppTheme.Dark => true,
        AppTheme.Light => false,
        _ => systemIsDark,
    };

    /// <summary>Windows' "Choose your app mode" setting; light when it cannot be read.</summary>
    public static bool SystemUsesDarkMode()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(PersonalizeKey);
            return key?.GetValue("AppsUseLightTheme") is int light && light == 0;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private void Show(bool dark)
    {
#pragma warning disable WPF0001 // ThemeMode is marked experimental; it is the supported way to get Fluent light/dark.
        _app.ThemeMode = dark ? ThemeMode.Dark : ThemeMode.Light;
#pragma warning restore WPF0001
        var colors = new ResourceDictionary
        {
            Source = new Uri($"pack://application:,,,/{ColorsPath}{(dark ? "Dark" : "Light")}.xaml"),
        };
        // Ours go after Fluent's dictionary so our keys win, replacing the previous ones.
        var merged = _app.Resources.MergedDictionaries;
        foreach (var old in merged.Where(IsOurs).ToList())
            merged.Remove(old);
        merged.Add(colors);
        merged.Add(CompactStyles());
        IsDark = dark;
        Changed?.Invoke();
    }

    private static bool IsOurs(ResourceDictionary d) =>
        d.Contains(CompactMarker) || d.Source?.OriginalString.Contains(ColorsPath, StringComparison.Ordinal) == true;

    /// <summary>
    /// Fluent sizes controls for touch (32 px rows, 120 px checkboxes); this app is a dense
    /// grid, so the standard controls are tightened. Built in code because the styles must be
    /// based on Fluent's, which exist only once <c>ThemeMode</c> is set.
    /// </summary>
    private ResourceDictionary CompactStyles()
    {
        var styles = new ResourceDictionary { [CompactMarker] = true };
        void Add(Type type, params (DependencyProperty Property, object Value)[] setters)
        {
            var style = new Style(type, _app.TryFindResource(type) as Style);
            foreach (var (property, value) in setters)
                style.Setters.Add(new Setter(property, value));
            styles[type] = style;
        }
        Add(typeof(CheckBox),
            (FrameworkElement.MinWidthProperty, 0.0), (FrameworkElement.MinHeightProperty, 0.0), (Control.PaddingProperty, new Thickness(6, 0, 0, 0)));
        Add(typeof(RadioButton), (FrameworkElement.MinWidthProperty, 0.0), (FrameworkElement.MinHeightProperty, 0.0));
        Add(typeof(TextBox), (FrameworkElement.MinHeightProperty, 0.0), (Control.PaddingProperty, new Thickness(6, 3, 6, 3)));
        Add(typeof(ComboBox), (FrameworkElement.MinHeightProperty, 0.0), (Control.PaddingProperty, new Thickness(8, 3, 0, 3)));
        Add(typeof(Button), (FrameworkElement.MinHeightProperty, 0.0), (Control.PaddingProperty, new Thickness(10, 3, 10, 3)));
        // Fluent's DataGrid style sets its own header and cell styles, so implicit ones would be ignored.
        var grid = _app.TryFindResource(typeof(DataGrid)) as Style;
        var header = new Style(typeof(DataGridColumnHeader), Setting(grid, DataGrid.ColumnHeaderStyleProperty)
                                                             ?? _app.TryFindResource(typeof(DataGridColumnHeader)) as Style);
        header.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(6, 4, 2, 4)));
        header.Setters.Add(new Setter(Control.FontSizeProperty, 12.0));
        var cell = new Style(typeof(DataGridCell), Setting(grid, DataGrid.CellStyleProperty)
                                                   ?? _app.TryFindResource(typeof(DataGridCell)) as Style);
        var selected = new Trigger { Property = DataGridCell.IsSelectedProperty, Value = true };
        selected.Setters.Add(new Setter(Control.BackgroundProperty, new DynamicResourceExtension("SelectionBackground")));
        selected.Setters.Add(new Setter(Control.BorderBrushProperty, new DynamicResourceExtension("SelectionBackground")));
        selected.Setters.Add(new Setter(Control.ForegroundProperty, new DynamicResourceExtension("TextBrush")));
        cell.Triggers.Add(selected);
        Add(typeof(DataGrid), (DataGrid.ColumnHeaderStyleProperty, header), (DataGrid.CellStyleProperty, cell));
        return styles;
    }

    private static Style? Setting(Style? style, DependencyProperty property)
    {
        for (; style is not null; style = style.BasedOn)
            if (style.Setters.OfType<Setter>().FirstOrDefault(x => x.Property == property)?.Value is Style value)
                return value;
        return null;
    }

    private const string CompactMarker = "NetWarden.CompactStyles";

    private void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
    {
        if (e.Category is UserPreferenceCategory.General or UserPreferenceCategory.Color)
            _app.Dispatcher.InvokeAsync(() =>
            {
                if (Theme == AppTheme.System && SystemUsesDarkMode() != IsDark)
                    Show(!IsDark);
            });
    }
}
