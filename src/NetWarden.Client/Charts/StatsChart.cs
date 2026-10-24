using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using NetWarden.Shared.Formatting;

namespace NetWarden.Client.Charts;

/// <summary>One bucket of a <see cref="StatsChart"/>: download and upload bytes side by side.</summary>
public sealed record StatsBar(string Label, string Title, long In, long Out);

/// <summary>Column chart of bytes per time bucket (or per hour of the day). Hovering a column shows its values.</summary>
public sealed class StatsChart : FrameworkElement
{
    private const double Left = 64, Top = 22, Bottom = 18, Right = 8;

    public static readonly DependencyProperty BarsProperty = DependencyProperty.Register(
        nameof(Bars), typeof(IReadOnlyList<StatsBar>), typeof(StatsChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender, (d, _) => ((StatsChart)d)._hover = -1));

    public static readonly DependencyProperty InBrushProperty = BrushProperty(nameof(InBrush), Color.FromRgb(0x25, 0x63, 0xEB));
    public static readonly DependencyProperty OutBrushProperty = BrushProperty(nameof(OutBrush), Color.FromRgb(0xEA, 0x58, 0x0C));
    public static readonly DependencyProperty GridBrushProperty = BrushProperty(nameof(GridBrush), Color.FromRgb(0xE5, 0xE7, 0xEB));
    public static readonly DependencyProperty LabelBrushProperty = BrushProperty(nameof(LabelBrush), Color.FromRgb(0x5F, 0x6B, 0x7A));
    public static readonly DependencyProperty HighlightBrushProperty = BrushProperty(nameof(HighlightBrush), Color.FromRgb(0xDB, 0xEA, 0xFE));

    private static DependencyProperty BrushProperty(string name, Color fallback) => DependencyProperty.Register(
        name, typeof(Brush), typeof(StatsChart),
        new FrameworkPropertyMetadata(Freeze(new SolidColorBrush(fallback)), FrameworkPropertyMetadataOptions.AffectsRender));

    private int _hover = -1;

    public IReadOnlyList<StatsBar>? Bars { get => (IReadOnlyList<StatsBar>?)GetValue(BarsProperty); set => SetValue(BarsProperty, value); }
    public Brush InBrush { get => (Brush)GetValue(InBrushProperty); set => SetValue(InBrushProperty, value); }
    public Brush OutBrush { get => (Brush)GetValue(OutBrushProperty); set => SetValue(OutBrushProperty, value); }
    public Brush GridBrush { get => (Brush)GetValue(GridBrushProperty); set => SetValue(GridBrushProperty, value); }
    public Brush LabelBrush { get => (Brush)GetValue(LabelBrushProperty); set => SetValue(LabelBrushProperty, value); }
    public Brush HighlightBrush { get => (Brush)GetValue(HighlightBrushProperty); set => SetValue(HighlightBrushProperty, value); }

    /// <summary>Index of the column under the mouse, or -1.</summary>
    public int HoverIndex => _hover;

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        SetHover(IndexAt(e.GetPosition(this).X));
    }

    protected override void OnMouseLeave(MouseEventArgs e)
    {
        base.OnMouseLeave(e);
        SetHover(-1);
    }

    private void SetHover(int index)
    {
        if (index == _hover)
            return;
        _hover = index;
        InvalidateVisual();
    }

    /// <summary>The column at an x position (in this element's coordinates), or -1.</summary>
    public int IndexAt(double x)
    {
        int count = Bars?.Count ?? 0;
        double width = ActualWidth - Left - Right;
        if (count == 0 || width <= 0 || x < Left || x >= Left + width)
            return -1;
        return Math.Min(count - 1, (int)((x - Left) / (width / count)));
    }

    protected override void OnRender(DrawingContext dc)
    {
        double width = ActualWidth - Left - Right;
        double height = ActualHeight - Top - Bottom;
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, ActualWidth, ActualHeight));
        if (width < 20 || height < 20)
            return;

        var bars = Bars ?? [];
        long max = Math.Max(1024, bars.Count == 0 ? 0 : bars.Max(b => Math.Max(b.In, b.Out)));
        long scale = NiceSizeCeiling(max);
        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var gridPen = Freeze(new Pen(GridBrush, 1));

        for (int i = 0; i <= 4; i++)
        {
            double y = Top + height * i / 4;
            dc.DrawLine(gridPen, new Point(Left, y), new Point(Left + width, y));
            var text = Text(ByteFormatter.Size(scale * (4 - i) / 4), dpi);
            dc.DrawText(text, new Point(Left - 6 - text.Width, y - text.Height / 2));
        }
        if (bars.Count == 0)
            return;

        double slot = width / bars.Count;
        if (_hover >= 0 && _hover < bars.Count)
            dc.DrawRectangle(HighlightBrush, null, new Rect(Left + slot * _hover, Top, slot, height));

        // Two columns per bucket with a gap; at least a hairline so tiny values stay visible.
        double gap = slot > 6 ? Math.Max(1, slot * 0.18) : 0;
        double column = Math.Max(0.5, (slot - gap) / 2);
        for (int i = 0; i < bars.Count; i++)
        {
            double x = Left + slot * i + gap / 2;
            Column(dc, InBrush, x, column, bars[i].In, scale, height);
            Column(dc, OutBrush, x + column, column, bars[i].Out, scale, height);
        }

        // As many x labels as fit without overlapping.
        double labelWidth = bars.Max(b => Text(b.Label, dpi).Width) + 8;
        int step = Math.Max(1, (int)Math.Ceiling(labelWidth / slot));
        for (int i = 0; i < bars.Count; i += step)
        {
            var text = Text(bars[i].Label, dpi);
            double x = Left + slot * i + slot / 2 - text.Width / 2;
            dc.DrawText(text, new Point(Math.Clamp(x, Left, Left + width - text.Width), Top + height + 2));
        }

        if (_hover >= 0 && _hover < bars.Count)
        {
            var bar = bars[_hover];
            var text = Text($"{bar.Title}    ↓ {ByteFormatter.Size(bar.In)}    ↑ {ByteFormatter.Size(bar.Out)}", dpi);
            dc.DrawText(text, new Point(Left, 2));
        }
    }

    /// <summary>
    /// Rounds up to 1, 2, 4, 5 or 10 times a power of ten of the largest fitting binary unit (KB, MB, GB...),
    /// so the axis reads "200 MB / 150 MB / 100 MB" rather than "191 MB / 143 MB".
    /// </summary>
    internal static long NiceSizeCeiling(long bytes)
    {
        long unit = 1;
        while (unit <= long.MaxValue / 1024 && unit * 1024 <= bytes)
            unit *= 1024;
        double value = (double)bytes / unit;
        double magnitude = Math.Pow(10, Math.Floor(Math.Log10(Math.Max(value, 1))));
        foreach (double step in new[] { 1, 2, 4, 5, 10 })
            if (step * magnitude >= value)
                return (long)Math.Ceiling(step * magnitude * unit);
        return (long)(10 * magnitude * unit);
    }

    private static void Column(DrawingContext dc, Brush brush, double x, double width, long value, long scale, double height)
    {
        if (value <= 0)
            return;
        double h = Math.Max(1, height * value / scale);
        dc.DrawRectangle(brush, null, new Rect(x, Top + height - h, width, h));
    }

    private FormattedText Text(string s, double dpi) =>
        new(s, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, new Typeface("Segoe UI"), 11, LabelBrush, dpi);

    private static T Freeze<T>(T freezable) where T : Freezable
    {
        if (freezable.CanFreeze)
            freezable.Freeze();
        return freezable;
    }
}
