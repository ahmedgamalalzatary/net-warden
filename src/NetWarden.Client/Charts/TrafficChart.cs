using System.Globalization;
using System.Windows;
using System.Windows.Media;
using NetWarden.Shared.Formatting;

namespace NetWarden.Client.Charts;

public enum ChartStyle
{
    Line,
    Column,
    Stacked,
}

/// <summary>Chart of download/upload rate over a time window. Call <see cref="Refresh"/> after new samples.</summary>
public sealed class TrafficChart : FrameworkElement
{
    public static readonly DependencyProperty HistoryProperty = DependencyProperty.Register(
        nameof(History), typeof(RateHistory), typeof(TrafficChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty WindowSecondsProperty = DependencyProperty.Register(
        nameof(WindowSeconds), typeof(int), typeof(TrafficChart),
        new FrameworkPropertyMetadata(60, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty UnitsProperty = DependencyProperty.Register(
        nameof(Units), typeof(UnitMode), typeof(TrafficChart),
        new FrameworkPropertyMetadata(UnitMode.Bytes, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty ChartStyleProperty = DependencyProperty.Register(
        nameof(ChartStyle), typeof(ChartStyle), typeof(TrafficChart),
        new FrameworkPropertyMetadata(ChartStyle.Line, FrameworkPropertyMetadataOptions.AffectsRender));

    /// <summary>Only the lines, without axes: the meter in the rail.</summary>
    public static readonly DependencyProperty IsCompactProperty = DependencyProperty.Register(
        nameof(IsCompact), typeof(bool), typeof(TrafficChart),
        new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender));

    public ChartStyle ChartStyle { get => (ChartStyle)GetValue(ChartStyleProperty); set => SetValue(ChartStyleProperty, value); }
    public bool IsCompact { get => (bool)GetValue(IsCompactProperty); set => SetValue(IsCompactProperty, value); }

    // Colors come from the theme (set with DynamicResource), so switching themes repaints the chart.
    public static readonly DependencyProperty InBrushProperty = BrushProperty(nameof(InBrush), Color.FromRgb(0x25, 0x63, 0xEB));
    public static readonly DependencyProperty OutBrushProperty = BrushProperty(nameof(OutBrush), Color.FromRgb(0xEA, 0x58, 0x0C));
    public static readonly DependencyProperty GridBrushProperty = BrushProperty(nameof(GridBrush), Color.FromRgb(0xE5, 0xE7, 0xEB));
    public static readonly DependencyProperty LabelBrushProperty = BrushProperty(nameof(LabelBrush), Color.FromRgb(0x5F, 0x6B, 0x7A));

    private static DependencyProperty BrushProperty(string name, Color fallback) => DependencyProperty.Register(
        name, typeof(Brush), typeof(TrafficChart),
        new FrameworkPropertyMetadata(Freeze(new SolidColorBrush(fallback)), FrameworkPropertyMetadataOptions.AffectsRender));

    public Brush InBrush { get => (Brush)GetValue(InBrushProperty); set => SetValue(InBrushProperty, value); }
    public Brush OutBrush { get => (Brush)GetValue(OutBrushProperty); set => SetValue(OutBrushProperty, value); }
    public Brush GridBrush { get => (Brush)GetValue(GridBrushProperty); set => SetValue(GridBrushProperty, value); }
    public Brush LabelBrush { get => (Brush)GetValue(LabelBrushProperty); set => SetValue(LabelBrushProperty, value); }

    public RateHistory? History
    {
        get => (RateHistory?)GetValue(HistoryProperty);
        set => SetValue(HistoryProperty, value);
    }

    public int WindowSeconds
    {
        get => (int)GetValue(WindowSecondsProperty);
        set => SetValue(WindowSecondsProperty, value);
    }

    public UnitMode Units
    {
        get => (UnitMode)GetValue(UnitsProperty);
        set => SetValue(UnitsProperty, value);
    }

    public void Refresh() => InvalidateVisual();

    protected override void OnRender(DrawingContext dc)
    {
        double left = IsCompact ? 0 : 72, top = IsCompact ? 1 : 8, bottom = IsCompact ? 1 : 18, right = IsCompact ? 0 : 8;
        double width = ActualWidth - left - right;
        double height = ActualHeight - top - bottom;
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, ActualWidth, ActualHeight));
        if (width < 20 || height < 20)
            return;

        var window = TimeSpan.FromSeconds(WindowSeconds);
        var points = History?.Last(window) ?? [];
        bool stacked = ChartStyle == ChartStyle.Stacked && !IsCompact;
        long max = Math.Max(1024, points.Count == 0 ? 0 : points.Max(p => stacked ? p.In + p.Out : Math.Max(p.In, p.Out)));
        long scale = NiceCeiling(max);
        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var gridPen = Freeze(new Pen(GridBrush, 1));

        for (int i = 0; i <= 4 && !IsCompact; i++)
        {
            double y = top + height * i / 4;
            dc.DrawLine(gridPen, new Point(left, y), new Point(left + width, y));
            long value = scale * (4 - i) / 4;
            var text = Text(ByteFormatter.Rate(value, Units), dpi);
            dc.DrawText(text, new Point(left - 6 - text.Width, y - text.Height / 2));
        }
        if (!IsCompact)
        {
            var now = Text("now", dpi);
            dc.DrawText(now, new Point(left + width - now.Width, top + height + 2));
            var start = Text($"-{WindowSeconds}s", dpi);
            dc.DrawText(start, new Point(left, top + height + 2));
        }

        if (points.Count < 2)
            return;

        DateTimeOffset end = points[^1].Time;
        Point Map(RatePoint p, long v) => new(
            left + width * (1 - (end - p.Time).TotalSeconds / window.TotalSeconds),
            top + height * (1 - (double)v / scale));

        if (!IsCompact && ChartStyle != ChartStyle.Line)
        {
            DrawColumns(dc, points, end, window, left, top, width, height, scale);
            return;
        }

        var inLine = new StreamGeometry();
        var inArea = new StreamGeometry();
        var outLine = new StreamGeometry();
        using (var g = inLine.Open())
            Polyline(g, points.Select(p => Map(p, p.In)), closed: false);
        using (var g = inArea.Open())
        {
            var mapped = points.Select(p => Map(p, p.In)).ToList();
            mapped.Add(new Point(mapped[^1].X, top + height));
            mapped.Add(new Point(mapped[0].X, top + height));
            Polyline(g, mapped, closed: true);
        }
        using (var g = outLine.Open())
            Polyline(g, points.Select(p => Map(p, p.Out)), closed: false);

        dc.PushClip(new RectangleGeometry(new Rect(left, top, width, height)));
        Brush inFill = InBrush.CloneCurrentValue();
        inFill.Opacity = 0.13;
        dc.DrawGeometry(Freeze(inFill), null, inArea);
        dc.DrawGeometry(null, Freeze(new Pen(InBrush, 1.6)), inLine);
        dc.DrawGeometry(null, Freeze(new Pen(OutBrush, 1.6)), outLine);
        dc.Pop();
    }

    /// <summary>One column per sample: side by side, or upload on top of download when stacked.</summary>
    private void DrawColumns(DrawingContext dc, IReadOnlyList<RatePoint> points, DateTimeOffset end, TimeSpan window,
        double left, double top, double width, double height, long scale)
    {
        bool stacked = ChartStyle == ChartStyle.Stacked;
        double slot = width / window.TotalSeconds;
        double bar = Math.Max(1, stacked ? slot - 1 : slot / 2 - 0.5);
        dc.PushClip(new RectangleGeometry(new Rect(left, top, width, height)));
        foreach (var p in points)
        {
            double x = left + width * (1 - (end - p.Time).TotalSeconds / window.TotalSeconds) - slot;
            double inHeight = height * p.In / scale, outHeight = height * p.Out / scale;
            double baseY = top + height;
            dc.DrawRectangle(InBrush, null, new Rect(x, baseY - inHeight, bar, inHeight));
            dc.DrawRectangle(OutBrush, null, stacked
                ? new Rect(x, baseY - inHeight - outHeight, bar, outHeight)
                : new Rect(x + bar + 0.5, baseY - outHeight, bar, outHeight));
        }
        dc.Pop();
    }

    private static void Polyline(StreamGeometryContext g, IEnumerable<Point> points, bool closed)
    {
        bool first = true;
        foreach (var p in points)
        {
            if (first)
            {
                g.BeginFigure(p, isFilled: closed, isClosed: closed);
                first = false;
            }
            else
            {
                g.LineTo(p, isStroked: true, isSmoothJoin: true);
            }
        }
    }

    /// <summary>Rounds up to 1, 2 or 5 times a power of ten so axis labels are readable.</summary>
    internal static long NiceCeiling(long value)
    {
        long magnitude = 1;
        while (magnitude * 10 <= value)
            magnitude *= 10;
        foreach (long step in new long[] { 1, 2, 5, 10 })
            if (step * magnitude >= value)
                return step * magnitude;
        return 10 * magnitude;
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
