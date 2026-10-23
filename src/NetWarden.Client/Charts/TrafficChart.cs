using System.Globalization;
using System.Windows;
using System.Windows.Media;
using NetWarden.Shared.Formatting;

namespace NetWarden.Client.Charts;

/// <summary>Line chart of download/upload rate over a time window. Call <see cref="Refresh"/> after new samples.</summary>
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

    private static readonly Pen InPen = Freeze(new Pen(new SolidColorBrush(Color.FromRgb(0x25, 0x63, 0xEB)), 1.6));
    private static readonly Pen OutPen = Freeze(new Pen(new SolidColorBrush(Color.FromRgb(0xEA, 0x58, 0x0C)), 1.6));
    private static readonly Pen GridPen = Freeze(new Pen(new SolidColorBrush(Color.FromRgb(0xE5, 0xE7, 0xEB)), 1));
    private static readonly Brush LabelBrush = Freeze(new SolidColorBrush(Color.FromRgb(0x5F, 0x6B, 0x7A)));
    private static readonly Brush InFill = Freeze(new SolidColorBrush(Color.FromArgb(0x22, 0x25, 0x63, 0xEB)));

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
        const double left = 72, top = 8, bottom = 18, right = 8;
        double width = ActualWidth - left - right;
        double height = ActualHeight - top - bottom;
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, ActualWidth, ActualHeight));
        if (width < 20 || height < 20)
            return;

        var window = TimeSpan.FromSeconds(WindowSeconds);
        var points = History?.Last(window) ?? [];
        long max = Math.Max(1024, points.Count == 0 ? 0 : points.Max(p => Math.Max(p.In, p.Out)));
        long scale = NiceCeiling(max);
        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;

        for (int i = 0; i <= 4; i++)
        {
            double y = top + height * i / 4;
            dc.DrawLine(GridPen, new Point(left, y), new Point(left + width, y));
            long value = scale * (4 - i) / 4;
            var text = Text(ByteFormatter.Rate(value, Units), dpi);
            dc.DrawText(text, new Point(left - 6 - text.Width, y - text.Height / 2));
        }
        var now = Text("now", dpi);
        dc.DrawText(now, new Point(left + width - now.Width, top + height + 2));
        var start = Text($"-{WindowSeconds}s", dpi);
        dc.DrawText(start, new Point(left, top + height + 2));

        if (points.Count < 2)
            return;

        DateTimeOffset end = points[^1].Time;
        Point Map(RatePoint p, long v) => new(
            left + width * (1 - (end - p.Time).TotalSeconds / window.TotalSeconds),
            top + height * (1 - (double)v / scale));

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
        dc.DrawGeometry(InFill, null, inArea);
        dc.DrawGeometry(null, InPen, inLine);
        dc.DrawGeometry(null, OutPen, outLine);
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

    private static FormattedText Text(string s, double dpi) =>
        new(s, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, new Typeface("Segoe UI"), 11, LabelBrush, dpi);

    private static T Freeze<T>(T freezable) where T : Freezable
    {
        freezable.Freeze();
        return freezable;
    }
}
