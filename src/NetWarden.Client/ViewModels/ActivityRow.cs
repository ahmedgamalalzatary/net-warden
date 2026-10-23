using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Formatting;

namespace NetWarden.Client.ViewModels;

/// <summary>
/// One row of the activity grid: an app (depth 0) or one of its connections (depth 1).
/// Rows are long-lived and updated in place every snapshot.
/// </summary>
public sealed partial class ActivityRow : ObservableObject
{
    private UnitMode _units;

    public ActivityRow(string key, int depth)
    {
        Key = key;
        Depth = depth;
    }

    public string Key { get; }
    public int Depth { get; }
    public bool IsApp => Depth == 0;

    public AppActivity? App { get; private set; }
    public ConnectionActivity? Connection { get; private set; }

    /// <summary>For connection rows: the app they belong to.</summary>
    public ActivityRow? Parent { get; init; }

    [ObservableProperty]
    private string _name = "";

    [ObservableProperty]
    private string _detail = "";

    [ObservableProperty]
    private ImageSource? _icon;

    [ObservableProperty]
    private bool _isExpanded;

    [ObservableProperty]
    private bool _hasChildren;

    [ObservableProperty]
    private bool _isOnline;

    /// <summary>A quick-block Deny rule covers incoming connections of this app.</summary>
    [ObservableProperty]
    private bool _isBlockedIn;

    [ObservableProperty]
    private bool _isBlockedOut;

    [ObservableProperty]
    private long _rateIn;

    [ObservableProperty]
    private long _rateOut;

    [ObservableProperty]
    private long _totalIn;

    [ObservableProperty]
    private long _totalOut;

    public double Indent => Depth * 18;

    public string RateInText => ByteFormatter.RateOrBlank(RateIn, _units);
    public string RateOutText => ByteFormatter.RateOrBlank(RateOut, _units);
    public string TotalInText => ByteFormatter.Size(TotalIn);
    public string TotalOutText => ByteFormatter.Size(TotalOut);

    partial void OnRateInChanged(long value) => OnPropertyChanged(nameof(RateInText));
    partial void OnRateOutChanged(long value) => OnPropertyChanged(nameof(RateOutText));
    partial void OnTotalInChanged(long value) => OnPropertyChanged(nameof(TotalInText));
    partial void OnTotalOutChanged(long value) => OnPropertyChanged(nameof(TotalOutText));

    public void SetUnits(UnitMode units)
    {
        if (_units == units)
            return;
        _units = units;
        OnPropertyChanged(nameof(RateInText));
        OnPropertyChanged(nameof(RateOutText));
    }

    public void Update(AppActivity app)
    {
        App = app;
        Name = app.App.DisplayName;
        Detail = app.App.Kind == AppKind.System ? "System" : app.App.Path;
        IsOnline = app.IsOnline;
        HasChildren = app.Connections.Count > 0;
        RateIn = app.RateIn;
        RateOut = app.RateOut;
        TotalIn = app.TotalIn;
        TotalOut = app.TotalOut;
        OnPropertyChanged(nameof(App));
    }

    public void Update(ConnectionActivity c, PortNames ports)
    {
        Connection = c;
        string proto = c.Protocol == TransportProtocol.Tcp ? "TCP" : "UDP";
        Name = c.Kind switch
        {
            ConnectionKind.Listen when c.Protocol == TransportProtocol.Udp && c.RemoteAddress is { } last =>
                $"{proto} :{ports.Describe(c.LocalPort, c.Protocol)}  (last {FormatHost(last)}:{c.RemotePort})",
            ConnectionKind.Listen => $"{proto} listening on :{ports.Describe(c.LocalPort, c.Protocol)}",
            ConnectionKind.Accept => $"{proto} ← {FormatHost(c.RemoteAddress)}:{c.RemotePort} on :{ports.Describe(c.LocalPort, c.Protocol)}",
            _ => $"{proto} → {FormatHost(c.RemoteAddress)}:{ports.Describe(c.RemotePort, c.Protocol)}",
        };
        Detail = $"{c.Kind} · {c.State} · PID {c.ProcessId}";
        IsOnline = c.State != "Closed";
        RateIn = c.RateIn;
        RateOut = c.RateOut;
        TotalIn = c.TotalIn;
        TotalOut = c.TotalOut;
        OnPropertyChanged(nameof(Connection));
    }

    private static string FormatHost(string? address) =>
        address is null ? "*" : address.Contains(':') ? $"[{address}]" : address;
}
