using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Formatting;
using NetWarden.Shared.Ipc;

namespace NetWarden.Client.ViewModels;

public sealed partial class InfoItem(string label, string value) : ObservableObject
{
    public string Label { get; } = label;

    [ObservableProperty]
    private string _value = value;
}

/// <summary>
/// Properties of the selected app or connection. <see cref="Refresh"/> runs every
/// snapshot and updates values in place; reverse DNS results are cached.
/// </summary>
public sealed partial class InfoViewModel(IServiceRequester service, PortNames ports) : ObservableObject
{
    private const string RemoteHostLabel = "Remote host";

    private readonly Dictionary<string, string> _hostNames = new(StringComparer.Ordinal);
    private readonly Dictionary<string, GeoInfo?> _countries = new(StringComparer.Ordinal);
    private ActivityRow? _row;
    private int _version;

    [ObservableProperty]
    private string _title = "Nothing selected";

    /// <summary>The public address the WHOIS, web and map lookups are for; null for private ones.</summary>
    [ObservableProperty]
    private string? _lookupAddress;

    /// <summary>Lower-case country code of <see cref="LookupAddress"/>, naming its flag.</summary>
    [ObservableProperty]
    private string? _flagCode;

    public ObservableCollection<InfoItem> Items { get; } = [];

    public static string WebLink(string address) => $"https://ipinfo.io/{address}";

    public static string MapLink(string place) => $"https://www.openstreetmap.org/search?query={Uri.EscapeDataString(place)}";

    /// <summary>What the map link searches for: the selected address's country.</summary>
    public string? MapPlace => LookupAddress is { } a ? _countries.GetValueOrDefault(a)?.Name : null;

    public async Task ShowAsync(ActivityRow? row)
    {
        if (row is not null && ReferenceEquals(row, _row))
            return;
        int version = ++_version;
        _row = row;
        Items.Clear();
        Refresh();

        if (row?.Connection?.RemoteAddress is { } remote)
        {
            if (!_countries.ContainsKey(remote))
            {
                GeoInfo? geo = null;
                try
                {
                    geo = await service.RequestAsync<GeoInfo>(Methods.GeoLookup, new AddressRequest(remote));
                }
                catch (Exception ex) when (ex is IpcRemoteException or IpcDisconnectedException)
                {
                }
                _countries[remote] = geo;
            }
            if (version == _version)
                Refresh();
        }

        if (row?.Connection?.RemoteAddress is { } address && !_hostNames.ContainsKey(address))
        {
            string? name = null;
            try
            {
                name = await service.RequestAsync<string>(Methods.DnsReverse, new ReverseDnsRequest(address));
            }
            catch (Exception ex) when (ex is IpcRemoteException or IpcDisconnectedException)
            {
            }
            _hostNames[address] = name ?? "Unresolved";
            if (version == _version)
                Refresh();
        }
    }

    /// <summary>Re-reads the current row (whose data is updated in place by snapshots).</summary>
    public void Refresh()
    {
        var items = new List<(string Label, string Value)>();
        if (_row?.App is { } activity && _row.IsApp)
            BuildApp(activity, items);
        else if (_row?.Connection is { } c)
            BuildConnection(c, _row.Parent?.App, items);
        else
            Title = "Nothing selected";

        // The country database has no private addresses, so a country also means "public".
        var country = _row?.Connection?.RemoteAddress is { } address ? _countries.GetValueOrDefault(address) : null;
        LookupAddress = country is null ? null : _row!.Connection!.RemoteAddress;
        FlagCode = country?.Code.ToLowerInvariant();
        OnPropertyChanged(nameof(MapPlace));

        if (Items.Select(i => i.Label).SequenceEqual(items.Select(i => i.Label)))
        {
            for (int i = 0; i < items.Count; i++)
                Items[i].Value = items[i].Value;
        }
        else
        {
            Items.Clear();
            foreach (var (label, value) in items)
                Items.Add(new InfoItem(label, value));
        }
    }

    private void BuildApp(AppActivity activity, List<(string, string)> items)
    {
        AppInfo app = activity.App;
        Title = app.DisplayName;
        Add(items, "Type", app.Kind switch
        {
            AppKind.Service => "System service",
            AppKind.Store => "Store app",
            AppKind.System => "System",
            _ => "Desktop app",
        });
        Add(items, "Path", app.Path);
        Add(items, "Company", app.CompanyName);
        Add(items, "Product", app.ProductName);
        Add(items, "Version", app.FileVersion);
        Add(items, "Package", app.PackageFamilyName);
        if (app.Services.Count > 0)
            Add(items, "Services", string.Join(", ", app.Services.Select(s => $"{s.DisplayName} ({s.Name})")));
        Add(items, "Process ids", activity.ProcessIds.Count > 0 ? string.Join(", ", activity.ProcessIds) : "Not running");
        Add(items, "Connections", activity.Connections.Count.ToString());
        Add(items, "Downloaded", ByteFormatter.Size(activity.TotalIn));
        Add(items, "Uploaded", ByteFormatter.Size(activity.TotalOut));
    }

    private void BuildConnection(ConnectionActivity c, AppActivity? owner, List<(string, string)> items)
    {
        Title = $"{c.Protocol.ToString().ToUpperInvariant()} connection";
        Add(items, "Application", owner?.App.DisplayName);
        Add(items, "Process id", c.ProcessId.ToString());
        Add(items, "Type", c.Kind switch
        {
            ConnectionKind.Connect => "Outgoing connection",
            ConnectionKind.Accept => "Incoming connection",
            _ => "Listening",
        });
        Add(items, "State", c.State);
        Add(items, "Local address", $"{c.LocalAddress} : {ports.Describe(c.LocalPort, c.Protocol)}");
        if (c.RemoteAddress is { } remote)
        {
            Add(items, c.Protocol == TransportProtocol.Udp ? "Last remote" : "Remote address",
                $"{remote} : {ports.Describe(c.RemotePort, c.Protocol)}");
            Add(items, RemoteHostLabel, _hostNames.GetValueOrDefault(remote, "Resolving..."));
            if (_countries.GetValueOrDefault(remote) is { } country)
                Add(items, "Country", $"{country.Name} ({country.Code})");
        }
        Add(items, "Downloaded", ByteFormatter.Size(c.TotalIn));
        Add(items, "Uploaded", ByteFormatter.Size(c.TotalOut));
    }

    private static void Add(List<(string, string)> items, string label, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
            items.Add((label, value));
    }
}
