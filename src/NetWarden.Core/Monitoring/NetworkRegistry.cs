using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Storage;

namespace NetWarden.Core.Monitoring;

/// <summary>A network the computer is on right now.</summary>
public sealed record DetectedNetwork(
    string InterfaceName,
    string InterfaceDescription,
    bool IsWifi,
    string? Ssid,
    string? GatewayMac,
    IReadOnlyList<IPAddress> Addresses);

/// <summary>
/// Remembers every network seen and knows which are active. A network is its SSID plus gateway MAC, so the
/// same Wi-Fi is one network on any adapter. A flow belongs to the network of its local address; a socket
/// bound to no particular address belongs to the first active network.
/// </summary>
public sealed class NetworkRegistry
{
    private readonly JsonFileStore<NetworksDocument> _store;
    private readonly Func<IReadOnlyList<DetectedNetwork>> _detect;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly Lock _lock = new();
    private readonly Dictionary<string, KnownNetwork> _known;
    private Dictionary<IPAddress, string> _byAddress = [];
    private List<string> _active = [];

    public NetworkRegistry(JsonFileStore<NetworksDocument> store, Func<IReadOnlyList<DetectedNetwork>> detect, TimeProvider time, ILogger? logger = null)
    {
        _store = store;
        _detect = detect;
        _time = time;
        _logger = logger ?? NullLogger.Instance;
        _known = store.Load().Networks.ToDictionary(n => n.Id, StringComparer.Ordinal);
    }

    /// <summary>Raised outside the lock when the set of active networks changed.</summary>
    public event Action? Changed;

    public static string IdOf(DetectedNetwork n)
    {
        string identity = n.Ssid is null && n.GatewayMac is null ? "if:" + n.InterfaceDescription : $"{n.Ssid}|{n.GatewayMac}";
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(identity)))[..16];
    }

    public void Refresh()
    {
        var detected = _detect();
        DateTimeOffset now = _time.GetUtcNow();
        bool changed;
        lock (_lock)
        {
            var byAddress = new Dictionary<IPAddress, string>();
            var active = new List<string>();
            foreach (var n in detected)
            {
                string id = IdOf(n);
                active.Add(id);
                _known[id] = new KnownNetwork(id, n.Ssid ?? n.InterfaceName, n.InterfaceName, n.InterfaceDescription, n.IsWifi, n.Ssid, n.GatewayMac,
                    _known.TryGetValue(id, out var known) ? known.FirstSeen : now, now);
                foreach (var address in n.Addresses)
                    byAddress[Endpoints.Normalize(address)] = id;
            }
            changed = !active.SequenceEqual(_active);
            _byAddress = byAddress;
            _active = active;
            if (changed)
                Save();
        }
        if (changed)
            Changed?.Invoke();
    }

    public IReadOnlyList<NetworkView> List()
    {
        lock (_lock)
            return _known.Values.Select(n => new NetworkView(n, _active.Contains(n.Id))).ToList();
    }

    public string? NetworkOf(IPAddress local)
    {
        lock (_lock)
            return _byAddress.TryGetValue(Endpoints.Normalize(local), out var id) ? id : _active.FirstOrDefault();
    }

    public string? NameOf(string id)
    {
        lock (_lock)
            return _known.TryGetValue(id, out var network) ? network.Name : null;
    }

    public void Delete(string id)
    {
        lock (_lock)
        {
            if (_active.Contains(id))
                throw new ArgumentException("A network in use can't be deleted.");
            _known.Remove(id);
            Save();
        }
    }

    public void Save()
    {
        lock (_lock)
        {
            try
            {
                _store.Save(new NetworksDocument { Networks = [.. _known.Values] });
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _logger.LogError(ex, "Could not save the networks list.");
            }
        }
    }
}

/// <summary>Finds the networks of the running computer: connected adapters with an address, their gateway's MAC and Wi-Fi name.</summary>
public static partial class NetworkProbe
{
    public static IReadOnlyList<DetectedNetwork> Detect()
    {
        var ssids = WifiNames();
        var found = new List<DetectedNetwork>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up
                || nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                continue;
            var props = nic.GetIPProperties();
            var addresses = props.UnicastAddresses.Select(a => a.Address)
                .Where(a => !IPAddress.IsLoopback(a) && !a.IsIPv6LinkLocal).ToList();
            var gateway = props.GatewayAddresses.Select(g => g.Address).FirstOrDefault(g => g.AddressFamily == AddressFamily.InterNetwork);
            // Virtual adapters (VPN clients, Hyper-V switches) usually have no gateway: not a network to speak of.
            if (addresses.Count == 0 || gateway is null)
                continue;
            bool wifi = nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211;
            found.Add(new DetectedNetwork(nic.Name, nic.Description, wifi,
                wifi ? ssids.GetValueOrDefault(nic.Id.ToUpperInvariant()) : null, GatewayMac(gateway), addresses));
        }
        return found;
    }

    private static string? GatewayMac(IPAddress gateway)
    {
        byte[] mac = new byte[6];
        int length = mac.Length;
#pragma warning disable CS0618 // IPAddress.Address is exactly what SendARP takes.
        uint rc = SendARP((uint)gateway.Address, 0, mac, ref length);
#pragma warning restore CS0618
        return rc == 0 && length == 6 ? Convert.ToHexString(mac).Chunk(2).Select(c => new string(c)).Aggregate((a, b) => $"{a}-{b}") : null;
    }

    /// <summary>SSID per interface GUID (upper case with braces, like NetworkInterface.Id). Empty without the WLAN service.</summary>
    private static Dictionary<string, string> WifiNames()
    {
        var names = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            if (WlanOpenHandle(2, 0, out _, out nint handle) != 0)
                return names;
            try
            {
                if (WlanEnumInterfaces(handle, 0, out nint list) != 0)
                    return names;
                int count = Marshal.ReadInt32(list);
                // WLAN_INTERFACE_INFO_LIST: two DWORDs, then 532-byte entries starting with the GUID.
                for (int i = 0; i < count; i++)
                {
                    nint entry = list + 8 + i * 532;
                    Guid id = Marshal.PtrToStructure<Guid>(entry);
                    if (WlanQueryInterface(handle, id, CurrentConnectionOpcode, 0, out _, out nint data, out _) != 0)
                        continue;
                    // WLAN_CONNECTION_ATTRIBUTES: state (4), mode (4), profile name (512), then DOT11_SSID (length + 32 bytes).
                    int length = Marshal.ReadInt32(data, 520);
                    if (length is > 0 and <= 32)
                    {
                        byte[] ssid = new byte[length];
                        Marshal.Copy(data + 524, ssid, 0, length);
                        names[id.ToString("B").ToUpperInvariant()] = Encoding.UTF8.GetString(ssid);
                    }
                    WlanFreeMemory(data);
                }
                WlanFreeMemory(list);
            }
            finally
            {
                WlanCloseHandle(handle, 0);
            }
        }
        catch (DllNotFoundException)
        {
            // Windows Server without the wireless feature.
        }
        return names;
    }

    private const int CurrentConnectionOpcode = 7;

    [LibraryImport("iphlpapi.dll")]
    private static partial uint SendARP(uint destination, uint source, [Out] byte[] mac, ref int length);

    [LibraryImport("wlanapi.dll")]
    private static partial uint WlanOpenHandle(uint version, nint reserved, out uint negotiated, out nint handle);

    [LibraryImport("wlanapi.dll")]
    private static partial uint WlanCloseHandle(nint handle, nint reserved);

    [LibraryImport("wlanapi.dll")]
    private static partial uint WlanEnumInterfaces(nint handle, nint reserved, out nint list);

    [LibraryImport("wlanapi.dll")]
    private static partial uint WlanQueryInterface(nint handle, in Guid iface, int opcode, nint reserved, out int size, out nint data, out int valueType);

    [LibraryImport("wlanapi.dll")]
    private static partial void WlanFreeMemory(nint memory);
}
