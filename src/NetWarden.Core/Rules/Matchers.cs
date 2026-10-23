using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text.RegularExpressions;
using NetWarden.Core.Monitoring;

namespace NetWarden.Core.Rules;

/// <summary>
/// An inclusive IP range: a single address ("10.0.0.1"), a span ("10.0.0.1 - 10.0.0.9")
/// or CIDR ("10.0.0.0/8", "fe80::/10"). IPv4 and IPv6 never match each other.
/// </summary>
public readonly record struct IpRange(AddressFamily Family, UInt128 First, UInt128 Last)
{
    public static bool TryParse(string text, out IpRange range)
    {
        range = default;
        text = text.Trim();
        int dash = text.IndexOf('-');
        if (dash > 0)
        {
            if (!IPAddress.TryParse(text[..dash].Trim(), out var a) || !IPAddress.TryParse(text[(dash + 1)..].Trim(), out var b))
                return false;
            a = Endpoints.Normalize(a);
            b = Endpoints.Normalize(b);
            if (a.AddressFamily != b.AddressFamily)
                return false;
            UInt128 x = ToNumber(a), y = ToNumber(b);
            range = new IpRange(a.AddressFamily, UInt128.Min(x, y), UInt128.Max(x, y));
            return true;
        }

        int slash = text.IndexOf('/');
        if (slash > 0)
        {
            if (!IPAddress.TryParse(text[..slash], out var network) || !int.TryParse(text[(slash + 1)..], out int prefix))
                return false;
            network = Endpoints.Normalize(network);
            int bits = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            if (prefix < 0 || prefix > bits)
                return false;
            int hostBits = bits - prefix;
            // Shifts are taken mod 128, so ::/0 needs the all-ones mask spelled out.
            UInt128 hostMask = hostBits == 0 ? UInt128.Zero : hostBits == 128 ? UInt128.MaxValue : (UInt128.One << hostBits) - 1;
            UInt128 first = ToNumber(network) & ~hostMask;
            range = new IpRange(network.AddressFamily, first, first | hostMask);
            return true;
        }

        if (!IPAddress.TryParse(text, out var single))
            return false;
        single = Endpoints.Normalize(single);
        UInt128 n = ToNumber(single);
        range = new IpRange(single.AddressFamily, n, n);
        return true;
    }

    public bool Contains(IPAddress address)
    {
        address = Endpoints.Normalize(address);
        if (address.AddressFamily != Family)
            return false;
        UInt128 n = ToNumber(address);
        return n >= First && n <= Last;
    }

    internal static UInt128 ToNumber(IPAddress address)
    {
        Span<byte> bytes = stackalloc byte[16];
        address.TryWriteBytes(bytes, out int written);
        UInt128 value = 0;
        for (int i = 0; i < written; i++)
            value = (value << 8) | bytes[i];
        return value;
    }
}

/// <summary>An inclusive port range: "80" or "1000 - 1100".</summary>
public readonly record struct PortRange(int First, int Last)
{
    public static bool TryParse(string text, out PortRange range)
    {
        range = default;
        string[] parts = text.Split('-', 2, StringSplitOptions.TrimEntries);
        if (!int.TryParse(parts[0], out int a))
            return false;
        int b = a;
        if (parts.Length == 2 && !int.TryParse(parts[1], out b))
            return false;
        if (a is < 0 or > 65535 || b is < 0 or > 65535)
            return false;
        range = new PortRange(Math.Min(a, b), Math.Max(a, b));
        return true;
    }

    public bool Contains(int port) => port >= First && port <= Last;
}

/// <summary>Case-insensitive '*' and '?' pattern, matched against the whole text.</summary>
public sealed class Wildcard
{
    private readonly Regex _regex;

    public Wildcard(string pattern)
    {
        string body = Regex.Escape(pattern.Trim()).Replace(@"\*", ".*").Replace(@"\?", ".");
        _regex = new Regex("^" + body + "$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    }

    public bool IsMatch(string? text) => text is not null && _regex.IsMatch(text);
}

/// <summary>
/// Classifies a remote address as loopback, local network or Internet. Local means
/// private, link-local, multicast/broadcast, or inside a subnet of a local interface.
/// </summary>
public sealed class ZoneClassifier
{
    private static readonly IpRange[] PrivateRanges = new[]
    {
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255",
        "fc00::/7", "fe80::/10", "ff00::/8",
    }.Select(r => IpRange.TryParse(r, out var range) ? range : throw new InvalidOperationException(r)).ToArray();

    private volatile IpRange[] _interfaceSubnets;

    public ZoneClassifier(IEnumerable<IpRange>? interfaceSubnets = null)
    {
        _interfaceSubnets = interfaceSubnets?.ToArray() ?? ReadInterfaceSubnets();
    }

    /// <summary>Re-reads interface subnets, e.g. after a network change.</summary>
    public void Refresh() => _interfaceSubnets = ReadInterfaceSubnets();

    public static bool IsLoopback(IPAddress remote, IPAddress? local = null)
    {
        remote = Endpoints.Normalize(remote);
        return IPAddress.IsLoopback(remote) || (local is not null && Endpoints.Normalize(local).Equals(remote));
    }

    public bool IsLocalNetwork(IPAddress remote, IPAddress? local = null)
    {
        if (IsLoopback(remote, local))
            return false;
        foreach (var range in PrivateRanges)
            if (range.Contains(remote))
                return true;
        foreach (var range in _interfaceSubnets)
            if (range.Contains(remote))
                return true;
        return false;
    }

    public bool IsInternet(IPAddress remote, IPAddress? local = null) =>
        !IsLoopback(remote, local) && !IsLocalNetwork(remote, local);

    private static IpRange[] ReadInterfaceSubnets()
    {
        var result = new List<IpRange>();
        try
        {
            foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up)
                    continue;
                foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
                {
                    // Skip host routes and absurdly wide prefixes that would swallow the Internet.
                    int bits = unicast.Address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
                    int prefix = unicast.PrefixLength;
                    if (prefix <= 0 || prefix >= bits || (bits == 32 && prefix < 8) || (bits == 128 && prefix < 48))
                        continue;
                    if (IpRange.TryParse($"{unicast.Address}/{prefix}", out var range))
                        result.Add(range);
                }
            }
        }
        catch (System.Net.NetworkInformation.NetworkInformationException)
        {
        }
        return [.. result];
    }
}
