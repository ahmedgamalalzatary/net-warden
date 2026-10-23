using System.Net;

namespace NetWarden.Core.Monitoring;

public static class Endpoints
{
    /// <summary>
    /// Canonical form for comparing addresses from different sources: IPv4-mapped
    /// IPv6 becomes IPv4, and IPv6 scope ids are dropped (ETW omits them).
    /// </summary>
    public static IPAddress Normalize(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
            return address.MapToIPv4();
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && address.ScopeId != 0)
            return new IPAddress(address.GetAddressBytes());
        return address;
    }

    public static bool IsUnspecified(IPAddress address) =>
        address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);
}
