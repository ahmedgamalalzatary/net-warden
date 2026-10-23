using System.Net;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Rules;

namespace NetWarden.Tests.Rules;

public class IpRangeTests
{
    [Theory]
    [InlineData("192.168.1.1", "192.168.1.1", true)]
    [InlineData("192.168.1.1", "192.168.1.2", false)]
    [InlineData("192.168.1.0 - 192.168.1.10", "192.168.1.10", true)]
    [InlineData("192.168.1.10-192.168.1.0", "192.168.1.5", true)]
    [InlineData("192.168.1.0 - 192.168.1.10", "192.168.1.11", false)]
    [InlineData("192.168.0.0/16", "192.168.255.255", true)]
    [InlineData("192.168.0.0/16", "192.169.0.0", false)]
    [InlineData("0.0.0.0/0", "8.8.8.8", true)]
    [InlineData("10.1.2.3/8", "10.200.0.1", true)]
    [InlineData("fe80::/10", "fe80::1234", true)]
    [InlineData("fe80::/10", "fec0::1", false)]
    [InlineData("::/0", "2001:db8::1", true)]
    [InlineData("2001:db8::1", "2001:db8::1", true)]
    [InlineData("192.168.0.0/16", "::ffff:192.168.3.4", true)]
    [InlineData("::ffff:10.0.0.1", "10.0.0.1", true)]
    [InlineData("10.0.0.0/8", "2001:db8::1", false)]
    public void Contains(string range, string address, bool expected)
    {
        Assert.True(IpRange.TryParse(range, out var r));
        Assert.Equal(expected, r.Contains(IPAddress.Parse(address)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not an ip")]
    [InlineData("10.0.0.0/33")]
    [InlineData("10.0.0.0/-1")]
    [InlineData("10.0.0.1 - 2001:db8::1")]
    [InlineData("300.1.1.1")]
    public void Rejects_invalid(string text)
    {
        Assert.False(IpRange.TryParse(text, out _));
    }

    [Fact]
    public void Ipv6_scope_ids_are_ignored()
    {
        Assert.True(IpRange.TryParse("fe80::1%12", out var r));
        Assert.True(r.Contains(IPAddress.Parse("fe80::1")));
    }
}

public class PortRangeTests
{
    [Theory]
    [InlineData("80", 80, true)]
    [InlineData("80", 81, false)]
    [InlineData("1000 - 1100", 1050, true)]
    [InlineData("1100-1000", 1000, true)]
    [InlineData("0-65535", 65535, true)]
    public void Contains(string text, int port, bool expected)
    {
        Assert.True(PortRange.TryParse(text, out var r));
        Assert.Equal(expected, r.Contains(port));
    }

    [Theory]
    [InlineData("")]
    [InlineData("http")]
    [InlineData("70000")]
    [InlineData("-1")]
    [InlineData("10-x")]
    public void Rejects_invalid(string text)
    {
        Assert.False(PortRange.TryParse(text, out _));
    }
}

public class WildcardTests
{
    [Theory]
    [InlineData("*.google.com", "www.google.com", true)]
    [InlineData("*.google.com", "google.com", false)]
    [InlineData("*google.com", "google.com", true)]
    [InlineData("*\\chrome.exe", @"C:\Program Files\Google\Chrome\chrome.exe", true)]
    [InlineData("*\\CHROME.EXE", @"c:\x\chrome.exe", true)]
    [InlineData("a?c", "abc", true)]
    [InlineData("a?c", "abbc", false)]
    [InlineData("a.c", "abc", false)]
    [InlineData("[x]", "[x]", true)]
    public void Matches_whole_text_case_insensitively(string pattern, string text, bool expected)
    {
        Assert.Equal(expected, new Wildcard(pattern).IsMatch(text));
    }

    [Fact]
    public void Null_never_matches()
    {
        Assert.False(new Wildcard("*").IsMatch(null));
    }
}

public class ZoneClassifierTests
{
    private readonly ZoneClassifier _zones = new([IpRange.TryParse("100.64.5.0/24", out var r) ? r : default]);

    [Theory]
    [InlineData("127.0.0.1", "loopback")]
    [InlineData("::1", "loopback")]
    [InlineData("192.168.1.1", "local")]
    [InlineData("10.20.30.40", "local")]
    [InlineData("172.20.0.1", "local")]
    [InlineData("172.32.0.1", "internet")]
    [InlineData("169.254.1.1", "local")]
    [InlineData("224.0.0.251", "local")]
    [InlineData("255.255.255.255", "local")]
    [InlineData("fe80::1", "local")]
    [InlineData("fd12::1", "local")]
    [InlineData("ff02::fb", "local")]
    [InlineData("100.64.5.9", "local")]
    [InlineData("100.64.6.9", "internet")]
    [InlineData("8.8.8.8", "internet")]
    [InlineData("2606:4700::1111", "internet")]
    public void Classifies_remote_address(string address, string zone)
    {
        var ip = IPAddress.Parse(address);

        Assert.Equal(zone == "loopback", ZoneClassifier.IsLoopback(ip));
        Assert.Equal(zone == "local", _zones.IsLocalNetwork(ip));
        Assert.Equal(zone == "internet", _zones.IsInternet(ip));
    }

    [Fact]
    public void Traffic_to_own_address_is_loopback()
    {
        var self = IPAddress.Parse("192.168.1.14");

        Assert.True(ZoneClassifier.IsLoopback(self, self));
        Assert.False(_zones.IsLocalNetwork(self, self));
    }

    [Fact]
    public void Real_interfaces_load_without_error()
    {
        var zones = new ZoneClassifier();
        Assert.True(zones.IsInternet(IPAddress.Parse("8.8.8.8")));
    }
}

public class DnsMapTests
{
    [Theory]
    [InlineData("::ffff:93.184.216.34;", new[] { "::ffff:93.184.216.34" })]
    [InlineData("type:  5 cdn.example.net;::ffff:1.2.3.4;::ffff:5.6.7.8;", new[] { "::ffff:1.2.3.4", "::ffff:5.6.7.8" })]
    [InlineData("2606:2800:220:1:248:1893:25c8:1946;", new[] { "2606:2800:220:1:248:1893:25c8:1946" })]
    [InlineData("", new string[0])]
    [InlineData("type:  5 only.alias;", new string[0])]
    public void Parses_query_results(string results, string[] expected)
    {
        Assert.Equal(expected.Select(IPAddress.Parse), DnsMap.ParseQueryResults(results));
    }

    [Fact]
    public void Lookup_normalizes_mapped_addresses_and_strips_trailing_dot()
    {
        var map = new DnsMap();
        map.Record("www.example.com.", DnsMap.ParseQueryResults("::ffff:93.184.216.34;"));

        Assert.Equal("www.example.com", map.Lookup(IPAddress.Parse("93.184.216.34")));
        Assert.Null(map.Lookup(IPAddress.Parse("1.1.1.1")));
    }

    [Fact]
    public void Latest_name_wins_and_capacity_evicts_oldest()
    {
        var map = new DnsMap(capacity: 2);
        map.Record("a.com", [IPAddress.Parse("1.0.0.1")]);
        map.Record("b.com", [IPAddress.Parse("1.0.0.2")]);
        map.Record("c.com", [IPAddress.Parse("1.0.0.2")]);
        map.Record("d.com", [IPAddress.Parse("1.0.0.3")]);

        Assert.Equal(2, map.Count);
        Assert.Null(map.Lookup(IPAddress.Parse("1.0.0.1")));
        Assert.Equal("c.com", map.Lookup(IPAddress.Parse("1.0.0.2")));
        Assert.Equal("d.com", map.Lookup(IPAddress.Parse("1.0.0.3")));
    }
}
