using System.Globalization;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Formatting;

namespace NetWarden.Tests.Formatting;

public class ByteFormatterTests
{
    public ByteFormatterTests()
    {
        CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
    }

    [Theory]
    [InlineData(0, "0 B")]
    [InlineData(1023, "1023 B")]
    [InlineData(1024, "1 KB")]
    [InlineData(1536, "1.5 KB")]
    [InlineData(10 * 1024 + 512, "10.5 KB")]
    [InlineData(150 * 1024, "150 KB")]
    [InlineData(5L * 1024 * 1024 * 1024, "5 GB")]
    [InlineData(3L * 1024 * 1024 * 1024 * 1024 * 1024, "3072 TB")]
    public void Size_uses_binary_units(long bytes, string expected)
    {
        Assert.Equal(expected, ByteFormatter.Size(bytes));
    }

    [Theory]
    [InlineData(1024, UnitMode.Bytes, "1 KB/s")]
    [InlineData(125_000, UnitMode.Bits, "1 Mbps")]
    [InlineData(100, UnitMode.Bits, "800 bps")]
    [InlineData(12_500_000, UnitMode.Bits, "100 Mbps")]
    public void Rate_formats_bytes_or_bits(long bytesPerSecond, UnitMode mode, string expected)
    {
        Assert.Equal(expected, ByteFormatter.Rate(bytesPerSecond, mode));
    }

    [Fact]
    public void Zero_rate_is_blank()
    {
        Assert.Equal("", ByteFormatter.RateOrBlank(0, UnitMode.Bytes));
        Assert.Equal("1 KB/s", ByteFormatter.RateOrBlank(1024, UnitMode.Bytes));
    }
}

public class PortNamesTests
{
    private static readonly string[] Sample =
    [
        "# Copyright header",
        "echo                7/tcp",
        "domain             53/tcp                           #Domain Name Server",
        "domain             53/udp                           #Domain Name Server",
        "http               80/tcp    www www-http           #World Wide Web",
        "bad                xx/tcp",
        "",
        "kerberos           88/tcp    krb5 kerberos-sec      #Kerberos",
        "kerberos-dup       88/tcp",
    ];

    [Fact]
    public void Parses_names_per_protocol_and_keeps_first_entry()
    {
        var names = new PortNames(Sample);

        Assert.Equal("http", names.Get(80, TransportProtocol.Tcp));
        Assert.Null(names.Get(80, TransportProtocol.Udp));
        Assert.Equal("domain", names.Get(53, TransportProtocol.Udp));
        Assert.Equal("kerberos", names.Get(88, TransportProtocol.Tcp));
        Assert.Null(names.Get(12345, TransportProtocol.Tcp));
    }

    [Fact]
    public void Describe_appends_name_when_known()
    {
        var names = new PortNames(Sample);

        Assert.Equal("80 (http)", names.Describe(80, TransportProtocol.Tcp));
        Assert.Equal("12345", names.Describe(12345, TransportProtocol.Tcp));
    }

    [Fact]
    public void System_services_file_knows_https()
    {
        Assert.Equal("https", PortNames.LoadSystem().Get(443, TransportProtocol.Tcp));
    }
}
