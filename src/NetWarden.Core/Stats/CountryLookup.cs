using System.Buffers.Binary;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using NetWarden.Core.Monitoring;

namespace NetWarden.Core.Stats;

/// <summary>
/// IP address to ISO country code, from DB-IP's free "IP to Country Lite" database (CC BY 4.0),
/// converted by scripts/update-geoip.py. IPv6 is looked up by its top 64 bits.
/// </summary>
public sealed class CountryLookup
{
    public const string DefaultFileName = "country.bin.gz";
    private static readonly byte[] Magic = "NWGEO1"u8.ToArray();

    private readonly uint[] _v4Starts;
    private readonly ushort[] _v4Codes;
    private readonly ulong[] _v6Starts;
    private readonly ushort[] _v6Codes;

    private CountryLookup(uint[] v4Starts, ushort[] v4Codes, ulong[] v6Starts, ushort[] v6Codes, string? date)
    {
        _v4Starts = v4Starts;
        _v4Codes = v4Codes;
        _v6Starts = v6Starts;
        _v6Codes = v6Codes;
        DatabaseDate = date;
    }

    /// <summary>Knows no country; used when the database file is missing.</summary>
    public static CountryLookup Empty { get; } = new([], [], [], [], null);

    /// <summary>Month of the DB-IP release, e.g. "2026-10".</summary>
    public string? DatabaseDate { get; }

    public int RangeCount => _v4Starts.Length + _v6Starts.Length;

    /// <summary>Loads the database next to the service; <see cref="Empty"/> when it is missing or unreadable.</summary>
    public static CountryLookup LoadDefault(Action<Exception>? onError = null)
    {
        string path = Path.Combine(AppContext.BaseDirectory, DefaultFileName);
        if (!File.Exists(path))
            return Empty;
        try
        {
            using var file = File.OpenRead(path);
            return Load(file);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException)
        {
            onError?.Invoke(ex);
            return Empty;
        }
    }

    /// <summary>Reads the gzip-compressed format written by scripts/update-geoip.py.</summary>
    public static CountryLookup Load(Stream compressed)
    {
        using var buffer = new MemoryStream();
        using (var gzip = new GZipStream(compressed, CompressionMode.Decompress))
            gzip.CopyTo(buffer);
        ReadOnlySpan<byte> data = buffer.GetBuffer().AsSpan(0, (int)buffer.Length);
        if (!data.StartsWith(Magic))
            throw new InvalidDataException("Not a NetWarden country database.");
        int pos = Magic.Length;

        int n4 = ReadCount(data, ref pos, 6);
        var v4Starts = new uint[n4];
        var v4Codes = new ushort[n4];
        for (int i = 0; i < n4; i++, pos += 6)
        {
            v4Starts[i] = BinaryPrimitives.ReadUInt32BigEndian(data[pos..]);
            v4Codes[i] = BinaryPrimitives.ReadUInt16BigEndian(data[(pos + 4)..]);
        }

        int n6 = ReadCount(data, ref pos, 10);
        var v6Starts = new ulong[n6];
        var v6Codes = new ushort[n6];
        for (int i = 0; i < n6; i++, pos += 10)
        {
            v6Starts[i] = BinaryPrimitives.ReadUInt64BigEndian(data[pos..]);
            v6Codes[i] = BinaryPrimitives.ReadUInt16BigEndian(data[(pos + 8)..]);
        }

        int dateLength = ReadCount(data, ref pos, 1);
        string? date = dateLength is > 0 and <= 64 ? System.Text.Encoding.UTF8.GetString(data.Slice(pos, dateLength)) : null;
        return new CountryLookup(v4Starts, v4Codes, v6Starts, v6Codes, date);
    }

    /// <summary>Reads a count and checks that that many entries of <paramref name="entrySize"/> bytes follow.</summary>
    private static int ReadCount(ReadOnlySpan<byte> data, ref int pos, int entrySize)
    {
        if (data.Length - pos < 4)
            throw new InvalidDataException("Country database is truncated.");
        uint count = BinaryPrimitives.ReadUInt32BigEndian(data[pos..]);
        pos += 4;
        if (count > (uint)(data.Length - pos) / (uint)entrySize)
            throw new InvalidDataException("Country database is corrupt.");
        return (int)count;
    }

    /// <summary>Two-letter country code (upper case), or null for private, reserved and unknown addresses.</summary>
    public string? Country(IPAddress address)
    {
        address = Endpoints.Normalize(address);
        Span<byte> bytes = stackalloc byte[16];
        if (!address.TryWriteBytes(bytes, out int written))
            return null;
        ushort code;
        if (address.AddressFamily == AddressFamily.InterNetwork && written == 4)
        {
            int i = Floor(_v4Starts, BinaryPrimitives.ReadUInt32BigEndian(bytes));
            code = i < 0 ? (ushort)0 : _v4Codes[i];
        }
        else if (address.AddressFamily == AddressFamily.InterNetworkV6 && written == 16)
        {
            int i = Floor(_v6Starts, BinaryPrimitives.ReadUInt64BigEndian(bytes));
            code = i < 0 ? (ushort)0 : _v6Codes[i];
        }
        else
        {
            return null;
        }
        return code == 0 ? null : new string([(char)(code >> 8), (char)(code & 0xFF)]);
    }

    /// <summary>English name of a country code ("US" -> "United States"); the code itself when Windows doesn't know it.</summary>
    public static string CountryName(string code)
    {
        try
        {
            return new RegionInfo(code).EnglishName;
        }
        catch (ArgumentException)
        {
            return code;
        }
    }

    /// <summary>Index of the last start that is not above <paramref name="value"/>, or -1.</summary>
    private static int Floor<T>(T[] starts, T value) where T : IComparable<T>
    {
        int i = Array.BinarySearch(starts, value);
        return i >= 0 ? i : ~i - 1;
    }
}
