using System.Globalization;

namespace NetWarden.Shared.Formatting;

public enum UnitMode
{
    /// <summary>B, KB, MB... (1024-based), rates as KB/s.</summary>
    Bytes,
    /// <summary>bps, Kbps, Mbps... (1000-based), as ISPs quote speeds.</summary>
    Bits,
}

public static class ByteFormatter
{
    private static readonly string[] ByteUnits = ["B", "KB", "MB", "GB", "TB"];
    private static readonly string[] BitUnits = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];

    public static string Size(long bytes)
    {
        double value = bytes;
        int unit = 0;
        while (Math.Abs(value) >= 1024 && unit < ByteUnits.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return Format(value, unit) + " " + ByteUnits[unit];
    }

    public static string Rate(long bytesPerSecond, UnitMode mode)
    {
        if (mode == UnitMode.Bytes)
            return Size(bytesPerSecond) + "/s";

        double value = bytesPerSecond * 8.0;
        int unit = 0;
        while (Math.Abs(value) >= 1000 && unit < BitUnits.Length - 1)
        {
            value /= 1000;
            unit++;
        }
        return Format(value, unit) + " " + BitUnits[unit];
    }

    /// <summary>Rates show blank instead of "0 B/s" so active rows stand out.</summary>
    public static string RateOrBlank(long bytesPerSecond, UnitMode mode) =>
        bytesPerSecond == 0 ? "" : Rate(bytesPerSecond, mode);

    private static string Format(double value, int unit) =>
        unit == 0
            ? value.ToString("0", CultureInfo.CurrentCulture)
            : value.ToString(Math.Abs(value) < 10 ? "0.##" : Math.Abs(value) < 100 ? "0.#" : "0", CultureInfo.CurrentCulture);
}
