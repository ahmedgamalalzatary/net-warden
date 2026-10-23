using NetWarden.Shared.Contracts;

namespace NetWarden.Shared.Formatting;

/// <summary>
/// Port number to service name, read from Windows' services file
/// (%SystemRoot%\System32\drivers\etc\services), e.g. 443/tcp is "https".
/// </summary>
public sealed class PortNames
{
    private readonly Dictionary<(int Port, TransportProtocol Protocol), string> _names;

    public PortNames(IEnumerable<string> servicesFileLines)
    {
        _names = Parse(servicesFileLines);
    }

    public static PortNames LoadSystem()
    {
        string path = Path.Combine(Environment.SystemDirectory, "drivers", "etc", "services");
        try
        {
            return new PortNames(File.Exists(path) ? File.ReadLines(path) : []);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new PortNames([]);
        }
    }

    public string? Get(int port, TransportProtocol protocol) =>
        _names.TryGetValue((port, protocol), out string? name) ? name : null;

    /// <summary>"443 (https)" or just "443".</summary>
    public string Describe(int port, TransportProtocol protocol) =>
        Get(port, protocol) is { } name ? $"{port} ({name})" : port.ToString();

    private static Dictionary<(int, TransportProtocol), string> Parse(IEnumerable<string> lines)
    {
        var result = new Dictionary<(int, TransportProtocol), string>();
        foreach (string raw in lines)
        {
            // Format: name  port/proto  [aliases...]  [#comment]
            string line = raw.Split('#', 2)[0];
            string[] parts = line.Split((char[])[' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
                continue;
            string[] portProto = parts[1].Split('/');
            if (portProto.Length != 2 || !int.TryParse(portProto[0], out int port))
                continue;
            TransportProtocol? protocol = portProto[1].ToLowerInvariant() switch
            {
                "tcp" => TransportProtocol.Tcp,
                "udp" => TransportProtocol.Udp,
                _ => null,
            };
            if (protocol is { } p)
                result.TryAdd((port, p), parts[0]);
        }
        return result;
    }
}
