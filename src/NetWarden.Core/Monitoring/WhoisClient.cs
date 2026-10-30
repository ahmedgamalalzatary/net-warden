using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace NetWarden.Core.Monitoring;

/// <summary>Sends one WHOIS query to a server and returns its answer.</summary>
public delegate Task<string> WhoisTransport(string host, string query, CancellationToken ct);

/// <summary>
/// Looks an address up the way WHOIS works: IANA names the registry, the registry may refer further.
/// Only the address is ever sent, and only on port 43 of the servers named along the way.
/// </summary>
public sealed partial class WhoisClient(WhoisTransport? transport = null)
{
    private const string Root = "whois.iana.org";
    private const int MaxServers = 4;
    private const int MaxAnswerBytes = 256 * 1024;
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private readonly WhoisTransport _transport = transport ?? AskAsync;

    public async Task<string> LookupAsync(IPAddress address, CancellationToken ct)
    {
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string host = Root;
        string answer = "";
        while (visited.Count < MaxServers && visited.Add(host))
        {
            // ARIN answers a bare address with a summary; "n +" asks for the full network record.
            string query = host.Equals("whois.arin.net", StringComparison.OrdinalIgnoreCase) ? $"n + {address}" : address.ToString();
            answer = await _transport(host, query, ct).ConfigureAwait(false);
            if (Referral(answer) is not { } next)
                break;
            host = next;
        }
        return answer;
    }

    private static string? Referral(string answer)
    {
        var match = ReferralPattern().Match(answer);
        return match.Success ? match.Groups[1].Value : null;
    }

    private static async Task<string> AskAsync(string host, string query, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(Timeout);
        using var client = new TcpClient();
        await client.ConnectAsync(host, 43, timeout.Token).ConfigureAwait(false);
        var stream = client.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes(query + "\r\n"), timeout.Token).ConfigureAwait(false);

        using var answer = new MemoryStream();
        byte[] buffer = new byte[8192];
        int read;
        while (answer.Length < MaxAnswerBytes && (read = await stream.ReadAsync(buffer, timeout.Token).ConfigureAwait(false)) > 0)
            answer.Write(buffer, 0, read);
        return Encoding.UTF8.GetString(answer.ToArray());
    }

    [GeneratedRegex(@"^\s*(?:refer|whois|ReferralServer):\s*(?:r?whois://)?([A-Za-z0-9.-]+)", RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex ReferralPattern();
}
