using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NetWarden.Client.Services;

public enum VirusTotalOutcome
{
    Found,
    Unknown,
    BadKey,
    TooManyRequests,
    Failed,
}

public sealed record VirusTotalResult(VirusTotalOutcome Outcome, int Malicious, int Suspicious, int Engines, string? Link)
{
    public string Text => Outcome switch
    {
        VirusTotalOutcome.Found when Malicious + Suspicious == 0 => $"Clean: none of {Engines} scanners flag this file.",
        VirusTotalOutcome.Found => $"{Malicious + Suspicious} of {Engines} scanners flag this file.",
        VirusTotalOutcome.Unknown => "VirusTotal has never seen this file. NetWarden doesn't upload files.",
        VirusTotalOutcome.BadKey => "VirusTotal refused the API key. Check it in Settings.",
        VirusTotalOutcome.TooManyRequests => "VirusTotal's limit for this API key is used up. Try again later.",
        _ => "VirusTotal didn't answer. Try again later.",
    };
}

/// <summary>Asks VirusTotal what it knows about a file. Only the file's SHA-256 leaves the computer, never its content.</summary>
public sealed class VirusTotalClient(HttpClient http)
{
    public async Task<VirusTotalResult> CheckFileAsync(string path, string apiKey, CancellationToken ct = default)
    {
        byte[] hash;
        await using (var file = File.OpenRead(path))
            hash = await SHA256.HashDataAsync(file, ct).ConfigureAwait(false);
        return await CheckHashAsync(Convert.ToHexString(hash), apiKey, ct).ConfigureAwait(false);
    }

    public async Task<VirusTotalResult> CheckHashAsync(string sha256, string apiKey, CancellationToken ct = default)
    {
        string hash = sha256.ToLowerInvariant();
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{hash}");
        request.Headers.Add("x-apikey", apiKey);
        try
        {
            using var response = await http.SendAsync(request, ct).ConfigureAwait(false);
            switch (response.StatusCode)
            {
                case HttpStatusCode.NotFound:
                    return new VirusTotalResult(VirusTotalOutcome.Unknown, 0, 0, 0, null);
                case HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden:
                    return new VirusTotalResult(VirusTotalOutcome.BadKey, 0, 0, 0, null);
                case HttpStatusCode.TooManyRequests:
                    return new VirusTotalResult(VirusTotalOutcome.TooManyRequests, 0, 0, 0, null);
                case HttpStatusCode.OK:
                    break;
                default:
                    return new VirusTotalResult(VirusTotalOutcome.Failed, 0, 0, 0, null);
            }
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            var stats = json.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("last_analysis_stats");
            int total = stats.EnumerateObject().Sum(p => p.Value.GetInt32());
            return new VirusTotalResult(VirusTotalOutcome.Found, stats.GetProperty("malicious").GetInt32(), stats.GetProperty("suspicious").GetInt32(),
                total, $"https://www.virustotal.com/gui/file/{hash}");
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or KeyNotFoundException or TaskCanceledException)
        {
            return new VirusTotalResult(VirusTotalOutcome.Failed, 0, 0, 0, null);
        }
    }
}

/// <summary>Encrypts a secret for the current Windows user before it goes into client.json.</summary>
public static class Secrets
{
    public static string Protect(string text) =>
        Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(text), null, DataProtectionScope.CurrentUser));

    /// <summary>Empty when there is nothing, or it was encrypted by another user or computer.</summary>
    public static string Unprotect(string? sealedText)
    {
        if (string.IsNullOrEmpty(sealedText))
            return "";
        try
        {
            return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(sealedText), null, DataProtectionScope.CurrentUser));
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            return "";
        }
    }
}
