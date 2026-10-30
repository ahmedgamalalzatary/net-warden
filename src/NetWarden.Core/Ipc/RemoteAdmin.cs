using System.IO.Pipes;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;
using NetWarden.Shared.Storage;

namespace NetWarden.Core.Ipc;

/// <summary>
/// Who may use the service besides Administrators and SYSTEM, who always may. A denied group wins over an
/// allowed one, as everywhere in Windows.
/// </summary>
public sealed class AccessList
{
    private const PipeAccessRights ClientRights = PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize;

    private static readonly SecurityIdentifier[] AlwaysIn =
    [
        new(WellKnownSidType.BuiltinAdministratorsSid, null),
        new(WellKnownSidType.LocalSystemSid, null),
    ];

    private readonly JsonFileStore<AccessDocument> _store;
    private readonly Lock _lock = new();
    private List<AccessEntry> _entries;

    public AccessList(JsonFileStore<AccessDocument> store)
    {
        _store = store;
        _entries = store.Load().Entries;
    }

    public IReadOnlyList<AccessEntry> Entries
    {
        get { lock (_lock) return [.. _entries]; }
    }

    /// <summary>Replaces the list. Accounts may be names; they are saved as SIDs, which survive renames.</summary>
    public void Set(IReadOnlyList<AccessEntry> entries)
    {
        var resolved = entries.Select(Resolve).ToList();
        lock (_lock)
        {
            _store.Save(new AccessDocument { Entries = resolved });
            _entries = resolved;
        }
    }

    public PipeSecurity Security()
    {
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in AlwaysIn)
            security.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.FullControl, AccessControlType.Allow));
        foreach (var entry in Entries)
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(entry.Account), ClientRights,
                entry.IsAllowed ? AccessControlType.Allow : AccessControlType.Deny));
        return security;
    }

    private static AccessEntry Resolve(AccessEntry entry)
    {
        SecurityIdentifier sid;
        try
        {
            sid = entry.Account.StartsWith("S-", StringComparison.OrdinalIgnoreCase)
                ? new SecurityIdentifier(entry.Account)
                : (SecurityIdentifier)new NTAccount(entry.Account).Translate(typeof(SecurityIdentifier));
        }
        catch (Exception ex) when (ex is IdentityNotMappedException or ArgumentException or SystemException)
        {
            throw new ArgumentException($"There is no user or group named '{entry.Account}'.", ex);
        }
        if (AlwaysIn.Contains(sid))
            throw new ArgumentException("Administrators and SYSTEM always have access.");

        string? name = entry.Name;
        try
        {
            name = sid.Translate(typeof(NTAccount)).Value;
        }
        catch (IdentityNotMappedException)
        {
            // A deleted account keeps the name it had.
        }
        return new AccessEntry(sid.Value, name, entry.IsAllowed);
    }
}

/// <summary>
/// Remote administration over TCP. Off until a password is set. Everything travels over TLS with a self-signed
/// certificate that clients pin the first time; the first message must be the password, checked against a salted
/// PBKDF2 hash, and an address that keeps guessing wrong is locked out for a while. After that a client has the
/// same API as on the pipe. Windows Firewall has to be opened by the owner, on purpose.
/// </summary>
public sealed class RemoteAdmin : IAsyncDisposable
{
    public const int MinPasswordLength = 8;
    public const int MaxFailures = 5;
    public static readonly TimeSpan LockoutTime = TimeSpan.FromMinutes(5);

    private const int Iterations = 200_000;
    private const int HashBytes = 32;
    private const int MaxLogonMessageBytes = 4096;
    private const int MaxPendingLogons = 16;
    private static readonly TimeSpan LogonTimeout = TimeSpan.FromSeconds(10);

    private readonly IpcServer _server;
    private readonly JsonFileStore<RemoteConfig> _store;
    private readonly string _certificatePath;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly IPAddress _bindAddress;
    private readonly Lock _lock = new();
    private readonly Dictionary<IPAddress, (int Count, DateTimeOffset Until)> _failures = [];
    private readonly SemaphoreSlim _logons = new(MaxPendingLogons, MaxPendingLogons);
    private RemoteConfig _config;
    private X509Certificate2? _certificate;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;
    private string? _error;

    public RemoteAdmin(IpcServer server, JsonFileStore<RemoteConfig> store, string dataDirectory, TimeProvider time, ILogger logger, IPAddress? bindAddress = null)
    {
        _server = server;
        _store = store;
        _certificatePath = Path.Combine(dataDirectory, "remote-certificate.bin");
        _time = time;
        _logger = logger;
        _bindAddress = bindAddress ?? IPAddress.Any;
        _config = store.Load();
        if (_config.IsEnabled)
            Start();
    }

    public RemoteStatus Status()
    {
        lock (_lock)
            return new RemoteStatus(_config.IsEnabled, _config.Port, _config.PasswordHash is not null, _listener is not null, _certificate?.GetCertHashString(HashAlgorithmName.SHA256), _error);
    }

    public RemoteStatus Configure(RemoteConfigureRequest request)
    {
        if (request.IsEnabled && request.Port is < 1 or > 65535)
            throw new ArgumentException("Choose a port from 1 to 65535.");
        bool newPassword = !string.IsNullOrEmpty(request.NewPassword);
        if (newPassword && request.NewPassword!.Length < MinPasswordLength)
            throw new ArgumentException($"Choose a password of at least {MinPasswordLength} characters.");
        if (request.IsEnabled && !newPassword && _config.PasswordHash is null)
            throw new ArgumentException($"Choose a password of at least {MinPasswordLength} characters.");

        Stop();
        lock (_lock)
        {
            _config.IsEnabled = request.IsEnabled;
            if (request.IsEnabled)
                _config.Port = request.Port;
            if (newPassword)
            {
                byte[] salt = RandomNumberGenerator.GetBytes(16);
                _config.PasswordSalt = Convert.ToBase64String(salt);
                _config.PasswordHash = Convert.ToBase64String(Hash(request.NewPassword!, salt, Iterations));
                _config.Iterations = Iterations;
            }
            _store.Save(_config);
        }
        if (request.IsEnabled)
            Start();
        return Status();
    }

    private static byte[] Hash(string password, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, HashBytes);

    private void Start()
    {
        lock (_lock)
        {
            try
            {
                _certificate ??= LoadOrCreateCertificate();
                var listener = new TcpListener(_bindAddress, _config.Port);
                listener.Start();
                _listener = listener;
                _cts = new CancellationTokenSource();
                _error = null;
                _acceptLoop = Task.Run(() => AcceptLoopAsync(listener, _cts.Token));
                _logger.LogInformation("Remote administration is listening on port {Port}.", _config.Port);
            }
            catch (Exception ex) when (ex is SocketException or IOException or CryptographicException or UnauthorizedAccessException)
            {
                _error = ex.Message;
                _logger.LogError(ex, "Remote administration failed to start.");
            }
        }
    }

    private void Stop()
    {
        Task? loop;
        lock (_lock)
        {
            _cts?.Cancel();
            _listener?.Stop();
            _listener = null;
            loop = _acceptLoop;
            _acceptLoop = null;
        }
        try
        {
            loop?.Wait(TimeSpan.FromSeconds(5));
        }
        catch (AggregateException ex)
        {
            _logger.LogDebug(ex, "Remote accept loop ended with an error.");
        }
        lock (_lock)
        {
            _cts?.Dispose();
            _cts = null;
        }
    }

    /// <summary>The private key is encrypted for the service's account, so other users can't read it from the data folder.</summary>
    private X509Certificate2 LoadOrCreateCertificate()
    {
        if (File.Exists(_certificatePath))
        {
            byte[] sealedPfx = File.ReadAllBytes(_certificatePath);
            return X509CertificateLoader.LoadPkcs12(ProtectedData.Unprotect(sealedPfx, null, DataProtectionScope.CurrentUser), null);
        }
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=NetWarden", key, HashAlgorithmName.SHA256);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using var created = request.CreateSelfSigned(now.AddDays(-1), now.AddYears(20));
        byte[] pfx = created.Export(X509ContentType.Pfx);
        Directory.CreateDirectory(Path.GetDirectoryName(_certificatePath)!);
        File.WriteAllBytes(_certificatePath, ProtectedData.Protect(pfx, null, DataProtectionScope.CurrentUser));
        return X509CertificateLoader.LoadPkcs12(pfx, null);
    }

    private async Task AcceptLoopAsync(TcpListener listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                if (ct.IsCancellationRequested)
                    return;
                _logger.LogDebug(ex, "Accepting a remote client failed.");
                continue;
            }
            _ = Task.Run(() => ServeAsync(client, ct), CancellationToken.None);
        }
    }

    private async Task ServeAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        {
            if (client.Client.RemoteEndPoint is not IPEndPoint { Address: var address })
                return;
            if (!await _logons.WaitAsync(0, ct).ConfigureAwait(false))
                return;
            SslStream? tls = null;
            bool loggedOn = false;
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(LogonTimeout);
                tls = new SslStream(client.GetStream());
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = _certificate }, timeout.Token).ConfigureAwait(false);
                loggedOn = await LogOnAsync(tls, address, timeout.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or InvalidDataException
                or System.Text.Json.JsonException or System.Security.Authentication.AuthenticationException or ObjectDisposedException)
            {
                _logger.LogDebug(ex, "A remote logon from {Address} failed.", address);
            }
            finally
            {
                _logons.Release();
            }

            if (loggedOn)
            {
                _logger.LogInformation("Remote client {Address} logged on.", address);
                await _server.ServeAsync(tls!, ct).ConfigureAwait(false);
            }
            else if (tls is not null)
            {
                await tls.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private async Task<bool> LogOnAsync(SslStream tls, IPAddress address, CancellationToken ct)
    {
        IpcMessage? message = await MessageFraming.ReadAsync(tls, ct, MaxLogonMessageBytes).ConfigureAwait(false);
        if (message is null)
            return false;
        string? refusal = message.Method != Methods.RemoteAuth ? "Log on first."
            : IsLockedOut(address) ? "Too many wrong passwords from this computer. Try again in a few minutes."
            : Verify(IpcJson.FromElement<RemoteAuthRequest>(message.Payload)?.Password) ? null
            : Failed(address);
        var answer = refusal is null
            ? new IpcMessage(MessageKind.Response, message.Id, message.Method, IpcJson.ToElement(true))
            : new IpcMessage(MessageKind.Response, message.Id, message.Method, Error: refusal);
        await MessageFraming.WriteAsync(tls, answer, ct).ConfigureAwait(false);
        if (refusal is not null)
        {
            _logger.LogWarning("Remote logon from {Address} refused: {Reason}", address, refusal);
            return false;
        }
        lock (_lock)
            _failures.Remove(address);
        return true;
    }

    private bool IsLockedOut(IPAddress address)
    {
        lock (_lock)
        {
            if (!_failures.TryGetValue(address, out var failure) || failure.Count < MaxFailures)
                return false;
            if (_time.GetUtcNow() < failure.Until)
                return true;
            _failures.Remove(address);
            return false;
        }
    }

    private string Failed(IPAddress address)
    {
        lock (_lock)
        {
            int count = _failures.GetValueOrDefault(address).Count + 1;
            _failures[address] = (count, _time.GetUtcNow() + LockoutTime);
        }
        return "Wrong password.";
    }

    private bool Verify(string? password)
    {
        RemoteConfig config;
        lock (_lock)
            config = _config;
        if (password is null || config.PasswordHash is null || config.PasswordSalt is null)
            return false;
        byte[] actual = Hash(password, Convert.FromBase64String(config.PasswordSalt), config.Iterations);
        return CryptographicOperations.FixedTimeEquals(actual, Convert.FromBase64String(config.PasswordHash));
    }

    public ValueTask DisposeAsync()
    {
        Stop();
        lock (_lock)
        {
            _certificate?.Dispose();
            _certificate = null;
        }
        return ValueTask.CompletedTask;
    }
}
