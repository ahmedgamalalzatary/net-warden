using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NetWarden.Client.Services;
using NetWarden.Client.ViewModels;
using NetWarden.Core.Ipc;
using NetWarden.Service;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;
using NetWarden.Shared.Storage;
using NetWarden.Tests.Client;

namespace NetWarden.Tests.Ipc;

public class AccessListTests : IDisposable
{
    private static readonly string Users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null).Value;
    private static readonly string Admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value;
    private static readonly string Guests = new SecurityIdentifier(WellKnownSidType.BuiltinGuestsSid, null).Value;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private AccessList New() => new(new JsonFileStore<AccessDocument>(_dir.File("access.json")));

    private static List<PipeAccessRule> Rules(PipeSecurity s) =>
        s.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<PipeAccessRule>().ToList();

    [Fact]
    public void Administrators_and_system_are_always_in()
    {
        var rules = Rules(New().Security());

        Assert.Equal(2, rules.Count);
        Assert.Contains(rules, r => r.IdentityReference.Value == Admins && r.AccessControlType == AccessControlType.Allow);
    }

    [Fact]
    public void Allowed_and_denied_accounts_become_pipe_rules_and_survive_a_restart()
    {
        New().Set([new AccessEntry(Users, null, true), new AccessEntry(Guests, null, false)]);

        var rules = Rules(New().Security());

        var allow = rules.Single(r => r.IdentityReference.Value == Users);
        Assert.Equal(AccessControlType.Allow, allow.AccessControlType);
        Assert.True(allow.PipeAccessRights.HasFlag(PipeAccessRights.ReadWrite));
        Assert.False(allow.PipeAccessRights.HasFlag(PipeAccessRights.ChangePermissions));
        Assert.Equal(AccessControlType.Deny, rules.Single(r => r.IdentityReference.Value == Guests).AccessControlType);
    }

    [Fact]
    public void Account_names_are_resolved_to_sids_and_named_back()
    {
        var list = New();
        string name = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null).Translate(typeof(NTAccount)).Value;

        list.Set([new AccessEntry(name, null, true)]);

        var entry = Assert.Single(list.Entries);
        Assert.Equal((Users, name), (entry.Account, entry.Name));
    }

    [Fact]
    public void Unknown_account_is_refused()
    {
        Assert.Throws<ArgumentException>(() => New().Set([new AccessEntry("NoSuchUser-" + Guid.NewGuid().ToString("N"), null, true)]));
    }

    [Theory]
    [InlineData(WellKnownSidType.BuiltinAdministratorsSid)]
    [InlineData(WellKnownSidType.LocalSystemSid)]
    public void Administrators_and_system_cant_be_listed(WellKnownSidType type)
    {
        string sid = new SecurityIdentifier(type, null).Value;
        Assert.Throws<ArgumentException>(() => New().Set([new AccessEntry(sid, null, false)]));
    }
}

/// <summary>Over real TCP on loopback, with real TLS.</summary>
public sealed class RemoteAdminTests : IAsyncLifetime
{
    private const string Password = "correct horse";
    private readonly TempDir _dir = new();
    private readonly FakeTimeProvider _time = new(DateTimeOffset.UtcNow);
    private IpcServer _server = null!;
    private RemoteAdmin _remote = null!;
    private int _port;

    public async Task InitializeAsync()
    {
        var dispatcher = new IpcDispatcher().Register("echo", _ => Task.FromResult("hello"));
        _server = new IpcServer(TestPipes.NewName(), dispatcher, NullLogger.Instance);
        _server.Start();
        _remote = NewRemote();
        var free = new TcpListener(IPAddress.Loopback, 0);
        free.Start();
        _port = ((IPEndPoint)free.LocalEndpoint).Port;
        free.Stop();
        await Task.CompletedTask;
    }

    private RemoteAdmin NewRemote() => new(_server, new JsonFileStore<RemoteConfig>(_dir.File("remote.json")), _dir.Path, _time,
        NullLogger.Instance, IPAddress.Loopback);

    public async Task DisposeAsync()
    {
        await _remote.DisposeAsync();
        await _server.DisposeAsync();
        _dir.Dispose();
    }

    private RemoteStatus Enable() => _remote.Configure(new RemoteConfigureRequest(true, _port, Password));

    private ServiceClient Client(string password = Password, string? pin = null, Action<string>? seen = null) =>
        ServiceClient.ForRemote(new RemoteTarget("127.0.0.1", _port, password, pin, seen));

    [Fact]
    public async Task Off_by_default_and_nothing_listens()
    {
        Assert.False(_remote.Status().IsEnabled);
        await using var client = Client();

        await Assert.ThrowsAnyAsync<Exception>(() => client.ConnectAsync(TimeSpan.FromSeconds(2)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("short")]
    public void Enabling_needs_a_real_password(string password) =>
        Assert.Throws<ArgumentException>(() => _remote.Configure(new RemoteConfigureRequest(true, 5317, password)));

    [Theory]
    [InlineData(0)]
    [InlineData(70000)]
    public void Port_must_be_valid(int port) =>
        Assert.Throws<ArgumentException>(() => _remote.Configure(new RemoteConfigureRequest(true, port, Password)));

    [Fact]
    public async Task Right_password_gets_the_whole_api_and_events_and_reports_the_certificate()
    {
        var status = Enable();
        Assert.True(status.IsListening);
        string? seen = null;
        var got = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var client = Client(seen: t => seen = t);
        client.EventReceived += (m, _) => got.TrySetResult(m);

        await client.ConnectAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("hello", await client.RequestAsync<string>("echo"));
        await _server.BroadcastAsync("tick", null);

        Assert.Equal("tick", await got.Task.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(status.Thumbprint, seen);
    }

    [Fact]
    public async Task Wrong_password_is_refused_and_says_so()
    {
        Enable();
        await using var client = Client("wrong password");

        await Assert.ThrowsAsync<IpcAuthFailedException>(() => client.ConnectAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task A_client_that_doesnt_authenticate_gets_no_answers()
    {
        Enable();
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, _port);
        using var tls = new System.Net.Security.SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await tls.AuthenticateAsClientAsync("netwarden");

        await MessageFraming.WriteAsync(tls, new IpcMessage(MessageKind.Request, 1, "echo"));
        var answer = await MessageFraming.ReadAsync(tls).WaitAsync(TimeSpan.FromSeconds(5));

        Assert.NotNull(answer!.Error);
        Assert.Null(await MessageFraming.ReadAsync(tls).WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task Plain_tcp_gets_nothing()
    {
        Enable();
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, _port);

        await tcp.GetStream().WriteAsync(new byte[] { 4, 0, 0, 0, 123, 125, 123, 125 });
        byte[] buffer = new byte[64];
        int read;
        try
        {
            read = await tcp.GetStream().ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (IOException)
        {
            read = 0;
        }

        Assert.DoesNotContain("hello", System.Text.Encoding.UTF8.GetString(buffer, 0, read));
    }

    [Fact]
    public async Task Repeated_wrong_passwords_lock_the_address_even_for_the_right_one_until_it_passes()
    {
        Enable();
        for (int i = 0; i < RemoteAdmin.MaxFailures; i++)
        {
            await using var bad = Client("wrong password");
            await Assert.ThrowsAsync<IpcAuthFailedException>(() => bad.ConnectAsync(TimeSpan.FromSeconds(5)));
        }

        await using (var locked = Client())
            await Assert.ThrowsAsync<IpcAuthFailedException>(() => locked.ConnectAsync(TimeSpan.FromSeconds(5)));

        _time.Advance(RemoteAdmin.LockoutTime + TimeSpan.FromSeconds(1));
        await using var good = Client();
        await good.ConnectAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("hello", await good.RequestAsync<string>("echo"));
    }

    [Fact]
    public async Task A_different_certificate_than_the_pinned_one_is_refused_before_the_password_is_sent()
    {
        Enable();
        await using var client = Client(pin: new string('0', 64));

        var error = await Assert.ThrowsAnyAsync<Exception>(() => client.ConnectAsync(TimeSpan.FromSeconds(5)));
        Assert.IsNotType<IpcAuthFailedException>(error);
    }

    [Fact]
    public async Task The_pinned_certificate_is_accepted_and_stays_the_same_after_a_restart()
    {
        string thumbprint = Enable().Thumbprint!;
        await _remote.DisposeAsync();

        _remote = NewRemote();

        Assert.True(_remote.Status().IsListening);
        Assert.Equal(thumbprint, _remote.Status().Thumbprint);
        await using var client = Client(pin: thumbprint);
        await client.ConnectAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("hello", await client.RequestAsync<string>("echo"));
    }

    [Fact]
    public async Task The_password_is_not_stored_and_can_stay_when_only_the_port_changes()
    {
        Enable();
        Assert.DoesNotContain(Password, await File.ReadAllTextAsync(_dir.File("remote.json")));

        var status = _remote.Configure(new RemoteConfigureRequest(true, _port, null));

        Assert.True(status.HasPassword);
        await using var client = Client();
        await client.ConnectAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task Turning_it_off_stops_listening_and_drops_remote_clients()
    {
        Enable();
        await using var client = Client();
        await client.ConnectAsync(TimeSpan.FromSeconds(5));
        var lost = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        client.Disconnected += _ => lost.TrySetResult();

        var status = _remote.Configure(new RemoteConfigureRequest(false, _port, null));

        Assert.False(status.IsListening);
        await lost.Task.WaitAsync(TimeSpan.FromSeconds(5));
    }
}

public sealed class ServiceConnectionRetargetTests : IAsyncLifetime
{
    private readonly string _pipeA = TestPipes.NewName();
    private readonly string _pipeB = TestPipes.NewName();
    private IpcServer _a = null!, _b = null!;

    private static IpcServer Server(string pipe, string name)
    {
        var server = new IpcServer(pipe, new IpcDispatcher().Register("who", _ => Task.FromResult(name)), NullLogger.Instance);
        server.Start();
        return server;
    }

    public Task InitializeAsync()
    {
        _a = Server(_pipeA, "a");
        _b = Server(_pipeB, "b");
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        await _a.DisposeAsync();
        await _b.DisposeAsync();
    }

    private static async Task Until(ServiceConnection c, ConnectionState state)
    {
        for (int i = 0; i < 200 && c.State != state; i++)
            await Task.Delay(25);
        Assert.Equal(state, c.State);
    }

    [Fact]
    public async Task Moves_to_another_target_at_once()
    {
        await using var connection = new ServiceConnection(_pipeA, TimeSpan.FromSeconds(2), TimeSpan.FromMilliseconds(50));
        connection.Start();
        await Until(connection, ConnectionState.Connected);
        Assert.Equal("a", await connection.RequestAsync<string>("who"));

        connection.UseTarget(() => new ServiceClient(_pipeB));
        for (int i = 0; i < 200 && (connection.State != ConnectionState.Connected || await Who(connection) != "b"); i++)
            await Task.Delay(25);

        Assert.Equal("b", await connection.RequestAsync<string>("who"));
    }

    private static async Task<string?> Who(ServiceConnection c)
    {
        try
        {
            return await c.RequestAsync<string>("who");
        }
        catch (IpcDisconnectedException)
        {
            return null;
        }
    }

    [Fact]
    public async Task A_refused_password_stops_retrying_until_a_new_target_is_chosen()
    {
        int attempts = 0;
        await using var connection = new ServiceConnection(_pipeA, TimeSpan.FromSeconds(2), TimeSpan.FromMilliseconds(10));
        connection.UseTarget(() =>
        {
            attempts++;
            return ServiceClient.FromConnector((_, _) => throw new IpcAuthFailedException("Wrong password."));
        });
        connection.Start();
        for (int i = 0; i < 100 && attempts == 0; i++)
            await Task.Delay(10);
        await Task.Delay(200);

        Assert.Equal(1, attempts);
        Assert.Equal("Wrong password.", connection.LastError);

        connection.UseTarget(() => new ServiceClient(_pipeB));
        await Until(connection, ConnectionState.Connected);
        Assert.Equal("b", await connection.RequestAsync<string>("who"));
    }
}

/// <summary>Runs the shipped module in the real Windows PowerShell against a real host.</summary>
public sealed class PowerShellModuleTests : IAsyncLifetime
{
    private readonly string _pipe = TestPipes.NewName();
    private readonly TempDir _dir = new();
    private IHost _host = null!;

    public async Task InitializeAsync()
    {
        _host = ServiceHost.Build([], new Dictionary<string, string?>
        {
            ["NetWarden:PipeName"] = _pipe,
            ["NetWarden:RestrictPipeToAdmins"] = "false",
            ["NetWarden:DataDirectory"] = _dir.Path,
            ["NetWarden:EnableTrafficSource"] = "false",
            ["NetWarden:EnablePacketFilter"] = "false",
        });
        await _host.StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _host.StopAsync();
        _host.Dispose();
        _dir.Dispose();
    }

    private async Task<string> RunAsync(string script)
    {
        string module = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "scripts", "NetWarden.psm1"));
        string full = $"$ErrorActionPreference='Stop'; Import-Module '{module}'; $PSDefaultParameterValues['*-NetWarden*:PipeName']='{_pipe}'; {script}";
        using var process = Process.Start(new ProcessStartInfo("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", full])
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        })!;
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(60));
        Assert.True(process.ExitCode == 0, await error);
        return (await output).Trim();
    }

    [Fact]
    public async Task Reads_the_service_and_changes_a_switch()
    {
        string answer = await RunAsync("""
            $info = Get-NetWardenInfo
            Set-NetWardenSwitch -Limiter $false | Out-Null
            $s = Get-NetWardenSettings
            "$($info.processId)|$($s.isLimiterEnabled)"
            """);

        Assert.Equal($"{Environment.ProcessId}|False", answer);
    }

    [Fact]
    public async Task Lists_filters_rules_and_toggles_a_rule()
    {
        string answer = await RunAsync("""
            $rule = (Get-NetWardenRule)[0].rule
            Set-NetWardenRuleEnabled -Id $rule.id -Enabled $false | Out-Null
            $again = (Get-NetWardenRule | Where-Object { $_.rule.id -eq $rule.id }).rule.isEnabled
            "$((Get-NetWardenFilter).Count -gt 0)|$again"
            """);

        Assert.Equal("True|False", answer);
    }

    [Fact]
    public async Task Service_errors_become_powershell_errors()
    {
        var error = await Assert.ThrowsAnyAsync<Exception>(() => RunAsync("Invoke-NetWardenRequest -Method 'no.such.method' | Out-Null"));

        Assert.Contains("no.such.method", error.Message);
    }
}

public class VirusTotalTests
{
    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public HttpRequestMessage? Last { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Last = request;
            return Task.FromResult(respond(request));
        }
    }

    private const string Hash = "ABC123";
    private const string Report = """{"data":{"attributes":{"last_analysis_stats":{"malicious":2,"suspicious":1,"undetected":60,"harmless":7,"timeout":1}}}}""";

    private static HttpResponseMessage Json(HttpStatusCode code, string body = "{}") =>
        new(code) { Content = new StringContent(body) };

    [Fact]
    public async Task Asks_for_the_hash_with_the_key_and_reads_the_verdict()
    {
        var handler = new Handler(_ => Json(HttpStatusCode.OK, Report));

        var result = await new VirusTotalClient(new HttpClient(handler)).CheckHashAsync(Hash, "my-key");

        Assert.Equal("https://www.virustotal.com/api/v3/files/abc123", handler.Last!.RequestUri!.ToString());
        Assert.Equal("my-key", handler.Last.Headers.GetValues("x-apikey").Single());
        Assert.Equal(HttpMethod.Get, handler.Last.Method);
        Assert.Equal((VirusTotalOutcome.Found, 2, 1, 71), (result.Outcome, result.Malicious, result.Suspicious, result.Engines));
        Assert.Equal("https://www.virustotal.com/gui/file/abc123", result.Link);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound, VirusTotalOutcome.Unknown)]
    [InlineData(HttpStatusCode.Unauthorized, VirusTotalOutcome.BadKey)]
    [InlineData(HttpStatusCode.Forbidden, VirusTotalOutcome.BadKey)]
    [InlineData(HttpStatusCode.TooManyRequests, VirusTotalOutcome.TooManyRequests)]
    [InlineData(HttpStatusCode.InternalServerError, VirusTotalOutcome.Failed)]
    public async Task Other_answers_map_to_outcomes(HttpStatusCode code, VirusTotalOutcome outcome)
    {
        var result = await new VirusTotalClient(new HttpClient(new Handler(_ => Json(code)))).CheckHashAsync(Hash, "k");

        Assert.Equal(outcome, result.Outcome);
    }

    [Fact]
    public async Task Hashes_the_file_and_never_sends_its_content()
    {
        using var dir = new TempDir();
        string file = dir.File("app.bin");
        await File.WriteAllTextAsync(file, "abc");
        var handler = new Handler(_ => Json(HttpStatusCode.OK, Report));

        await new VirusTotalClient(new HttpClient(handler)).CheckFileAsync(file, "k");

        // SHA-256 of "abc".
        Assert.EndsWith("/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", handler.Last!.RequestUri!.ToString());
        Assert.Null(handler.Last.Content);
    }

    [Theory]
    [InlineData(VirusTotalOutcome.Found, 0, 0, "Clean: none of 71 scanners flag this file.")]
    [InlineData(VirusTotalOutcome.Found, 2, 1, "3 of 71 scanners flag this file.")]
    [InlineData(VirusTotalOutcome.Unknown, 0, 0, "VirusTotal has never seen this file. NetWarden doesn't upload files.")]
    [InlineData(VirusTotalOutcome.BadKey, 0, 0, "VirusTotal refused the API key. Check it in Settings.")]
    public void Verdicts_read_plainly(VirusTotalOutcome outcome, int malicious, int suspicious, string text) =>
        Assert.Equal(text, new VirusTotalResult(outcome, malicious, suspicious, 71, null).Text);

    [Fact]
    public void The_key_is_stored_encrypted_and_comes_back()
    {
        var settings = new NetWarden.Client.ClientSettings();
        var vm = new SettingsViewModel(settings, () => { }, new StartupTask("x", _ => 0));

        vm.VirusTotalKey = "secret-key";

        Assert.DoesNotContain("secret-key", settings.VirusTotalKey ?? "");
        Assert.NotEmpty(settings.VirusTotalKey!);
        Assert.Equal("secret-key", new SettingsViewModel(settings, () => { }, new StartupTask("x", _ => 0)).VirusTotalKey);
    }
}

public class AdvancedViewModelTests
{
    [Fact]
    public async Task Remote_view_model_shows_status_and_sends_a_new_password_once()
    {
        var status = new RemoteStatus(true, 6000, true, true, "THUMB", null);
        var service = new FakeService { Handler = (m, _) => m is Methods.RemoteGet or Methods.RemoteConfigure ? status : null };
        var vm = new RemoteAdminViewModel(service);

        await vm.RefreshAsync();
        Assert.Equal((true, 6000, "THUMB"), (vm.IsEnabled, vm.Port, vm.Thumbprint));

        await vm.ApplyAsync("new password");
        await vm.ApplyAsync(null);

        var sent = service.Calls.Where(c => c.Method == Methods.RemoteConfigure).Select(c => (RemoteConfigureRequest)c.Payload!).ToList();
        Assert.Equal("new password", sent[0].NewPassword);
        Assert.Null(sent[1].NewPassword);
    }

    [Fact]
    public async Task Service_refusal_shows_as_an_error()
    {
        var service = new FakeService { Handler = (_, _) => new IpcRemoteException("remote.configure", "Choose a password of at least 8 characters.") };
        var vm = new RemoteAdminViewModel(service);

        await vm.ApplyAsync("x");

        Assert.Equal("Choose a password of at least 8 characters.", vm.Error);
    }

    [Fact]
    public async Task Permissions_list_adds_and_removes_and_saves_the_whole_list()
    {
        var entries = new List<AccessEntry> { new("S-1", "PC\\a", true) };
        var service = new FakeService
        {
            Handler = (m, p) =>
            {
                if (m == Methods.AccessSet)
                    entries = ((AccessSetRequest)p!).Entries.Select(e => e with { Name = e.Account }).ToList();
                return entries;
            },
        };
        var vm = new PermissionsViewModel(service);
        await vm.RefreshAsync();
        Assert.Equal("PC\\a", Assert.Single(vm.Entries).Name);

        vm.NewAccount = "PC\\b";
        vm.NewIsAllowed = false;
        await vm.AddCommand.ExecuteAsync(null);
        Assert.Equal(["S-1", "PC\\b"], ((AccessSetRequest)service.Calls.Last(c => c.Method == Methods.AccessSet).Payload!).Entries.Select(e => e.Account));
        Assert.False(entries[1].IsAllowed);
        Assert.Equal("", vm.NewAccount);

        await vm.RemoveCommand.ExecuteAsync(vm.Entries[0]);
        Assert.Equal(["PC\\b"], vm.Entries.Select(e => e.Account));
    }

    [Fact]
    public void Connecting_pins_the_certificate_seen_first_and_reuses_it()
    {
        var settings = new NetWarden.Client.ClientSettings();
        RemoteTarget? target = null;
        bool local = false;
        var vm = new RemoteConnectViewModel(settings, () => { }, t => target = t, () => local = true) { Host = "server", Port = 6000 };

        vm.Connect("pw");
        Assert.Equal(("server", 6000, "pw", (string?)null), (target!.Host, target.Port, target.Password, target.PinnedThumbprint));

        target.OnThumbprint!("ABCD");
        Assert.Equal("ABCD", settings.KnownHosts["server:6000"]);
        Assert.Contains("ABCD", vm.StatusText);

        vm.Connect("pw");
        Assert.Equal("ABCD", target.PinnedThumbprint);
        Assert.True(vm.IsRemote);

        vm.UseThisComputerCommand.Execute(null);
        Assert.True(local);
        Assert.False(vm.IsRemote);
    }

    [Fact]
    public void Forgetting_a_certificate_allows_a_server_that_was_reinstalled()
    {
        var settings = new NetWarden.Client.ClientSettings();
        settings.KnownHosts["server:6000"] = "OLD";
        RemoteTarget? target = null;
        var vm = new RemoteConnectViewModel(settings, () => { }, t => target = t, () => { }) { Host = "server", Port = 6000 };

        vm.ForgetCertificateCommand.Execute(null);
        vm.Connect("pw");

        Assert.Null(target!.PinnedThumbprint);
    }
}

public sealed class RemoteOverPipeTests : IAsyncLifetime
{
    private readonly string _pipe = TestPipes.NewName();
    private readonly TempDir _dir = new();
    private IHost _host = null!;
    private ServiceClient _client = null!;

    public async Task InitializeAsync()
    {
        _host = ServiceHost.Build([], new Dictionary<string, string?>
        {
            ["NetWarden:PipeName"] = _pipe,
            ["NetWarden:RestrictPipeToAdmins"] = "false",
            ["NetWarden:DataDirectory"] = _dir.Path,
            ["NetWarden:EnableTrafficSource"] = "false",
            ["NetWarden:EnablePacketFilter"] = "false",
            ["NetWarden:RemoteBindAddress"] = "127.0.0.1",
        });
        await _host.StartAsync();
        _client = new ServiceClient(_pipe);
        await _client.ConnectAsync(TimeSpan.FromSeconds(5));
    }

    public async Task DisposeAsync()
    {
        await _client.DisposeAsync();
        await _host.StopAsync();
        _host.Dispose();
        _dir.Dispose();
    }

    [Fact]
    public async Task The_service_is_off_for_remote_clients_until_told_otherwise()
    {
        var status = await _client.RequestAsync<RemoteStatus>(Methods.RemoteGet);

        Assert.False(status!.IsEnabled);
        Assert.False(status.IsListening);
    }

    [Fact]
    public async Task Settings_never_carry_the_password_hash()
    {
        var free = new TcpListener(IPAddress.Loopback, 0);
        free.Start();
        int port = ((IPEndPoint)free.LocalEndpoint).Port;
        free.Stop();

        var status = await _client.RequestAsync<RemoteStatus>(Methods.RemoteConfigure, new RemoteConfigureRequest(true, port, "long enough password"));
        Assert.True(status!.IsListening);

        string json = JsonSerializer.Serialize(await _client.RequestAsync<JsonElement>(Methods.RemoteGet));
        Assert.DoesNotContain("hash", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("salt", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Access_list_can_be_read_and_set_without_losing_the_connection_for_good()
    {
        string users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null).Value;

        await _client.RequestAsync<List<AccessEntry>>(Methods.AccessSet, new AccessSetRequest([new AccessEntry(users, null, true)]));

        await using var next = new ServiceClient(_pipe);
        await next.ConnectAsync(TimeSpan.FromSeconds(5));
        var entries = await next.RequestAsync<List<AccessEntry>>(Methods.AccessGet);
        Assert.Equal(users, Assert.Single(entries!).Account);
    }
}
