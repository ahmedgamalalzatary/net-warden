using NetWarden.Service;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;
using Microsoft.Extensions.Hosting;

namespace NetWarden.Tests.Service;

/// <summary>Starts the real service host in-process and talks to it over the pipe.</summary>
public sealed class ServiceHostTests : IAsyncLifetime
{
    private readonly string _pipeName = TestPipes.NewName();
    private readonly TempDir _dir = new();
    private IHost _host = null!;
    private ServiceClient _client = null!;

    public async Task InitializeAsync()
    {
        _host = ServiceHost.Build([], new Dictionary<string, string?>
        {
            ["NetWarden:PipeName"] = _pipeName,
            ["NetWarden:RestrictPipeToAdmins"] = "false",
            ["NetWarden:SettingsPath"] = _dir.File("settings.json"),
        });
        await _host.StartAsync();
        _client = new ServiceClient(_pipeName);
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
    public async Task Service_info_describes_the_running_host()
    {
        var info = await _client.RequestAsync<ServiceInfo>(Methods.ServiceInfo);

        Assert.NotNull(info);
        Assert.Equal(Environment.ProcessId, info.ProcessId);
        Assert.Equal("0.1.0", info.Version);
        Assert.False(info.IsWindowsService);
        Assert.Equal(Environment.MachineName, info.MachineName);
        Assert.True(info.StartedAt <= DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task Settings_get_returns_defaults_when_no_file()
    {
        var settings = await _client.RequestAsync<ServiceSettings>(Methods.SettingsGet);

        Assert.NotNull(settings);
        Assert.True(settings.IsLimiterEnabled);
    }

    [Fact]
    public async Task Apps_resolve_identifies_a_process()
    {
        var app = await _client.RequestAsync<AppInfo>(Methods.AppsResolve, new ResolveAppRequest(Environment.ProcessId));

        Assert.NotNull(app);
        Assert.Equal(AppKind.Desktop, app.Kind);
    }

    [Fact]
    public async Task Apps_resolve_returns_null_for_dead_pid()
    {
        Assert.Null(await _client.RequestAsync<AppInfo>(Methods.AppsResolve, new ResolveAppRequest(int.MaxValue - 2)));
    }

    [Fact]
    public async Task Stopping_host_disconnects_client()
    {
        var disconnected = new TaskCompletionSource();
        _client.Disconnected += _ => disconnected.TrySetResult();

        await _host.StopAsync();

        await disconnected.Task.WaitAsync(TimeSpan.FromSeconds(5));
    }
}
