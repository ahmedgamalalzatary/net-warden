using System.Diagnostics;
using Microsoft.Extensions.Time.Testing;
using NetWarden.Core.Apps;
using NetWarden.Shared.Contracts;

namespace NetWarden.Tests.Apps;

public class AppIdentityResolverTests
{
    private static readonly string Notepad = Path.Combine(Environment.SystemDirectory, "notepad.exe");
    private static readonly string Svchost = Path.Combine(Environment.SystemDirectory, "svchost.exe");

    private sealed class Fakes
    {
        public Dictionary<int, ProcessFacts> Processes { get; } = [];
        public Dictionary<int, List<ServiceEntry>> Services { get; } = [];
        public int InspectCalls { get; private set; }
        public int ServiceCalls { get; private set; }
        public FakeTimeProvider Time { get; } = new();

        public AppIdentityResolver Create() => new(
            pid => { InspectCalls++; return Processes.GetValueOrDefault(pid); },
            () => { ServiceCalls++; return Services.ToDictionary(kv => kv.Key, kv => kv.Value.ToList()); },
            Time);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    public void System_pids_resolve_to_system_app(int pid)
    {
        var app = new Fakes().Create().Resolve(pid);

        Assert.NotNull(app);
        Assert.Equal(AppKind.System, app.Kind);
        Assert.Equal(AppIdentityResolver.SystemAppId, app.Id);
    }

    [Fact]
    public void Unknown_pid_resolves_to_null()
    {
        Assert.Null(new Fakes().Create().Resolve(1234));
    }

    [Fact]
    public void Desktop_app_uses_lowercase_path_as_id_and_file_description_as_name()
    {
        var fakes = new Fakes();
        fakes.Processes[100] = new ProcessFacts(100, Notepad, 1, null);

        var app = fakes.Create().Resolve(100)!;

        Assert.Equal(AppKind.Desktop, app.Kind);
        Assert.Equal(Notepad.ToLowerInvariant(), app.Id);
        Assert.Equal(Notepad, app.Path);
        Assert.Equal("Notepad", app.DisplayName, ignoreCase: true);
        Assert.Equal("Microsoft Corporation", app.CompanyName);
    }

    [Fact]
    public void Missing_file_falls_back_to_file_name()
    {
        var fakes = new Fakes();
        fakes.Processes[100] = new ProcessFacts(100, @"C:\does\not\exist\tool.exe", 1, null);

        var app = fakes.Create().Resolve(100)!;

        Assert.Equal("tool.exe", app.DisplayName);
        Assert.Null(app.CompanyName);
    }

    [Fact]
    public void Single_service_host_is_identified_by_service_name()
    {
        var fakes = new Fakes();
        fakes.Processes[200] = new ProcessFacts(200, Svchost, 1, null);
        fakes.Services[200] = [new ServiceEntry("Dnscache", "DNS Client")];

        var app = fakes.Create().Resolve(200)!;

        Assert.Equal(AppKind.Service, app.Kind);
        Assert.Equal("svc:dnscache", app.Id);
        Assert.Equal("DNS Client", app.DisplayName);
        Assert.Single(app.Services);
    }

    [Fact]
    public void Shared_service_host_is_identified_by_path_and_lists_services()
    {
        var fakes = new Fakes();
        fakes.Processes[300] = new ProcessFacts(300, Svchost, 1, null);
        fakes.Services[300] = [new ServiceEntry("a", "A"), new ServiceEntry("b", "B")];

        var app = fakes.Create().Resolve(300)!;

        Assert.Equal(AppKind.Service, app.Kind);
        Assert.Equal(Svchost.ToLowerInvariant(), app.Id);
        Assert.EndsWith("(2 services)", app.DisplayName);
        Assert.Equal(2, app.Services.Count);
    }

    [Fact]
    public void Packaged_app_is_identified_by_package_family()
    {
        var fakes = new Fakes();
        fakes.Processes[400] = new ProcessFacts(400, @"C:\Program Files\WindowsApps\x\app.exe", 1, "Contoso.App_8wekyb3d8bbwe");

        var app = fakes.Create().Resolve(400)!;

        Assert.Equal(AppKind.Store, app.Kind);
        Assert.Equal("pkg:contoso.app_8wekyb3d8bbwe", app.Id);
        Assert.Equal("Contoso.App_8wekyb3d8bbwe", app.PackageFamilyName);
    }

    [Fact]
    public void Same_process_is_cached()
    {
        var fakes = new Fakes();
        fakes.Processes[100] = new ProcessFacts(100, Notepad, 1, null);
        var resolver = fakes.Create();

        var first = resolver.Resolve(100);
        var second = resolver.Resolve(100);

        Assert.Same(first, second);
        Assert.Equal(1, fakes.ServiceCalls);
    }

    [Fact]
    public void Reused_pid_with_new_creation_time_resolves_fresh()
    {
        var fakes = new Fakes();
        fakes.Processes[100] = new ProcessFacts(100, Notepad, 1, null);
        var resolver = fakes.Create();
        Assert.Equal(AppKind.Desktop, resolver.Resolve(100)!.Kind);

        fakes.Processes[100] = new ProcessFacts(100, Svchost, 2, null);
        fakes.Services[100] = [new ServiceEntry("Dnscache", "DNS Client")];
        fakes.Time.Advance(TimeSpan.FromSeconds(3));

        Assert.Equal("svc:dnscache", resolver.Resolve(100)!.Id);
    }

    [Fact]
    public void Service_map_is_refreshed_only_after_it_goes_stale()
    {
        var fakes = new Fakes();
        for (int pid = 1000; pid < 1005; pid++)
            fakes.Processes[pid] = new ProcessFacts(pid, Notepad, 1, null);
        var resolver = fakes.Create();

        for (int pid = 1000; pid < 1005; pid++)
            resolver.Resolve(pid);
        Assert.Equal(1, fakes.ServiceCalls);

        fakes.Time.Advance(TimeSpan.FromSeconds(3));
        fakes.Processes[2000] = new ProcessFacts(2000, Notepad, 1, null);
        resolver.Resolve(2000);
        Assert.Equal(2, fakes.ServiceCalls);
    }
}

/// <summary>Tests against the real OS.</summary>
public class ProcessInspectorTests
{
    [Fact]
    public void Inspects_current_process()
    {
        using var self = Process.GetCurrentProcess();

        var facts = ProcessInspector.TryInspect(Environment.ProcessId);

        Assert.NotNull(facts);
        Assert.Equal(self.MainModule!.FileName, facts.ImagePath, ignoreCase: true);
        Assert.True(facts.CreationTime > 0);
        Assert.Null(facts.PackageFamilyName);
    }

    [Fact]
    public void Nonexistent_pid_returns_null()
    {
        // PIDs are multiples of 4; an odd value can never be a live process.
        Assert.Null(ProcessInspector.TryInspect(int.MaxValue - 2));
    }

    [Fact]
    public void Running_services_include_a_known_service_host()
    {
        var services = ProcessInspector.GetRunningServices();

        Assert.NotEmpty(services);
        Assert.Contains(services.Values.SelectMany(s => s), s => s.Name.Equals("Dnscache", StringComparison.OrdinalIgnoreCase)
            || s.Name.Equals("RpcSs", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Real_resolver_identifies_current_process_as_desktop_app()
    {
        var app = new AppIdentityResolver().Resolve(Environment.ProcessId);

        Assert.NotNull(app);
        Assert.Equal(AppKind.Desktop, app.Kind);
        Assert.False(string.IsNullOrWhiteSpace(app.DisplayName));
    }
}
