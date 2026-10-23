using Microsoft.Extensions.Options;
using NetWarden.Core;
using NetWarden.Core.Apps;
using NetWarden.Core.Ipc;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Packets;
using NetWarden.Core.Rules;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;
using NetWarden.Shared.Storage;

namespace NetWarden.Service;

public sealed class ServiceOptions
{
    public const string SectionName = "NetWarden";

    public string PipeName { get; set; } = PipeNames.Default;

    /// <summary>When false the pipe uses default security (tests only).</summary>
    public bool RestrictPipeToAdmins { get; set; } = true;

    /// <summary>Directory for settings.json and rules.json; defaults to %ProgramData%\NetWarden.</summary>
    public string? DataDirectory { get; set; }

    /// <summary>When false no ETW sessions are started (tests, which must not steal the real service's sessions).</summary>
    public bool EnableTrafficSource { get; set; } = true;

    public string TrafficSessionName { get; set; } = EtwTrafficSource.DefaultSessionName;
    public string DnsSessionName { get; set; } = EtwDnsSource.DefaultSessionName;

    /// <summary>When false WinDivert is never opened (tests).</summary>
    public bool EnablePacketFilter { get; set; } = true;

    public string ResolveDataDirectory() => DataDirectory ?? AppPaths.DataDirectory;
}

public static class ServiceHost
{
    public const string ServiceName = "NetWarden";

    public static IHost Build(string[] args, IDictionary<string, string?>? configOverrides = null,
        Action<IServiceCollection>? configureServices = null)
    {
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            Args = args,
            ContentRootPath = AppContext.BaseDirectory,
        });
        if (configOverrides is not null)
            builder.Configuration.AddInMemoryCollection(configOverrides);

        builder.Services.AddWindowsService(o => o.ServiceName = ServiceName);
        builder.Services.Configure<ServiceOptions>(builder.Configuration.GetSection(ServiceOptions.SectionName));
        var services = builder.Services;

        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<AppIdentityResolver>();
        services.AddSingleton<ProcessUsers>();
        services.AddSingleton(sp => new SettingsService(new JsonFileStore<ServiceSettings>(
            Path.Combine(Options(sp).ResolveDataDirectory(), "settings.json"),
            sp.GetRequiredService<ILogger<JsonFileStore<ServiceSettings>>>())));

        // Monitoring
        services.AddSingleton<ISocketTable, SocketTable>();
        services.AddSingleton(_ => new HostNameCache());
        services.AddSingleton(sp => new TrafficMonitor(
            sp.GetRequiredService<ISocketTable>(),
            sp.GetRequiredService<AppIdentityResolver>().Resolve,
            sp.GetRequiredService<TimeProvider>()));
        services.AddSingleton<ITrafficSource>(sp => Options(sp).EnableTrafficSource
            ? new EtwTrafficSource(sp.GetRequiredService<ILogger<EtwTrafficSource>>(), Options(sp).TrafficSessionName)
            : new NullTrafficSource());

        // Rules
        services.AddSingleton(_ => new DnsMap());
        services.AddSingleton(sp => Options(sp).EnableTrafficSource
            ? new EtwDnsSource(sp.GetRequiredService<DnsMap>(), sp.GetRequiredService<ILogger<EtwDnsSource>>(), Options(sp).DnsSessionName)
            : null!);
        services.AddSingleton(_ => new ZoneClassifier());
        services.AddSingleton(sp => new RuleRepository(
            new JsonFileStore<RulesDocument>(Path.Combine(Options(sp).ResolveDataDirectory(), "rules.json"),
                sp.GetRequiredService<ILogger<JsonFileStore<RulesDocument>>>()),
            sp.GetRequiredService<ZoneClassifier>(),
            sp.GetRequiredService<TimeProvider>(),
            sp.GetRequiredService<ILogger<RuleRepository>>()));
        services.AddSingleton(sp => new FlowContextFactory(
            sp.GetRequiredService<AppIdentityResolver>().Resolve,
            sp.GetRequiredService<ProcessUsers>().Get,
            sp.GetRequiredService<DnsMap>()));

        // Packet filtering
        services.AddSingleton<IFlowOwnerLookup>(sp => new SocketOwnerLookup(sp.GetRequiredService<ISocketTable>(), sp.GetRequiredService<TimeProvider>()));
        services.AddSingleton(sp => new Blocker(
            () => sp.GetRequiredService<RuleRepository>().Current,
            () => sp.GetRequiredService<SettingsService>().Current,
            sp.GetRequiredService<IFlowOwnerLookup>(),
            sp.GetRequiredService<FlowContextFactory>(),
            sp.GetRequiredService<TimeProvider>()));
        services.AddSingleton<PacketDeviceFactory>(_ => filter => new WinDivertDevice(filter));
        services.AddSingleton<PacketFilterService>();

        // IPC
        services.AddSingleton(ServiceMethods.Create);
        services.AddSingleton(sp => new IpcServer(
            Options(sp).PipeName,
            sp.GetRequiredService<IpcDispatcher>(),
            sp.GetRequiredService<ILogger<IpcServer>>(),
            Options(sp).RestrictPipeToAdmins ? PipeSecurityFactory.AdminsAndSystem() : null));

        services.AddHostedService<IpcHostedService>();
        services.AddHostedService<ActivityService>();
        services.AddHostedService<RulesService>();
        services.AddHostedService(sp => sp.GetRequiredService<PacketFilterService>());

        configureServices?.Invoke(services);

        return builder.Build();
    }

    private static ServiceOptions Options(IServiceProvider sp) => sp.GetRequiredService<IOptions<ServiceOptions>>().Value;
}
