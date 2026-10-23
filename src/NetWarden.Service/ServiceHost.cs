using System.Diagnostics;
using System.Security.Principal;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Options;
using NetWarden.Core;
using NetWarden.Core.Apps;
using NetWarden.Core.Ipc;
using NetWarden.Core.Settings;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;

namespace NetWarden.Service;

public sealed class ServiceOptions
{
    public const string SectionName = "NetWarden";

    public string PipeName { get; set; } = PipeNames.Default;

    /// <summary>When false the pipe uses default security (tests only).</summary>
    public bool RestrictPipeToAdmins { get; set; } = true;

    public string? SettingsPath { get; set; }
}

public static class ServiceHost
{
    public const string ServiceName = "NetWarden";

    public static IHost Build(string[] args, IDictionary<string, string?>? configOverrides = null)
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

        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<AppIdentityResolver>();
        builder.Services.AddSingleton(sp => new JsonFileStore<ServiceSettings>(
            sp.GetRequiredService<IOptions<ServiceOptions>>().Value.SettingsPath ?? AppPaths.SettingsFile,
            sp.GetRequiredService<ILogger<JsonFileStore<ServiceSettings>>>()));
        builder.Services.AddSingleton(CreateDispatcher);
        builder.Services.AddHostedService<IpcHostedService>();

        return builder.Build();
    }

    private static IpcDispatcher CreateDispatcher(IServiceProvider sp)
    {
        var resolver = sp.GetRequiredService<AppIdentityResolver>();
        var settings = sp.GetRequiredService<JsonFileStore<ServiceSettings>>();
        var info = CreateServiceInfo();

        return new IpcDispatcher()
            .Register(Methods.ServiceInfo, _ => Task.FromResult(info))
            .Register(Methods.SettingsGet, _ => Task.FromResult(settings.Load()))
            .Register<ResolveAppRequest, AppInfo?>(Methods.AppsResolve, (request, _) =>
                Task.FromResult(request is null ? null : resolver.Resolve(request.ProcessId)));
    }

    private static ServiceInfo CreateServiceInfo()
    {
        using var process = Process.GetCurrentProcess();
        using var identity = WindowsIdentity.GetCurrent();
        return new ServiceInfo(
            Version: typeof(ServiceHost).Assembly.GetName().Version?.ToString(3) ?? "0.0.0",
            ProcessId: Environment.ProcessId,
            StartedAt: process.StartTime.ToUniversalTime(),
            IsElevated: new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator),
            IsWindowsService: WindowsServiceHelpers.IsWindowsService(),
            MachineName: Environment.MachineName);
    }
}
