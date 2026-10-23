using System.Net.NetworkInformation;
using NetWarden.Core;
using NetWarden.Core.Ipc;
using NetWarden.Core.Monitoring;
using NetWarden.Core.Rules;
using NetWarden.Shared.Ipc;

namespace NetWarden.Service;

/// <summary>
/// Keeps rule inputs fresh: starts DNS tracking, re-reads local subnets on network
/// changes, deletes expired rules, and tells clients when rules or settings change.
/// </summary>
public sealed class RulesService(
    RuleRepository rules,
    SettingsService settings,
    ZoneClassifier zones,
    IpcServer server,
    IServiceProvider services,
    ILogger<RulesService> logger) : BackgroundService
{
    public static readonly TimeSpan ExpiryInterval = TimeSpan.FromSeconds(5);

    private EtwDnsSource? _dns;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        rules.Changed += generation => _ = server.BroadcastAsync(Events.RulesChanged, generation);
        settings.Changed += s => _ = server.BroadcastAsync(Events.SettingsChanged, s);
        NetworkChange.NetworkAddressChanged += OnNetworkChanged;

        _dns = services.GetService<EtwDnsSource>();
        try
        {
            _dns?.Start();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "DNS tracking failed to start; domain-name filters will not match.");
        }

        using var timer = new PeriodicTimer(ExpiryInterval);
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                int removed = rules.RemoveExpired();
                if (removed > 0)
                    logger.LogInformation("Removed {Count} expired rules.", removed);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Expired rule cleanup failed.");
            }
        }
    }

    private void OnNetworkChanged(object? sender, EventArgs e) => zones.Refresh();

    public override void Dispose()
    {
        NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
        _dns?.Dispose();
        base.Dispose();
    }
}
