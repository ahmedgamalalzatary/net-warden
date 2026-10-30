using System.IO;
using Microsoft.Extensions.Hosting;
using NetWarden.Client;
using NetWarden.Client.Services;
using NetWarden.Client.ViewModels;
using NetWarden.Service;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Formatting;
using NetWarden.Shared.Ipc;

namespace NetWarden.Tests.Client;

/// <summary>
/// Walks the real window against a real in-process service with real traffic data, on a private pipe and
/// data folder, and saves a picture of every page. Packet filtering stays off. Run it with
/// NETWARDEN_TOUR=&lt;folder&gt; dotnet test --filter UiTour.
/// </summary>
[Collection(WpfCollection.Name)]
public sealed class UiTourTests(WpfHarness wpf)
{
    private static string? Folder => Environment.GetEnvironmentVariable("NETWARDEN_TOUR");

    [Fact]
    public async Task Tour()
    {
        if (Folder is not { } folder)
            return;
        Directory.CreateDirectory(folder);
        using var data = new TempDir();
        string pipe = TestPipes.NewName();
        using var host = ServiceHost.Build([], new Dictionary<string, string?>
        {
            ["NetWarden:PipeName"] = pipe,
            ["NetWarden:RestrictPipeToAdmins"] = "false",
            ["NetWarden:DataDirectory"] = data.Path,
            ["NetWarden:EnablePacketFilter"] = "false",
            ["NetWarden:TrafficSessionName"] = "NetWarden-Tour-" + Guid.NewGuid().ToString("N"),
            ["NetWarden:DnsSessionName"] = "NetWarden-TourDns-" + Guid.NewGuid().ToString("N"),
        });
        await host.StartAsync();
        var connection = new ServiceConnection(pipe);
        try
        {
            await wpf.RunAsync(async () =>
            {
                var vm = new MainViewModel(connection, System.Windows.Threading.Dispatcher.CurrentDispatcher,
                    new ClientSettings(), () => { }, new IconCache(), new PortNames([]));
                var window = new MainWindow { DataContext = vm, Width = 1360, Height = 820, ShowInTaskbar = false };
                window.Show();
                connection.Start();
                await WpfHarness.Settle(4000);
                await SeedAsync(vm);
                foreach (var theme in new[] { AppTheme.Light, AppTheme.Dark })
                {
                    wpf.Themes.Apply(theme);
                    foreach (string page in window.PageNames)
                    {
                        window.ShowPage(page);
                        await WpfHarness.Settle(1200);
                        ThemeTests.Save(window, Path.Combine(folder, $"{theme}-{page}.png"));
                    }
                    window.ShowPage("Activity");
                    vm.SelectedRow = vm.Activity.Rows.FirstOrDefault(r => r.IsApp && r.HasChildren);
                    await WpfHarness.Settle(1200);
                    ThemeTests.Save(window, Path.Combine(folder, $"{theme}-Inspector.png"));
                    vm.SelectedRow = null;
                    var editor = new NetWarden.Client.Dialogs.RuleEditorWindow(
                        new RuleEditorViewModel(null, PredefinedFilters.All, PredefinedFilters.Internet, RuleKind.Quota), _ => Task.FromResult<string?>(null));
                    editor.Show();
                    await WpfHarness.Settle(500);
                    ThemeTests.Save(editor, Path.Combine(folder, $"{theme}-RuleEditor.png"));
                    editor.Close();
                }
                window.Close();

                Loc.Current = new Loc("ar");
                var arabic = new MainWindow
                {
                    DataContext = new MainViewModel(connection, System.Windows.Threading.Dispatcher.CurrentDispatcher, new ClientSettings(), () => { }, new IconCache(), new PortNames([])),
                    Width = 1360, Height = 820, ShowInTaskbar = false, FlowDirection = System.Windows.FlowDirection.RightToLeft,
                };
                arabic.Show();
                arabic.ShowPage("Settings");
                await WpfHarness.Settle(1000);
                ThemeTests.Save(arabic, Path.Combine(folder, "Arabic-Settings.png"));
                arabic.Close();
                Loc.Current = new Loc("en");
            });
        }
        finally
        {
            wpf.Run(() => wpf.Themes.Apply(AppTheme.Light));
            await connection.DisposeAsync();
            await host.StopAsync();
        }
    }

    private static async Task SeedAsync(MainViewModel vm)
    {
        if (vm.Rules.Snapshot?.Rules.Any(r => r.Rule.Kind == RuleKind.Quota) == true)
            return;
        var block = await vm.Rules.CreateRuleAsync(new RuleDefinition(Guid.Empty, PredefinedFilters.Internet, RuleKind.Firewall, RuleDirection.In,
            IsEnabled: false, Action: FirewallAction.Deny, Notes: "Turned on by a quota"));
        await vm.Rules.CreateRuleAsync(new RuleDefinition(Guid.Empty, PredefinedFilters.Internet, RuleKind.Quota, RuleDirection.Both,
            QuotaBytes: 1L << 34, QuotaReset: new TimeSchedule(ScheduleRepeat.DayOfMonth), OverflowRuleIds: [block!.Id], OverflowAlert: true));
        await vm.Rules.CreateRuleAsync(new RuleDefinition(Guid.Empty, PredefinedFilters.LocalNetwork, RuleKind.Limit, RuleDirection.In, LimitBytesPerSecond: 1 << 20,
            Schedule: [new ScheduleCondition(ScheduleAction.Start, new TimeSchedule(ScheduleRepeat.EveryDay, 480))]));
    }

}
