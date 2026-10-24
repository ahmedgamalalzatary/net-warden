using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Formatting;
using NetWarden.Shared.Ipc;

namespace NetWarden.Client.ViewModels;

/// <summary>An app with records in the stats database.</summary>
public sealed record StatsAppItem(string Id, string Name, long Bytes)
{
    public override string ToString() => $"{Name}  ({ByteFormatter.Size(Bytes)})";
}

/// <summary>The stats manager dialog: database facts, deleting records and compacting the file.</summary>
public sealed partial class StatsManagerViewModel(IServiceRequester service, TimeProvider? time = null) : ObservableObject
{
    private readonly TimeProvider _time = time ?? TimeProvider.System;

    [ObservableProperty] private StatsInfo? _info;
    [ObservableProperty] private IReadOnlyList<StatsAppItem> _apps = [];
    [ObservableProperty] private StatsAppItem? _selectedApp;
    [ObservableProperty] private DateTime _deleteBefore = DateTime.Today.AddMonths(-3);
    [ObservableProperty] private string _status = "";
    [ObservableProperty] private string? _error;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsIdle))]
    private bool _isBusy;

    public bool IsIdle => !IsBusy;

    public string PathText => Info?.Path ?? "";
    public string SizeText => Info is { } i ? ByteFormatter.Size(i.FileBytes) : "";
    public string RecordsText => Info is { } i ? $"{i.Records.ToString("N0", CultureInfo.CurrentCulture)} records · {i.Apps} apps" : "";
    public string RangeText => Info is { FirstRecord: { } first, LastRecord: { } last }
        ? $"{first.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)} - {last.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)}"
        : "No records yet";
    public string GeoText => Info?.GeoDatabaseDate is { } date
        ? $"Countries: DB-IP Lite {date} (db-ip.com, CC BY 4.0)"
        : "Countries: database missing";

    partial void OnInfoChanged(StatsInfo? value)
    {
        foreach (string name in new[] { nameof(PathText), nameof(SizeText), nameof(RecordsText), nameof(RangeText), nameof(GeoText) })
            OnPropertyChanged(name);
    }

    public async Task LoadAsync()
    {
        await RunAsync(async () =>
        {
            Info = await service.RequestAsync<StatsInfo>(Methods.StatsInfo);
            var now = _time.GetUtcNow();
            DateTimeOffset from = Info?.FirstRecord ?? now;
            var all = await service.RequestAsync<StatsResult>(Methods.StatsQuery,
                new StatsQuery(from, now.AddMinutes(2), StatsBucket.Month, StatsGroupBy.App, MaxRows: 10_000));
            string? selected = SelectedApp?.Id;
            Apps = all?.Rows.Select(r => new StatsAppItem(r.Key, r.Label, r.In + r.Out)).ToList() ?? [];
            SelectedApp = Apps.FirstOrDefault(a => a.Id == selected);
        });
    }

    public Task DeleteOlderThanAsync() =>
        DeleteAsync(new StatsDeleteRequest(To: new DateTimeOffset(DeleteBefore.Date, TimeZoneInfo.Local.GetUtcOffset(DeleteBefore.Date))),
            $"before {DeleteBefore.ToString("d", CultureInfo.CurrentCulture)}");

    public Task DeleteSelectedAppAsync() => SelectedApp is { } app
        ? DeleteAsync(new StatsDeleteRequest(AppId: app.Id), $"of {app.Name}")
        : Task.CompletedTask;

    public Task DeleteAllAsync() => DeleteAsync(new StatsDeleteRequest(), "");

    public async Task CompactAsync()
    {
        long before = Info?.FileBytes ?? 0;
        await RunAsync(async () =>
        {
            Info = await service.RequestAsync<StatsInfo>(Methods.StatsCompact);
            Status = $"Compacted: {ByteFormatter.Size(before)} → {SizeText}.";
        });
    }

    private async Task DeleteAsync(StatsDeleteRequest request, string what)
    {
        bool ok = await RunAsync(async () =>
        {
            long deleted = await service.RequestAsync<long>(Methods.StatsDelete, request);
            Status = $"Deleted {deleted.ToString("N0", CultureInfo.CurrentCulture)} records{(what.Length > 0 ? " " + what : "")}.";
        });
        if (ok)
        {
            string status = Status;
            await LoadAsync();
            Status = status;
        }
    }

    private async Task<bool> RunAsync(Func<Task> action)
    {
        IsBusy = true;
        Error = null;
        try
        {
            await action();
            return true;
        }
        catch (Exception ex) when (ex is IpcRemoteException or IpcDisconnectedException or TimeoutException)
        {
            Error = ex is IpcRemoteException remote ? remote.RemoteMessage : ex.Message;
            return false;
        }
        finally
        {
            IsBusy = false;
        }
    }
}
