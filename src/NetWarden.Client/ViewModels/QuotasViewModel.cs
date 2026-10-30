using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Formatting;
using NetWarden.Shared.Ipc;

namespace NetWarden.Client.ViewModels;

public sealed record QuotaRow(QuotaStatus Status)
{
    public string Name => Status.FilterName;
    public string Direction => Status.Direction.ToString();
    public string Used => ByteFormatter.Size(Status.Used);
    public string Limit => ByteFormatter.Size(Status.Limit);
    public double Share => Status.Limit > 0 ? Math.Min(1, (double)Status.Used / Status.Limit) : 0;
    public string NextReset => Status.NextReset?.ToLocalTime().ToString("g") ?? "Never";
    public string State => !Status.IsEnabled ? "Off" : Status.OverflowedAt is not null ? "Exceeded" : "Counting";
    public string ExceededAt => Status.OverflowedAt?.ToLocalTime().ToString("g") ?? "";
}

/// <summary>The Quotas tab: how much of each quota is used, reset, and init from statistics.</summary>
public sealed partial class QuotasViewModel(IServiceRequester service) : ObservableObject
{
    public ObservableCollection<QuotaRow> Rows { get; } = [];

    [ObservableProperty]
    private QuotaRow? _selected;

    [ObservableProperty]
    private string? _lastError;

    public async Task RefreshAsync()
    {
        try
        {
            var statuses = await service.RequestAsync<List<QuotaStatus>>(Methods.QuotasStatus);
            Guid? selected = Selected?.Status.RuleId;
            Rows.Clear();
            foreach (var status in statuses ?? [])
                Rows.Add(new QuotaRow(status));
            Selected = Rows.FirstOrDefault(r => r.Status.RuleId == selected);
            LastError = null;
        }
        catch (Exception ex) when (ex is IpcRemoteException or IpcDisconnectedException)
        {
            LastError = ex.Message;
        }
    }

    [RelayCommand]
    private Task ResetAsync(QuotaRow? row) => SendAsync(Methods.QuotasReset, row);

    [RelayCommand]
    private Task InitFromStatsAsync(QuotaRow? row) => SendAsync(Methods.QuotasInitFromStats, row);

    private async Task SendAsync(string method, QuotaRow? row)
    {
        if (row is null)
            return;
        try
        {
            await service.RequestAsync<bool>(method, new QuotaRequest(row.Status.RuleId));
            await RefreshAsync();
        }
        catch (Exception ex) when (ex is IpcRemoteException or IpcDisconnectedException)
        {
            LastError = ex is IpcRemoteException remote ? remote.RemoteMessage : ex.Message;
        }
    }
}
