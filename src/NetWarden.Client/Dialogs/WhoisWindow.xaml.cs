using System.Windows;
using NetWarden.Shared.Contracts;
using NetWarden.Shared.Ipc;

namespace NetWarden.Client.Dialogs;

public partial class WhoisWindow : Window
{
    public WhoisWindow(IServiceRequester service, string address)
    {
        InitializeComponent();
        Title = $"WHOIS · {address}";
        Loaded += async (_, _) =>
        {
            try
            {
                Answer.Text = await service.RequestAsync<string>(Methods.WhoisLookup, new AddressRequest(address)) ?? "No answer.";
            }
            catch (Exception ex) when (ex is IpcRemoteException or IpcDisconnectedException)
            {
                Answer.Text = ex is IpcRemoteException remote ? remote.RemoteMessage : ex.Message;
            }
        };
    }
}
