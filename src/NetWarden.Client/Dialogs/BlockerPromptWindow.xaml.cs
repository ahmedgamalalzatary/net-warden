using System.Windows;
using NetWarden.Client.ViewModels;

namespace NetWarden.Client.Dialogs;

/// <summary>Non-modal prompt that stays open while requests are pending and closes when none are left.</summary>
public partial class BlockerPromptWindow : Window
{
    public BlockerPromptWindow(BlockerPromptViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        viewModel.Finished += Close;
        Closed += (_, _) => viewModel.Detach();
    }
}
