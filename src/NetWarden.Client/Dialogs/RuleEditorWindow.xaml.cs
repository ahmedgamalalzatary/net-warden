using System.Windows;
using NetWarden.Client.ViewModels;
using NetWarden.Shared.Contracts;

namespace NetWarden.Client.Dialogs;

public partial class RuleEditorWindow : Window
{
    private readonly Func<RuleDefinition, Task<string?>> _save;

    /// <param name="save">Saves the rule and returns an error message, or null on success.</param>
    public RuleEditorWindow(RuleEditorViewModel viewModel, Func<RuleDefinition, Task<string?>> save)
    {
        InitializeComponent();
        DataContext = viewModel;
        _save = save;
    }

    private RuleEditorViewModel ViewModel => (RuleEditorViewModel)DataContext;

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.Build() is not { } rule)
            return;
        IsEnabled = false;
        string? error = await _save(rule);
        IsEnabled = true;
        if (error is null)
            DialogResult = true;
        else
            ViewModel.Error = error;
    }
}
