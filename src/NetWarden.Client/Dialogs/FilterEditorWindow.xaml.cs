using System.Windows;
using NetWarden.Client.ViewModels;
using NetWarden.Shared.Contracts;

namespace NetWarden.Client.Dialogs;

public partial class FilterEditorWindow : Window
{
    private readonly Func<FilterDefinition, Task<string?>> _save;

    /// <param name="save">Saves the filter and returns an error message, or null on success.</param>
    public FilterEditorWindow(FilterEditorViewModel viewModel, Func<FilterDefinition, Task<string?>> save)
    {
        InitializeComponent();
        DataContext = viewModel;
        _save = save;
    }

    private FilterEditorViewModel ViewModel => (FilterEditorViewModel)DataContext;

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.Build() is not { } filter)
            return;
        IsEnabled = false;
        string? error = await _save(filter);
        IsEnabled = true;
        if (error is null)
            DialogResult = true;
        else
            ViewModel.Error = error;
    }
}
