using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;

namespace NetWarden.Client.Services;

public sealed class GridColumnLayout
{
    public string Id { get; set; } = "";
    public int DisplayIndex { get; set; }
    public double Width { get; set; }
    public DataGridLengthUnitType Unit { get; set; } = DataGridLengthUnitType.Pixel;
    public bool Visible { get; set; } = true;
}

/// <summary>What a user arranged in one grid.</summary>
public sealed class GridLayout
{
    public List<GridColumnLayout> Columns { get; set; } = [];
    public string? SortId { get; set; }
    public ListSortDirection? SortDirection { get; set; }
}

/// <summary>
/// Makes every grid remember its sort, column widths, column order and hidden columns. Right-clicking a
/// column header chooses the columns. Grids whose view model owns the sort pass rememberSort false.
/// </summary>
public sealed class LayoutMemory(ClientSettings settings, Action save)
{
    private static string IdOf(DataGridColumn column) => column.Header as string ?? column.SortMemberPath ?? "";

    public void Attach(DataGrid grid, string key, bool rememberSort = true)
    {
        Restore(grid, key, rememberSort);

        grid.ColumnReordered += (_, _) => Capture(grid, key);
        // The sort is applied after this event, so read it afterwards.
        grid.Sorting += (_, _) => grid.Dispatcher.BeginInvoke(() => Capture(grid, key), System.Windows.Threading.DispatcherPriority.Background);
        grid.PreviewMouseRightButtonUp += (_, e) =>
        {
            if (e.OriginalSource is DependencyObject source && FindHeader(source) is not null)
            {
                var menu = new ContextMenu { PlacementTarget = grid, IsOpen = true };
                foreach (var item in ColumnMenu(grid, key))
                    menu.Items.Add(item);
                e.Handled = true;
            }
        };
        grid.AddHandler(Thumb.DragCompletedEvent, new DragCompletedEventHandler((_, _) => Capture(grid, key)));
    }

    /// <summary>One checkable item per column. The last visible column can't be hidden.</summary>
    public IReadOnlyList<MenuItem> ColumnMenu(DataGrid grid, string key)
    {
        var items = new List<MenuItem>();
        foreach (var column in grid.Columns.Where(c => IdOf(c).Length > 0))
        {
            var item = new MenuItem { Header = IdOf(column), IsCheckable = true, IsChecked = column.Visibility == Visibility.Visible };
            item.Checked += (_, _) =>
            {
                column.Visibility = Visibility.Visible;
                Capture(grid, key);
            };
            item.Unchecked += (_, _) =>
            {
                if (grid.Columns.Count(c => c.Visibility == Visibility.Visible) <= 1)
                {
                    item.IsChecked = true;
                    return;
                }
                column.Visibility = Visibility.Collapsed;
                Capture(grid, key);
            };
            items.Add(item);
        }
        return items;
    }

    /// <summary>Sorts a grid the way a header click does.</summary>
    public void Sort(DataGrid grid, DataGridColumn column, ListSortDirection direction)
    {
        foreach (var c in grid.Columns)
            c.SortDirection = null;
        column.SortDirection = direction;
        var view = CollectionViewSource.GetDefaultView(grid.ItemsSource);
        if (view is not null)
        {
            view.SortDescriptions.Clear();
            view.SortDescriptions.Add(new SortDescription(column.SortMemberPath, direction));
        }
    }

    public void Capture(DataGrid grid, string key)
    {
        var sorted = grid.Columns.FirstOrDefault(c => c.SortDirection is not null);
        settings.Grids[key] = new GridLayout
        {
            SortId = sorted is null ? null : IdOf(sorted),
            SortDirection = sorted?.SortDirection,
            Columns = grid.Columns.Select(c => new GridColumnLayout
            {
                Id = IdOf(c),
                DisplayIndex = c.DisplayIndex,
                Width = c.Width.Value,
                Unit = c.Width.UnitType,
                Visible = c.Visibility == Visibility.Visible,
            }).ToList(),
        };
        save();
    }

    public void Restore(DataGrid grid, string key, bool rememberSort = true)
    {
        if (!settings.Grids.TryGetValue(key, out var layout))
            return;
        foreach (var saved in layout.Columns.OrderBy(c => c.DisplayIndex))
        {
            if (grid.Columns.FirstOrDefault(c => IdOf(c) == saved.Id) is not { } column)
                continue;
            if (saved.Width > 0 && saved.Unit is DataGridLengthUnitType.Pixel or DataGridLengthUnitType.Star)
                column.Width = new DataGridLength(saved.Width, saved.Unit);
            column.Visibility = saved.Visible ? Visibility.Visible : Visibility.Collapsed;
            if (saved.DisplayIndex >= 0 && saved.DisplayIndex < grid.Columns.Count)
                column.DisplayIndex = saved.DisplayIndex;
        }
        if (rememberSort && layout.SortDirection is { } direction
            && grid.Columns.FirstOrDefault(c => IdOf(c) == layout.SortId) is { } sortColumn)
            Sort(grid, sortColumn, direction);
    }

    private static DataGridColumnHeader? FindHeader(DependencyObject? element)
    {
        for (; element is not null; element = System.Windows.Media.VisualTreeHelper.GetParent(element))
            if (element is DataGridColumnHeader header)
                return header;
        return null;
    }
}

/// <summary>Named snapshots of how the window is arranged.</summary>
public sealed class LayoutProfile
{
    public bool ShowInfoPane { get; set; }
    public bool ShowChart { get; set; }
    public int ChartWindowSeconds { get; set; }
    public double InfoPaneWidth { get; set; }
    public Dictionary<string, GridLayout> Grids { get; set; } = [];
}

public sealed class LayoutProfiles(ClientSettings settings, Action save)
{
    public void Save(string name)
    {
        settings.LayoutProfiles[name] = new LayoutProfile
        {
            ShowInfoPane = settings.ShowInfoPane,
            ShowChart = settings.ShowChart,
            ChartWindowSeconds = settings.ChartWindowSeconds,
            InfoPaneWidth = settings.InfoPaneWidth,
            Grids = Copy(settings.Grids),
        };
        save();
    }

    /// <summary>Puts a saved arrangement back into the settings; false when there is no such profile.</summary>
    public bool Apply(string name)
    {
        if (!settings.LayoutProfiles.TryGetValue(name, out var profile))
            return false;
        settings.ShowInfoPane = profile.ShowInfoPane;
        settings.ShowChart = profile.ShowChart;
        settings.ChartWindowSeconds = profile.ChartWindowSeconds;
        settings.InfoPaneWidth = profile.InfoPaneWidth;
        settings.Grids = Copy(profile.Grids);
        save();
        return true;
    }

    public void Delete(string name)
    {
        if (settings.LayoutProfiles.Remove(name))
            save();
    }

    private static Dictionary<string, GridLayout> Copy(Dictionary<string, GridLayout> grids) =>
        grids.ToDictionary(g => g.Key, g => new GridLayout
        {
            SortId = g.Value.SortId,
            SortDirection = g.Value.SortDirection,
            Columns = g.Value.Columns.Select(c => new GridColumnLayout { Id = c.Id, DisplayIndex = c.DisplayIndex, Width = c.Width, Unit = c.Unit, Visible = c.Visible }).ToList(),
        });
}

public static class WindowMemory
{
    /// <summary>Keeps a saved window on the screen: a monitor it was on may be gone.</summary>
    public static Rect Fit(Rect saved, Rect workArea)
    {
        double width = Math.Min(saved.Width, workArea.Width);
        double height = Math.Min(saved.Height, workArea.Height);
        double left = Math.Clamp(saved.Left, workArea.Left, workArea.Right - width);
        double top = Math.Clamp(saved.Top, workArea.Top, workArea.Bottom - height);
        return new Rect(left, top, width, height);
    }
}
