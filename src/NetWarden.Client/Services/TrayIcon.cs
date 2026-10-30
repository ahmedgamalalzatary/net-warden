using System.Windows;
using Forms = System.Windows.Forms;

namespace NetWarden.Client.Services;

public interface ITrayIcon : IDisposable
{
    void Notify(string title, string text);
}

/// <summary>The notification-area icon: show or hide the window, the global switches, waiting requests, exit, and balloons.</summary>
public sealed class TrayIcon : ITrayIcon
{
    private readonly Forms.NotifyIcon _icon;
    private readonly Forms.ToolStripMenuItem _limiter = new("Limiter") { CheckOnClick = true };
    private readonly Forms.ToolStripMenuItem _blocker = new("Blocker") { CheckOnClick = true };
    private readonly Forms.ToolStripMenuItem _priorities = new("Priorities") { CheckOnClick = true };
    private readonly Forms.ToolStripMenuItem _pending = new("") { Visible = false };

    public TrayIcon(TrayActions actions)
    {
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add(Loc.Current["Show or hide NetWarden"], null, (_, _) => actions.ToggleWindow());
        menu.Items.Add(_pending);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(_limiter);
        menu.Items.Add(_blocker);
        menu.Items.Add(_priorities);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(Loc.Current["Exit"], null, (_, _) => actions.Exit());
        _limiter.Click += (_, _) => actions.SetLimiter(_limiter.Checked);
        _blocker.Click += (_, _) => actions.SetBlocker(_blocker.Checked);
        _priorities.Click += (_, _) => actions.SetPriorities(_priorities.Checked);
        _pending.Click += (_, _) => actions.ShowPending();
        menu.Opening += (_, _) => Update(actions.Read());

        using var stream = Application.GetResourceStream(new Uri("pack://application:,,,/NetWarden.Client;component/Assets/NetWarden.ico")).Stream;
        _icon = new Forms.NotifyIcon { Icon = new System.Drawing.Icon(stream), Text = "NetWarden", Visible = true, ContextMenuStrip = menu };
        _icon.DoubleClick += (_, _) => actions.ToggleWindow();
        _icon.BalloonTipClicked += (_, _) => actions.ShowWindow();
        // Windows keeps showing an icon its process never removed, so remove it on every way out.
        AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
    }

    private void OnProcessExit(object? sender, EventArgs e) => Dispose();

    /// <summary>The window and id Windows knows the icon by.</summary>
    internal Forms.NotifyIcon Icon => _icon;

    public void Notify(string title, string text) => _icon.ShowBalloonTip(5000, title, text, Forms.ToolTipIcon.Info);

    private void Update(TrayState state)
    {
        _limiter.Checked = state.Limiter;
        _blocker.Checked = state.Blocker;
        _priorities.Checked = state.Priorities;
        _pending.Visible = state.PendingRequests > 0;
        _pending.Text = $"{state.PendingRequests} {Loc.Current["waiting connection requests"]}";
    }

    public void Dispose()
    {
        AppDomain.CurrentDomain.ProcessExit -= OnProcessExit;
        _icon.Visible = false;
        _icon.Dispose();
    }
}

public sealed record TrayState(bool Limiter, bool Blocker, bool Priorities, int PendingRequests);

public sealed record TrayActions(
    Action ToggleWindow,
    Action ShowWindow,
    Action ShowPending,
    Action Exit,
    Action<bool> SetLimiter,
    Action<bool> SetBlocker,
    Action<bool> SetPriorities,
    Func<TrayState> Read);
