using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;

namespace NetWarden.Tests.Client;

/// <summary>
/// Runs code on one shared STA thread that owns the WPF <see cref="Application"/>
/// (only one may exist per process), pumping the dispatcher between steps.
/// </summary>
public sealed class WpfHarness : IDisposable
{
    private readonly Thread _thread;
    private readonly TaskCompletionSource<Dispatcher> _ready = new();

    public WpfHarness()
    {
        _thread = new Thread(() =>
        {
            var app = new NetWarden.Client.App { ShutdownMode = ShutdownMode.OnExplicitShutdown };
            app.InitializeComponent();
            _ready.SetResult(Dispatcher.CurrentDispatcher);
            Dispatcher.Run();
        });
        _thread.SetApartmentState(ApartmentState.STA);
        _thread.IsBackground = true;
        _thread.Start();
    }

    public Dispatcher Dispatcher => _ready.Task.Result;

    public Task<T> RunAsync<T>(Func<Task<T>> action) => Dispatcher.InvokeAsync(action).Task.Unwrap();

    public Task RunAsync(Func<Task> action) => Dispatcher.InvokeAsync(action).Task.Unwrap();

    public T Run<T>(Func<T> action) => Dispatcher.Invoke(action);

    public void Run(Action action) => Dispatcher.Invoke(action);

    /// <summary>Lets pending layout, bindings and posted work complete.</summary>
    public static async Task Settle(int milliseconds = 50)
    {
        await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
        await Task.Delay(milliseconds);
        await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
    }

    public static IEnumerable<T> Descendants<T>(DependencyObject root) where T : DependencyObject
    {
        int count = VisualTreeHelper.GetChildrenCount(root);
        for (int i = 0; i < count; i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is T match)
                yield return match;
            foreach (var nested in Descendants<T>(child))
                yield return nested;
        }
    }

    public void Dispose()
    {
        Dispatcher.InvokeShutdown();
        _thread.Join(TimeSpan.FromSeconds(5));
    }
}

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class WpfCollection : ICollectionFixture<WpfHarness>
{
    public const string Name = "WPF";
}
