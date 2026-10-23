using NetWarden.Service;

using IHost host = ServiceHost.Build(args);
await host.RunAsync();
