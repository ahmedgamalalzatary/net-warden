# Development

## Requirements
- Windows 10/11 x64
- .NET 10 SDK
- An elevated (Administrator) terminal for running the service or client

## Layout
| Path | What |
|---|---|
| `src/NetWarden.Shared` | IPC protocol (framing, messages, `ServiceClient`, `ServiceConnection`) and contracts shared by service and client |
| `src/NetWarden.Core` | Engine: IPC server, app identity (Win32), settings storage |
| `src/NetWarden.Service` | Windows service host (also runs as a console app) |
| `src/NetWarden.Client` | WPF desktop client |
| `tests/NetWarden.Tests` | xUnit tests (unit, in-process service host, real WPF window via `WpfHarness`, opt-in E2E) |
| `scripts/` | Service install/uninstall |

## Architecture
```
NetWarden.Client (WPF, elevated)
        |  named pipe "NetWarden.Service.v1"
        |  4-byte length + JSON message (request / response / event)
NetWarden.Service (LocalSystem)
        |-- IpcServer -> IpcDispatcher -> method handlers
        |-- AppIdentityResolver (pid -> app: desktop / service / store / system)
        |-- EtwTrafficSource (kernel TCP/IP events) --> TrafficMonitor <-- SocketTable (IP Helper)
        |       TrafficMonitor.Tick() every 1 s -> "activity.snapshot" event to all clients
        |-- RuleRepository (rules.json) -> CompiledRuleSet (immutable, swapped on change)
        |       inputs: ZoneClassifier, DnsMap (ETW DNS-Client), ProcessUsers (token SID)
        '-- SettingsService  %ProgramData%\NetWarden\settings.json (+ .bak)
```
The pipe only admits Administrators and SYSTEM, so the client requires elevation.

## Common tasks
```powershell
dotnet build                                   # build everything (warnings are errors)
dotnet test                                    # unit + in-process integration tests

# Run the service as a console app (elevated terminal)
dotnet run --project src/NetWarden.Service

# Install / remove as a real Windows service (elevated)
.\scripts\install-service.ps1
.\scripts\uninstall-service.ps1

# End-to-end tests against the installed service
$env:NETWARDEN_E2E = '1'; dotnet test --filter "FullyQualifiedName~E2E"
```

## IPC methods
| Method | Request | Response |
|---|---|---|
| `service.info` | - | `ServiceInfo` |
| `settings.get` | - | `ServiceSettings` |
| `apps.resolve` | `ResolveAppRequest { processId }` | `AppInfo` or null |
| `activity.get` | - | `ActivitySnapshot` (latest) |
| `activity.resetTotals` | - | `true` |
| `connections.kill` | `KillConnectionRequest` | `true` (IPv4 TCP only) |
| `dns.reverse` | `ReverseDnsRequest { address }` | host name or null |
| `settings.update` | `ServiceSettings` | saved settings |
| `rules.get` | - | `RulesSnapshot` (filters, rules with state and effective weight) |
| `filters.save` / `filters.delete` | `FilterDefinition` / `DeleteRequest` | saved filter / `true` |
| `filters.ensureForApp` | `EnsureAppFilterRequest` | the app's filter (created if missing) |
| `rules.save` / `rules.delete` | `RuleDefinition` / `DeleteRequest` | saved rule / `true` |
| `rules.setEnabled` / `rules.reorder` | `SetRuleEnabledRequest` / `ReorderRulesRequest` | `true` |
| `rules.evaluate` | `EvaluateRequest` | `FlowDecision` |

| Event | Payload |
|---|---|
| `activity.snapshot` | `ActivitySnapshot`, every second |
| `rules.changed` | new generation (long) |
| `settings.changed` | `ServiceSettings` |

## Rules semantics
- Filter = AND of functions; a function matches if any of its values matches; "is not" negates.
- Composite = (any base filter matches) AND its own functions; base filters can't be composite.
- Default weight: whole computer 1, zones 2, other filters 3; explicit weight overrides. Higher wins.
- Blocker: first matching rule by (weight desc, list order); otherwise default In/Out action.
  Direction In = incoming/listening connections, Out = outgoing.
- Limits: every matching limit applies (traffic must fit all), except limits whose weight is not above
  a matching "ignore limit" rule. Per-type splits buckets per app / process / connection.
- Default rules: ignore limits for Local network and Loopback. Rules with `ExpiresAt` are deleted when due.
- Domain names come from the DNS-Client ETW provider (event 3008), mapped IP -> last queried name.

## Monitoring notes
- ETW kernel TCP/IP events: `saddr`/`sport` are always local, `daddr`/`dport` remote (verified).
- Byte counts are payload bytes; verified within 1% of curl's own count.
- ETW delivers in ~1 s batches, so rates are averaged over the last two 1 s ticks.
- UDP is keyed by (process, local port): sockets bind 0.0.0.0 while events carry the real address.
- The ETW session is named `NetWarden-Traffic`; tests use unique names so they never steal the service's session.

## Client notes
- Client preferences: `%LocalAppData%\NetWarden\client.json`; unhandled UI errors: `client.log` next to it.
- Two-way bindings inside DataGrid cells need an explicit `UpdateSourceTrigger=PropertyChanged`,
  otherwise the row BindingGroup defers them forever (read-only grids never commit).

## Workflow
- One roadmap item at a time (`docs/FEATURES.md`); tests with every change.
- Commit at the end of each phase (and at stable points inside long phases).
