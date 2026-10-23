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
| `tests/NetWarden.Tests` | xUnit tests |
| `scripts/` | Service install/uninstall |

## Architecture
```
NetWarden.Client (WPF, elevated)
        |  named pipe "NetWarden.Service.v1"
        |  4-byte length + JSON message (request / response / event)
NetWarden.Service (LocalSystem)
        |-- IpcServer -> IpcDispatcher -> method handlers
        |-- AppIdentityResolver (pid -> app: desktop / service / store / system)
        '-- JsonFileStore<ServiceSettings>  %ProgramData%\NetWarden\settings.json (+ .bak)
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

## Workflow
- One roadmap item at a time (`docs/FEATURES.md`); tests with every change.
- Commit at the end of each phase (and at stable points inside long phases).
