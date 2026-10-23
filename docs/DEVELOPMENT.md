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
        |-- PacketFilterService -> PacketFilter (WinDivert, priority 100) -> Blocker (verdicts, Ask)
        |                       -> PacketFilter (WinDivert, priority 0)   -> Limiter (token buckets)
        |                                                                   + PriorityScheduler (per direction)
        |                                                                   + LimiterPump (sends due packets)
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

# Release: tests, self-contained publish, installer -> artifacts\release\NetWarden-Setup-<version>.exe
.\scripts\build-release.ps1            # -SkipTests to skip the test run
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
| `packetfilter.status` | - | `PacketFilterStatus` (blocker counters + `Limiter`: delayed, dropped, queued bytes, `Priorities`) |
| `blocker.pending` | - | `BlockerRequest[]` |
| `blocker.answer` | `BlockerAnswer` | `true` if the request was still pending |

| Event | Payload |
|---|---|
| `activity.snapshot` | `ActivitySnapshot`, every second |
| `rules.changed` | new generation (long) |
| `settings.changed` | `ServiceSettings` |
| `blocker.request` / `blocker.resolved` | `BlockerRequest` / `BlockerResolved` |
| `packetfilter.status` | `PacketFilterStatus` |

## Release / installer
- `scripts\build-release.ps1` publishes the client as one self-contained file (renamed `NetWarden.exe`;
  the assembly stays `NetWarden.Client` because pack URIs use it) and the service as a self-contained
  folder (WinDivert.dll/.sys must sit next to it), then compiles `installer\NetWarden.iss`.
- Inno Setup 6.7.1 comes from the `Tools.InnoSetup` NuGet package into `tools\` (gitignored); the
  script checks ISCC.exe's Authenticode signature before running it.
- The installer (admin, x64, Windows 10+) installs to Program Files, replaces any existing `NetWarden`
  service (including one from `install-service.ps1`) and registers it: auto start, restart on failure.
- Upgrades stop the old service and the WinDivert driver first (the loaded driver locks WinDivert64.sys);
  the WinDivert files are installed without `ignoreversion`, so an identical version is skipped.
- Uninstall stops and deletes the service and stops the WinDivert driver; `%ProgramData%\NetWarden`
  (rules, settings) is kept.
- Size is ~85 MB because both programs carry the .NET runtime; nothing needs to be installed first.
- Version comes from `Directory.Build.props`. Icon: `scripts\make-icon.py` (Pillow) draws
  `src\NetWarden.Client\Assets\NetWarden.ico`.

## Blocker notes
- WinDivert 2.2.2 (x64, LGPL) lives in `third_party/WinDivert` and is copied next to the service.
- Diverted: `!loopback and !impostor and ((tcp and tcp.Syn and !tcp.Ack) or udp)` - connection
  attempts only. The handle is open only while blocker rules or non-Allow defaults exist.
- Owner of a packet: socket tables (SYN_SENT row, listener, or UDP bind); unknown owners pass.
- Verdicts are cached per flow and re-evaluated when the rules generation changes.
- Ask: first packet(s) held, similar flows grouped into one request, denied after 60 s unanswered.
  Remembered answers become rules (app / app + remote address / app + remote port; optional expiry).
- When rules change, established IPv4 TCP connections that are now denied are reset.
- Fail-open: if the service stops, the WinDivert handle closes and Windows passes traffic normally.

## Limiter notes
- Diverted: `!loopback and !impostor and (tcp or udp)` - every packet, on a second WinDivert handle
  at priority 0. The blocker's handle is priority 100, so packets pass the blocker first. A packet a
  handle re-injects skips every handle of the same or higher priority (live tests use 1000 for that reason).
- The handle is open only while the Limiter switch is on and at least one limit rule exists.
- Each flow's owner is looked up once (socket tables) and its limit bindings cached until the rules
  generation changes. Limits apply to connections that already existed, unlike the blocker.
- Token bucket per binding (`BucketKey`: rule, or rule + app / pid / flow for per-type filters).
  Burst = 50 ms of the rate, at least 1514 bytes. Buckets may go into debt: a packet that doesn't fit
  is queued until the debt is paid; a packet arriving while a bucket's backlog exceeds 500 ms is dropped.
- Payload bytes are counted (like the Activity view), so "200 KB/s" means the same in both places.
- Packets of one flow keep their order; other flows are not held behind them.
- The pump thread uses a 1 ms timer resolution while running. Stopping sends what is still queued.
- Measured: 200 KB/s download limit -> curl 199 KB/s; 100 KB/s E2E test passes against the installed service.
- Ignore rules: "ignore limit" is applied by the rule engine; "ignore data" is exposed on
  `FlowDecision.IgnoreData` for statistics and quotas (phases 6 and 7) to skip that traffic.

## Priority notes
- Rule kind `Priority` with a level (Low / Normal / High / Critical) per direction; the first matching
  rule by (weight desc, list order) wins. Flows no priority rule matches are Normal.
- The limiter's filter also runs while Priorities are on and a priority rule exists. The Limiter switch
  only turns limits off; the Priorities switch only turns priorities off.
- `PriorityScheduler` (one per direction) measures each level's rate every reaction interval
  (Low 1 s, Normal 250 ms, Fast 100 ms, Custom 50-5000 ms) and estimates the line capacity.
- Allocation from the top: the highest active level is never restricted. Every level below gets
  `capacity - sum of reservations of the active levels above it` (at least 3% of the line / 4 KB/s);
  a level's reservation is `max(its % of the line, its rate + headroom %)`. Low has no reservation.
- Active: at least 2 KB/s in the last interval, held for 4 reaction intervals (min 500 ms). Without
  adaptive allocation a level stays active for 30 s after its last packet, even when idle.
- Capacity: the highest total rate seen, clamped to the min/max settings (min = max fixes it). It only
  decays (half-life 10 min) while nothing is restricted, because restricted traffic understates the line.
  Measuring starts when the limiter's filter opens (i.e. once a priority rule exists).
- Restricted levels draw from a token bucket like a limit, so they queue and drop the same way.
- Measured live (line set to 2000 KB/s): Normal download alone ~3.5 MB/s; next to a 300 KB/s Critical
  stream 565-568 KB/s (expected 600); back to 2.3-2.9 MB/s after the stream ended. Across runs the
  squeezed rate was 0.94x-1.42x of the expected share; the stream kept 300-320 KB/s.
- The priority E2E test downloads ~30 MB at full line speed from Hetzner's public test file (Cloudflare's
  speed test answers 429 to repeated large downloads; the test returns early on a refused download).

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
- DL/UL Limit cells: a "quick limit" is one permanent Limit rule on the app's filter per direction.
  The checkbox enables/disables it (keeping the value); typing a value + Enter sets it and turns it on.
- Themes: View > Theme (Follow Windows / Light / Dark), saved in client.json. `ThemeManager` sets WPF's
  Fluent `Application.ThemeMode` (styles standard controls and the title bar) and swaps
  `Themes/Light.xaml` / `Themes/Dark.xaml` (our brushes; same keys in both). Views must use
  `{DynamicResource Key}` for these brushes, never StaticResource or hard-coded colors.
- Fluent is sized for touch; `ThemeManager.CompactStyles` tightens CheckBox/TextBox/ComboBox/Button and
  the DataGrid header/cell styles (selection colors come from the theme). They are built in code because
  they must be based on Fluent's styles, which only exist once ThemeMode is set.
- Styles without `BasedOn` (e.g. `LimitBox`) fall back to the classic look and must set their own
  theme brushes (Foreground, BorderBrush) or text turns black on dark.
- DataGrid squeezes fixed columns to fit a star column; give them `MinWidth` so it scrolls instead.
- Visual check: `NETWARDEN_SHOTS=<folder> dotnet test --filter ThemeTests` writes each dialog in both themes as PNG.
- Priority cell: a "quick priority" is one permanent Both-direction Priority rule on the app's filter;
  choosing Normal deletes it.
- Two-way bindings inside DataGrid cells need an explicit `UpdateSourceTrigger=PropertyChanged`,
  otherwise the row BindingGroup defers them forever (read-only grids never commit).

## Workflow
- One roadmap item at a time (`docs/FEATURES.md`); tests with every change.
- Commit at the end of each phase (and at stable points inside long phases).
