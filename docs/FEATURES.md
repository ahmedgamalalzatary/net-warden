# Feature roadmap

Reference: NetLimiter 5.3.8 (installed). Features below were identified from its UI, settings and public docs.

Stack: C# / .NET 10. Windows service (admin) + WPF client, connected over a named pipe.
Packet limiting via WinDivert (signed, LGPL); blocking via Windows Filtering Platform; monitoring via ETW + IP Helper APIs.

Status: [ ] todo  [~] in progress  [x] done

## Phase 0 - Foundation
- [x] 0.1 Solution layout: Service, Client (WPF), Shared (contracts), Core (engine)
- [x] 0.2 Windows service host, install/uninstall, runs elevated
- [x] 0.3 Client <-> service IPC (named pipe), connection state
- [x] 0.4 App identity: desktop apps, Windows services (svchost split), Store apps; name/company/version
- [x] 0.5 Settings storage (JSON) in ProgramData

## Phase 1 - Monitoring
- [x] 1.1 Activity view: per-app DL/UL rate and DL/UL totals, live refresh, app icons
- [x] 1.2 App -> connections tree (protocol, local/remote addr+port, type: connect/accept/listen)
- [x] 1.3 View options: online/offline/all/hidden, search, units (auto bytes/bits), column selection, reset totals
- [x] 1.4 Info pane: app properties, process id, connection properties, port names, reverse DNS
- [x] 1.5 Kill connection(s) (IPv4 TCP only: Windows has no API for IPv6/UDP)
- [x] 1.6 Realtime traffic chart (DL/UL line chart, 1/5/10 min window, per selected app or whole computer)

## Phase 2 - Filters & rules engine
- [ ] 2.1 Zones: Internet, Local network, Loopback, Forwarded
- [ ] 2.2 Filters: app, path (wildcards), remote/local IP range, remote/local port range, protocol, domain name (wildcards), user, process id, network, tag; negation (is / is not)
- [ ] 2.3 Filter types: Filter, Zone, Composite (base filters); per-type: none / per-app / per-process / per-connection
- [ ] 2.4 Rule list: enable/disable, direction (in/out/both), weight/order, notes, rule state (active/inactive/disabled)

## Phase 3 - Blocker (firewall)
- [ ] 3.1 Allow/Deny rules per filter, in/out
- [ ] 3.2 Default action in/out (Allow / Deny / Ask), global Blocker on/off
- [ ] 3.3 Quick block toggle per app, quick zone blocker
- [ ] 3.4 Ask mode: prompt window for new connections, remember / temporary, pending requests list

## Phase 4 - Limiter
- [ ] 4.1 DL/UL speed limit rules per filter, global Limiter on/off
- [ ] 4.2 Per-app / per-process / per-connection limits
- [ ] 4.3 Ignore rules (ignore limit / ignore data accounting)

## Phase 5 - Priorities
- [ ] 5.1 Priority rules: Low / Normal / High / Critical
- [ ] 5.2 Bandwidth reservation %, adaptive allocation, reaction speed, min/max bandwidth

## Phase 6 - Statistics
- [ ] 6.1 Stats database (SQLite), periodic save, save Internet/Local/Loopback toggles
- [ ] 6.2 Stats view: time ranges (hour, today, week, month, year, custom), 24h histogram, time chart
- [ ] 6.3 Breakdown by apps, IPs/domains, ports, countries, users; filter by zone/protocol/network
- [ ] 6.4 Export CSV; stats manager (DB info, delete by time, delete per app, compact)

## Phase 7 - Quotas
- [ ] 7.1 Quota rules: data cap per filter, in/out, reset period
- [ ] 7.2 Overflow actions: enable other rules (e.g. block/limit), alert window, kill connections
- [ ] 7.3 Quota status, reset, init from stats

## Phase 8 - Scheduler
- [ ] 8.1 Time conditions on any rule: start / stop / reset / delete
- [ ] 8.2 Once, every day, selected days, day of month

## Phase 9 - Connection log & history
- [ ] 9.1 Realtime connection log: connect/accept/listen/closed, allowed/blocked, start/stop/clear, export
- [ ] 9.2 Connection history per app: IP, hostname, port, data in/out, first/last transfer, export CSV

## Phase 10 - Apps, networks, geo
- [ ] 10.1 Apps list (apps / services / store packages), installed/uninstalled, delete apps
- [ ] 10.2 Tags for apps (usable in filters)
- [ ] 10.3 Networks list: detected networks (SSID, gateway MAC, interface), network-based filters
- [ ] 10.4 Geo-IP country/flag/town, WHOIS lookup, "ask web" / map link

## Phase 11 - Client polish
- [ ] 11.1 Tray icon (min/close to tray, show/hide, pending requests menu)
- [ ] 11.2 Global hotkeys to toggle rules
- [ ] 11.3 Run on startup, notifications
- [ ] 11.4 Themes / accent colors, dockable panes and layout profiles, column/stacked chart styles
- [ ] 11.5 Localization

## Phase 12 - Advanced
- [ ] 12.1 Remote administration (TCP, connect to another machine)
- [ ] 12.2 Permissions: user/group allow/deny access to the service
- [ ] 12.3 Public API / PowerShell usage
- [ ] 12.4 VirusTotal file checks (API key)

## Out of scope
Licensing/registration, version checker, NetLimiter 4 stats import.
