# Public API

Everything the app does goes through the service's API, so scripts and programs can do the same.
The list of methods is in `DEVELOPMENT.md` under "IPC methods".

## Access
- Local: named pipe `NetWarden.Service.v1`. Administrators and SYSTEM always have access (from an elevated process);
  other users and groups need an entry in Settings > Permissions. A denied group wins over an allowed one.
- Remote: TLS over TCP (default port 5317), only after it is turned on with a password in Settings. Windows Firewall has to
  allow the port. Anyone who logs on has the full API, including changing the rules, so choose a strong password.

## PowerShell
`scripts\NetWarden.psm1`, installed to `C:\Program Files\NetWarden\powershell`. Works in Windows PowerShell 5.1 and PowerShell 7.

```powershell
Import-Module "C:\Program Files\NetWarden\powershell\NetWarden.psm1"

Get-NetWardenActivity | Sort-Object rateIn -Descending | Select-Object -First 5 @{n='App';e={$_.app.displayName}}, rateIn, rateOut
Get-NetWardenRule | Where-Object { $_.rule.kind -eq 'Quota' }
Set-NetWardenSwitch -Limiter $false
Set-NetWardenRuleEnabled -Id $id -Enabled $true
Reset-NetWardenQuota -RuleId $id

# Anything else: every API method by name.
Invoke-NetWardenRequest -Method 'stats.info'
```

## .NET
Reference `NetWarden.Shared`:

```csharp
await using var client = new ServiceClient();
await client.ConnectAsync(TimeSpan.FromSeconds(2));
var snapshot = await client.RequestAsync<ActivitySnapshot>(Methods.ActivityGet);
client.EventReceived += (method, payload) => { /* Events.* */ };

// Another computer: the first connection reports the certificate; pin it for the next ones.
await using var remote = ServiceClient.ForRemote(new RemoteTarget("server", 5317, password, pinnedThumbprint));
```

## Protocol
Each message is a 4-byte little-endian length, then UTF-8 JSON (camelCase names, enums as strings, at most 16 MB):

```json
{"kind":"Request","id":1,"method":"rules.get","payload":null}
{"kind":"Response","id":1,"method":"rules.get","payload":{},"error":null}
{"kind":"Event","id":0,"method":"activity.snapshot","payload":{}}
```

Answers carry the id of their request, and `error` when it failed. Events can arrive between them.
Over TCP the first message after the TLS handshake must be `remote.auth` with `{"password":"..."}`. Five wrong passwords lock
the address out for five minutes.
