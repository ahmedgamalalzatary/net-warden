# NetWarden from PowerShell, in Windows PowerShell 5.1 or PowerShell 7. Run elevated, or as a user allowed in
# Settings > Permissions. Import-Module "C:\Program Files\NetWarden\powershell\NetWarden.psm1"; see docs/API.md.

function Invoke-NetWardenRequest {
    <#
    .SYNOPSIS
    Calls any method of the NetWarden service and returns its answer.
    .EXAMPLE
    Invoke-NetWardenRequest -Method 'quotas.status'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Method,
        [object]$Payload,
        [string]$PipeName = 'NetWarden.Service.v1',
        [int]$TimeoutMilliseconds = 5000
    )
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
    try {
        $pipe.Connect($TimeoutMilliseconds)
        $request = @{ kind = 'Request'; id = 1; method = $Method }
        if ($PSBoundParameters.ContainsKey('Payload')) { $request.payload = $Payload }
        $body = [System.Text.Encoding]::UTF8.GetBytes(($request | ConvertTo-Json -Depth 32 -Compress))
        $pipe.Write([System.BitConverter]::GetBytes([int]$body.Length), 0, 4)
        $pipe.Write($body, 0, $body.Length)
        $pipe.Flush()
        while ($true) {
            $length = [System.BitConverter]::ToInt32((Read-NetWardenBytes $pipe 4), 0)
            $text = [System.Text.Encoding]::UTF8.GetString((Read-NetWardenBytes $pipe $length))
            # The service also pushes events on the pipe; only the answer to this request counts.
            if ($text -notmatch '"kind":"Response"') { continue }
            # ConvertFrom-Json in 5.1 refuses large answers, so give it the length it needs.
            Add-Type -AssemblyName System.Web.Extensions -ErrorAction SilentlyContinue
            $message = if ($PSVersionTable.PSVersion.Major -lt 6) {
                $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
                $serializer.MaxJsonLength = [int]::MaxValue
                $serializer.RecursionLimit = 256
                ConvertTo-NetWardenObject $serializer.DeserializeObject($text)
            } else {
                $text | ConvertFrom-Json -Depth 64
            }
            if ($message.error) { throw "NetWarden ${Method}: $($message.error)" }
            return $message.payload
        }
    }
    finally {
        $pipe.Dispose()
    }
}

function Read-NetWardenBytes($Stream, [int]$Count) {
    $buffer = New-Object byte[] $Count
    $read = 0
    while ($read -lt $Count) {
        $n = $Stream.Read($buffer, $read, $Count - $read)
        if ($n -le 0) { throw 'The NetWarden service closed the connection.' }
        $read += $n
    }
    return , $buffer
}

function ConvertTo-NetWardenObject($Value) {
    if ($Value -is [System.Collections.IDictionary]) {
        $object = New-Object psobject
        foreach ($key in $Value.Keys) {
            $object | Add-Member -NotePropertyName $key -NotePropertyValue (ConvertTo-NetWardenObject $Value[$key])
        }
        return $object
    }
    if ($Value -is [array]) {
        return , @($Value | ForEach-Object { ConvertTo-NetWardenObject $_ })
    }
    return $Value
}

function Get-NetWardenInfo { [CmdletBinding()] param([string]$PipeName = 'NetWarden.Service.v1')
    Invoke-NetWardenRequest -Method 'service.info' -PipeName $PipeName }

function Get-NetWardenSettings { [CmdletBinding()] param([string]$PipeName = 'NetWarden.Service.v1')
    Invoke-NetWardenRequest -Method 'settings.get' -PipeName $PipeName }

function Get-NetWardenActivity { [CmdletBinding()] param([string]$PipeName = 'NetWarden.Service.v1')
    (Invoke-NetWardenRequest -Method 'activity.get' -PipeName $PipeName).apps }

function Get-NetWardenRule { [CmdletBinding()] param([string]$PipeName = 'NetWarden.Service.v1')
    (Invoke-NetWardenRequest -Method 'rules.get' -PipeName $PipeName).rules }

function Get-NetWardenFilter { [CmdletBinding()] param([string]$PipeName = 'NetWarden.Service.v1')
    (Invoke-NetWardenRequest -Method 'rules.get' -PipeName $PipeName).filters }

function Get-NetWardenQuota { [CmdletBinding()] param([string]$PipeName = 'NetWarden.Service.v1')
    Invoke-NetWardenRequest -Method 'quotas.status' -PipeName $PipeName }

function Reset-NetWardenQuota {
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$RuleId, [string]$PipeName = 'NetWarden.Service.v1')
    Invoke-NetWardenRequest -Method 'quotas.reset' -Payload @{ ruleId = "$RuleId" } -PipeName $PipeName
}

function Set-NetWardenRuleEnabled {
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$Id, [Parameter(Mandatory)][bool]$Enabled, [string]$PipeName = 'NetWarden.Service.v1')
    Invoke-NetWardenRequest -Method 'rules.setEnabled' -Payload @{ id = "$Id"; isEnabled = $Enabled } -PipeName $PipeName
}

function Set-NetWardenSwitch {
    <#
    .SYNOPSIS
    Turns the limiter, the blocker or priorities on or off for the whole computer.
    .EXAMPLE
    Set-NetWardenSwitch -Limiter $false
    #>
    [CmdletBinding()]
    param([Nullable[bool]]$Limiter, [Nullable[bool]]$Blocker, [Nullable[bool]]$Priorities, [string]$PipeName = 'NetWarden.Service.v1')
    $settings = Invoke-NetWardenRequest -Method 'settings.get' -PipeName $PipeName
    if ($null -ne $Limiter) { $settings.isLimiterEnabled = [bool]$Limiter }
    if ($null -ne $Blocker) { $settings.isBlockerEnabled = [bool]$Blocker }
    if ($null -ne $Priorities) { $settings.isPriorityEnabled = [bool]$Priorities }
    Invoke-NetWardenRequest -Method 'settings.update' -Payload $settings -PipeName $PipeName
}

Export-ModuleMember -Function Invoke-NetWardenRequest, Get-NetWardenInfo, Get-NetWardenSettings, Get-NetWardenActivity,
    Get-NetWardenRule, Get-NetWardenFilter, Get-NetWardenQuota, Reset-NetWardenQuota, Set-NetWardenRuleEnabled, Set-NetWardenSwitch
