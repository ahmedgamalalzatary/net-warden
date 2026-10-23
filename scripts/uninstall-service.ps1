#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Stops and removes the NetWarden Windows service. Settings in %ProgramData%\NetWarden are kept.
#>
param(
    [string]$ServiceName = 'NetWarden'
)

$ErrorActionPreference = 'Stop'
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service) {
    Write-Host "Service '$ServiceName' is not installed."
    return
}

if ($service.Status -ne 'Stopped') {
    Stop-Service -Name $ServiceName -Force
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
sc.exe delete $ServiceName | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed ($LASTEXITCODE)." }
Write-Host "Service '$ServiceName' removed."
