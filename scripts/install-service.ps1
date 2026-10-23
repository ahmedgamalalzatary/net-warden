#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Publishes NetWarden.Service and registers it as an auto-start Windows service.
.PARAMETER InstallDir
    Where the service binaries are published. Defaults to artifacts\service in the repo.
#>
param(
    [string]$InstallDir = (Join-Path $PSScriptRoot '..\artifacts\service'),
    [string]$ServiceName = 'NetWarden'
)

$ErrorActionPreference = 'Stop'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..')
$project = Join-Path $repo 'src\NetWarden.Service\NetWarden.Service.csproj'

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Service '$ServiceName' already exists; reinstalling."
    & (Join-Path $PSScriptRoot 'uninstall-service.ps1') -ServiceName $ServiceName
}

Write-Host "Publishing service to $InstallDir ..."
dotnet publish $project -c Release -o $InstallDir --nologo -v q
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed ($LASTEXITCODE)." }

$exe = Join-Path (Resolve-Path $InstallDir) 'NetWarden.Service.exe'
sc.exe create $ServiceName binPath= "`"$exe`"" start= auto DisplayName= "NetWarden Service" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed ($LASTEXITCODE)." }
sc.exe description $ServiceName "Monitors, limits and filters network traffic per application." | Out-Null
# Restart on crash: after 5s, 10s, then 60s; reset the failure count after a day.
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/60000 | Out-Null

Start-Service -Name $ServiceName
Get-Service -Name $ServiceName | Format-Table Name, Status, StartType -AutoSize
