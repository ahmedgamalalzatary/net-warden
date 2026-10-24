<#
.SYNOPSIS
    Builds the NetWarden desktop release: a self-contained client exe, the service, and
    the installer NetWarden-Setup-<version>.exe (Inno Setup), all in artifacts\release.
.DESCRIPTION
    Nothing needs to be installed on the target PC: both programs carry the .NET runtime.
    Inno Setup's compiler is downloaded once into tools\innosetup (NuGet package
    Tools.InnoSetup, signed by the Inno Setup maintainers).
.PARAMETER SkipTests
    Skip the test run before packaging.
#>
param([switch]$SkipTests)

$ErrorActionPreference = 'Stop'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..')
$out = Join-Path $repo 'artifacts\release'
$stage = Join-Path $out 'stage'
$innoVersion = '6.7.1'
$iscc = Join-Path $repo 'tools\innosetup\tools\ISCC.exe'

[xml]$props = Get-Content (Join-Path $repo 'Directory.Build.props')
$version = $props.Project.PropertyGroup.Version
Write-Host "NetWarden $version"

if (-not $SkipTests) {
    Write-Host 'Running tests...'
    dotnet test (Join-Path $repo 'tests\NetWarden.Tests') -c Release --nologo -v q
    if ($LASTEXITCODE -ne 0) { throw "Tests failed ($LASTEXITCODE); not packaging." }
}

if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }

Write-Host 'Publishing client (single file, self-contained)...'
dotnet publish (Join-Path $repo 'src\NetWarden.Client') -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true `
    -p:DebugType=none -o (Join-Path $stage 'client-publish') --nologo -v q
if ($LASTEXITCODE -ne 0) { throw "Client publish failed ($LASTEXITCODE)." }
New-Item -ItemType Directory -Force (Join-Path $stage 'client') | Out-Null
# The assembly stays NetWarden.Client (resource URIs use it); only the file is renamed.
Copy-Item (Join-Path $stage 'client-publish\NetWarden.Client.exe') (Join-Path $stage 'client\NetWarden.exe')

Write-Host 'Publishing service (self-contained)...'
# A folder, not a single file: WinDivert.dll and WinDivert64.sys must sit next to the exe.
dotnet publish (Join-Path $repo 'src\NetWarden.Service') -c Release -r win-x64 --self-contained true `
    -p:DebugType=none -o (Join-Path $stage 'service') --nologo -v q
if ($LASTEXITCODE -ne 0) { throw "Service publish failed ($LASTEXITCODE)." }
foreach ($f in 'WinDivert.dll', 'WinDivert64.sys', 'NetWarden.Service.exe', 'e_sqlite3.dll', 'country.bin.gz') {
    if (-not (Test-Path (Join-Path $stage "service\$f"))) { throw "Service publish is missing $f." }
}

if (-not (Test-Path $iscc)) {
    Write-Host "Downloading Inno Setup $innoVersion..."
    $zip = Join-Path $repo 'tools\innosetup.zip'
    New-Item -ItemType Directory -Force (Split-Path $zip) | Out-Null
    Invoke-WebRequest "https://api.nuget.org/v3-flatcontainer/tools.innosetup/$innoVersion/tools.innosetup.$innoVersion.nupkg" -OutFile $zip
    Expand-Archive $zip (Join-Path $repo 'tools\innosetup') -Force
    Remove-Item $zip
    $signature = Get-AuthenticodeSignature $iscc
    if ($signature.Status -ne 'Valid') { throw "ISCC.exe signature is $($signature.Status); refusing to run it." }
}

Write-Host 'Building installer...'
& $iscc /Q "/DAppVersion=$version" "/DStage=$stage" "/DOutDir=$out" (Join-Path $repo 'installer\NetWarden.iss')
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed ($LASTEXITCODE)." }

$setup = Join-Path $out "NetWarden-Setup-$version.exe"
Write-Host ''
Write-Host "Installer: $setup ($([math]::Round((Get-Item $setup).Length / 1MB, 1)) MB)"
Write-Host "App files: $stage\client\NetWarden.exe and $stage\service\"
