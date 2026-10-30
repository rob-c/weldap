<#
.SYNOPSIS
    Builds WeldapCredentialProvider.dll (Release) for x64 and ARM64 into .\out\<Platform>\.

.DESCRIPTION
    Runs on the Windows build VM. Finds Visual Studio 2022 (Build Tools) with vswhere, runs
    each build inside VsDevCmd.bat for the target architecture, then checks the result with
    dumpbin: exports, ASLR / high-entropy VA / NX / CFG flags and no dynamic VC++ runtime.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File build.ps1
    powershell -ExecutionPolicy Bypass -File build.ps1 -Platform ARM64
#>
[CmdletBinding()]
param(
    [ValidateSet('x64', 'ARM64')]
    [string[]]$Platform = @('x64', 'ARM64')
)
$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot 'WeldapCredentialProvider.vcxproj'

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { throw "vswhere not found: $vswhere" }
$vsPath = & $vswhere -latest -products * -version '[17.0,18.0)' `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 Microsoft.VisualStudio.Component.VC.Tools.ARM64 `
    -property installationPath
if (-not $vsPath) { throw 'Visual Studio 2022 with the x64 and ARM64 C++ tools was not found' }
$devCmd = Join-Path $vsPath 'Common7\Tools\VsDevCmd.bat'

# Host architecture of the OS (not of this PowerShell process, which may be emulated).
$osArch = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').PROCESSOR_ARCHITECTURE
$hostArch = if ($osArch -eq 'ARM64') { 'arm64' } else { 'amd64' }

# Runs a command line inside the VS developer environment for the given target architecture.
# (Via a temporary .cmd file: Windows PowerShell 5.1 mangles quotes passed to cmd.exe /c.)
function Invoke-InDevEnv([string]$TargetArch, [string]$CommandLine) {
    $cmdFile = Join-Path $env:TEMP "ppecp-build-$PID.cmd"
    Set-Content -LiteralPath $cmdFile -Encoding ASCII -Value @(
        '@echo off'
        "call `"$devCmd`" -no_logo -arch=$TargetArch -host_arch=$hostArch || exit /b 1"
        $CommandLine
    )
    try {
        & cmd.exe /d /c $cmdFile
        if ($LASTEXITCODE -ne 0) { throw "failed ($LASTEXITCODE): $CommandLine" }
    } finally {
        Remove-Item -LiteralPath $cmdFile -ErrorAction SilentlyContinue
    }
}

foreach ($p in $Platform) {
    $arch = if ($p -eq 'ARM64') { 'arm64' } else { 'amd64' }
    Write-Host "=== Building Release|$p ==="
    Invoke-InDevEnv $arch "msbuild `"$project`" /nologo /m /t:Rebuild /p:Configuration=Release /p:Platform=$p /v:minimal"

    $dll = Join-Path $PSScriptRoot "out\$p\WeldapCredentialProvider.dll"
    if (-not (Test-Path $dll)) { throw "missing output: $dll" }

    # Verify exports and hardening flags.
    $tmp = Join-Path $env:TEMP "ppecp-dumpbin-$p.txt"
    Invoke-InDevEnv $arch "dumpbin /nologo /headers /exports /dependents /loadconfig `"$dll`" > `"$tmp`""
    $info = Get-Content $tmp -Raw
    $checks = [ordered]@{
        'export DllGetClassObject'  = $info -match '\bDllGetClassObject\b'
        'export DllCanUnloadNow'    = $info -match '\bDllCanUnloadNow\b'
        'DYNAMICBASE'               = $info -match 'Dynamic base'
        'HIGHENTROPYVA'             = $info -match 'High Entropy Virtual Addresses'
        'NXCOMPAT'                  = $info -match 'NX compatible'
        'guard:cf'                  = $info -match 'Control Flow Guard'
        'static CRT (no VCRUNTIME)' = $info -notmatch '(?i)vcruntime|msvcp|ucrtbase|api-ms-win-crt'
    }
    if ($p -eq 'x64') { $checks['CETCOMPAT'] = $info -match 'CET compatible' }
    $bad = @($checks.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object { $_.Key })
    $checks.GetEnumerator() | ForEach-Object { Write-Host ("  {0,-28} {1}" -f $_.Key, $(if ($_.Value) { 'ok' } else { 'MISSING' })) }
    if ($bad.Count) { throw "$p build failed checks: $($bad -join ', ')" }
    Write-Host "  -> $dll"
}
