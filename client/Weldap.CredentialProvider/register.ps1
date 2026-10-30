<#
.SYNOPSIS
    DEV ONLY: installs and registers the WELDAP credential provider (the MSI does this in production).

.DESCRIPTION
    Copies WeldapCredentialProvider.dll to C:\Program Files\WELDAP\ and writes
      HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32  (= HKCR\CLSID\..., ThreadingModel=Apartment)
      HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{CLSID}
    No credential provider filter is registered and the default providers are not touched,
    so the stock password tile always stays available. Run as Administrator or SYSTEM.

.PARAMETER DllPath
    DLL to install. Default: .\out\<OS architecture>\WeldapCredentialProvider.dll next to this script.
#>
[CmdletBinding()]
param(
    [string]$DllPath
)
$ErrorActionPreference = 'Stop'

$clsid = '{E239AAAB-FFFD-4525-A894-1B9D6314B1CB}'
$name = 'WeldapCredentialProvider'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -and
    $id.User.Value -ne 'S-1-5-18') {
    throw 'Run as Administrator.'
}

$osArch = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').PROCESSOR_ARCHITECTURE
$platform = if ($osArch -eq 'ARM64') { 'ARM64' } elseif ($osArch -eq 'AMD64') { 'x64' } else { throw "unsupported OS architecture $osArch" }
if (-not $DllPath) { $DllPath = Join-Path $PSScriptRoot "out\$platform\$name.dll" }
if (-not (Test-Path -LiteralPath $DllPath)) { throw "DLL not found: $DllPath" }

# Refuse a DLL whose machine type does not match the OS (LogonUI would silently skip it).
$bytes = [IO.File]::ReadAllBytes($DllPath)
$pe = [BitConverter]::ToInt32($bytes, 0x3C)
$machine = [BitConverter]::ToUInt16($bytes, $pe + 4)
$expected = @{ 'ARM64' = 0xAA64; 'x64' = 0x8664 }[$platform]
if ($machine -ne $expected) { throw ("{0} is machine type 0x{1:X4}; this OS needs 0x{2:X4} ({3})" -f $DllPath, $machine, $expected, $platform) }

$programFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$destDir = Join-Path $programFiles 'WELDAP'
$dest = Join-Path $destDir "$name.dll"
New-Item -ItemType Directory -Force -Path $destDir | Out-Null
try {
    Copy-Item -LiteralPath $DllPath -Destination $dest -Force
} catch {
    # LogonUI may still have the old DLL loaded: a loaded DLL can be renamed, not overwritten.
    $old = "$dest.old-$([DateTime]::UtcNow.Ticks)"
    Move-Item -LiteralPath $dest -Destination $old -Force
    Copy-Item -LiteralPath $DllPath -Destination $dest -Force
    Write-Host "previous DLL was in use; renamed to $old (delete it after a reboot)"
}

# 64-bit registry view explicitly (this PowerShell may be an emulated x64 process on ARM64).
$hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
try {
    $k = $hklm.CreateSubKey("SOFTWARE\Classes\CLSID\$clsid")
    $k.SetValue('', $name); $k.Close()
    $k = $hklm.CreateSubKey("SOFTWARE\Classes\CLSID\$clsid\InprocServer32")
    $k.SetValue('', $dest, 'ExpandString')
    $k.SetValue('ThreadingModel', 'Apartment')
    $k.Close()
    $k = $hklm.CreateSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid")
    $k.SetValue('', $name); $k.Close()
} finally {
    $hklm.Close()
}
Write-Host "registered $clsid -> $dest ($platform)"
