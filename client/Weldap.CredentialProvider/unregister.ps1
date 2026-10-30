<#
.SYNOPSIS
    DEV ONLY: unregisters the WELDAP credential provider and removes its DLL.

.DESCRIPTION
    Deletes the Credential Providers\{CLSID} and CLSID\{CLSID} keys, then deletes
    C:\Program Files\WELDAP\WeldapCredentialProvider.dll. If LogonUI still has the DLL loaded,
    it is renamed and scheduled for deletion at the next reboot. Run as Administrator or SYSTEM.

.PARAMETER KeepFiles
    Only remove the registration.
#>
[CmdletBinding()]
param(
    [switch]$KeepFiles
)
$ErrorActionPreference = 'Stop'

$clsid = '{E239AAAB-FFFD-4525-A894-1B9D6314B1CB}'
$name = 'WeldapCredentialProvider'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -and
    $id.User.Value -ne 'S-1-5-18') {
    throw 'Run as Administrator.'
}

$hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
try {
    # Remove the provider registration first, so LogonUI stops loading the DLL.
    $hklm.DeleteSubKeyTree("SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid", $false)
    $hklm.DeleteSubKeyTree("SOFTWARE\Classes\CLSID\$clsid", $false)
} finally {
    $hklm.Close()
}
Write-Host "unregistered $clsid"

if ($KeepFiles) { return }

$programFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$destDir = Join-Path $programFiles 'WELDAP'
Add-Type -Namespace WeldapDev -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool MoveFileEx(string existing, string newName, int flags);
'@
foreach ($f in @(Get-ChildItem -LiteralPath $destDir -Filter "$name.dll*" -ErrorAction SilentlyContinue)) {
    try {
        Remove-Item -LiteralPath $f.FullName -Force
        Write-Host "deleted $($f.FullName)"
    } catch {
        $pending = $f.FullName
        if ($f.Name -eq "$name.dll") {
            $pending = "$($f.FullName).old-$([DateTime]::UtcNow.Ticks)"
            Move-Item -LiteralPath $f.FullName -Destination $pending -Force
        }
        # MOVEFILE_DELAY_UNTIL_REBOOT = 4
        [void][WeldapDev.Native]::MoveFileEx($pending, $null, 4)
        Write-Host "in use: $pending will be deleted at the next reboot"
    }
}
if ((Test-Path -LiteralPath $destDir) -and -not (Get-ChildItem -LiteralPath $destDir -Force)) {
    Remove-Item -LiteralPath $destDir -Force
}
