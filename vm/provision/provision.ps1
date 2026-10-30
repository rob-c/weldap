# First-logon provisioning for WELDAP sign-in test VMs.
# Runs once, elevated, from the provision ISO (see autounattend.xml.tmpl).
# Leaves the VM at the logon screen with no inbound network exposure and the
# QEMU guest agent running, so the host drives it with `vm/vmctl.sh ps` / `push`.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$state = 'C:\ProgramData\WELDAP-Provision'
New-Item -ItemType Directory -Force -Path $state | Out-Null
Start-Transcript -Path "$state\provision.log" -Append

# 1. UTM guest tools package: VirtIO drivers + QEMU guest agent (host control channel, no network).
$gt = Get-ChildItem -Path $root -Filter 'utm-guest-tools-*.exe' | Select-Object -First 1
if ($gt) {
    Write-Host "Installing $($gt.Name)"
    Start-Process -FilePath $gt.FullName -ArgumentList '/S' -Wait
} else {
    Write-Warning 'UTM guest tools installer not found on provision ISO'
}

# 2. Power: never sleep or hibernate (the host snapshots running VMs).
powercfg /hibernate off
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0

# 3. Network surface: every profile on, all inbound blocked including allow rules.
Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow `
    -AllowInboundRules False -AllowLocalFirewallRules False -NotifyOnListen False
Get-NetConnectionProfile -ErrorAction SilentlyContinue | Set-NetConnectionProfile -NetworkCategory Public
reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 1 /f | Out-Null
reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance' /v fAllowToGetHelp /t REG_DWORD /d 0 /f | Out-Null

# 3b. No automatic Windows Update installs or restarts: a test VM rebooting mid-run breaks the host's test
#     sessions. (Isolated dev VMs only; update them deliberately, e.g. before taking a new snapshot.)
$au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
New-Item -Path $au -Force | Out-Null
Set-ItemProperty -Path $au -Name NoAutoUpdate -Value 1 -Type DWord
Set-ItemProperty -Path $au -Name NoAutoRebootWithLoggedOnUsers -Value 1 -Type DWord

# 4. No lingering auto-logon or plaintext setup passwords.
$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty -Path $winlogon -Name AutoAdminLogon -Value '0'
Remove-ItemProperty -Path $winlogon -Name DefaultPassword -ErrorAction SilentlyContinue
Remove-Item -Force -ErrorAction SilentlyContinue 'C:\Windows\Panther\unattend.xml', 'C:\Windows\Panther\Unattend\*.xml'

# 5. Marker the host waits for, then reboot so new drivers load and the VM rests at the logon screen.
Get-Date -Format o | Set-Content -Path "$state\done.txt"
Stop-Transcript
shutdown /r /t 10 /c "WELDAP provisioning complete"
