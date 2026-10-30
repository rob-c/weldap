# Dev install of the WELDAP Service (the MSI does the same in production). Run as SYSTEM/admin in a test VM:
#   install-dev.ps1 -Source <dir> -ServerKey <base64 public key> -ServerPin <base64 SHA-256> [-ServerKeyId k1]
#   install-dev.ps1 -Uninstall
# The device knows only the WELDAP server: its address, its TLS key pin and its public password key. Its own
# certificate is installed by register-device.ps1.
param(
    [string]$Source = 'C:\ProgramData\WELDAP-Provision\service',
    [string]$ServerHost = '10.0.2.2',   # the Mac's loopback through QEMU user-mode NAT; trust is the pin, not the name
    [int]$ServerPort = 16637,
    [string]$ServerKey,
    [string]$ServerKeyId = 'k1',
    [string]$ServerPin,
    [int]$MaxOfflineDays = 180,
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$dest = 'C:\Program Files\WELDAP'
$keyPath = 'HKLM:\SOFTWARE\WELDAP'

if (Get-Service Weldap -ErrorAction SilentlyContinue) {
    Stop-Service Weldap -Force -ErrorAction SilentlyContinue
    sc.exe delete Weldap | Out-Null
    Start-Sleep -Seconds 2
}
if ($Uninstall) { "Weldap service removed (accounts, profiles and config kept)"; return }

New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item -Path "$Source\*" -Destination $dest -Recurse -Force

# Config key, writable only by SYSTEM and Administrators (SR-10), readable by all.
if (-not (Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
$acl = New-Object System.Security.AccessControl.RegistrySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
    $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit', 'None', 'Allow')))
}
$acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
    (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')), 'ReadKey', 'ContainerInherit', 'None', 'Allow')))
$acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))
Set-Acl -Path $keyPath -AclObject $acl

if (-not $ServerKey) { throw '-ServerKey (the server public password key) is required' }
if (-not $ServerPin) { throw '-ServerPin (SHA-256 of the server TLS public key, base64) is required' }
# Values from earlier designs: gone from the device for good.
foreach ($old in 'LdapHost', 'LdapPort', 'UserDnTemplate', 'PeopleBase', 'UsersGroupDn', 'AdminsGroupDn', 'ServiceBindDn',
                 'ServiceBindSecret', 'HideDefaultTile', 'GatewayHost', 'GatewayPort', 'DeviceCaIssuer', 'GatewayPasswordKey',
                 'GatewayKeyId', 'ManagedGroup', 'PinnedSpkiSha256', 'ConnectTimeoutSeconds', 'TimeoutSeconds', 'CleanupIntervalMinutes') {
    Remove-ItemProperty -Path $keyPath -Name $old -ErrorAction SilentlyContinue
}
Remove-ItemProperty -Path "$keyPath\Secret" -Name ServiceBindSecret -ErrorAction SilentlyContinue
$values = @{
    ServerHost  = $ServerHost
    ServerKey   = $ServerKey
    ServerKeyId = $ServerKeyId
    TileLabel   = 'WELDAP sign-in'
}
foreach ($k in $values.Keys) { Set-ItemProperty -Path $keyPath -Name $k -Value $values[$k] -Type String }
Set-ItemProperty -Path $keyPath -Name ServerPins -Value @($ServerPin) -Type MultiString
Set-ItemProperty -Path $keyPath -Name ServerPort -Value $ServerPort -Type DWord
Set-ItemProperty -Path $keyPath -Name MaxOfflineDays -Value $MaxOfflineDays -Type DWord
Set-ItemProperty -Path $keyPath -Name ExcludedAccounts -Value @('administrator', 'breakglass') -Type MultiString

# Event source registered against the message DLL shipped next to the exe (as the MSI does).
if ([System.Diagnostics.EventLog]::SourceExists('WELDAP')) {
    [System.Diagnostics.EventLog]::DeleteEventSource('WELDAP')
}
$src = New-Object System.Diagnostics.EventSourceCreationData('WELDAP', 'Application')
$src.MessageResourceFile = "$dest\System.Diagnostics.EventLog.Messages.dll"
[System.Diagnostics.EventLog]::CreateEventSource($src)

sc.exe create Weldap binPath= "`"$dest\WeldapService.exe`"" start= auto obj= LocalSystem DisplayName= "WELDAP Service" | Out-Null
sc.exe description Weldap "Relays sealed sign-ins to the WELDAP server and keeps managed local accounts in step." | Out-Null
sc.exe failure Weldap reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
Start-Service Weldap
Start-Sleep -Seconds 3
Get-Service Weldap | Format-Table -AutoSize Name, Status | Out-String
