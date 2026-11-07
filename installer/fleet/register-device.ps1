# Fleet: register this device for WELDAP device trust. Run as SYSTEM.
#   register-device.ps1 -NewRequest            key pair + CSR (prints the CSR path; send it to the device CA)
#   register-device.ps1 -Accept <signed.crt>   install the signed certificate, bound to that key
#   register-device.ps1 -Status                show this device's WELDAP certificates
# The private key never leaves the device: non-exportable, in the TPM (Microsoft Platform Crypto
# Provider) when there is one, otherwise the software key store. Renewal = -NewRequest again; the
# service presents the newest valid certificate named "WELDAP device" (set here on -Accept).
param(
    [switch]$NewRequest,
    [string]$Accept,
    [switch]$Status,
    [string]$Dir = "$env:ProgramData\WELDAP\registration"
)
$ErrorActionPreference = 'Stop'

# The folder (and its parent) belong to SYSTEM and Administrators alone, whatever was there before: an ordinary user
# can create folders under ProgramData, so one could have pre-created either with an ACL of their own (or as a link
# elsewhere) to swap the CSR for one of their keys. So: no links, owner Administrators, and a fresh protected ACL
# (not icacls /grant, which keeps every other explicit entry), applied by SID (group names are localised).
function Lock-Folder([string]$Path) {
    if (Test-Path -LiteralPath $Path) {
        if ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "$Path is a link; refusing to use it (remove it, then run this again)"
        }
    } else {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
Lock-Folder (Split-Path -Parent $Dir)
Lock-Folder $Dir

function New-DeviceRequest([string]$Provider, [string]$Algorithm) {
    $inf = Join-Path $Dir 'request.inf'
    $csr = Join-Path $Dir "$env:COMPUTERNAME.csr"
    Remove-Item $csr -ErrorAction SilentlyContinue
    $keyLines = if ($Algorithm -eq 'ECDSA_P256') { "KeyAlgorithm = ECDSA_P256`r`nKeyLength = 256" } else { "KeyAlgorithm = RSA`r`nKeyLength = 2048" }
    Set-Content -Path $inf -Encoding ASCII -Value @"
[Version]
Signature = "`$Windows NT`$"
[NewRequest]
Subject = "CN=$($env:COMPUTERNAME.ToLowerInvariant())"
$keyLines
HashAlgorithm = SHA256
MachineKeySet = TRUE
Exportable = FALSE
ProviderName = "$Provider"
KeyUsage = 0x80
RequestType = PKCS10
FriendlyName = "WELDAP device"
[EnhancedKeyUsageExtension]
OID = 1.3.6.1.5.5.7.3.2
"@
    $out = & certreq.exe -new -machine -q -f $inf $csr 2>&1
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $csr)) { return $null }
    $csr
}

if ($NewRequest) {
    # Start from an empty folder: nothing in it but what this run writes.
    Get-ChildItem -LiteralPath $Dir -Force | Remove-Item -Recurse -Force
    $tpm = $false
    try { $tpm = [bool](Get-Tpm).TpmReady } catch { }
    $attempts = [System.Collections.Generic.List[string[]]]::new()
    if ($tpm) {
        $attempts.Add([string[]]@('Microsoft Platform Crypto Provider', 'ECDSA_P256'))
        $attempts.Add([string[]]@('Microsoft Platform Crypto Provider', 'RSA'))
    }
    $attempts.Add([string[]]@('Microsoft Software Key Storage Provider', 'ECDSA_P256'))
    foreach ($a in $attempts) {
        $csr = New-DeviceRequest $a[0] $a[1]
        if ($csr) { "csr=$csr provider=$($a[0]) algorithm=$($a[1]) tpm=$tpm"; exit 0 }
    }
    throw 'certreq could not create a device key and CSR'
}

if ($Accept) {
    # Not `certreq -accept`: that needs the device CA as a trusted root, and a device must never trust the
    # device CA (it would then accept server certificates from it). Add the certificate to the machine's
    # personal store and link it to the key created by -NewRequest.
    $Accept = (Resolve-Path -LiteralPath $Accept).Path   # .NET resolves a relative path against the process, not $PWD
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Accept)
    $out = & certutil.exe -f -addstore My $Accept 2>&1
    if ($LASTEXITCODE -ne 0) { throw "certutil -addstore failed: $out" }
    $out = & certutil.exe -repairstore My $cert.Thumbprint 2>&1
    if ($LASTEXITCODE -ne 0) {
        # Leave no certificate behind that is not bound to this device's own key.
        Remove-Item "Cert:\LocalMachine\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
        throw "certutil -repairstore failed (no matching key from -NewRequest?): $out"
    }
    $installed = Get-Item "Cert:\LocalMachine\My\$($cert.Thumbprint)"
    if (-not $installed.HasPrivateKey) { throw 'certificate installed without its private key (wrong CSR?)' }
    $installed.FriendlyName = 'WELDAP device'   # what the service looks for (LoginSettings.DeviceCertificateName)
    # Drop the now-fulfilled pending request.
    Get-ChildItem Cert:\LocalMachine\REQUEST -ErrorAction SilentlyContinue |
        Where-Object { $_.PublicKey.EncodedKeyValue.RawData -join ',' -eq ($cert.PublicKey.EncodedKeyValue.RawData -join ',') } |
        Remove-Item -ErrorAction SilentlyContinue
    "installed $($installed.Thumbprint) subject=$($installed.Subject) issuer=$($installed.Issuer) notAfter=$($installed.NotAfter.ToString('o'))"
    if (Get-Service Weldap -ErrorAction SilentlyContinue) {
        Restart-Service Weldap -ErrorAction SilentlyContinue
        if ((Get-Service Weldap).Status -ne 'Running') {
            Write-Warning 'the certificate is installed, but the WELDAP service is not running: see the Application log (source WELDAP)'
            exit 1
        }
    }
    exit 0
}

if ($Status) {
    Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.FriendlyName -eq 'WELDAP device' } |
        ForEach-Object { '{0} {1} issuer="{2}" notAfter={3} key={4}' -f $_.Thumbprint, $_.Subject, $_.Issuer, $_.NotAfter.ToString('yyyy-MM-dd'), $_.HasPrivateKey }
    exit 0
}
Get-Content $MyInvocation.MyCommand.Path | Select-Object -First 7
