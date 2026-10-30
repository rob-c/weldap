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
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
icacls $Dir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null

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
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Accept)
    $out = & certutil.exe -f -addstore My $Accept 2>&1
    if ($LASTEXITCODE -ne 0) { throw "certutil -addstore failed: $out" }
    $out = & certutil.exe -repairstore My $cert.Thumbprint 2>&1
    if ($LASTEXITCODE -ne 0) { throw "certutil -repairstore failed (no matching key from -NewRequest?): $out" }
    $installed = Get-Item "Cert:\LocalMachine\My\$($cert.Thumbprint)"
    if (-not $installed.HasPrivateKey) { throw 'certificate installed without its private key (wrong CSR?)' }
    $installed.FriendlyName = 'WELDAP device'   # what the service looks for (LoginSettings.DeviceCertificateName)
    # Drop the now-fulfilled pending request.
    Get-ChildItem Cert:\LocalMachine\REQUEST -ErrorAction SilentlyContinue |
        Where-Object { $_.PublicKey.EncodedKeyValue.RawData -join ',' -eq ($cert.PublicKey.EncodedKeyValue.RawData -join ',') } |
        Remove-Item -ErrorAction SilentlyContinue
    Restart-Service Weldap -ErrorAction SilentlyContinue
    "installed $($installed.Thumbprint) subject=$($installed.Subject) issuer=$($installed.Issuer) notAfter=$($installed.NotAfter.ToString('o'))"
    exit 0
}

if ($Status) {
    Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.FriendlyName -eq 'WELDAP device' } |
        ForEach-Object { '{0} {1} issuer="{2}" notAfter={3} key={4}' -f $_.Thumbprint, $_.Subject, $_.Issuer, $_.NotAfter.ToString('yyyy-MM-dd'), $_.HasPrivateKey }
    exit 0
}
Get-Content $MyInvocation.MyCommand.Path | Select-Object -First 7
