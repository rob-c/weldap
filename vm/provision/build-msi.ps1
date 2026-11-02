# In the build VM (vm1): credential provider for x64 + ARM64, then one MSI per architecture.
# Expects the tree that vm/build-in-vm.sh unpacks at $Root, including out\service-win-* and out\admin-win-*
# published on the host. Results land in $Root\artifacts\.
#
# Code signing (anti-tamper) is optional and off by default; set ONE of these in the VM to sign the binaries
# and the MSI, then the service's integrity pins are taken over the SIGNED files:
#   $env:WELDAP_SIGN_THUMBPRINT              SHA-1 thumbprint of a code-signing cert in Cert:\*\My
#   $env:WELDAP_SIGN_PFX (+ _PFX_PASSWORD)   path to a PFX file (and its password)
#   $env:WELDAP_SIGN_TIMESTAMP_URL           RFC-3161 timestamp server (default: DigiCert)
# With none set, the build is unsigned (a dev build), exactly as an unset ProviderHash means "not pinned".
param([string]$Root = 'C:\src\windev')
$ErrorActionPreference = 'Stop'
$env:PATH = "C:\Program Files\dotnet;$env:PATH"
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'
$art = Join-Path $Root 'artifacts'
Remove-Item -Recurse -Force $art -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $art | Out-Null

$script:SignTool = $null
function Get-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $found = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\(x64|arm64)\\' } | Sort-Object FullName -Descending | Select-Object -First 1
    if ($found) { return $found.FullName }
    throw 'signtool.exe not found (install the Windows SDK), or unset WELDAP_SIGN_* to build unsigned'
}

# Authenticode-signs each file, or no-ops (with a note) when no cert is configured.
function Invoke-Sign([string[]]$Files) {
    $thumb = $env:WELDAP_SIGN_THUMBPRINT
    $pfx = $env:WELDAP_SIGN_PFX
    if (-not $thumb -and -not $pfx) {
        Write-Host '  signing: WELDAP_SIGN_* unset; unsigned dev build'
        return
    }
    if (-not $script:SignTool) { $script:SignTool = Get-SignTool }
    $ts = if ($env:WELDAP_SIGN_TIMESTAMP_URL) { $env:WELDAP_SIGN_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' }
    $args = @('sign', '/fd', 'SHA256', '/tr', $ts, '/td', 'SHA256')
    if ($thumb) {
        # /sm: look in the Local Machine store (the build runs as SYSTEM, so the cert lives in Cert:\LocalMachine\My,
        # not the per-user store signtool searches by default).
        $args += @('/sm', '/sha1', $thumb)
    } else {
        $args += @('/f', $pfx)
        if ($env:WELDAP_SIGN_PFX_PASSWORD) { $args += @('/p', $env:WELDAP_SIGN_PFX_PASSWORD) }
    }
    foreach ($f in $Files) {
        & $script:SignTool @args $f
        if ($LASTEXITCODE -ne 0) { throw "signing failed: $f" }
        Write-Host "  signed $f"
    }
}

& (Join-Path $Root 'client\Weldap.CredentialProvider\build.ps1')

foreach ($t in @(@{ Wix = 'x64'; Rid = 'win-x64'; Cp = 'x64' }, @{ Wix = 'arm64'; Rid = 'win-arm64'; Cp = 'ARM64' })) {
    $cpDir = Join-Path $Root "client\Weldap.CredentialProvider\out\$($t.Cp)"
    $serviceDir = Join-Path $Root "out\service-$($t.Rid)"
    $adminDir = Join-Path $Root "out\admin-$($t.Rid)"
    $outDir = Join-Path $Root "installer\bin\$($t.Wix)"
    $providerDll = Join-Path $cpDir 'WeldapCredentialProvider.dll'
    $serviceExe = Join-Path $serviceDir 'WeldapService.exe'
    $adminExe = Join-Path $adminDir 'weldapadm.exe'

    # Sign first, then pin: the anti-tamper hashes must be taken over the exact (signed) bytes we ship, so the
    # service's check matches after signing. A swapped or patched binary then fails both the signature and the pin.
    Invoke-Sign @($serviceExe, $adminExe, $providerDll)
    $providerHash = (Get-FileHash -Algorithm SHA256 $providerDll).Hash
    $serviceHash = (Get-FileHash -Algorithm SHA256 $serviceExe).Hash
    $adminHash = (Get-FileHash -Algorithm SHA256 $adminExe).Hash

    dotnet build (Join-Path $Root 'installer\Weldap.wixproj') -c Release --nologo -v q `
        "-p:InstallerPlatform=$($t.Wix)" "-p:ServiceDir=$serviceDir" "-p:ProviderDir=$cpDir" "-p:AdminDir=$adminDir" `
        "-p:ProviderHash=$providerHash" "-p:ServiceHash=$serviceHash" "-p:AdminHash=$adminHash" `
        "-p:IntermediateOutputPath=obj\$($t.Wix)\" `
        -o $outDir
    if ($LASTEXITCODE -ne 0) { throw "MSI build failed for $($t.Wix)" }
    $msi = Get-ChildItem -Path $outDir -Recurse -Filter "Weldap-$($t.Wix).msi" | Select-Object -First 1
    if (-not $msi) { throw "no MSI produced for $($t.Wix)" }
    Invoke-Sign @($msi.FullName)
    Copy-Item $msi.FullName $art
    New-Item -ItemType Directory -Force -Path "$art\provider-$($t.Cp)" | Out-Null
    Copy-Item $providerDll "$art\provider-$($t.Cp)\"
}
Get-ChildItem -Recurse $art | Where-Object { -not $_.PSIsContainer } |
    ForEach-Object { '{0,12:N0}  {1}' -f $_.Length, $_.FullName.Substring($art.Length + 1) }
