# In the build VM (vm1): credential provider for x64 + ARM64, then one MSI per architecture.
# Expects the tree that vm/build-in-vm.sh unpacks at $Root, including out\service-win-x64 and
# out\service-win-arm64 published on the host. Results land in $Root\artifacts\.
param([string]$Root = 'C:\src\windev')
$ErrorActionPreference = 'Stop'
$env:PATH = "C:\Program Files\dotnet;$env:PATH"
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'
$art = Join-Path $Root 'artifacts'
Remove-Item -Recurse -Force $art -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $art | Out-Null

& (Join-Path $Root 'client\Weldap.CredentialProvider\build.ps1')

foreach ($t in @(@{ Wix = 'x64'; Rid = 'win-x64'; Cp = 'x64' }, @{ Wix = 'arm64'; Rid = 'win-arm64'; Cp = 'ARM64' })) {
    $cpDir = Join-Path $Root "client\Weldap.CredentialProvider\out\$($t.Cp)"
    $outDir = Join-Path $Root "installer\bin\$($t.Wix)"
    # Anti-tamper: pin this arch's provider DLL by SHA-256; the service refuses to start if the registered DLL differs.
    $providerHash = (Get-FileHash -Algorithm SHA256 (Join-Path $cpDir 'WeldapCredentialProvider.dll')).Hash
    dotnet build (Join-Path $Root 'installer\Weldap.wixproj') -c Release --nologo -v q `
        "-p:InstallerPlatform=$($t.Wix)" "-p:ServiceDir=$Root\out\service-$($t.Rid)" "-p:ProviderDir=$cpDir" `
        "-p:ProviderHash=$providerHash" `
        "-p:IntermediateOutputPath=obj\$($t.Wix)\" `
        -o $outDir
    if ($LASTEXITCODE -ne 0) { throw "MSI build failed for $($t.Wix)" }
    $msi = Get-ChildItem -Path $outDir -Recurse -Filter "Weldap-$($t.Wix).msi" | Select-Object -First 1
    if (-not $msi) { throw "no MSI produced for $($t.Wix)" }
    Copy-Item $msi.FullName $art
    New-Item -ItemType Directory -Force -Path "$art\provider-$($t.Cp)" | Out-Null
    Copy-Item "$cpDir\WeldapCredentialProvider.dll" "$art\provider-$($t.Cp)\"
}
Get-ChildItem -Recurse $art | Where-Object { -not $_.PSIsContainer } |
    ForEach-Object { '{0,12:N0}  {1}' -f $_.Length, $_.FullName.Substring($art.Length + 1) }
