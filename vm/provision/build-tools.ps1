# Installs the build toolchain on the build VM (VM1). Run as SYSTEM via:
#   vm/vmctl.sh exec vm1 build-tools
# MSVC for x64 + ARM64 (credential provider DLL), Windows SDK, .NET 10 SDK
# (service; WiX comes in as an MSBuild SDK package, so no global tool).
$ErrorActionPreference = 'Stop'
$state = 'C:\ProgramData\WELDAP-Provision'
$dl = "$state\downloads"
New-Item -ItemType Directory -Force -Path $dl | Out-Null
Start-Transcript -Path "$state\build-tools.log" -Append
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
$ProgressPreference = 'SilentlyContinue'

$nativeArch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }

# Visual Studio 2022 Build Tools: C++ for x64 and ARM64, Windows 11 SDK.
Invoke-WebRequest -Uri 'https://aka.ms/vs/17/release/vs_BuildTools.exe' -OutFile "$dl\vs_BuildTools.exe"
$vsArgs = @(
    '--quiet', '--wait', '--norestart', '--nocache',
    '--add', 'Microsoft.VisualStudio.Workload.VCTools',
    '--add', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
    '--add', 'Microsoft.VisualStudio.Component.VC.Tools.ARM64',
    '--add', 'Microsoft.VisualStudio.Component.Windows11SDK.26100',
    '--includeRecommended'
)
$p = Start-Process -FilePath "$dl\vs_BuildTools.exe" -ArgumentList $vsArgs -Wait -PassThru
# 3010 = success, reboot required
if ($p.ExitCode -notin 0, 3010) { throw "VS Build Tools install failed: $($p.ExitCode)" }

# .NET 10 SDK (LTS, supported to Nov 2028), machine-wide.
Invoke-WebRequest -Uri 'https://dot.net/v1/dotnet-install.ps1' -OutFile "$dl\dotnet-install.ps1"
& "$dl\dotnet-install.ps1" -Channel 10.0 -Architecture $nativeArch -InstallDir 'C:\Program Files\dotnet' -NoPath
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($machinePath -notlike '*C:\Program Files\dotnet*') {
    [Environment]::SetEnvironmentVariable('Path', "$machinePath;C:\Program Files\dotnet", 'Machine')
}
[Environment]::SetEnvironmentVariable('DOTNET_CLI_TELEMETRY_OPTOUT', '1', 'Machine')

& 'C:\Program Files\dotnet\dotnet.exe' --info
Get-Date -Format o | Set-Content -Path "$state\build-tools.done"
Stop-Transcript
