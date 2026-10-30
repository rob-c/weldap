<#
.SYNOPSIS
    TEST ONLY: builds WeldapClientTest.exe (native OS architecture) into .\out\ — links the
    credential provider's WeldapClient.cpp and WeldapSeal.cpp, so they are tested as shipped.
#>
param([ValidateSet('native', 'x64', 'arm64')] [string]$Arch = 'native')
$ErrorActionPreference = 'Stop'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) { throw 'Visual Studio C++ tools not found' }
$devCmd = Join-Path $vsPath 'Common7\Tools\VsDevCmd.bat'
$osArch = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').PROCESSOR_ARCHITECTURE
$hostArch = if ($osArch -eq 'ARM64') { 'arm64' } else { 'amd64' }
$target = switch ($Arch) { 'x64' { 'amd64' } 'arm64' { 'arm64' } default { $hostArch } }
$src = Resolve-Path (Join-Path $PSScriptRoot '..\..\client\Weldap.CredentialProvider')
$out = Join-Path $PSScriptRoot $(if ($Arch -eq 'native') { 'out' } else { "out-$Arch" })
New-Item -ItemType Directory -Force -Path $out | Out-Null
# /analyze: MSVC code analysis over the harness and the provider sources it links; with /WX its warnings fail the build.
$cl = "cl /nologo /std:c++17 /W4 /WX /sdl /analyze /EHsc /MT /O2 /guard:cf /DUNICODE /D_UNICODE /Fo`"$out\\`" /Fe`"$out\WeldapClientTest.exe`" " +
      "`"$PSScriptRoot\WeldapClientTest.cpp`" `"$src\WeldapClient.cpp`" `"$src\WeldapSeal.cpp`" advapi32.lib bcrypt.lib crypt32.lib /link /guard:cf"
# (Via a temporary .cmd file: Windows PowerShell 5.1 mangles quotes passed to cmd.exe /c.)
$cmdFile = Join-Path $env:TEMP "ppecp-test-build-$PID.cmd"
Set-Content -LiteralPath $cmdFile -Encoding ASCII -Value @(
    '@echo off'
    "call `"$devCmd`" -no_logo -arch=$target -host_arch=$hostArch || exit /b 1"
    $cl
)
& cmd.exe /d /c $cmdFile
$code = $LASTEXITCODE
Remove-Item -LiteralPath $cmdFile -ErrorAction SilentlyContinue
if ($code -ne 0) { throw "cl failed ($code)" }
"built $out\WeldapClientTest.exe"
