# Fleet: Windows account lockout policy for the local accounts (SR-13), as defence in depth. WELDAP itself
# bounds offline guessing (the service checks the offline verifier and stops after OfflineMaxFailures); this
# policy limits guessing against any local password typed at the standard Windows tile: 10 bad attempts, then
# locked for 10 minutes; the counter resets after 10 minutes.
param([int]$Threshold = 10, [int]$DurationMinutes = 10, [int]$WindowMinutes = 10)
$ErrorActionPreference = 'Stop'
net accounts /lockoutthreshold:$Threshold /lockoutduration:$DurationMinutes /lockoutwindow:$WindowMinutes | Out-Null
if ($LASTEXITCODE -ne 0) { throw "net accounts failed ($LASTEXITCODE)" }
net accounts | Select-String -Pattern 'Lockout'
