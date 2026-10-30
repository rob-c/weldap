# Fleet: Windows account lockout policy that bounds offline password guessing (SR-13).
# Offline, Windows checks the password against the local account, so this policy is the limit:
# 10 bad attempts, then locked for 10 minutes; the counter resets after 10 minutes.
param([int]$Threshold = 10, [int]$DurationMinutes = 10, [int]$WindowMinutes = 10)
$ErrorActionPreference = 'Stop'
net accounts /lockoutthreshold:$Threshold /lockoutduration:$DurationMinutes /lockoutwindow:$WindowMinutes | Out-Null
if ($LASTEXITCODE -ne 0) { throw "net accounts failed ($LASTEXITCODE)" }
net accounts | Select-String -Pattern 'Lockout'
