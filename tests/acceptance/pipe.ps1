# TEST ONLY. Attacks the WELDAP service's pipe from inside the VM (as SYSTEM unless run otherwise):
#   pipe.ps1 frames  -Kind <v2json|random|truncated|oversize|zero> [-Count N] [-Seed S]
#                    -> "sent=N replies=R refused=F"  (the service must answer none of these)
#   pipe.ps1 remote  -> "refused" | "connected"        (\\127.0.0.1\pipe\weldap: through the network redirector)
#   pipe.ps1 open    -> "refused" | "connected"        (local open; run as a non-SYSTEM account to test the DACL)
#   pipe.ps1 sddl    -> the pipe's security descriptor (owner + DACL)
param([Parameter(Mandatory)] [ValidateSet('frames', 'remote', 'open', 'sddl')] [string]$Mode,
      [ValidateSet('v2json', 'random', 'truncated', 'oversize', 'zero')] [string]$Kind = 'random',
      [int]$Count = 1, [int]$Seed = 1)
$ErrorActionPreference = 'Stop'

function Connect([string]$Server) {
    $c = New-Object System.IO.Pipes.NamedPipeClientStream($Server, 'weldap', [System.IO.Pipes.PipeDirection]::InOut)
    try { $c.Connect(5000); return $c } catch { $c.Dispose(); return $null }
}

function Frame([byte[]]$Body, [int]$Declared = -1) {
    if ($Declared -lt 0) { $Declared = $Body.Length }
    [byte[]]([BitConverter]::GetBytes([int]$Declared) + $Body)
}

switch ($Mode) {
    'frames' {
        $rng = New-Object Random $Seed
        $replies = 0; $refused = 0
        for ($i = 0; $i -lt $Count; $i++) {
            $frame = switch ($Kind) {
                'v2json' {   # the previous protocol's request: must be dropped, never parsed as v3
                    Frame ([Text.Encoding]::UTF8.GetBytes('{"v":2,"scenario":"logon","uun":"alice","kid":"k1","enc":"AAAA","ct":"AAAA","ts":1793320000,"rid":"AAAAAAAAAAAAAAAAAAAAAA==","verifier":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}'))
                }
                'random' {   # random bodies; half start like a v3 request (version 3, scenario 0/1)
                    $b = New-Object byte[] ($rng.Next(1, 1500)); $rng.NextBytes($b)
                    if ($i % 2 -eq 0) { $b[0] = 3; if ($b.Length -gt 1) { $b[1] = [byte]($i % 4 -eq 0) } }
                    Frame $b
                }
                'truncated' {   # a plausible v3 header that ends early
                    $n = $rng.Next(1, 60); $b = New-Object byte[] $n; $rng.NextBytes($b); $b[0] = 3
                    if ($n -gt 1) { $b[1] = 0 }; if ($n -gt 2) { $b[2] = 5 }
                    Frame $b
                }
                'oversize' { Frame ([byte[]](3, 0)) 0x7FFFFFFF }   # length prefix far over 4096
                'zero' { Frame ([byte[]]@()) }
            }
            $c = Connect '.'
            if (-not $c) { $refused++; continue }
            try {
                $c.Write($frame, 0, $frame.Length); $c.Flush()
                $buf = New-Object byte[] 8
                $t = $c.ReadAsync($buf, 0, 8)
                if ($t.Wait(3000) -and $t.Result -gt 0) { $replies++ }
            } catch { } finally { $c.Dispose() }
        }
        "sent=$Count replies=$replies refused=$refused"
    }
    'remote' { $c = Connect '127.0.0.1'; if ($c) { $c.Dispose(); 'connected' } else { 'refused' } }
    'open' { $c = Connect '.'; if ($c) { $c.Dispose(); 'connected' } else { 'refused' } }
    'sddl' {
        Add-Type -Namespace W -Name P -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
[DllImport("advapi32.dll")]
public static extern uint GetSecurityInfo(Microsoft.Win32.SafeHandles.SafeFileHandle h, int type, uint info, IntPtr o, IntPtr g, IntPtr d, IntPtr s, out IntPtr sd);
[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr sd, uint rev, uint info, out IntPtr str, IntPtr len);
'@
        $h = [W.P]::CreateFile('\\.\pipe\weldap', 0x20000 <# READ_CONTROL #>, 0, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
        if ($h.IsInvalid) { "unopenable: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"; return }
        $sd = [IntPtr]::Zero; $str = [IntPtr]::Zero
        $rc = [W.P]::GetSecurityInfo($h, 6 <# SE_KERNEL_OBJECT #>, 5 <# OWNER|DACL #>, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$sd)
        $h.Dispose()
        if ($rc -ne 0) { "GetSecurityInfo: $rc"; return }
        [void][W.P]::ConvertSecurityDescriptorToStringSecurityDescriptor($sd, 1, 5, [ref]$str, [IntPtr]::Zero)
        [Runtime.InteropServices.Marshal]::PtrToStringUni($str)
    }
}
