# TEST ONLY. Reads every committed, readable region of a process's memory in place (VirtualQueryEx +
# ReadProcessMemory: no dump file is ever written) and searches it for secrets (UTF-8 and UTF-16LE), as SYSTEM:
#   memscan.ps1 -ProcessName WeldapService -SecretsFile <file> [-Control <string that must be found>]
# Prints "scanned <bytes>, <hits> hits, control <found|missing>" and "HIT secret#<n> <encoding>" lines; the
# secrets themselves are never printed. "unreadable: ..." if the process cannot be opened (e.g. LSA protection).
param([Parameter(Mandatory)] [string]$ProcessName, [Parameter(Mandatory)] [string]$SecretsFile, [string]$Control)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class WeldapMemScan {
    [StructLayout(LayoutKind.Sequential)]
    struct MBI { public IntPtr BaseAddress, AllocationBase; public uint AllocationProtect; public IntPtr RegionSize; public uint State, Protect, Type; }
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, IntPtr size);
    [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
    const uint MEM_COMMIT = 0x1000, PAGE_NOACCESS = 0x01, PAGE_GUARD = 0x100;

    // Returns [scannedBytes, hit flags per needle...] or throws if the process cannot be opened.
    public static long[] Scan(int pid, List<byte[]> needles) {
        IntPtr h = OpenProcess(0x0410 /* QUERY_INFORMATION | VM_READ */, false, pid);
        if (h == IntPtr.Zero) throw new Exception("OpenProcess failed: " + Marshal.GetLastWin32Error());
        var result = new long[needles.Count + 1];
        var latin1 = Encoding.GetEncoding(28591);
        var hay = new List<string>();
        foreach (var n in needles) hay.Add(latin1.GetString(n));
        try {
            IntPtr addr = IntPtr.Zero; MBI m;
            while (VirtualQueryEx(h, addr, out m, (IntPtr)Marshal.SizeOf(typeof(MBI))) != IntPtr.Zero) {
                long size = m.RegionSize.ToInt64();
                if (m.State == MEM_COMMIT && (m.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0 && size < (1L << 31)) {
                    var buf = new byte[size]; IntPtr read;
                    if (ReadProcessMemory(h, m.BaseAddress, buf, (IntPtr)size, out read) && read.ToInt64() > 0) {
                        result[0] += read.ToInt64();
                        string s = latin1.GetString(buf, 0, (int)read.ToInt64());   // 1 byte = 1 char
                        for (int i = 0; i < hay.Count; i++)
                            if (result[i + 1] == 0 && s.IndexOf(hay[i], StringComparison.Ordinal) >= 0) result[i + 1] = 1;
                    }
                    Array.Clear(buf, 0, buf.Length);
                }
                long next = m.BaseAddress.ToInt64() + size;
                if (next <= addr.ToInt64()) break;
                addr = (IntPtr)next;
            }
        } finally { CloseHandle(h); }
        return result;
    }
}
'@
$proc = Get-Process -Name $ProcessName | Select-Object -First 1
$labels = @(); $needles = New-Object 'System.Collections.Generic.List[byte[]]'
$i = 0
foreach ($secret in Get-Content $SecretsFile) {
    if (-not $secret) { continue }
    $needles.Add([Text.Encoding]::UTF8.GetBytes($secret)); $labels += "secret#$i utf8"
    $needles.Add([Text.Encoding]::Unicode.GetBytes($secret)); $labels += "secret#$i utf16"
    $i++
}
$controlAt = -1
if ($Control) {
    $controlAt = $needles.Count
    $needles.Add([Text.Encoding]::UTF8.GetBytes($Control)); $needles.Add([Text.Encoding]::Unicode.GetBytes($Control))
}
try {
    $r = [WeldapMemScan]::Scan($proc.Id, $needles)
} catch {
    "unreadable: $($_.Exception.InnerException.Message)$($_.Exception.Message)"
    return
}
$hits = 0
for ($k = 0; $k -lt $labels.Count; $k++) { if ($r[$k + 1]) { "HIT $($labels[$k])"; $hits++ } }
$controlState = if ($controlAt -lt 0) { 'n/a' } elseif ($r[$controlAt + 1] -or $r[$controlAt + 2]) { 'found' } else { 'missing' }
"scanned $($r[0]), $hits hits, control $controlState"
