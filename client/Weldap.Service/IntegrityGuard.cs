using System.Security.Cryptography;
using Microsoft.Win32;

namespace Weldap.Service;

/// <summary>
/// Anti-tamper (SR, defence in depth): before the service serves a single sign-in, it checks that the
/// credential-provider DLL Windows will actually load — the one registered under the WELDAP CLSID's
/// <c>InprocServer32</c> — is the exact binary we shipped. It must sit next to the service (the install
/// folder) and its SHA-256 must equal the hash pinned at build time (<c>HKLM\SOFTWARE\WELDAP\ProviderHash</c>,
/// written by the MSI, SYSTEM-only like the rest of the config). A swapped DLL, or a CLSID quietly repointed at
/// an attacker's DLL elsewhere, fails the check and the service refuses to start — so nothing tampered ever
/// gets to seal a password. With no pin configured (a dev install) the check is skipped with a note.
/// </summary>
internal static class IntegrityGuard
{
    // Keep in sync with client/Weldap.CredentialProvider/guid.h and the installer.
    private const string ProviderClsid = "{E239AAAB-FFFD-4525-A894-1B9D6314B1CB}";

    /// <summary>Throws <see cref="InvalidOperationException"/> if a provider is registered but is not the
    /// pinned binary in the install folder. Returns a one-line status for the log.</summary>
    public static string Verify()
    {
        var pinnedHex = (Registry.GetValue($@"HKEY_LOCAL_MACHINE\{RegistrySettings.KeyPath}", "ProviderHash", null) as string)?.Trim();
        // Empty, or the all-zeros sentinel the MSI leaves when no hash was supplied, means "not pinned".
        if (string.IsNullOrEmpty(pinnedHex) || pinnedHex.All(c => c == '0'))
            return "provider integrity: not pinned (ProviderHash unset); skipping";
        if (!IsSha256Hex(pinnedHex))
            throw new InvalidOperationException("ProviderHash is not a SHA-256 hex string");

        var registered = RegisteredProviderPath();
        if (registered is null)
            return "provider integrity: no provider registered; nothing to load, skipping";

        // The registered DLL must live in the service's own install folder, so the pin cannot be dodged by
        // repointing the CLSID at a same-named DLL somewhere else.
        var installDir = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var dir = Path.GetDirectoryName(Path.GetFullPath(registered))?.TrimEnd(Path.DirectorySeparatorChar);
        if (!string.Equals(dir, installDir, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"the registered credential provider is outside the install folder ({registered})");
        if (!File.Exists(registered))
            throw new InvalidOperationException($"the registered credential provider is missing ({registered})");

        byte[] actual;
        using (var stream = File.OpenRead(registered))
            actual = SHA256.HashData(stream);
        var pinned = Convert.FromHexString(pinnedHex);
        if (!CryptographicOperations.FixedTimeEquals(actual, pinned))
            throw new InvalidOperationException("the registered credential provider does not match the pinned hash (tampered or wrong build)");

        return "provider integrity: registered DLL matches the pinned hash";
    }

    /// <summary>The <c>InprocServer32</c> path registered for the WELDAP provider CLSID, or null if none.</summary>
    private static string? RegisteredProviderPath()
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = hklm.OpenSubKey($@"SOFTWARE\Classes\CLSID\{ProviderClsid}\InprocServer32");
        return key?.GetValue(null) as string is { Length: > 0 } path ? Environment.ExpandEnvironmentVariables(path) : null;
    }

    private static bool IsSha256Hex(string s) => s.Length == 64 && s.All(Uri.IsHexDigit);
}
