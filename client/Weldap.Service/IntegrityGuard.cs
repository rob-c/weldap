using System.Security.Cryptography;
using Microsoft.Win32;

namespace Weldap.Service;

/// <summary>
/// Anti-tamper (SR, defence in depth): before the service serves a single sign-in, it checks that the WELDAP
/// binaries on disk are the exact ones we shipped. The credential-provider DLL Windows will actually load — the
/// one registered under the WELDAP CLSID's <c>InprocServer32</c> — plus the service's own exe and the admin CLI
/// must each sit in the install folder and match the SHA-256 pinned at build time
/// (<c>HKLM\SOFTWARE\WELDAP\{ProviderHash,ServiceHash,AdminHash}</c>, written by the MSI over the signed
/// binaries, SYSTEM-only like the rest of the config). A swapped or patched binary — or a CLSID quietly
/// repointed at an attacker's DLL elsewhere — fails the check and the service refuses to start, so nothing
/// tampered ever gets to seal a password. Each pin left unset (a dev install) is skipped with a note.
/// </summary>
internal static class IntegrityGuard
{
    // Keep in sync with client/Weldap.CredentialProvider/guid.h and the installer.
    private const string ProviderClsid = "{E239AAAB-FFFD-4525-A894-1B9D6314B1CB}";

    /// <summary>Throws <see cref="InvalidOperationException"/> if any pinned binary is present but is not the
    /// shipped build. Returns a status line (one clause per binary) for the log.</summary>
    public static string Verify() => string.Join("; ",
        VerifyProvider(),
        VerifyInstallBinary("service", "WeldapService.exe", "ServiceHash", required: true),
        VerifyInstallBinary("admin CLI", "weldapadm.exe", "AdminHash", required: false));

    private static string VerifyProvider()
    {
        if (ReadPin("ProviderHash") is not { } pinned)
            return "provider integrity: not pinned (ProviderHash unset); skipping";

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
        if (!HashMatches(registered, pinned))
            throw new InvalidOperationException("the registered credential provider does not match the pinned hash (tampered or wrong build)");

        return "provider integrity: registered DLL matches the pinned hash";
    }

    /// <summary>Verifies a binary that ships in the install folder against its pin.</summary>
    private static string VerifyInstallBinary(string label, string fileName, string pinName, bool required)
    {
        if (ReadPin(pinName) is not { } pinned)
            return $"{label} integrity: not pinned ({pinName} unset); skipping";

        var path = Path.Combine(AppContext.BaseDirectory, fileName);
        if (!File.Exists(path))
            return required
                ? throw new InvalidOperationException($"the {label} binary is missing ({path})")
                : $"{label} integrity: not installed; skipping";
        if (!HashMatches(path, pinned))
            throw new InvalidOperationException($"the {label} binary does not match the pinned hash (tampered or wrong build)");

        return $"{label} integrity: matches the pinned hash";
    }

    /// <summary>The pinned SHA-256, or null when the pin is unset or the all-zeros "not pinned" sentinel.</summary>
    private static byte[]? ReadPin(string pinName)
    {
        var hex = (Registry.GetValue($@"HKEY_LOCAL_MACHINE\{RegistrySettings.KeyPath}", pinName, null) as string)?.Trim();
        if (string.IsNullOrEmpty(hex) || hex.All(c => c == '0')) return null;
        if (!IsSha256Hex(hex)) throw new InvalidOperationException($"{pinName} is not a SHA-256 hex string");
        return Convert.FromHexString(hex);
    }

    private static bool HashMatches(string path, byte[] pinned)
    {
        using var stream = File.OpenRead(path);
        return CryptographicOperations.FixedTimeEquals(SHA256.HashData(stream), pinned);
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
