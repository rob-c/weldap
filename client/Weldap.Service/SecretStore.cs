using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using Microsoft.Win32;
using static Weldap.Service.Native;

namespace Weldap.Service;

/// <summary>
/// HKLM\SOFTWARE\WELDAP\Secret\Accounts\&lt;uun&gt;: LocalPassword and Verifier (machine-scope DPAPI blobs) and
/// OfflineFailures. The Secret key has a protected DACL granting SYSTEM only; the service refuses to start if
/// anyone else can read it. Plaintext only ever sits in pinned buffers that are zeroed after use.
/// </summary>
internal sealed unsafe class RegistrySecretStore : ISecretStore
{
    private const string AccountsPath = RegistrySettings.SecretKeyPath + @"\Accounts";
    private const string SystemOnly = "O:SYG:SYD:P(A;CI;KA;;;SY)";

    /// <summary>Creates the Secret key (SYSTEM only) if missing, then insists nobody else can read it.</summary>
    public static void EnsureKey()
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        if (hklm.OpenSubKey(RegistrySettings.SecretKeyPath) is { } existing)
        {
            existing.Dispose();
        }
        else
        {
            var security = new RegistrySecurity();
            security.SetSecurityDescriptorSddlForm(SystemOnly);
            using var created = hklm.CreateSubKey(RegistrySettings.SecretKeyPath, RegistryKeyPermissionCheck.ReadWriteSubTree, security);
        }
        if (RegistrySettings.SecretKeyProblem() is { } problem) throw new InvalidOperationException(problem);
    }

    private static RegistryKey? Account(string uun, bool create)
    {
        if (!Uun.IsValid(uun)) throw new LocalAccountException("invalid account name for the secret store");
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        try
        {
            if (create)
            {
                // Never let CreateSubKey make a missing Secret key itself: it would inherit the config key's ACL,
                // which Users can read. (Deleted while running, say.) Re-create it SYSTEM-only, and check it, first.
                using (var secret = hklm.OpenSubKey(RegistrySettings.SecretKeyPath))
                {
                    if (secret is null) EnsureKey();
                }
                return hklm.CreateSubKey($@"{AccountsPath}\{uun}", writable: true);
            }
            return hklm.OpenSubKey($@"{AccountsPath}\{uun}", writable: true);
        }
        catch (InvalidOperationException ex)
        {
            throw new LocalAccountException($"secret store: {ex.Message}");
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            throw new LocalAccountException($"secret store: {ex.GetType().Name}");
        }
    }

    public char[]? GetLocalPassword(string uun)
    {
        using var key = Account(uun, create: false);
        if (key?.GetValue("LocalPassword") is not byte[] blob) return null;
        var plain = Unprotect(blob);
        if (plain is null) return null;
        try
        {
            var chars = MemoryMarshal.Cast<byte, char>(plain.AsSpan());
            var buffer = GC.AllocateArray<char>(chars.Length, pinned: true);
            chars.CopyTo(buffer);
            return buffer;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    public void SetLocalPassword(string uun, ReadOnlySpan<char> password)
    {
        var blob = Protect(MemoryMarshal.AsBytes(password));
        Store(uun, key => key.SetValue("LocalPassword", blob, RegistryValueKind.Binary));
    }

    public byte[]? GetVerifier(string uun)
    {
        using var key = Account(uun, create: false);
        return key?.GetValue("Verifier") is byte[] blob ? Unprotect(blob) : null;
    }

    public void SetVerifier(string uun, ReadOnlySpan<byte> verifier)
    {
        var blob = Protect(verifier);
        Store(uun, key => key.SetValue("Verifier", blob, RegistryValueKind.Binary));
    }

    public void ClearVerifier(string uun)
    {
        using var key = Account(uun, create: false);
        if (key is null) return;
        Guard(() => key.DeleteValue("Verifier", throwOnMissingValue: false));
    }

    public int GetOfflineFailures(string uun)
    {
        using var key = Account(uun, create: false);
        return key?.GetValue("OfflineFailures") is int n ? n : 0;
    }

    public void SetOfflineFailures(string uun, int count) =>
        Store(uun, key => key.SetValue("OfflineFailures", count, RegistryValueKind.DWord));

    private static void Store(string uun, Action<RegistryKey> write)
    {
        using var key = Account(uun, create: true)!;
        Guard(() => write(key));
    }

    // Registry faults surface as LocalAccountException, which the login and reconcile paths handle per account
    // (anything else would abort a whole reconcile pass, or turn a sign-in into a generic error).
    private static void Guard(Action op)
    {
        try
        {
            op();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            throw new LocalAccountException($"secret store: {ex.GetType().Name}");
        }
    }

    private static byte[] Protect(ReadOnlySpan<byte> plain)
    {
        fixed (byte* input = plain)
        {
            var inBlob = new DATA_BLOB { cbData = (uint)plain.Length, pbData = input };
            DATA_BLOB outBlob = default;
            if (!CryptProtectData(&inBlob, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                    CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, &outBlob))
                throw new LocalAccountException("secret store: DPAPI protect failed", Marshal.GetLastPInvokeError());
            try
            {
                return new ReadOnlySpan<byte>(outBlob.pbData, (int)outBlob.cbData).ToArray(); // ciphertext
            }
            finally
            {
                LocalFree((IntPtr)outBlob.pbData);
            }
        }
    }

    /// <summary>A pinned plaintext buffer the caller zeroes, or null if the blob does not decrypt.</summary>
    private static byte[]? Unprotect(byte[] blob)
    {
        fixed (byte* input = blob)
        {
            var inBlob = new DATA_BLOB { cbData = (uint)blob.Length, pbData = input };
            DATA_BLOB outBlob = default;
            if (!CryptUnprotectData(&inBlob, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN, &outBlob))
                return null;
            try
            {
                var plain = GC.AllocateArray<byte>((int)outBlob.cbData, pinned: true);
                new ReadOnlySpan<byte>(outBlob.pbData, (int)outBlob.cbData).CopyTo(plain);
                return plain;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(new Span<byte>(outBlob.pbData, (int)outBlob.cbData));
                LocalFree((IntPtr)outBlob.pbData);
            }
        }
    }
}
