using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32;
using static Weldap.Service.Native;

namespace Weldap.Service;

/// <summary>HKLM\SOFTWARE\WELDAP. SR-10: refuses to load if anyone but SYSTEM/Administrators can change it.</summary>
internal static unsafe class RegistrySettings
{
    public const string KeyPath = @"SOFTWARE\WELDAP";
    /// <summary>
    /// Per-account secrets (local passwords, offline verifiers) live in this subkey, readable by SYSTEM only.
    /// A machine-scope DPAPI blob can be decrypted by any process on the machine, so the ACL is what protects it.
    /// </summary>
    public const string SecretKeyPath = KeyPath + @"\Secret";

    private static readonly HashSet<SecurityIdentifier> Trusted =
    [
        new(WellKnownSidType.LocalSystemSid, null),
        new(WellKnownSidType.BuiltinAdministratorsSid, null),
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"), // TrustedInstaller
    ];

    private const RegistryRights WriteRights = RegistryRights.SetValue | RegistryRights.CreateSubKey
        | RegistryRights.Delete | RegistryRights.ChangePermissions | RegistryRights.TakeOwnership
        | RegistryRights.CreateLink;

    public static LoginSettings Load()
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = hklm.OpenSubKey(KeyPath) ?? throw new InvalidOperationException($@"HKLM\{KeyPath} missing");
        CheckAcl(key);

        string Str(string name) => key.GetValue(name) as string is { Length: > 0 } s
            ? s : throw new InvalidOperationException($"{name} not set");
        int Dword(string name, int fallback) => key.GetValue(name) is int i ? i : fallback;
        var settings = new LoginSettings
        {
            ServerHost = Str("ServerHost"),
            ServerPort = Dword("ServerPort", 636),
            ServerPins = SettingsText.SplitList(key.GetValue("ServerPins")),
            ExcludedAccounts = SettingsText.SplitList(key.GetValue("ExcludedAccounts")).Select(s => s.ToLowerInvariant()).ToArray(),
            MaxOfflineDays = Math.Clamp(Dword("MaxOfflineDays", 180), 0, 3650),
            OfflineMaxFailures = Math.Clamp(Dword("OfflineMaxFailures", 10), 1, 100),
        };
        return SettingsText.Validate(settings);
    }

    private static void CheckAcl(RegistryKey key)
    {
        var security = key.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !Trusted.Contains(owner))
            throw new InvalidOperationException($@"HKLM\{KeyPath} owner is not SYSTEM/Administrators");
        foreach (RegistryAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow) continue;
            if (rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly)) continue; // doesn't apply to this key
            if ((rule.RegistryRights & WriteRights) == 0) continue;
            if (rule.IdentityReference is SecurityIdentifier sid && Trusted.Contains(sid)) continue;
            throw new InvalidOperationException($@"HKLM\{KeyPath} is writable by {rule.IdentityReference}; refusing to run (SR-10)");
        }
    }

    private const RegistryRights ReadRights = RegistryRights.QueryValues | RegistryRights.ReadPermissions
        | RegistryRights.ChangePermissions | RegistryRights.TakeOwnership | RegistryRights.SetValue;

    /// <summary>Null when only SYSTEM (or TrustedInstaller) can read or change the secret key, else why not.</summary>
    public static string? SecretKeyProblem()
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = hklm.OpenSubKey(SecretKeyPath);
        if (key is null) return null;
        var security = key.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !Trusted.Contains(owner))
            return $@"HKLM\{SecretKeyPath} owner is not SYSTEM/Administrators";
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        foreach (RegistryAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow) continue;
            if (rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly)) continue;
            if ((rule.RegistryRights & ReadRights) == 0) continue;
            if (rule.IdentityReference is SecurityIdentifier sid
                && (sid == system || sid.Value == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")) continue;
            return $@"HKLM\{SecretKeyPath} is readable by {rule.IdentityReference}; refusing to use it (SR-9)";
        }
        return null;
    }
}
