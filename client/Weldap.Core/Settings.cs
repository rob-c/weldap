using System.Text.RegularExpressions;

namespace Weldap;

/// <summary>
/// Settings from HKLM\SOFTWARE\WELDAP (see the Configuration table in the requirements). The device knows only
/// how to reach the WELDAP server and how to recognise it; nothing about what sits behind it.
/// </summary>
public sealed record LoginSettings
{
    /// <summary>The WELDAP server (address; also sent as the TLS server name).</summary>
    public required string ServerHost { get; init; }
    public int ServerPort { get; init; } = 636;
    /// <summary>SHA-256 of the server certificate's SubjectPublicKeyInfo, base64. The only server trust: no CA.</summary>
    public required IReadOnlyList<string> ServerPins { get; init; }
    public IReadOnlyList<string> ExcludedAccounts { get; init; } = [];
    public int MaxOfflineDays { get; init; } = 180;
    /// <summary>Consecutive wrong offline passwords before offline sign-in stops until the next online one.</summary>
    public int OfflineMaxFailures { get; init; } = 10;
    /// <summary>Take over a pre-existing local account that shares an LDAP user's name (after the user consents).</summary>
    public bool AdoptPreexisting { get; init; } = true;
    /// <summary>Arm the lockdown: actually disable accounts unknown to LDAP. Off = report only (dry run).</summary>
    public bool LockdownEnforce { get; init; }
    /// <summary>Disable a managed account with no interactive logon for this many days; 0 = never.</summary>
    public int IdleDisableDays { get; init; } = 30;

    public const string ManagedGroup = "WELDAP-Managed";
    /// <summary>Protected backup accounts that WELDAP never adopts, disables or idle-reaps (always work locally).</summary>
    public const string ForceLocalGroup = "WELDAP-ForceLocal";
    /// <summary>Friendly name of this device's registered certificate in LocalMachine\My (SR-14), set by
    /// register-device.ps1; the newest currently valid one with its private key is used.</summary>
    public const string DeviceCertificateName = "WELDAP device";
    /// <summary>
    /// Time budget, outermost first: the credential provider gives up after 15 s (WELDAP_CLIENT_DEADLINE_MS, from
    /// before it opens the pipe); the service serves one pipe client within 14 s (PipeServer); one round trip to
    /// the WELDAP server -- connect, TLS handshake, request and reply -- is cut off after
    /// <see cref="ServerBudgetSeconds"/>, leaving the rest for the local account work. So the service always
    /// answers before the tile gives up, and a slow server becomes the offline path, not "service unavailable".
    /// </summary>
    public const int ServerBudgetSeconds = 9;
    /// <summary>The TCP connect to one of the server's addresses, within <see cref="ServerBudgetSeconds"/>.</summary>
    public const int ConnectTimeoutSeconds = 3;
    public const int CleanupIntervalMinutes = 60;

    /// <summary>Built-in names the WELDAP tile always refuses, whatever ExcludedAccounts says.</summary>
    public static readonly IReadOnlyList<string> BuiltInExcluded =
        ["administrator", "guest", "defaultaccount", "wdagutilityaccount"];

    public bool IsExcluded(string uun) =>
        BuiltInExcluded.Contains(uun, StringComparer.OrdinalIgnoreCase)
        || ExcludedAccounts.Contains(uun, StringComparer.OrdinalIgnoreCase);
}

public static partial class Uun
{
    [GeneratedRegex(@"^[a-z0-9]{1,20}\z", RegexOptions.CultureInvariant)] // \z, not $: $ also matches before a final \n
    private static partial Regex Pattern();

    /// <summary>SR-3: the only UUNs ever used anywhere (account name, events, the wire).</summary>
    public static bool IsValid(string? uun) => uun is not null && Pattern().IsMatch(uun);
}

/// <summary>Registry value parsing and checks, separate from the registry so they are unit-tested.</summary>
public static class SettingsText
{
    /// <summary>
    /// A REG_MULTI_SZ or REG_SZ list. Entries may also be separated by ',' ';' or a literal "[~]" (msiexec
    /// writes a property holding "a[~]b" as one string, not as two values). Empty entries are dropped.
    /// </summary>
    public static string[] SplitList(object? value) => (value switch
    {
        string[] values => values,
        string one => [one],
        _ => [],
    })
        .SelectMany(v => v.Split([",", ";", "[~]"], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        .ToArray();

    /// <summary>
    /// A pin is base64 of a SHA-256 digest: 44 characters that decode to 32 bytes, in canonical form (pins are
    /// compared as strings, so one with stray bits before the padding could never match).
    /// </summary>
    public static bool IsPin(string pin)
    {
        Span<byte> digest = stackalloc byte[33];
        return pin.Length == 44 && Convert.TryFromBase64String(pin, digest, out var n) && n == 32
            && Convert.ToBase64String(digest[..32]) == pin;
    }

    /// <summary>
    /// The server's public password key as the credential provider uses it: base64 of an uncompressed P-256 point
    /// (65 bytes, 0x04 first). Checked by the service at start so a bad MSI value fails loudly there, not at the tile.
    /// </summary>
    public static bool IsServerKey(string key)
    {
        Span<byte> point = stackalloc byte[66];
        return key.Length == 88 && Convert.TryFromBase64String(key, point, out var n) && n == Protocol.EncBytes && point[0] == 0x04;
    }

    /// <summary>A key id as the pipe protocol carries it: 1..32 of [a-z0-9-].</summary>
    public static bool IsKeyId(string kid) =>
        kid.Length is >= 1 and <= Protocol.MaxKidChars && kid.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-');

    /// <summary>
    /// Throws InvalidOperationException (the service then refuses to start) on anything unusable, and returns the
    /// settings with the day and failure counts clamped to their documented ranges (MaxOfflineDays and
    /// IdleDisableDays 0..3650, OfflineMaxFailures 1..100), so no later date arithmetic can overflow.
    /// </summary>
    public static LoginSettings Validate(LoginSettings s)
    {
        if (s.ServerPort is < 1 or > 65535) throw new InvalidOperationException("ServerPort out of range");
        if (s.ServerHost.Length is 0 or > 253 || s.ServerHost.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or ':')))
            throw new InvalidOperationException("ServerHost is not a host name or address");
        if (s.ServerPins.Count == 0) throw new InvalidOperationException("ServerPins not set");
        if (!s.ServerPins.All(IsPin)) throw new InvalidOperationException("ServerPins: not base64 SHA-256 digests");
        return s with
        {
            MaxOfflineDays = Math.Clamp(s.MaxOfflineDays, 0, 3650),
            IdleDisableDays = Math.Clamp(s.IdleDisableDays, 0, 3650),
            OfflineMaxFailures = Math.Clamp(s.OfflineMaxFailures, 1, 100),
        };
    }
}
