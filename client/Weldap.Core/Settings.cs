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

    public const string ManagedGroup = "WELDAP-Managed";
    /// <summary>Friendly name of this device's registered certificate in LocalMachine\My (SR-14), set by
    /// register-device.ps1; the newest currently valid one with its private key is used.</summary>
    public const string DeviceCertificateName = "WELDAP device";
    public const int ConnectTimeoutSeconds = 3;
    public const int TimeoutSeconds = 10;
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

    /// <summary>Throws InvalidOperationException (the service then refuses to start) on anything unusable.</summary>
    public static LoginSettings Validate(LoginSettings s)
    {
        if (s.ServerPort is < 1 or > 65535) throw new InvalidOperationException("ServerPort out of range");
        if (s.ServerHost.Length is 0 or > 253 || s.ServerHost.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or ':')))
            throw new InvalidOperationException("ServerHost is not a host name or address");
        if (s.ServerPins.Count == 0) throw new InvalidOperationException("ServerPins not set");
        if (!s.ServerPins.All(IsPin)) throw new InvalidOperationException("ServerPins: not base64 SHA-256 digests");
        return s;
    }
}
