namespace Weldap;

public enum ServerOutcome
{
    /// <summary>The WELDAP server accepted the password; the flags say what the user may do.</summary>
    Success,
    /// <summary>Wrong password or no such user.</summary>
    InvalidCredentials,
    /// <summary>The server refused for now (its own lockout or rate limit).</summary>
    Throttled,
    /// <summary>No answer: server unreachable, TLS refused (unregistered/revoked device), timed out, or the
    /// server's own back end unavailable. Leads to the offline path.</summary>
    NoAnswer,
    /// <summary>Any other definite failure. Deny.</summary>
    Error,
}

/// <summary>All a client ever learns about a user: two flags.</summary>
public sealed record UserFlags(bool IsUser, bool IsAdmin);

/// <summary>
/// The password as it leaves LogonUI: HPKE-sealed to the server's key (only the server can open it), bound
/// to the key id, user, scenario, timestamp and request id. Not a secret to this process: it cannot read it.
/// </summary>
public sealed record SealedPassword(string Kid, byte[] Enc, byte[] Ct, long Ts, byte[] Rid);

public sealed record ServerAnswer(ServerOutcome Outcome, UserFlags? User = null, string? Detail = null)
{
    public static ServerAnswer NoAnswer(string detail) => new(ServerOutcome.NoAnswer, null, detail);
    public static ServerAnswer Failed(string detail) => new(ServerOutcome.Error, null, detail);
}

/// <summary>Which of the UUNs asked about are users and admins (FR-12).</summary>
public sealed record StatusSnapshot(IReadOnlySet<string> Users, IReadOnlySet<string> Admins);

/// <summary>The WELDAP server: this device's only network peer.</summary>
public interface IWeldapServer
{
    /// <summary>Hands the sealed password to the server, which alone can open and check it.</summary>
    ServerAnswer Authenticate(string uun, Scenario scenario, SealedPassword sealedPassword);

    /// <summary>Flags for the given UUNs (the accounts this device manages), or null if there was no answer.</summary>
    StatusSnapshot? ReadStatus(IReadOnlyCollection<string> uuns);
}

/// <summary>
/// Per-account secrets on this device, readable by SYSTEM only. The local account's password is random and
/// never the user's: LSASS only ever sees it, so the user's password is not cached in Windows. The offline
/// verifier is PBKDF2 of the user's password, computed in the credential provider.
/// Implementations throw <see cref="LocalAccountException"/>; returned buffers are pinned, caller zeroes them.
/// </summary>
public interface ISecretStore
{
    char[]? GetLocalPassword(string uun);
    void SetLocalPassword(string uun, ReadOnlySpan<char> password);
    byte[]? GetVerifier(string uun);
    void SetVerifier(string uun, ReadOnlySpan<byte> verifier);
    void ClearVerifier(string uun);
    int GetOfflineFailures(string uun);
    void SetOfflineFailures(string uun, int count);
}

public sealed record LocalAccount(string Name, bool IsManaged, bool Enabled, bool IsAdmin, DateTimeOffset? Expires);

public sealed class LocalAccountException(string message, int errorCode = 0) : Exception(message)
{
    public int ErrorCode { get; } = errorCode;
}

/// <summary>Local SAM operations. Implementations throw <see cref="LocalAccountException"/>.</summary>
public interface ILocalAccounts
{
    LocalAccount? Find(string name);
    IReadOnlyList<LocalAccount> ListManaged();
    /// <summary>Creates the account (password never expires, user cannot change it) in the managed group and Users.</summary>
    void Create(string name, ReadOnlySpan<char> password);
    void SetPassword(string name, ReadOnlySpan<char> password);
    void SetEnabled(string name, bool enabled);
    /// <summary>Account expiry; null = never.</summary>
    void SetExpiry(string name, DateTimeOffset? expires);
    void SetAdmin(string name, bool admin);
    void EnsureUser(string name);
}

public enum AuditKind
{
    AllowOnline = 1000,
    AllowOffline = 1001,
    Deny = 1100,
    Error = 1300,
    AccountCreated = 1200,
    PasswordSet = 1201,
    AccountEnabled = 1202,
    AccountDisabled = 1203,
    AdminAdded = 1204,
    AdminRemoved = 1205,
    CleanupRun = 1210,
    CleanupSkipped = 1211,
    ServerUnreachable = 1400,
}

public enum Reason
{
    None,
    BadFormat,
    EmptyPassword,
    Excluded,
    NotManaged,
    RateLimited,
    InvalidCredentials,
    NotAuthorised,
    ServerError,
    AccountError,
    OfflineDisabled,
    OfflineNoAccount,
    OfflineExpired,
    OfflineLocked,
    AccountDisabledLocally,
    RemovedFromUsers,
    AdminSync,
}

/// <summary>One audit record. Never carries a password.</summary>
public sealed record AuditEvent(AuditKind Kind, string Uun, Reason Reason = Reason.None, string? Detail = null);

public interface IAudit
{
    void Write(AuditEvent e);
}

public interface IClock
{
    DateTimeOffset UtcNow { get; }
}

public sealed class SystemClock : IClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
