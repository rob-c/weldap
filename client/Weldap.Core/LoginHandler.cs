using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Weldap;

/// <summary>
/// The login decision (requirements: Login flow, FR-2..FR-9, FR-15, SR-3, SR-7, SR-8, SR-13). This process
/// never sees the user's password: it relays the sealed password to the WELDAP server, whose definite answer always
/// wins, and otherwise (no answer) checks the offline verifier. On success it hands the credential provider the
/// account's random local password, which is what Windows logs on with.
///
/// Concurrency: the server round trip (up to ServerBudgetSeconds) runs outside <paramref name="accountLock"/>, so
/// sign-ins on several sessions proceed in parallel; everything that reads or changes the local account and its
/// secrets runs under it (shared with the reconciler's Apply), against the account as it is by then.
/// </summary>
public sealed class LoginHandler(
    LoginSettings settings, IWeldapServer server, ILocalAccounts accounts, ISecretStore secrets,
    IAudit audit, IClock clock, RateLimiter limiter, Lock? accountLock = null)
{
    private readonly Lock _gate = accountLock ?? new Lock();

    internal static class Messages
    {
        public const string BadFormat = "Enter your username (lower-case letters and digits).";
        public const string Excluded = "This account can't sign in here. Use the standard Windows sign-in.";
        public const string NotManaged = "A local account with this name already exists and isn't managed by WELDAP sign-in.";
        public const string AdoptConsent = "This PC already has a local account with your name. To use it with your network sign-in from now on, tick Continue and sign in again. Its own password will then stop working.";
        public const string RateLimited = "Too many failed attempts. Try again in 5 minutes.";
        // The server's own throttle: per user (failures, 5 min) or per device (requests, 1 min); the reply does not say which.
        public const string ServerThrottled = "Too many sign-in attempts. Wait a few minutes and try again.";
        public const string InvalidCredentials = "The username or password is incorrect.";
        public const string NotAuthorised = "You aren't allowed to sign in to this PC.";
        public const string ServerError = "The login server returned an error. Try again, or contact IT.";
        public const string AccountError = "Couldn't update your account on this PC. Contact IT.";
        public const string OfflineDisabled = "Can't reach the login server. Check the network and try again.";
        public const string OfflineNoAccount = "Can't reach the login server, and you haven't signed in to this PC before.";
        public const string OfflineExpired = "Can't reach the login server, and your offline sign-in has expired. Connect to the network.";
        public const string OfflineLocked = "Too many failed offline attempts. Connect to the network and sign in.";
        public const string AccountDisabled = "Your account on this PC is disabled. Connect to the network and try again.";
    }

    public LoginReply Handle(LoginRequest request)
    {
        var uun = request.Uun;
        if (!Uun.IsValid(uun)) return Deny("(invalid)", Reason.BadFormat, Messages.BadFormat);
        if (settings.IsExcluded(uun)) return Deny(uun, Reason.Excluded, Messages.Excluded);
        // A first look, so that an account this tile may not sign in is refused before its password goes anywhere.
        if (Classify(uun, out _, out _) is { } refused) return Refuse(uun, refused);
        if (limiter.IsBlocked(uun)) return Deny(uun, Reason.RateLimited, Messages.RateLimited);

        var answer = server.Authenticate(uun, request.Scenario, request.Sealed); // the slow part: outside the lock
        switch (answer.Outcome)
        {
            case ServerOutcome.InvalidCredentials:
                limiter.RecordFailure(uun);
                return Deny(uun, Reason.InvalidCredentials, Messages.InvalidCredentials);
            case ServerOutcome.Throttled:
                return Deny(uun, Reason.RateLimited, Messages.ServerThrottled);
            case ServerOutcome.Error:
                return Fail(uun, Reason.ServerError, answer.Detail, Messages.ServerError);
        }
        // Fail closed: only a success that carries the flags is a success.
        if (answer is not ({ Outcome: ServerOutcome.NoAnswer } or { Outcome: ServerOutcome.Success, User: not null }))
            return Fail(uun, Reason.ServerError, "server: unexpected answer", Messages.ServerError);

        lock (_gate)
        {
            // The account may have changed while the server was asked (another sign-in, the reconciler, an admin):
            // decide on it as it is now.
            if (Classify(uun, out var local, out var adopting) is { } refusedNow) return Refuse(uun, refusedNow);
            if (answer.Outcome == ServerOutcome.NoAnswer)
            {
                audit.Write(new AuditEvent(AuditKind.ServerUnreachable, uun, Reason.None, answer.Detail));
                return Offline(uun, local, request.Verifier);
            }
            return Online(request, answer.User!, local, adopting);
        }
    }

    /// <summary>
    /// The local account, and whether signing in would adopt it; or the refusal if this tile may not sign it in: a
    /// protected account (a force-local backup, or a Windows built-in recognised by SID) always belongs to the
    /// standard tile, managed or not, and a pre-existing unmanaged one is refused unless adoption is on.
    /// </summary>
    private Refusal? Classify(string uun, out LocalAccount? local, out bool adopting)
    {
        adopting = false;
        try
        {
            local = accounts.Find(uun);
        }
        catch (LocalAccountException ex)
        {
            local = null;
            return new Refusal(Reason.AccountError, Messages.AccountError, ex.Message);
        }
        if (local is { IsBuiltIn: true }) return new Refusal(Reason.Excluded, Messages.Excluded);
        if (local is { IsForceLocal: true }) return new Refusal(Reason.ForceLocal, Messages.Excluded);
        if (local is { IsManaged: false } && !settings.AdoptPreexisting) return new Refusal(Reason.NotManaged, Messages.NotManaged);
        adopting = local is { IsManaged: false };
        return null;
    }

    /// <summary>Why <see cref="Classify"/> refused; an account lookup failure (Detail set) is an error, the rest denials.</summary>
    private readonly record struct Refusal(Reason Reason, string Message, string? Detail = null);

    private LoginReply Refuse(string uun, Refusal r) =>
        r.Detail is null ? Deny(uun, r.Reason, r.Message) : Fail(uun, r.Reason, r.Detail, r.Message);

    /// <summary>The server said yes to the password: apply its flags to the account (under the account lock).</summary>
    private LoginReply Online(LoginRequest request, UserFlags user, LocalAccount? local, bool adopting)
    {
        var uun = request.Uun;
        limiter.RecordSuccess(uun);
        if (!user.IsUser)
        {
            // Only ever disable an account WELDAP manages; a pre-existing account we were about to adopt is left
            // untouched (the server just says this person may not sign in here).
            if (local is { IsManaged: true }) RemoveUser(local);
            return Deny(uun, Reason.NotAuthorised, Messages.NotAuthorised);
        }

        // A pre-existing account is adopted only when that takes nothing from it the directory would not give
        // back: never one someone disabled on purpose, nor a local administrator the directory does not make one
        // (the last-admin guard could then keep a non-admin user an administrator for good).
        if (adopting && (!local!.Enabled || (local.IsAdmin && !user.IsAdmin)))
            return Deny(uun, Reason.NotManaged, Messages.NotManaged);

        // The user is real: before taking over a pre-existing account, make them accept the warning (Continue),
        // unless they already did (a resubmit carrying consent). Nothing is changed until they do.
        if (adopting && !request.Consent) return LoginReply.Adopt(Messages.AdoptConsent);

        char[] localPassword;
        try
        {
            if (adopting)
            {
                accounts.Adopt(uun);
                audit.Write(new AuditEvent(AuditKind.AccountAdopted, uun));
                local = local! with { IsManaged = true };
            }
            localPassword = SyncAccount(uun, local, user, request.Verifier, freshPassword: adopting);
        }
        catch (LocalAccountException ex)
        {
            return Fail(uun, Reason.AccountError, ex.Message, Messages.AccountError);
        }

        audit.Write(new AuditEvent(AuditKind.AllowOnline, uun, Reason.None, user.IsAdmin ? "admin" : "user"));
        return LoginReply.Ok(SignInMode.Online, localPassword);
    }

    /// <summary>
    /// Creates or refreshes the account; returns its local password (pinned, owned by the reply). The stored local
    /// password is applied to the account on every online sign-in, so an account whose password was reset by hand
    /// (or restored from a backup) converges back instead of failing at Windows logon for ever. An adopted account
    /// always gets a fresh one: anything stored is from an earlier life of the name, and the account's own password
    /// must stop working, as the consent text promised.
    /// </summary>
    private char[] SyncAccount(string uun, LocalAccount? local, UserFlags user, ReadOnlySpan<byte> verifier, bool freshPassword)
    {
        var password = freshPassword ? null : StoredPassword(uun);
        try
        {
            var generated = password is null;
            password ??= LocalPasswords.Generate();
            if (local is null)
            {
                accounts.Create(uun, password);
                audit.Write(new AuditEvent(AuditKind.AccountCreated, uun));
                local = new LocalAccount(uun, IsManaged: true, Enabled: true, IsAdmin: false, Expires: null);
            }
            else
            {
                accounts.SetPassword(uun, password);
                if (generated) audit.Write(new AuditEvent(AuditKind.PasswordSet, uun));
            }
            if (generated) secrets.SetLocalPassword(uun, password);

            if (!local.Enabled)
            {
                accounts.SetEnabled(uun, true);
                audit.Write(new AuditEvent(AuditKind.AccountEnabled, uun));
            }
            accounts.SetExpiry(uun, settings.MaxOfflineDays > 0 ? clock.UtcNow.AddDays(settings.MaxOfflineDays) : null);
            accounts.EnsureUser(uun);
            if (user.IsAdmin != local.IsAdmin)
            {
                if (!user.IsAdmin && IsLastEnabledAdmin(uun))
                {
                    audit.Write(new AuditEvent(AuditKind.DemotionSkipped, uun, Reason.LastAdmin));
                }
                else
                {
                    accounts.SetAdmin(uun, user.IsAdmin);
                    audit.Write(new AuditEvent(user.IsAdmin ? AuditKind.AdminAdded : AuditKind.AdminRemoved, uun, Reason.AdminSync));
                }
            }

            // The verifier is only ever stored after the server confirmed this exact password.
            secrets.SetVerifier(uun, verifier);
            secrets.SetOfflineFailures(uun, 0);
            return password;
        }
        catch
        {
            if (password is not null) CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(password.AsSpan()));
            throw;
        }
    }

    private LoginReply Offline(string uun, LocalAccount? local, ReadOnlySpan<byte> verifier)
    {
        if (settings.MaxOfflineDays <= 0) return Deny(uun, Reason.OfflineDisabled, Messages.OfflineDisabled);
        // FR-15: offline is only ever for an account WELDAP manages (and has seen this user sign in to online); never
        // for a pre-existing account, which nothing has vouched for.
        if (local is not { IsManaged: true }) return Deny(uun, Reason.OfflineNoAccount, Messages.OfflineNoAccount);
        if (local.Expires is { } expires && expires <= clock.UtcNow)
            return Deny(uun, Reason.OfflineExpired, Messages.OfflineExpired);
        if (!local.Enabled) return Deny(uun, Reason.AccountDisabledLocally, Messages.AccountDisabled);

        byte[]? stored = null;
        char[]? password = null;
        try
        {
            var failures = secrets.GetOfflineFailures(uun);
            if (failures < 0 || failures >= settings.OfflineMaxFailures) return Deny(uun, Reason.OfflineLocked, Messages.OfflineLocked);
            stored = secrets.GetVerifier(uun);
            if (stored is null || stored.Length != Protocol.VerifierBytes)
                return Deny(uun, Reason.OfflineNoAccount, Messages.OfflineNoAccount);

            if (!CryptographicOperations.FixedTimeEquals(stored, verifier))
            {
                secrets.SetOfflineFailures(uun, failures + 1);
                limiter.RecordFailure(uun);
                return Deny(uun, Reason.InvalidCredentials, Messages.InvalidCredentials);
            }
            password = StoredPassword(uun);
            if (password is null) return Deny(uun, Reason.OfflineNoAccount, Messages.OfflineNoAccount);
            secrets.SetOfflineFailures(uun, 0);
        }
        catch (LocalAccountException ex)
        {
            if (password is not null) CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(password.AsSpan()));
            return Fail(uun, Reason.AccountError, ex.Message, Messages.AccountError);
        }
        finally
        {
            if (stored is not null) CryptographicOperations.ZeroMemory(stored);
        }

        audit.Write(new AuditEvent(AuditKind.AllowOffline, uun));
        return LoginReply.Ok(SignInMode.Offline, password);
    }

    /// <summary>
    /// The server says this managed account's user may no longer sign in here: disable the account unless it is
    /// the last enabled local admin, and forget its offline verifier (as the reconciler does). The two are
    /// independent, so neither failing stops the other. Best effort: the sign-in is refused either way, and the
    /// hourly reconcile retries anything that failed.
    /// </summary>
    private void RemoveUser(LocalAccount local)
    {
        try
        {
            if (local.Enabled && local.IsAdmin && IsLastEnabledAdmin(local.Name))
            {
                audit.Write(new AuditEvent(AuditKind.DisableSkipped, local.Name, Reason.LastAdmin));
            }
            else if (local.Enabled)
            {
                accounts.SetEnabled(local.Name, false);
                audit.Write(new AuditEvent(AuditKind.AccountDisabled, local.Name, Reason.RemovedFromUsers));
            }
        }
        catch (LocalAccountException ex)
        {
            audit.Write(new AuditEvent(AuditKind.Error, local.Name, Reason.AccountError, ex.Message));
        }
        try
        {
            secrets.ClearVerifier(local.Name);
        }
        catch (LocalAccountException ex)
        {
            audit.Write(new AuditEvent(AuditKind.Error, local.Name, Reason.AccountError, ex.Message));
        }
    }

    /// <summary>The last-admin invariant: the device always keeps at least one enabled local administrator.</summary>
    private bool IsLastEnabledAdmin(string name) => Reconciler.IsLastEnabledAdmin(accounts.ListAll(), name);

    /// <summary>
    /// The stored local password, or null if there is none or it is not what the generator makes (restored,
    /// hand-edited or from another version): an unusable one is treated as lost, so an online sign-in replaces it
    /// and an offline one is refused, instead of the reply failing to encode.
    /// </summary>
    private char[]? StoredPassword(string uun)
    {
        var password = secrets.GetLocalPassword(uun);
        if (password is null || LocalPasswords.IsValid(password)) return password;
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(password.AsSpan()));
        audit.Write(new AuditEvent(AuditKind.Error, uun, Reason.AccountError, "stored local secret unusable"));
        return null;
    }

    private LoginReply Deny(string uun, Reason reason, string message)
    {
        audit.Write(new AuditEvent(AuditKind.Deny, uun, reason));
        return LoginReply.Deny(message);
    }

    private LoginReply Fail(string uun, Reason reason, string? detail, string message)
    {
        audit.Write(new AuditEvent(AuditKind.Error, uun, reason, detail));
        return reason == Reason.ServerError ? LoginReply.Deny(message) : LoginReply.Error(message);
    }
}
