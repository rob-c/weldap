using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Weldap;

/// <summary>
/// The login decision (requirements: Login flow, FR-2..FR-9, FR-15, SR-3, SR-7, SR-8, SR-13). This process
/// never sees the user's password: it relays the sealed password to the WELDAP server, whose definite answer always
/// wins, and otherwise (no answer) checks the offline verifier. On success it hands the credential provider the
/// account's random local password, which is what Windows logs on with.
/// </summary>
public sealed class LoginHandler(
    LoginSettings settings, IWeldapServer server, ILocalAccounts accounts, ISecretStore secrets,
    IAudit audit, IClock clock, RateLimiter limiter)
{
    internal static class Messages
    {
        public const string BadFormat = "Enter your username (lower-case letters and digits).";
        public const string Excluded = "This account can't sign in here. Use the standard Windows sign-in.";
        public const string NotManaged = "A local account with this name already exists and isn't managed by WELDAP sign-in.";
        public const string RateLimited = "Too many failed attempts. Try again in 5 minutes.";
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

        LocalAccount? local;
        try
        {
            local = accounts.Find(uun);
        }
        catch (LocalAccountException ex)
        {
            return Fail(uun, Reason.AccountError, ex.Message, Messages.AccountError);
        }
        if (local is { IsManaged: false }) return Deny(uun, Reason.NotManaged, Messages.NotManaged);
        if (limiter.IsBlocked(uun)) return Deny(uun, Reason.RateLimited, Messages.RateLimited);

        var answer = server.Authenticate(uun, request.Scenario, request.Sealed);
        switch (answer.Outcome)
        {
            case ServerOutcome.InvalidCredentials:
                limiter.RecordFailure(uun);
                return Deny(uun, Reason.InvalidCredentials, Messages.InvalidCredentials);
            case ServerOutcome.Throttled:
                return Deny(uun, Reason.RateLimited, Messages.RateLimited);
            case ServerOutcome.Error:
                return Fail(uun, Reason.ServerError, answer.Detail, Messages.ServerError);
            case ServerOutcome.NoAnswer:
                audit.Write(new AuditEvent(AuditKind.ServerUnreachable, uun, Reason.None, answer.Detail));
                return Offline(uun, local, request.Verifier);
        }
        // Fail closed: only a success that carries the flags is a success.
        if (answer is not { Outcome: ServerOutcome.Success, User: { } user })
            return Fail(uun, Reason.ServerError, "server: unexpected answer", Messages.ServerError);

        limiter.RecordSuccess(uun);
        if (!user.IsUser)
        {
            if (local is { Enabled: true }) TryDisable(uun, Reason.RemovedFromUsers);
            return Deny(uun, Reason.NotAuthorised, Messages.NotAuthorised);
        }

        char[] localPassword;
        try
        {
            localPassword = SyncAccount(uun, local, user, request.Verifier);
        }
        catch (LocalAccountException ex)
        {
            return Fail(uun, Reason.AccountError, ex.Message, Messages.AccountError);
        }

        audit.Write(new AuditEvent(AuditKind.AllowOnline, uun, Reason.None, user.IsAdmin ? "admin" : "user"));
        return LoginReply.Ok(SignInMode.Online, localPassword);
    }

    /// <summary>Creates or refreshes the account; returns its local password (pinned, owned by the reply).</summary>
    private char[] SyncAccount(string uun, LocalAccount? local, UserFlags user, ReadOnlySpan<byte> verifier)
    {
        var password = secrets.GetLocalPassword(uun);
        try
        {
            if (local is null)
            {
                password ??= LocalPasswords.Generate();
                accounts.Create(uun, password);
                secrets.SetLocalPassword(uun, password);
                audit.Write(new AuditEvent(AuditKind.AccountCreated, uun));
                local = new LocalAccount(uun, IsManaged: true, Enabled: true, IsAdmin: false, Expires: null);
            }
            else
            {
                if (password is null)
                {
                    // No stored local password (account from before sealed passwords, or lost): set a new one.
                    password = LocalPasswords.Generate();
                    accounts.SetPassword(uun, password);
                    secrets.SetLocalPassword(uun, password);
                    audit.Write(new AuditEvent(AuditKind.PasswordSet, uun));
                }
            }

            if (!local.Enabled)
            {
                accounts.SetEnabled(uun, true);
                audit.Write(new AuditEvent(AuditKind.AccountEnabled, uun));
            }
            accounts.SetExpiry(uun, settings.MaxOfflineDays > 0 ? clock.UtcNow.AddDays(settings.MaxOfflineDays) : null);
            accounts.EnsureUser(uun);
            if (user.IsAdmin != local.IsAdmin)
            {
                accounts.SetAdmin(uun, user.IsAdmin);
                audit.Write(new AuditEvent(user.IsAdmin ? AuditKind.AdminAdded : AuditKind.AdminRemoved, uun, Reason.AdminSync));
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
        if (local is null) return Deny(uun, Reason.OfflineNoAccount, Messages.OfflineNoAccount);
        if (local.Expires is { } expires && expires <= clock.UtcNow)
            return Deny(uun, Reason.OfflineExpired, Messages.OfflineExpired);
        if (!local.Enabled) return Deny(uun, Reason.AccountDisabledLocally, Messages.AccountDisabled);

        byte[]? stored = null;
        char[]? password = null;
        try
        {
            var failures = secrets.GetOfflineFailures(uun);
            if (failures >= settings.OfflineMaxFailures) return Deny(uun, Reason.OfflineLocked, Messages.OfflineLocked);
            stored = secrets.GetVerifier(uun);
            if (stored is null || stored.Length != Protocol.VerifierBytes)
                return Deny(uun, Reason.OfflineNoAccount, Messages.OfflineNoAccount);

            if (!CryptographicOperations.FixedTimeEquals(stored, verifier))
            {
                secrets.SetOfflineFailures(uun, failures + 1);
                limiter.RecordFailure(uun);
                return Deny(uun, Reason.InvalidCredentials, Messages.InvalidCredentials);
            }
            password = secrets.GetLocalPassword(uun);
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

    private void TryDisable(string uun, Reason reason)
    {
        try
        {
            accounts.SetEnabled(uun, false);
            secrets.ClearVerifier(uun);
            audit.Write(new AuditEvent(AuditKind.AccountDisabled, uun, reason));
        }
        catch (LocalAccountException ex)
        {
            audit.Write(new AuditEvent(AuditKind.Error, uun, Reason.AccountError, ex.Message));
        }
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
