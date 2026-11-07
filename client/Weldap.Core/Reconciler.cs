namespace Weldap;

/// <summary>What the server said about the names it was asked about (<see cref="Reconciler.Read"/>). Only those names are acted on.</summary>
public sealed record ReconcilePlan(IReadOnlySet<string> Asked, IReadOnlySet<string> Users, IReadOnlySet<string> Admins);

/// <summary>
/// FR-12 and the account-lockdown policy: hourly (and at start) bring every local account in step with the
/// WELDAP server. For a managed account: disable it when it is no longer a user, idle-disable it when it has
/// not been used for <see cref="LoginSettings.IdleDisableDays"/>, and match local Administrators to the admin
/// flag. For an unmanaged account that is not protected (not excluded, force-local or built-in): a lockdown
/// candidate -- left alone if its name is a known LDAP user (it is adopted at its next sign-in), else reported,
/// and disabled once <see cref="LoginSettings.LockdownEnforce"/> is armed.
///
/// A pass is two phases so the network never holds the account lock: <see cref="Read"/> asks the server (slow,
/// lock-free), <see cref="Apply"/> acts on the answer against the accounts as they are by then (under the lock the
/// sign-in path also takes). <see cref="Run"/> is both, for callers with no lock to manage.
///
/// Safety invariants: any status-read failure changes nothing (an outage can never disable anyone); the last
/// enabled local administrator is never disabled or demoted; protected accounts are never touched; a wrong clock
/// cannot idle-disable everyone at once (idleness is measured against the device's own most recent logon too).
/// </summary>
public sealed class Reconciler(
    LoginSettings settings, IWeldapServer server, ILocalAccounts accounts, ISecretStore secrets, IAudit audit, IClock clock)
{
    public void Run()
    {
        if (Read() is { } plan) Apply(plan);
    }

    /// <summary>Phase 1, no lock: ask the server about every subject that could be an LDAP user. Null = nothing to do.</summary>
    public ReconcilePlan? Read()
    {
        if (ReadAccounts() is not { } everything) return null;
        var subjects = Subjects(everything);
        if (subjects.Count == 0)
        {
            audit.Write(new AuditEvent(AuditKind.CleanupRun, "-", Reason.None, "0 subjects, 0 changes"));
            return null;
        }

        // Only valid UUNs can be LDAP users. The server answers at most MaxStatusUuns per request; act only if every
        // batch was answered, so a name left out of one request is never mistaken for "not a user".
        var asked = subjects.Select(a => a.Name).Where(Uun.IsValid).ToHashSet(StringComparer.Ordinal);
        var users = new HashSet<string>(StringComparer.Ordinal);
        var admins = new HashSet<string>(StringComparer.Ordinal);
        foreach (var batch in asked.Chunk(ServerMessages.MaxStatusUuns))
        {
            if (server.ReadStatus(batch) is not { } status)
            {
                audit.Write(new AuditEvent(AuditKind.CleanupSkipped, "-", Reason.ServerError, "status read failed"));
                return null;
            }
            users.UnionWith(status.Users);
            admins.UnionWith(status.Admins);
        }
        return new ReconcilePlan(asked, users, admins);
    }

    /// <summary>
    /// Phase 2, under the account lock: act on the plan against a fresh list of accounts. An account whose name
    /// the server was not asked about (it appeared since <see cref="Read"/>) waits for the next pass.
    /// </summary>
    public void Apply(ReconcilePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (ReadAccounts() is not { } everything) return;
        var subjects = Subjects(everything);

        // The set of enabled local admins, kept current as we change accounts: its emptiness is what the last-admin
        // invariant guards against. Protected accounts count here too (a backup admin is the real backstop).
        var enabledAdmins = new HashSet<string>(
            everything.Where(a => a is { IsAdmin: true, Enabled: true }).Select(a => a.Name), StringComparer.Ordinal);

        // Idle is measured against the clock and against the most recent logon of any account on this device, so a
        // clock stepped forward (or a device left switched off for a month) does not make every account idle at once.
        var newest = everything.Max(a => a.LastLogon);
        var reference = newest is { } n && n < clock.UtcNow ? n : clock.UtcNow;

        // Managed accounts first: when the last-admin guard has to keep someone, it then keeps a working local
        // account (a lockdown candidate has a password someone knows) rather than a removed WELDAP user nobody can
        // sign in as. (OrderBy is stable: SAM order within each group.)
        var changes = 0;
        foreach (var account in subjects.OrderBy(a => a.IsManaged ? 0 : 1))
        {
            if (Uun.IsValid(account.Name) && !plan.Asked.Contains(account.Name)) continue;
            try
            {
                changes += account.IsManaged
                    ? ReconcileManaged(account, plan, enabledAdmins, reference)
                    : Lockdown(account, plan, enabledAdmins);
            }
            catch (LocalAccountException ex)
            {
                audit.Write(new AuditEvent(AuditKind.Error, account.Name, Reason.AccountError, ex.Message));
            }
        }

        audit.Write(new AuditEvent(AuditKind.CleanupRun, "-", Reason.None, $"{subjects.Count} subjects, {changes} changes"));
    }

    /// <summary>The last-admin invariant: true when <paramref name="name"/> is the only enabled local administrator.</summary>
    public static bool IsLastEnabledAdmin(IEnumerable<LocalAccount> everything, string name)
    {
        var admins = everything.Where(a => a is { IsAdmin: true, Enabled: true }).Select(a => a.Name).Take(2).ToList();
        return admins is [var only] && only == name;
    }

    private IReadOnlyList<LocalAccount>? ReadAccounts()
    {
        try
        {
            return accounts.ListAll();
        }
        catch (LocalAccountException ex)
        {
            audit.Write(new AuditEvent(AuditKind.CleanupSkipped, "-", Reason.AccountError, ex.Message));
            return null;
        }
    }

    /// <summary>Every account a pass may act on: excluded and protected ones never are.</summary>
    private List<LocalAccount> Subjects(IEnumerable<LocalAccount> everything) =>
        everything.Where(a => !settings.IsExcluded(a.Name) && !a.IsProtected).ToList();

    private static bool IsOnly(HashSet<string> enabledAdmins, string name) => enabledAdmins.Count == 1 && enabledAdmins.Contains(name);

    private int ReconcileManaged(LocalAccount account, ReconcilePlan plan, HashSet<string> enabledAdmins, DateTimeOffset reference)
    {
        var user = plan.Users.Contains(account.Name);
        var admin = user && plan.Admins.Contains(account.Name);
        var changes = 0;

        if (!user)
        {
            // Forget the offline verifier whatever happens to the disable (declined by the guard, or failed):
            // re-enabling the account by hand must not bring back offline sign-in with a password the server no
            // longer vouches for. Afterwards, so a failure to forget cannot stop the disable either.
            try
            {
                if (account.Enabled && Disable(account, Reason.RemovedFromUsers, enabledAdmins)) changes++;
            }
            finally
            {
                secrets.ClearVerifier(account.Name);
            }
        }
        else if (account.Enabled && IsIdle(account, reference) && Disable(account, Reason.Idle, enabledAdmins))
        {
            secrets.ClearVerifier(account.Name);
            changes++;
        }

        if (admin != account.IsAdmin)
        {
            if (!admin && IsOnly(enabledAdmins, account.Name))
            {
                audit.Write(new AuditEvent(AuditKind.DemotionSkipped, account.Name, Reason.LastAdmin));
                return changes;
            }
            accounts.SetAdmin(account.Name, admin);
            if (!admin) enabledAdmins.Remove(account.Name);
            audit.Write(new AuditEvent(admin ? AuditKind.AdminAdded : AuditKind.AdminRemoved, account.Name,
                user ? Reason.AdminSync : Reason.RemovedFromUsers));
            changes++;
        }

        return changes;
    }

    private int Lockdown(LocalAccount account, ReconcilePlan plan, HashSet<string> enabledAdmins)
    {
        // Known to LDAP: left alone -- it is adopted at the next sign-in. Otherwise it does not belong here.
        if (plan.Users.Contains(account.Name) || !account.Enabled) return 0;
        if (!settings.LockdownEnforce)
        {
            audit.Write(new AuditEvent(AuditKind.WouldDisable, account.Name, Reason.Lockdown));
            return 0;
        }
        return Disable(account, Reason.Lockdown, enabledAdmins) ? 1 : 0;
    }

    private bool IsIdle(LocalAccount account, DateTimeOffset reference) =>
        settings.IdleDisableDays > 0 && account.LastLogon is { } last && last <= reference.AddDays(-settings.IdleDisableDays);

    /// <summary>Disables the account, unless that would remove the last enabled local admin. Returns whether it did.</summary>
    private bool Disable(LocalAccount account, Reason reason, HashSet<string> enabledAdmins)
    {
        if (account.IsAdmin && IsOnly(enabledAdmins, account.Name))
        {
            audit.Write(new AuditEvent(AuditKind.DisableSkipped, account.Name, Reason.LastAdmin, $"would have been: {reason}"));
            return false;
        }
        if (account.IsManaged) accounts.SetEnabled(account.Name, false);
        else accounts.DisableUnmanaged(account.Name);
        enabledAdmins.Remove(account.Name);
        audit.Write(new AuditEvent(AuditKind.AccountDisabled, account.Name, reason));
        return true;
    }
}
