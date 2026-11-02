namespace Weldap;

/// <summary>
/// FR-12 and the account-lockdown policy: hourly (and at start) bring every local account in step with the
/// WELDAP server. For a managed account: disable it when it is no longer a user, idle-disable it when it has
/// not been used for <see cref="LoginSettings.IdleDisableDays"/>, and match local Administrators to the admin
/// flag. For an unmanaged account not protected (not excluded, not force-local): a lockdown candidate -- left
/// alone if its name is a known LDAP user (it is adopted at the next sign-in), else reported, and disabled once
/// <see cref="LoginSettings.LockdownEnforce"/> is armed.
///
/// Safety invariants: any status-read failure changes nothing (an outage can never disable anyone); the last
/// enabled local administrator is never disabled (a protected backup admin is the backstop); excluded and
/// force-local accounts are never touched.
/// </summary>
public sealed class Reconciler(
    LoginSettings settings, IWeldapServer server, ILocalAccounts accounts, ISecretStore secrets, IAudit audit, IClock clock)
{
    public void Run()
    {
        List<LocalAccount> everything;
        try
        {
            everything = accounts.ListAll().ToList();
        }
        catch (LocalAccountException ex)
        {
            audit.Write(new AuditEvent(AuditKind.CleanupSkipped, "-", Reason.AccountError, ex.Message));
            return;
        }

        // Excluded and force-local accounts are never touched; everything else is a subject of this pass.
        var subjects = everything.Where(a => !settings.IsExcluded(a.Name) && !a.IsForceLocal).ToList();
        if (subjects.Count == 0)
        {
            audit.Write(new AuditEvent(AuditKind.CleanupRun, "-", Reason.None, "0 subjects, 0 changes"));
            return;
        }

        // Ask the server about every subject whose name could be an LDAP user (only valid UUNs can). The server
        // answers at most MaxStatusUuns per request; act only if every batch was answered, so a name left out of
        // one request is never mistaken for "not a user". Any failure leaves the whole pass a no-op.
        var users = new HashSet<string>(StringComparer.Ordinal);
        var admins = new HashSet<string>(StringComparer.Ordinal);
        foreach (var batch in subjects.Select(a => a.Name).Where(Uun.IsValid).Chunk(ServerMessages.MaxStatusUuns))
        {
            if (server.ReadStatus(batch) is not { } status)
            {
                audit.Write(new AuditEvent(AuditKind.CleanupSkipped, "-", Reason.ServerError, "status read failed"));
                return;
            }
            users.UnionWith(status.Users);
            admins.UnionWith(status.Admins);
        }

        // The set of enabled local admins, kept current as we disable; its emptiness is what the last-admin
        // invariant guards against. Protected accounts count here too (the backup admin is the backstop).
        var enabledAdmins = new HashSet<string>(
            everything.Where(a => a is { IsAdmin: true, Enabled: true }).Select(a => a.Name), StringComparer.Ordinal);

        var changes = 0;
        foreach (var account in subjects)
        {
            try
            {
                changes += account.IsManaged
                    ? ReconcileManaged(account, users, admins, enabledAdmins)
                    : Lockdown(account, users, enabledAdmins);
            }
            catch (LocalAccountException ex)
            {
                audit.Write(new AuditEvent(AuditKind.Error, account.Name, Reason.AccountError, ex.Message));
            }
        }

        audit.Write(new AuditEvent(AuditKind.CleanupRun, "-", Reason.None, $"{subjects.Count} subjects, {changes} changes"));
    }

    private int ReconcileManaged(LocalAccount account, HashSet<string> users, HashSet<string> admins, HashSet<string> enabledAdmins)
    {
        var user = users.Contains(account.Name);
        var admin = user && admins.Contains(account.Name);
        var changes = 0;

        if (!user)
        {
            // Forget the offline verifier too: re-enabling the account by hand must not bring back offline
            // sign-in with a password the server no longer vouches for.
            secrets.ClearVerifier(account.Name);
            if (account.Enabled && Disable(account, Reason.RemovedFromUsers, enabledAdmins)) changes++;
        }
        else if (account.Enabled && IsIdle(account) && Disable(account, Reason.Idle, enabledAdmins))
        {
            changes++;
        }

        if (admin != account.IsAdmin)
        {
            accounts.SetAdmin(account.Name, admin);
            if (!admin) enabledAdmins.Remove(account.Name);
            audit.Write(new AuditEvent(admin ? AuditKind.AdminAdded : AuditKind.AdminRemoved, account.Name,
                user ? Reason.AdminSync : Reason.RemovedFromUsers));
            changes++;
        }

        return changes;
    }

    private int Lockdown(LocalAccount account, HashSet<string> users, HashSet<string> enabledAdmins)
    {
        // Known to LDAP: left alone -- it is adopted at the next sign-in. Otherwise it does not belong here.
        if ((Uun.IsValid(account.Name) && users.Contains(account.Name)) || !account.Enabled) return 0;
        if (!settings.LockdownEnforce)
        {
            audit.Write(new AuditEvent(AuditKind.WouldDisable, account.Name, Reason.Lockdown));
            return 0;
        }
        return Disable(account, Reason.Lockdown, enabledAdmins) ? 1 : 0;
    }

    private bool IsIdle(LocalAccount account) =>
        settings.IdleDisableDays > 0 && account.LastLogon is { } last
        && last <= clock.UtcNow.AddDays(-settings.IdleDisableDays);

    /// <summary>Disables the account, unless that would remove the last enabled local admin. Returns whether it did.</summary>
    private bool Disable(LocalAccount account, Reason reason, HashSet<string> enabledAdmins)
    {
        if (account.IsAdmin && enabledAdmins.Count == 1 && enabledAdmins.Contains(account.Name))
        {
            audit.Write(new AuditEvent(AuditKind.DisableSkipped, account.Name, Reason.LastAdmin));
            return false;
        }
        accounts.SetEnabled(account.Name, false);
        secrets.ClearVerifier(account.Name);
        enabledAdmins.Remove(account.Name);
        audit.Write(new AuditEvent(AuditKind.AccountDisabled, account.Name, reason));
        return true;
    }
}
