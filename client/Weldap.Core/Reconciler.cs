namespace Weldap;

/// <summary>
/// FR-12: hourly (and at start) bring managed accounts in step with the WELDAP server. Asks only about the
/// accounts this device manages; disables those that are no longer users and matches local Administrators to
/// the admin flag. No answer changes nothing, so an outage can never disable everyone.
/// </summary>
public sealed class Reconciler(
    LoginSettings settings, IWeldapServer server, ILocalAccounts accounts, ISecretStore secrets, IAudit audit)
{
    public void Run()
    {
        List<LocalAccount> managed;
        try
        {
            // Never act on names the tile refuses, even if someone added them to the managed group.
            managed = accounts.ListManaged().Where(a => Uun.IsValid(a.Name) && !settings.IsExcluded(a.Name)).ToList();
        }
        catch (LocalAccountException ex)
        {
            audit.Write(new AuditEvent(AuditKind.CleanupSkipped, "-", Reason.AccountError, ex.Message));
            return;
        }
        if (managed.Count == 0)
        {
            audit.Write(new AuditEvent(AuditKind.CleanupRun, "-", Reason.None, "0 managed, 0 changes"));
            return;
        }

        // The server answers for at most MaxStatusUuns names per request. Ask in batches and act only if every
        // batch was answered: a name left out of the question must never read as "no longer a user".
        var users = new HashSet<string>(StringComparer.Ordinal);
        var admins = new HashSet<string>(StringComparer.Ordinal);
        foreach (var batch in managed.Select(a => a.Name).Chunk(ServerMessages.MaxStatusUuns))
        {
            if (server.ReadStatus(batch) is not { } status)
            {
                audit.Write(new AuditEvent(AuditKind.CleanupSkipped, "-", Reason.ServerError, "status read failed"));
                return;
            }
            users.UnionWith(status.Users);
            admins.UnionWith(status.Admins);
        }

        var changes = 0;
        foreach (var account in managed)
        {
            try
            {
                var user = users.Contains(account.Name);
                var admin = user && admins.Contains(account.Name);
                if (!user)
                {
                    // Forget the offline verifier too: re-enabling the account by hand must not bring back
                    // offline sign-in with a password the server no longer vouches for.
                    secrets.ClearVerifier(account.Name);
                }
                if (!user && account.Enabled)
                {
                    accounts.SetEnabled(account.Name, false);
                    audit.Write(new AuditEvent(AuditKind.AccountDisabled, account.Name, Reason.RemovedFromUsers));
                    changes++;
                }
                if (admin != account.IsAdmin)
                {
                    accounts.SetAdmin(account.Name, admin);
                    audit.Write(new AuditEvent(admin ? AuditKind.AdminAdded : AuditKind.AdminRemoved, account.Name,
                        user ? Reason.AdminSync : Reason.RemovedFromUsers));
                    changes++;
                }
            }
            catch (LocalAccountException ex)
            {
                audit.Write(new AuditEvent(AuditKind.Error, account.Name, Reason.AccountError, ex.Message));
            }
        }

        audit.Write(new AuditEvent(AuditKind.CleanupRun, "-", Reason.None, $"{managed.Count} managed, {changes} changes"));
    }
}
