namespace Weldap;

/// <summary>Platform-neutral severity, mapped to EventLogEntryType by the Windows audit sink.</summary>
public enum AuditSeverity
{
    Information,
    Warning,
    Error,
}

/// <summary>
/// How an <see cref="AuditEvent"/> is turned into an event-log line (FR-13), kept out of the Windows sink so it
/// is unit-tested. The line is built only from the UUN, kind, reason and detail, which already never hold a
/// password or verifier, so the audit log cannot leak one however it is called.
/// </summary>
public static class AuditFormat
{
    public static AuditSeverity SeverityOf(AuditKind kind) => kind switch
    {
        AuditKind.Error => AuditSeverity.Error,
        AuditKind.Deny or AuditKind.ServerUnreachable or AuditKind.CleanupSkipped => AuditSeverity.Warning,
        _ => AuditSeverity.Information,
    };

    public static string Describe(AuditEvent e)
    {
        ArgumentNullException.ThrowIfNull(e);
        var message = $"uun={e.Uun} event={e.Kind} reason={e.Reason}";
        return string.IsNullOrEmpty(e.Detail) ? message : $"{message} detail={e.Detail}";
    }
}
