using System.Diagnostics;
using Weldap;

namespace Weldap.Service;

/// <summary>FR-13: one Application-log event per allow, deny and account change. Never the password.</summary>
internal sealed class EventLogAudit : IAudit
{
    public const string Source = "WELDAP";
    public const string MessagesDll = "System.Diagnostics.EventLog.Messages.dll";

    public EventLogAudit()
    {
        // Normally registered by the MSI; this covers a bare copy. Without a message file on disk
        // Event Viewer shows "the description for Event ID ... cannot be found" instead of the text.
        if (EventLog.SourceExists(Source)) return;
        var messages = Path.Combine(AppContext.BaseDirectory, MessagesDll);
        EventLog.CreateEventSource(new EventSourceCreationData(Source, "Application")
        {
            MessageResourceFile = File.Exists(messages) ? messages : null,
        });
    }

    public void Write(AuditEvent e)
    {
        var type = AuditFormat.SeverityOf(e.Kind) switch
        {
            AuditSeverity.Error => EventLogEntryType.Error,
            AuditSeverity.Warning => EventLogEntryType.Warning,
            _ => EventLogEntryType.Information,
        };
        EventLog.WriteEntry(Source, AuditFormat.Describe(e), type, (int)e.Kind);
    }
}
