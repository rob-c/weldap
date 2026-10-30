using Xunit;

namespace Weldap.Tests;

public class AuditFormatTests
{
    [Theory]
    [InlineData(AuditKind.Error, AuditSeverity.Error)]
    [InlineData(AuditKind.Deny, AuditSeverity.Warning)]
    [InlineData(AuditKind.ServerUnreachable, AuditSeverity.Warning)]
    [InlineData(AuditKind.CleanupSkipped, AuditSeverity.Warning)]
    [InlineData(AuditKind.AllowOnline, AuditSeverity.Information)]
    [InlineData(AuditKind.AllowOffline, AuditSeverity.Information)]
    [InlineData(AuditKind.AccountCreated, AuditSeverity.Information)]
    [InlineData(AuditKind.PasswordSet, AuditSeverity.Information)]
    [InlineData(AuditKind.AccountEnabled, AuditSeverity.Information)]
    [InlineData(AuditKind.AccountDisabled, AuditSeverity.Information)]
    [InlineData(AuditKind.AdminAdded, AuditSeverity.Information)]
    [InlineData(AuditKind.AdminRemoved, AuditSeverity.Information)]
    [InlineData(AuditKind.CleanupRun, AuditSeverity.Information)]
    public void SeverityOf(AuditKind kind, AuditSeverity expected) => Assert.Equal(expected, AuditFormat.SeverityOf(kind));

    [Fact]
    public void Every_kind_maps_to_a_severity() =>
        Assert.All(Enum.GetValues<AuditKind>(), k => Assert.True(Enum.IsDefined(AuditFormat.SeverityOf(k))));

    [Fact]
    public void Describe_without_detail()
    {
        var line = AuditFormat.Describe(new AuditEvent(AuditKind.Deny, "alice", Reason.InvalidCredentials));
        Assert.Equal("uun=alice event=Deny reason=InvalidCredentials", line);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Describe_drops_an_absent_detail(string? detail) =>
        Assert.Equal("uun=bob event=Error reason=AccountError",
            AuditFormat.Describe(new AuditEvent(AuditKind.Error, "bob", Reason.AccountError, detail)));

    [Fact]
    public void Describe_with_detail()
    {
        var line = AuditFormat.Describe(new AuditEvent(AuditKind.ServerUnreachable, "carol", Reason.None, "server: timeout"));
        Assert.Equal("uun=carol event=ServerUnreachable reason=None detail=server: timeout", line);
    }

    [Fact]
    public void Describe_rejects_null() => Assert.Throws<ArgumentNullException>(() => AuditFormat.Describe(null!));

    [Fact]
    public void Describe_only_ever_names_the_four_safe_fields()
    {
        // The line is built solely from UUN, kind, reason and detail: the audit log cannot carry a secret.
        var line = AuditFormat.Describe(new AuditEvent(AuditKind.AllowOnline, "alice", Reason.None, "admin"));
        foreach (var part in line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            Assert.Contains('=', (string)part);
        Assert.StartsWith("uun=alice event=AllowOnline reason=None", line);
    }
}
