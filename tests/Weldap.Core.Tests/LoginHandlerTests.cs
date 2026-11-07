using System.Reflection;
using System.Text;
using Xunit;

namespace Weldap.Tests;

public class LoginHandlerTests
{
    private readonly FakeClock _clock = new();
    private readonly FakeServer _server = new();
    private readonly FakeAccounts _accounts = new();
    private readonly FakeSecrets _secrets = new();
    private readonly ListAudit _audit = new();
    private LoginSettings _settings = TestSettings.Create();

    internal static readonly string[] AllMessages = typeof(LoginHandler.Messages)
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Select(f => (string)f.GetValue(null)!)
        .ToArray();

    public LoginHandlerTests()
    {
        _server.Passwords["alice"] = "alice-pw";
        _server.Users.Add("alice");
        _server.Passwords["bob"] = "bob-pw";
        _server.Users.Add("bob");
        _server.Admins.Add("bob");
        _server.Passwords["carol"] = "carol-pw"; // known to the server, not a user of this PC
        _server.Passwords["dave"] = "dave-pw";   // admin flag without the user flag
        _server.Admins.Add("dave");
        _server.Passwords["breakglass"] = "bg-pw";
        _server.Users.Add("breakglass");
    }

    private LoginHandler Handler(RateLimiter? limiter = null) =>
        new(_settings, _server, _accounts, _secrets, _audit, _clock, limiter ?? new RateLimiter(_clock));

    private sealed record Outcome(ReplyResult Result, SignInMode Mode, string Message, string? LocalPassword, byte[] Wire);

    private Outcome Login(string uun, string password, LoginHandler? handler = null, Scenario scenario = Scenario.Logon,
        bool consent = false)
    {
        var b = RequestBuilder.For(uun, password, scenario);
        if (consent) b = b with { Scenario = (byte)(b.Scenario | Protocol.FlagConsent) };
        using var request = ProtocolCodec.TryParseRequest(b.Build())!;
        var outcome = Run(request, handler);
        AssertNoLeak(password, outcome);
        return outcome;
    }

    private Outcome Run(LoginRequest request, LoginHandler? handler = null)
    {
        using var reply = (handler ?? Handler()).Handle(request);
        var wire = ProtocolCodec.EncodeReply(reply);
        var outcome = new Outcome(reply.Result, reply.Mode, reply.Message,
            reply.LocalPassword is null ? null : new string(reply.LocalPassword), wire);
        if (outcome.Result == ReplyResult.Ok)
        {
            Assert.Equal("", outcome.Message);
            Assert.Equal(LocalPasswords.Length, outcome.LocalPassword!.Length);
        }
        else
        {
            Assert.Contains(outcome.Message, AllMessages);
            Assert.Null(outcome.LocalPassword);
        }
        return outcome;
    }

    private static bool Contains(byte[] haystack, byte[] needle) => needle.Length > 0 && haystack.AsSpan().IndexOf(needle) >= 0;

    /// <summary>The user's password, its encodings and its verifier never reach the audit log or the reply.</summary>
    private void AssertNoLeak(string password, Outcome outcome)
    {
        var verifier = FakeSeal.Verifier(password);
        var audit = _audit.AllText();
        var pwUtf8 = Encoding.UTF8.GetBytes(password);
        string[] secrets = password.Length >= 6
            ? [password, Convert.ToBase64String(pwUtf8), Convert.ToHexString(pwUtf8)]
            : [];
        foreach (var secret in secrets.Concat(new[]
                 {
                     Convert.ToBase64String(verifier), Convert.ToHexString(verifier), Convert.ToHexString(verifier).ToLowerInvariant(),
                 }))
            Assert.DoesNotContain(secret, audit, StringComparison.Ordinal);
        foreach (var local in _secrets.LocalPasswords.Values.Concat(_accounts.All.Values.Select(a => a.Password)).Where(p => p.Length > 0))
            Assert.DoesNotContain(local, audit, StringComparison.Ordinal);

        if (password.Length >= 4)
        {
            Assert.False(Contains(outcome.Wire, pwUtf8));
            Assert.False(Contains(outcome.Wire, Encoding.Unicode.GetBytes(password)));
        }
        Assert.False(Contains(outcome.Wire, verifier[..8]));
        Assert.NotEqual(password, outcome.LocalPassword);
        if (outcome.Result != ReplyResult.Ok)
        {
            foreach (var local in _secrets.LocalPasswords.Values)
                Assert.False(Contains(outcome.Wire, Encoding.ASCII.GetBytes(local)));
        }
    }

    // ---- online ----

    [Fact]
    public void First_login_creates_account_with_a_random_local_password()
    {
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Ok, r.Result);
        Assert.Equal(SignInMode.Online, r.Mode);
        var a = _accounts.All["alice"];
        // The local account never gets the user's password: LSASS only ever sees the random one.
        Assert.NotEqual("alice-pw", a.Password);
        Assert.Equal(LocalPasswords.Length, a.Password.Length);
        Assert.Equal(a.Password, r.LocalPassword);
        Assert.Equal(a.Password, _secrets.LocalPasswords["alice"]);
        Assert.Equal(FakeSeal.Verifier("alice-pw"), _secrets.Verifiers["alice"]);
        Assert.True(a.Enabled);
        Assert.True(a.User);
        Assert.False(a.Admin);
        Assert.Equal(_clock.UtcNow.AddDays(180), a.Expires);
        Assert.Equal(0, _secrets.Failures["alice"]);
        Assert.True(_audit.Has(AuditKind.AccountCreated));
        Assert.Equal("user", Assert.Single(_audit.Events, e => e.Kind == AuditKind.AllowOnline).Detail);
        // The reply on the wire carries exactly that local password.
        Assert.Equal(a.Password, Encoding.ASCII.GetString(r.Wire, 5, 32));
    }

    [Fact]
    public void Later_logins_keep_the_local_password_so_DPAPI_data_survives()
    {
        var first = Login("alice", "alice-pw").LocalPassword;
        _clock.UtcNow = _clock.UtcNow.AddDays(1);
        _server.Passwords["alice"] = "alice-new-pw"; // changed on the server
        var second = Login("alice", "alice-new-pw");
        Assert.Equal(ReplyResult.Ok, second.Result);
        Assert.Equal(first, second.LocalPassword);
        Assert.Equal(first, _accounts.All["alice"].Password);
        Assert.Equal(FakeSeal.Verifier("alice-new-pw"), _secrets.Verifiers["alice"]);
        Assert.Equal(_clock.UtcNow.AddDays(180), _accounts.All["alice"].Expires);
        Assert.False(_audit.Has(AuditKind.PasswordSet));
        Assert.Single(_audit.Events, e => e.Kind == AuditKind.AccountCreated);
    }

    [Fact]
    public void Existing_account_without_a_stored_local_password_gets_a_new_one()
    {
        _accounts.Add("alice").Password = "alice-pw"; // from an old design: local = user password
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Ok, r.Result);
        Assert.NotEqual("alice-pw", _accounts.All["alice"].Password);
        Assert.Equal(r.LocalPassword, _accounts.All["alice"].Password);
        Assert.Equal(r.LocalPassword, _secrets.LocalPasswords["alice"]);
        Assert.True(_audit.Has(AuditKind.PasswordSet));
        Assert.False(_audit.Has(AuditKind.AccountCreated));
    }

    [Fact]
    public void Stored_local_password_is_reused_when_the_account_was_deleted()
    {
        _secrets.LocalPasswords["alice"] = "ABCDEFGHJKLMNPQRabcdefgh23456789";
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Ok, r.Result);
        Assert.Equal("ABCDEFGHJKLMNPQRabcdefgh23456789", r.LocalPassword);
        Assert.Equal("ABCDEFGHJKLMNPQRabcdefgh23456789", _accounts.All["alice"].Password);
    }

    [Fact]
    public void Admin_flag_syncs_both_ways()
    {
        _accounts.Add("backup", managed: false, admin: true, forceLocal: true); // so bob is never the last admin
        Assert.Equal(ReplyResult.Ok, Login("bob", "bob-pw").Result);
        Assert.True(_accounts.All["bob"].Admin);
        Assert.True(_audit.Has(AuditKind.AdminAdded, Reason.AdminSync));
        Assert.Equal("admin", _audit.Events.Last(e => e.Kind == AuditKind.AllowOnline).Detail);
        _server.Admins.Remove("bob");
        Assert.Equal(ReplyResult.Ok, Login("bob", "bob-pw").Result);
        Assert.False(_accounts.All["bob"].Admin);
        Assert.True(_audit.Has(AuditKind.AdminRemoved, Reason.AdminSync));
    }

    [Fact]
    public void Not_a_user_is_denied_and_an_existing_account_disabled()
    {
        Login("alice", "alice-pw");
        _server.Users.Remove("alice");
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Deny, r.Result);
        Assert.Equal(LoginHandler.Messages.NotAuthorised, r.Message);
        Assert.Null(r.LocalPassword);
        Assert.False(_accounts.All["alice"].Enabled);
        Assert.False(_secrets.Verifiers.ContainsKey("alice"));
        Assert.True(_audit.Has(AuditKind.AccountDisabled, Reason.RemovedFromUsers));
        Assert.True(_audit.Has(AuditKind.Deny, Reason.NotAuthorised));
    }

    [Fact]
    public void Not_a_user_creates_nothing()
    {
        Assert.Equal(LoginHandler.Messages.NotAuthorised, Login("carol", "carol-pw").Message);
        Assert.Empty(_accounts.All);
        Assert.Empty(_secrets.Verifiers);
        Assert.Empty(_secrets.LocalPasswords);
        Assert.Equal(0, _accounts.Mutations);
    }

    [Fact]
    public void Admin_flag_without_user_flag_grants_nothing()
    {
        Assert.Equal(LoginHandler.Messages.NotAuthorised, Login("dave", "dave-pw").Message);
        Assert.Empty(_accounts.All);
        _accounts.Add("dave");
        Assert.Equal(LoginHandler.Messages.NotAuthorised, Login("dave", "dave-pw").Message);
        Assert.False(_accounts.All["dave"].Admin);
        Assert.False(_accounts.All["dave"].Enabled);
        Assert.DoesNotContain("SetAdmin", _accounts.Calls);
    }

    [Fact]
    public void Wrong_password_is_denied_and_changes_nothing()
    {
        var r = Login("alice", "nope");
        Assert.Equal(ReplyResult.Deny, r.Result);
        Assert.Equal(LoginHandler.Messages.InvalidCredentials, r.Message);
        Assert.Empty(_accounts.All);
        Assert.Empty(_secrets.Verifiers);
        Assert.True(_audit.Has(AuditKind.Deny, Reason.InvalidCredentials));
    }

    [Fact]
    public void The_sealed_password_is_relayed_as_is()
    {
        var b = RequestBuilder.For("alice", "alice-pw");
        using var request = ProtocolCodec.TryParseRequest(b.Build())!;
        Run(request);
        Assert.Equal("alice", _server.LastUun);
        Assert.Equal(b.Ct, _server.LastSealed!.Ct);
        Assert.Equal(b.Enc, _server.LastSealed.Enc);
        Assert.Equal(b.Rid, _server.LastSealed.Rid);
        Assert.Equal(b.Ts, _server.LastSealed.Ts);
        Assert.Equal("k1", _server.LastSealed.Kid);
        Assert.Same(request.Sealed, _server.LastSealed);
    }

    [Theory]
    [InlineData(Scenario.Logon)]
    [InlineData(Scenario.Unlock)]
    public void The_scenario_is_relayed(Scenario scenario)
    {
        Assert.Equal(ReplyResult.Ok, Login("alice", "alice-pw", scenario: scenario).Result);
        Assert.Equal(scenario, _server.LastScenario);
    }

    [Fact]
    public void Server_throttling_is_a_rate_limit_message()
    {
        _server.Forced = ServerOutcome.Throttled;
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Deny, r.Result);
        // Not "failed attempts": a device-wide throttle refuses users who have not failed at all.
        Assert.Equal(LoginHandler.Messages.ServerThrottled, r.Message);
        Assert.True(_audit.Has(AuditKind.Deny, Reason.RateLimited));
    }

    [Fact]
    public void Server_error_is_a_deny_with_the_server_message()
    {
        _server.ForcedAnswer = ServerAnswer.Failed("server: account refused");
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Deny, r.Result);
        Assert.Equal(LoginHandler.Messages.ServerError, r.Message);
        var e = Assert.Single(_audit.Events, e => e.Kind == AuditKind.Error);
        Assert.Equal(Reason.ServerError, e.Reason);
        Assert.Equal("server: account refused", e.Detail);
        Assert.Empty(_accounts.All);
    }

    [Fact]
    public void Success_without_flags_fails_closed()
    {
        _accounts.Add("alice");
        _server.ForcedAnswer = new ServerAnswer(ServerOutcome.Success);
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Deny, r.Result);
        Assert.Equal(LoginHandler.Messages.ServerError, r.Message);
        Assert.Equal(0, _accounts.Mutations);
        Assert.Empty(_secrets.Verifiers);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(5)]
    [InlineData(99)]
    public void Unknown_outcome_fails_closed_even_with_flags(int outcome)
    {
        _server.ForcedAnswer = new ServerAnswer((ServerOutcome)outcome, new UserFlags(true, true));
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Deny, r.Result);
        Assert.Equal(LoginHandler.Messages.ServerError, r.Message);
        Assert.Empty(_accounts.All);
        Assert.Empty(_secrets.Verifiers);
    }

    [Fact]
    public void Server_exceptions_propagate_without_changes()
    {
        // The pipe server turns any exception into a generic error reply; nothing may have changed by then.
        var server = new ThrowingServer();
        using var request = ProtocolCodec.TryParseRequest(RequestBuilder.For("alice", "alice-pw").Build())!;
        var handler = new LoginHandler(_settings, server, _accounts, _secrets, _audit, _clock, new RateLimiter(_clock));
        Assert.Throws<TimeoutException>(() => handler.Handle(request));
        Assert.Equal(0, _accounts.Mutations);
        Assert.Empty(_secrets.Verifiers);
    }

    private sealed class ThrowingServer : IWeldapServer
    {
        public ServerAnswer Authenticate(string uun, Scenario scenario, SealedPassword sealedPassword) => throw new TimeoutException();
        public StatusSnapshot? ReadStatus(IReadOnlyCollection<string> uuns) => throw new TimeoutException();
    }

    [Theory]
    [InlineData("administrator")]
    [InlineData("guest")]
    [InlineData("defaultaccount")]
    [InlineData("wdagutilityaccount")]
    [InlineData("breakglass")]
    public void Excluded_names_never_reach_the_server(string uun)
    {
        _accounts.Add(uun, managed: true); // even if someone put it in the managed group
        var r = Login(uun, "bg-pw");
        Assert.Equal(ReplyResult.Deny, r.Result);
        Assert.Equal(LoginHandler.Messages.Excluded, r.Message);
        Assert.Equal(0, _server.AuthCalls);
        Assert.Equal(0, _accounts.Mutations);
        Assert.DoesNotContain("Find", _accounts.Calls);
        Assert.True(_audit.Has(AuditKind.Deny, Reason.Excluded));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Unmanaged_local_account_is_never_taken_over_when_adoption_is_off(bool enabled)
    {
        _settings = TestSettings.Create() with { AdoptPreexisting = false };
        _accounts.Add("alice", managed: false, enabled: enabled).Password = "theirs";
        foreach (var outcome in new ServerOutcome?[] { null, ServerOutcome.NoAnswer })
        {
            _server.ForcedAnswer = outcome is { } o ? new ServerAnswer(o) : null;
            var r = Login("alice", "alice-pw");
            Assert.Equal(LoginHandler.Messages.NotManaged, r.Message);
        }
        Assert.Equal(0, _server.AuthCalls);
        Assert.Equal(0, _accounts.Mutations);
        Assert.Equal("theirs", _accounts.All["alice"].Password);
        Assert.Empty(_secrets.Calls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Force_local_backup_account_is_refused_at_the_tile(bool adoption)
    {
        _settings = TestSettings.Create() with { AdoptPreexisting = adoption };
        _accounts.Add("backup", managed: false, forceLocal: true, admin: true).Password = "theirs";
        var r = Login("backup", "alice-pw");
        Assert.Equal(ReplyResult.Deny, r.Result);
        Assert.Equal(LoginHandler.Messages.Excluded, r.Message);
        Assert.Equal(0, _server.AuthCalls);
        Assert.Equal(0, _accounts.Mutations);
        Assert.Equal("theirs", _accounts.All["backup"].Password);
        Assert.True(_audit.Has(AuditKind.Deny, Reason.ForceLocal));
    }

    public static TheoryData<string> BadUuns() =>
    [
        "Alice", "ALICE", "a=b", "a,ou=x", "*", "abcdefghijklmnopqrstu", "a-b", "a.b", "a_b", "",
        "alice\n", "a b", "alice\0", "аlice", "alicé", "ａlice",
    ];

    /// <summary>
    /// The handler applies the UUN rule itself (the codec lets any printable ASCII through), and never writes the
    /// rejected text into the audit log.
    /// </summary>
    [Theory]
    [MemberData(nameof(BadUuns))]
    public void Bad_username_is_denied_without_lookup_or_logging_it(string uun)
    {
        using var request = new LoginRequest(Scenario.Logon, false, uun,
            new SealedPassword("k1", RequestBuilder.DefaultEnc(), FakeSeal.Seal("x-password"), 1, new byte[16]),
            FakeSeal.Verifier("x-password"));
        var r = Run(request);
        Assert.Equal(ReplyResult.Deny, r.Result);
        Assert.Equal(LoginHandler.Messages.BadFormat, r.Message);
        var e = Assert.Single(_audit.Events);
        Assert.Equal(new AuditEvent(AuditKind.Deny, "(invalid)", Reason.BadFormat), e);
        Assert.Equal(0, _server.AuthCalls);
        Assert.Empty(_accounts.Calls);
        Assert.Empty(_secrets.Calls);
    }

    [Fact]
    public void Account_lookup_failure_is_an_error_without_asking_the_server()
    {
        _accounts.ThrowOn.Add("Find");
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Error, r.Result);
        Assert.Equal(LoginHandler.Messages.AccountError, r.Message);
        Assert.Equal(0, _server.AuthCalls);
        Assert.Equal("Find failed", Assert.Single(_audit.Events, e => e.Kind == AuditKind.Error).Detail);
    }

    [Fact]
    public void Account_failure_is_an_error_without_a_password()
    {
        _accounts.Throw = true;
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Error, r.Result);
        Assert.Null(r.LocalPassword);
    }

    public enum LocalState { None, Enabled, Disabled, EnabledAdmin, DisabledAdmin }

    public static TheoryData<LocalState, bool, bool> SuccessTable()
    {
        var data = new TheoryData<LocalState, bool, bool>();
        foreach (var state in Enum.GetValues<LocalState>())
            foreach (var admin in new[] { false, true })
                foreach (var stored in new[] { false, true })
                    data.Add(state, admin, stored);
        return data;
    }

    /// <summary>Every local state x admin flag x stored password: the account always ends up in step.</summary>
    [Theory]
    [MemberData(nameof(SuccessTable))]
    public void Online_success_brings_the_account_in_step(LocalState state, bool serverAdmin, bool storedPassword)
    {
        const string Stored = "ABCDEFGHJKLMNPQRabcdefgh23456789";
        if (state != LocalState.None)
        {
            var a = _accounts.Add("alice",
                enabled: state is LocalState.Enabled or LocalState.EnabledAdmin,
                admin: state is LocalState.EnabledAdmin or LocalState.DisabledAdmin,
                expires: _clock.UtcNow.AddDays(-3));
            a.Password = storedPassword ? Stored : "";
        }
        if (storedPassword) _secrets.LocalPasswords["alice"] = Stored;
        _secrets.Failures["alice"] = 4;
        _server.ForcedAnswer = new ServerAnswer(ServerOutcome.Success, new UserFlags(true, serverAdmin));
        _accounts.Add("backup", managed: false, admin: true, forceLocal: true); // so alice is never the last admin

        var r = Login("alice", "alice-pw");

        Assert.Equal(ReplyResult.Ok, r.Result);
        Assert.Equal(SignInMode.Online, r.Mode);
        var acct = _accounts.All["alice"];
        Assert.True(acct.Enabled);
        Assert.True(acct.User);
        Assert.Equal(serverAdmin, acct.Admin);
        Assert.Equal(_clock.UtcNow.AddDays(180), acct.Expires);
        Assert.Equal(acct.Password, r.LocalPassword);
        Assert.Equal(acct.Password, _secrets.LocalPasswords["alice"]);
        if (storedPassword) Assert.Equal(Stored, r.LocalPassword);
        Assert.Equal(FakeSeal.Verifier("alice-pw"), _secrets.Verifiers["alice"]);
        Assert.Equal(0, _secrets.Failures["alice"]);

        var wasAdmin = state is LocalState.EnabledAdmin or LocalState.DisabledAdmin;
        Assert.Equal(state == LocalState.None, _audit.Has(AuditKind.AccountCreated));
        Assert.Equal(state != LocalState.None && !storedPassword, _audit.Has(AuditKind.PasswordSet));
        Assert.Equal(state is LocalState.Disabled or LocalState.DisabledAdmin, _audit.Has(AuditKind.AccountEnabled));
        Assert.Equal(serverAdmin && !wasAdmin, _audit.Has(AuditKind.AdminAdded, Reason.AdminSync));
        Assert.Equal(!serverAdmin && wasAdmin, _audit.Has(AuditKind.AdminRemoved, Reason.AdminSync));
        Assert.Equal(serverAdmin ? "admin" : "user", Assert.Single(_audit.Events, e => e.Kind == AuditKind.AllowOnline).Detail);

        // The verifier is stored last, after every account change succeeded.
        Assert.Equal(["SetVerifier", "SetOfflineFailures"], _secrets.Calls.TakeLast(2));
    }

    public static TheoryData<ServerOutcome?, LocalState> DenyTable()
    {
        var data = new TheoryData<ServerOutcome?, LocalState>();
        foreach (var outcome in new ServerOutcome?[] { ServerOutcome.InvalidCredentials, ServerOutcome.Throttled, ServerOutcome.Error, null })
            foreach (var state in new[] { LocalState.None, LocalState.Enabled, LocalState.Disabled, LocalState.EnabledAdmin })
                data.Add(outcome, state);
        return data;
    }

    /// <summary>
    /// Definite no from the server (wrong password, throttled, error, or null here: not a user): denied, nothing
    /// created, no verifier stored; only "not a user" touches an existing account (disables it, clears its verifier).
    /// </summary>
    [Theory]
    [MemberData(nameof(DenyTable))]
    public void Online_definite_no(ServerOutcome? outcome, LocalState state)
    {
        var notUser = outcome is null;
        var old = new byte[32];
        _accounts.Add("backup", managed: false, admin: true, forceLocal: true); // so alice is never the last admin
        if (state != LocalState.None)
        {
            _accounts.Add("alice", enabled: state is LocalState.Enabled or LocalState.EnabledAdmin, admin: state == LocalState.EnabledAdmin);
            _secrets.Verifiers["alice"] = old;
        }
        _server.ForcedAnswer = notUser
            ? new ServerAnswer(ServerOutcome.Success, new UserFlags(false, false))
            : new ServerAnswer(outcome!.Value, null, "forced");

        var r = Login("alice", "alice-pw");

        Assert.Equal(ReplyResult.Deny, r.Result);
        Assert.Equal(outcome switch
        {
            ServerOutcome.InvalidCredentials => LoginHandler.Messages.InvalidCredentials,
            ServerOutcome.Throttled => LoginHandler.Messages.ServerThrottled,
            ServerOutcome.Error => LoginHandler.Messages.ServerError,
            _ => LoginHandler.Messages.NotAuthorised,
        }, r.Message);
        Assert.DoesNotContain("SetVerifier", _secrets.Calls);
        Assert.DoesNotContain("Create", _accounts.Calls);
        Assert.DoesNotContain("SetPassword", _accounts.Calls);
        Assert.DoesNotContain("SetAdmin", _accounts.Calls);
        if (state == LocalState.None)
        {
            Assert.False(_accounts.All.ContainsKey("alice"));
            return;
        }
        var disables = notUser && state is LocalState.Enabled or LocalState.EnabledAdmin;
        Assert.Equal(!disables && state != LocalState.Disabled, _accounts.All["alice"].Enabled);
        // "Not a user" always forgets the offline verifier, as the reconciler does, even of a disabled account.
        Assert.Equal(!notUser, _secrets.Verifiers.ContainsKey("alice"));
        Assert.Equal(disables ? 1 : 0, _accounts.Mutations);
    }

    [Theory]
    [InlineData(0, null)]
    [InlineData(1, 1)]
    [InlineData(30, 30)]
    [InlineData(180, 180)]
    [InlineData(3650, 3650)]
    public void Account_expiry_follows_MaxOfflineDays(int days, int? expected)
    {
        _settings = TestSettings.Create(maxOfflineDays: days);
        Assert.Equal(ReplyResult.Ok, Login("alice", "alice-pw").Result);
        Assert.Equal(expected is { } d ? _clock.UtcNow.AddDays(d) : null, _accounts.All["alice"].Expires);
    }

    [Theory]
    [InlineData("alice-pw")]
    [InlineData("ABCDEFGHJKLMNPQRabcdefgh23456789")] // shaped like a local password
    [InlineData("p")]
    [InlineData("pässwörd with spaces and ünïcode 😀")]
    public void Local_password_never_equals_the_user_password(string password)
    {
        _server.Passwords["alice"] = password;
        for (var i = 0; i < 5; i++)
        {
            _accounts.All.Clear();
            _secrets.LocalPasswords.Clear();
            var r = Login("alice", password);
            Assert.Equal(ReplyResult.Ok, r.Result);
            Assert.NotEqual(password, r.LocalPassword);
            Assert.NotEqual(password, _accounts.All["alice"].Password);
        }
    }

    [Fact]
    public void Created_account_and_store_and_reply_agree()
    {
        var r = Login("alice", "alice-pw");
        // A first look before the server is asked, and a fresh one under the account lock after it answered.
        Assert.Equal(["Find", "Find", "Create", "SetExpiry", "EnsureUser"], _accounts.Calls);
        Assert.Equal(r.LocalPassword, _accounts.All["alice"].Password);
        Assert.Equal(r.LocalPassword, _secrets.LocalPasswords["alice"]);
    }

    public static TheoryData<string, string> OnlineFailureSteps() => new()
    {
        { "secrets", "GetLocalPassword" },
        { "accounts", "Create" },
        { "secrets", "SetLocalPassword" },
        { "accounts", "SetPassword" },
        { "accounts", "SetEnabled" },
        { "accounts", "SetExpiry" },
        { "accounts", "EnsureUser" },
        { "accounts", "SetAdmin" },
        { "secrets", "SetVerifier" },
        { "secrets", "SetOfflineFailures" },
    };

    /// <summary>A store failure at any step of the online path: an error, no password, the buffers zeroed.</summary>
    [Theory]
    [MemberData(nameof(OnlineFailureSteps))]
    public void Online_store_failure_at_each_step(string store, string op)
    {
        // Arrange so the step is reached: SetPassword needs an existing account without a stored password,
        // SetEnabled a disabled one, SetAdmin a flag change; the rest run on first sign-in of an admin.
        switch (op)
        {
            case "SetPassword":
                _accounts.Add("bob");
                break;
            case "SetEnabled":
                _accounts.Add("bob", enabled: false, admin: true);
                _secrets.LocalPasswords["bob"] = "ABCDEFGHJKLMNPQRabcdefgh23456789";
                break;
            case "GetLocalPassword":
                _secrets.LocalPasswords["bob"] = "ABCDEFGHJKLMNPQRabcdefgh23456789";
                break;
        }
        (store == "accounts" ? _accounts.ThrowOn : _secrets.ThrowOn).Add(op);

        var r = Login("bob", "bob-pw");

        Assert.Equal(ReplyResult.Error, r.Result);
        Assert.Equal(LoginHandler.Messages.AccountError, r.Message);
        Assert.Null(r.LocalPassword);
        Assert.Equal(5, r.Wire.Length - 2 * r.Message.Length);
        var e = Assert.Single(_audit.Events, e => e.Kind == AuditKind.Error);
        Assert.Equal(Reason.AccountError, e.Reason);
        Assert.Equal($"{op} failed", e.Detail);
        Assert.False(_audit.Has(AuditKind.AllowOnline));
        if (op != "SetOfflineFailures") Assert.False(_secrets.Verifiers.ContainsKey("bob"));
        Assert.All(_secrets.IssuedPasswords, p => Assert.All(p, c => Assert.Equal('\0', c)));
    }

    // ---- adopting a pre-existing account ----

    [Fact]
    public void Adoption_is_offered_before_anything_changes()
    {
        _accounts.Add("alice", managed: false, admin: false).Password = "theirs";
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Adopt, r.Result);
        Assert.Equal(LoginHandler.Messages.AdoptConsent, r.Message);
        Assert.Null(r.LocalPassword);
        Assert.Equal(1, _server.AuthCalls);              // the password was checked first
        Assert.Equal(0, _accounts.Mutations);            // but nothing was taken over
        Assert.Equal("theirs", _accounts.All["alice"].Password);
        Assert.False(_accounts.All["alice"].Managed);
        Assert.Empty(_secrets.Verifiers);
    }

    [Fact]
    public void Consent_adopts_the_account_and_resets_its_password()
    {
        _accounts.Add("alice", managed: false).Password = "theirs";
        var r = Login("alice", "alice-pw", consent: true);
        Assert.Equal(ReplyResult.Ok, r.Result);
        Assert.Equal(SignInMode.Online, r.Mode);
        var a = _accounts.All["alice"];
        Assert.True(a.Managed);
        Assert.True(a.Enabled);
        Assert.NotEqual("theirs", a.Password);           // its old local password no longer works
        Assert.Equal(a.Password, r.LocalPassword);
        Assert.Equal(a.Password, _secrets.LocalPasswords["alice"]);
        Assert.Equal(FakeSeal.Verifier("alice-pw"), _secrets.Verifiers["alice"]);
        Assert.Equal(_clock.UtcNow.AddDays(180), a.Expires);
        Assert.True(_audit.Has(AuditKind.AccountAdopted));
        Assert.True(_audit.Has(AuditKind.PasswordSet));
        Assert.False(_audit.Has(AuditKind.AccountCreated));
        Assert.Equal(["Find", "Find", "Adopt", "SetPassword", "SetExpiry", "EnsureUser"], _accounts.Calls);
    }

    [Fact]
    public void Consent_adopts_an_admin_user_as_a_local_admin()
    {
        _accounts.Add("bob", managed: false).Password = "theirs";
        var r = Login("bob", "bob-pw", consent: true);
        Assert.Equal(ReplyResult.Ok, r.Result);
        Assert.True(_accounts.All["bob"].Admin);
        Assert.True(_audit.Has(AuditKind.AdminAdded, Reason.AdminSync));
    }

    [Fact]
    public void Adoption_off_refuses_a_pre_existing_account()
    {
        _settings = TestSettings.Create() with { AdoptPreexisting = false };
        _accounts.Add("alice", managed: false).Password = "theirs";
        var r = Login("alice", "alice-pw", consent: true); // even with consent, policy wins
        Assert.Equal(ReplyResult.Deny, r.Result);
        Assert.Equal(LoginHandler.Messages.NotManaged, r.Message);
        Assert.Equal(0, _server.AuthCalls);
        Assert.Equal(0, _accounts.Mutations);
    }

    [Fact]
    public void Wrong_password_on_an_adoptable_account_adopts_nothing()
    {
        _accounts.Add("alice", managed: false).Password = "theirs";
        var r = Login("alice", "nope", consent: true);
        Assert.Equal(ReplyResult.Deny, r.Result);
        Assert.Equal(LoginHandler.Messages.InvalidCredentials, r.Message);
        Assert.Equal(0, _accounts.Mutations);
        Assert.False(_accounts.All["alice"].Managed);
        Assert.Equal("theirs", _accounts.All["alice"].Password);
    }

    [Fact]
    public void A_pre_existing_account_whose_user_is_not_authorised_is_left_untouched()
    {
        _accounts.Add("carol", managed: false, enabled: true).Password = "theirs";
        var r = Login("carol", "carol-pw", consent: true); // carol authenticates but is not a user here
        Assert.Equal(ReplyResult.Deny, r.Result);
        Assert.Equal(LoginHandler.Messages.NotAuthorised, r.Message);
        Assert.Equal(0, _accounts.Mutations);              // not adopted, and not disabled: it isn't ours
        Assert.True(_accounts.All["carol"].Enabled);
        Assert.False(_audit.Has(AuditKind.AccountDisabled));
    }

    [Fact]
    public void Adoption_failure_is_an_error_without_a_password()
    {
        _accounts.Add("alice", managed: false).Password = "theirs";
        _accounts.ThrowOn.Add("Adopt");
        var r = Login("alice", "alice-pw", consent: true);
        Assert.Equal(ReplyResult.Error, r.Result);
        Assert.Equal(LoginHandler.Messages.AccountError, r.Message);
        Assert.Null(r.LocalPassword);
        Assert.Equal("Adopt failed", Assert.Single(_audit.Events, e => e.Kind == AuditKind.Error).Detail);
        Assert.Empty(_secrets.Verifiers);
    }

    [Fact]
    public void Rate_limit_still_applies_to_an_adoptable_account()
    {
        _accounts.Add("alice", managed: false);
        var handler = Handler();
        for (var i = 0; i < RateLimiter.MaxFailures; i++) Login("alice", "nope", handler);
        var calls = _server.AuthCalls;
        Assert.Equal(LoginHandler.Messages.RateLimited, Login("alice", "alice-pw", handler, consent: true).Message);
        Assert.Equal(calls, _server.AuthCalls);
    }

    // ---- offline ----

    private string SignInOnlineThenGoOffline()
    {
        var local = Login("alice", "alice-pw").LocalPassword!;
        _server.Forced = ServerOutcome.NoAnswer;
        return local;
    }

    [Fact]
    public void Offline_right_password_gets_the_same_local_password()
    {
        var local = SignInOnlineThenGoOffline();
        _server.ForcedAnswer = ServerAnswer.NoAnswer("tls: handshake refused");
        var mutations = _accounts.Mutations;
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Ok, r.Result);
        Assert.Equal(SignInMode.Offline, r.Mode);
        Assert.Equal(1, r.Wire[2]);
        Assert.Equal(local, r.LocalPassword);
        Assert.True(_audit.Has(AuditKind.AllowOffline));
        Assert.Equal("tls: handshake refused", Assert.Single(_audit.Events, e => e.Kind == AuditKind.ServerUnreachable).Detail);
        Assert.Equal(mutations, _accounts.Mutations); // offline never changes the account
    }

    [Fact]
    public void Offline_wrong_password_is_denied_and_counted()
    {
        SignInOnlineThenGoOffline();
        var r = Login("alice", "nope");
        Assert.Equal(ReplyResult.Deny, r.Result);
        Assert.Equal(LoginHandler.Messages.InvalidCredentials, r.Message);
        Assert.Equal(1, _secrets.Failures["alice"]);
        Login("alice", "nope2");
        Assert.Equal(2, _secrets.Failures["alice"]);
    }

    [Fact]
    public void Offline_locks_after_repeated_failures_until_an_online_sign_in()
    {
        _settings = TestSettings.Create() with { OfflineMaxFailures = 3 };
        SignInOnlineThenGoOffline();
        for (var i = 0; i < 3; i++) Login("alice", "nope", Handler()); // fresh handler: no in-memory limiter help
        Assert.Equal(LoginHandler.Messages.OfflineLocked, Login("alice", "alice-pw").Message);
        _server.ForcedAnswer = null;
        Assert.Equal(ReplyResult.Ok, Login("alice", "alice-pw").Result);
        Assert.Equal(0, _secrets.Failures["alice"]);
        _server.Forced = ServerOutcome.NoAnswer;
        Assert.Equal(ReplyResult.Ok, Login("alice", "alice-pw").Result);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(10)]
    [InlineData(100)]
    public void Offline_lockout_threshold(int max)
    {
        _settings = TestSettings.Create() with { OfflineMaxFailures = max };
        SignInOnlineThenGoOffline();
        for (var i = 0; i < max - 1; i++)
            Assert.Equal(LoginHandler.Messages.InvalidCredentials, Login("alice", "nope", Handler()).Message);
        // One below the threshold the right password still works and resets the count.
        Assert.Equal(ReplyResult.Ok, Login("alice", "alice-pw").Result);
        Assert.Equal(0, _secrets.Failures["alice"]);
        for (var i = 0; i < max; i++) Login("alice", "nope", Handler());
        Assert.Equal(max, _secrets.Failures["alice"]);
        var r = Login("alice", "alice-pw");
        Assert.Equal(LoginHandler.Messages.OfflineLocked, r.Message);
        Assert.Equal(max, _secrets.Failures["alice"]); // a locked attempt is not checked, so not counted
        Assert.Equal("GetOfflineFailures", _secrets.Calls[^1]);
    }

    [Fact]
    public void Offline_never_signed_in_here_is_denied()
    {
        _server.Forced = ServerOutcome.NoAnswer;
        Assert.Equal(LoginHandler.Messages.OfflineNoAccount, Login("alice", "alice-pw").Message);
        Assert.Empty(_secrets.Calls);
    }

    [Fact]
    public void Offline_expired_account_is_denied()
    {
        SignInOnlineThenGoOffline();
        _clock.UtcNow = _clock.UtcNow.AddDays(181);
        Assert.Equal(LoginHandler.Messages.OfflineExpired, Login("alice", "alice-pw").Message);
    }

    [Theory]
    [InlineData(-86400, false)]
    [InlineData(-1, false)]
    [InlineData(0, false)] // expires at "now": expired
    [InlineData(1, true)]
    [InlineData(86400, true)]
    public void Offline_expiry_boundary(int secondsFromNow, bool allowed)
    {
        SignInOnlineThenGoOffline();
        _accounts.All["alice"].Expires = _clock.UtcNow.AddSeconds(secondsFromNow);
        var r = Login("alice", "alice-pw");
        Assert.Equal(allowed ? ReplyResult.Ok : ReplyResult.Deny, r.Result);
        if (!allowed) Assert.Equal(LoginHandler.Messages.OfflineExpired, r.Message);
    }

    [Fact]
    public void Offline_account_without_expiry_is_allowed()
    {
        SignInOnlineThenGoOffline();
        _accounts.All["alice"].Expires = null;
        _clock.UtcNow = _clock.UtcNow.AddYears(20);
        Assert.Equal(ReplyResult.Ok, Login("alice", "alice-pw").Result);
    }

    [Fact]
    public void Offline_disabled_account_is_denied()
    {
        SignInOnlineThenGoOffline();
        _accounts.All["alice"].Enabled = false;
        Assert.Equal(LoginHandler.Messages.AccountDisabled, Login("alice", "alice-pw").Message);
        Assert.True(_audit.Has(AuditKind.Deny, Reason.AccountDisabledLocally));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Offline_turned_off_is_denied(int days)
    {
        SignInOnlineThenGoOffline();
        _settings = TestSettings.Create(maxOfflineDays: days);
        Assert.Equal(LoginHandler.Messages.OfflineDisabled, Login("alice", "alice-pw").Message);
    }

    [Fact]
    public void Offline_without_a_verifier_is_denied()
    {
        SignInOnlineThenGoOffline();
        _secrets.Verifiers.Clear();
        Assert.Equal(LoginHandler.Messages.OfflineNoAccount, Login("alice", "alice-pw").Message);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]
    public void Offline_with_a_stored_verifier_of_the_wrong_size_is_denied(int size)
    {
        SignInOnlineThenGoOffline();
        byte[] padded = [.. FakeSeal.Verifier("alice-pw"), .. new byte[64]];
        _secrets.Verifiers["alice"] = padded[..size];
        Assert.Equal(LoginHandler.Messages.OfflineNoAccount, Login("alice", "alice-pw").Message);
        Assert.DoesNotContain("SetOfflineFailures", _secrets.Calls.Skip(_secrets.Calls.LastIndexOf("GetVerifier")));
    }

    [Fact]
    public void Offline_without_a_stored_local_password_is_denied()
    {
        SignInOnlineThenGoOffline();
        _secrets.LocalPasswords.Clear();
        _secrets.Failures["alice"] = 2;
        Assert.Equal(LoginHandler.Messages.OfflineNoAccount, Login("alice", "alice-pw").Message);
        Assert.Equal(2, _secrets.Failures["alice"]);
    }

    public enum OfflineCase
    {
        Ok, OfflineOff, NoAccount, Expired, Disabled, ExpiredAndDisabled, Locked, WrongPassword, NoVerifier,
        NoLocalPassword, LockedButRightPassword, OneBelowLock,
    }

    public static TheoryData<OfflineCase> OfflineCases() => [.. Enum.GetValues<OfflineCase>()];

    /// <summary>The whole offline decision table, with the reason recorded for each.</summary>
    [Theory]
    [MemberData(nameof(OfflineCases))]
    public void Offline_decision_table(OfflineCase c)
    {
        var local = SignInOnlineThenGoOffline();
        _audit.Events.Clear();
        var password = c == OfflineCase.WrongPassword ? "wrong" : "alice-pw";
        switch (c)
        {
            case OfflineCase.OfflineOff: _settings = TestSettings.Create(maxOfflineDays: 0); break;
            case OfflineCase.NoAccount: _accounts.All.Clear(); break;
            case OfflineCase.Expired: _clock.UtcNow = _clock.UtcNow.AddDays(180); break;
            case OfflineCase.Disabled: _accounts.All["alice"].Enabled = false; break;
            case OfflineCase.ExpiredAndDisabled:
                _accounts.All["alice"].Enabled = false;
                _clock.UtcNow = _clock.UtcNow.AddDays(200);
                break;
            case OfflineCase.Locked or OfflineCase.LockedButRightPassword: _secrets.Failures["alice"] = 10; break;
            case OfflineCase.OneBelowLock: _secrets.Failures["alice"] = 9; break;
            case OfflineCase.NoVerifier: _secrets.Verifiers.Clear(); break;
            case OfflineCase.NoLocalPassword: _secrets.LocalPasswords.Clear(); break;
        }

        var r = Login("alice", password);

        var (message, reason) = c switch
        {
            OfflineCase.Ok or OfflineCase.OneBelowLock => ((string?)null, Reason.None),
            OfflineCase.OfflineOff => (LoginHandler.Messages.OfflineDisabled, Reason.OfflineDisabled),
            OfflineCase.NoAccount or OfflineCase.NoVerifier or OfflineCase.NoLocalPassword =>
                (LoginHandler.Messages.OfflineNoAccount, Reason.OfflineNoAccount),
            OfflineCase.Expired or OfflineCase.ExpiredAndDisabled => (LoginHandler.Messages.OfflineExpired, Reason.OfflineExpired),
            OfflineCase.Disabled => (LoginHandler.Messages.AccountDisabled, Reason.AccountDisabledLocally),
            OfflineCase.Locked or OfflineCase.LockedButRightPassword => (LoginHandler.Messages.OfflineLocked, Reason.OfflineLocked),
            _ => (LoginHandler.Messages.InvalidCredentials, Reason.InvalidCredentials),
        };
        Assert.Equal(AuditKind.ServerUnreachable, _audit.Events[0].Kind);
        if (message is null)
        {
            Assert.Equal(ReplyResult.Ok, r.Result);
            Assert.Equal(SignInMode.Offline, r.Mode);
            Assert.Equal(local, r.LocalPassword);
            Assert.Equal(0, _secrets.Failures["alice"]);
            Assert.Equal(AuditKind.AllowOffline, _audit.Events[^1].Kind);
        }
        else
        {
            Assert.Equal(ReplyResult.Deny, r.Result);
            Assert.Equal(message, r.Message);
            Assert.Equal(new AuditEvent(AuditKind.Deny, "alice", reason), _audit.Events[^1]);
        }
        Assert.All(_secrets.IssuedVerifiers, v => Assert.All(v, b => Assert.Equal(0, b)));
    }

    public static TheoryData<string, bool> OfflineFailureSteps() => new()
    {
        { "GetOfflineFailures", true },
        { "GetVerifier", true },
        { "GetLocalPassword", true },
        { "SetOfflineFailures", true },  // the reset after a match
        { "SetOfflineFailures", false }, // the count after a mismatch
    };

    [Theory]
    [MemberData(nameof(OfflineFailureSteps))]
    public void Offline_store_failure_at_each_step(string op, bool rightPassword)
    {
        SignInOnlineThenGoOffline();
        _secrets.IssuedPasswords.Clear();
        _secrets.ThrowOn.Add(op);
        var r = Login("alice", rightPassword ? "alice-pw" : "nope");
        Assert.Equal(ReplyResult.Error, r.Result);
        Assert.Equal(LoginHandler.Messages.AccountError, r.Message);
        Assert.Null(r.LocalPassword);
        Assert.Equal($"{op} failed", Assert.Single(_audit.Events, e => e.Kind == AuditKind.Error).Detail);
        Assert.False(_audit.Has(AuditKind.AllowOffline));
        Assert.All(_secrets.IssuedVerifiers, v => Assert.All(v, b => Assert.Equal(0, b)));
        Assert.All(_secrets.IssuedPasswords, p => Assert.All(p, c => Assert.Equal('\0', c)));
    }

    [Fact]
    public void Offline_wrong_passwords_feed_the_local_rate_limiter()
    {
        SignInOnlineThenGoOffline();
        var handler = Handler();
        for (var i = 0; i < RateLimiter.MaxFailures; i++)
            Assert.Equal(LoginHandler.Messages.InvalidCredentials, Login("alice", "nope", handler).Message);
        var calls = _server.AuthCalls;
        Assert.Equal(LoginHandler.Messages.RateLimited, Login("alice", "alice-pw", handler).Message);
        Assert.Equal(calls, _server.AuthCalls);
    }

    [Fact]
    public void Offline_before_any_verifier_is_stored_cannot_be_used_to_plant_one()
    {
        // An account that exists but never had a confirmed online sign-in: offline must not store anything.
        _accounts.Add("alice");
        _secrets.LocalPasswords["alice"] = "ABCDEFGHJKLMNPQRabcdefgh23456789";
        _server.Forced = ServerOutcome.NoAnswer;
        Assert.Equal(LoginHandler.Messages.OfflineNoAccount, Login("alice", "alice-pw").Message);
        Assert.DoesNotContain("SetVerifier", _secrets.Calls);
        Assert.Empty(_secrets.Verifiers);
    }

    // ---- rate limiting ----

    [Fact]
    public void Local_rate_limit_stops_asking_the_server()
    {
        var handler = Handler();
        for (var i = 0; i < 5; i++) Login("alice", "nope", handler);
        var calls = _server.AuthCalls;
        var r = Login("alice", "alice-pw", handler);
        Assert.Equal(LoginHandler.Messages.RateLimited, r.Message);
        Assert.Equal(calls, _server.AuthCalls);
        Assert.True(_audit.Has(AuditKind.Deny, Reason.RateLimited));
    }

    [Fact]
    public void Rate_limit_lifts_after_the_lockout()
    {
        var handler = Handler();
        for (var i = 0; i < 5; i++) Login("alice", "nope", handler);
        _clock.UtcNow += RateLimiter.Lockout - TimeSpan.FromSeconds(1);
        Assert.Equal(LoginHandler.Messages.RateLimited, Login("alice", "alice-pw", handler).Message);
        _clock.UtcNow += TimeSpan.FromSeconds(1);
        Assert.Equal(ReplyResult.Ok, Login("alice", "alice-pw", handler).Result);
    }

    [Fact]
    public void Success_resets_the_failure_count()
    {
        var handler = Handler();
        for (var i = 0; i < 4; i++) Login("alice", "nope", handler);
        Assert.Equal(ReplyResult.Ok, Login("alice", "alice-pw", handler).Result);
        for (var i = 0; i < 4; i++) Login("alice", "nope", handler);
        Assert.Equal(ReplyResult.Ok, Login("alice", "alice-pw", handler).Result);
    }

    [Theory]
    [InlineData(ServerOutcome.Throttled)]
    [InlineData(ServerOutcome.Error)]
    public void Server_refusals_other_than_wrong_password_do_not_count(ServerOutcome outcome)
    {
        var handler = Handler();
        _server.Forced = outcome;
        for (var i = 0; i < 10; i++) Login("alice", "alice-pw", handler);
        _server.ForcedAnswer = null;
        Assert.Equal(ReplyResult.Ok, Login("alice", "alice-pw", handler).Result);
    }

    [Fact]
    public void Rate_limit_is_per_uun()
    {
        var handler = Handler();
        for (var i = 0; i < 5; i++) Login("alice", "nope", handler);
        Assert.Equal(ReplyResult.Ok, Login("bob", "bob-pw", handler).Result);
        Assert.Equal(LoginHandler.Messages.RateLimited, Login("alice", "alice-pw", handler).Message);
    }

    [Fact]
    public void Exclusion_and_management_are_checked_before_the_rate_limit()
    {
        _settings = TestSettings.Create() with { AdoptPreexisting = false };
        var limiter = new RateLimiter(_clock);
        for (var i = 0; i < 5; i++)
        {
            limiter.RecordFailure("breakglass");
            limiter.RecordFailure("alice");
        }
        _accounts.Add("alice", managed: false);
        Assert.Equal(LoginHandler.Messages.Excluded, Login("breakglass", "bg-pw", Handler(limiter)).Message);
        Assert.Equal(LoginHandler.Messages.NotManaged, Login("alice", "alice-pw", Handler(limiter)).Message);
    }

    // ---- disabling a removed user ----

    [Theory]
    [InlineData("SetEnabled")]
    [InlineData("ClearVerifier")]
    public void Failure_to_disable_a_removed_user_is_audited_and_still_denied(string op)
    {
        _accounts.Add("carol");
        _secrets.Verifiers["carol"] = new byte[32];
        (op == "SetEnabled" ? _accounts.ThrowOn : _secrets.ThrowOn).Add(op);
        var r = Login("carol", "carol-pw");
        Assert.Equal(ReplyResult.Deny, r.Result);
        Assert.Equal(LoginHandler.Messages.NotAuthorised, r.Message);
        Assert.Equal($"{op} failed", Assert.Single(_audit.Events, e => e.Kind == AuditKind.Error).Detail);
        // Independent steps: a failed disable still forgets the verifier, a failed forget still disables.
        Assert.Equal(op == "ClearVerifier", _audit.Has(AuditKind.AccountDisabled));
        Assert.Equal(op == "SetEnabled", _accounts.All["carol"].Enabled);
        Assert.Equal(op == "ClearVerifier", _secrets.Verifiers.ContainsKey("carol"));
    }

    [Fact]
    public void Removed_user_with_a_disabled_account_is_left_alone()
    {
        _accounts.Add("carol", enabled: false);
        Assert.Equal(LoginHandler.Messages.NotAuthorised, Login("carol", "carol-pw").Message);
        Assert.Equal(0, _accounts.Mutations);
    }

    // ---- messages and secrets ----

    [Fact]
    public void Messages_are_the_expected_set() => Assert.Equal(15, AllMessages.Distinct().Count());

    public static TheoryData<string> Messages() => [.. AllMessages];

    [Theory]
    [MemberData(nameof(Messages))]
    public void Messages_fit_the_reply_and_are_plain_sentences(string message)
    {
        Assert.InRange(message.Length, 1, Protocol.MaxMessageChars);
        Assert.True(message.EndsWith('.'), message);
        Assert.All(message, c => Assert.False(char.IsControl(c) || char.IsSurrogate(c)));
        Assert.DoesNotContain("{", message, StringComparison.Ordinal);
    }

    /// <summary>Every message in the set is actually produced by some path, and no path produces anything else.</summary>
    [Fact]
    public void Every_message_is_reachable()
    {
        // Each case arranges a fresh rig and may return the handler to use (for in-memory rate limiting).
        var cases = new (Func<LoginHandlerTests, LoginHandler?> Arrange, string Uun, string Password)[]
        {
            (_ => null, "Alice", "alice-pw"),
            (_ => null, "guest", "alice-pw"),
            (x => { x._settings = TestSettings.Create() with { AdoptPreexisting = false }; x._accounts.Add("alice", managed: false); return null; }, "alice", "alice-pw"),
            (x => { x._accounts.Add("alice", managed: false); return null; }, "alice", "alice-pw"), // adoption offered
            (x =>
            {
                var h = x.Handler();
                for (var i = 0; i < RateLimiter.MaxFailures; i++) x.Login("alice", "nope", h);
                return h;
            }, "alice", "alice-pw"),
            (_ => null, "alice", "nope"),
            (_ => null, "carol", "carol-pw"),
            (x => { x._server.Forced = ServerOutcome.Error; return null; }, "alice", "alice-pw"),
            (x => { x._server.Forced = ServerOutcome.Throttled; return null; }, "alice", "alice-pw"),
            (x => { x._accounts.ThrowOn.Add("Create"); return null; }, "alice", "alice-pw"),
            (x => { x._settings = TestSettings.Create(0); x._server.Forced = ServerOutcome.NoAnswer; return null; }, "alice", "alice-pw"),
            (x => { x._server.Forced = ServerOutcome.NoAnswer; return null; }, "alice", "alice-pw"),
            (x => { x._accounts.Add("alice", expires: x._clock.UtcNow); x._server.Forced = ServerOutcome.NoAnswer; return null; }, "alice", "alice-pw"),
            (x => { x._accounts.Add("alice"); x._secrets.Failures["alice"] = 10; x._server.Forced = ServerOutcome.NoAnswer; return null; }, "alice", "alice-pw"),
            (x => { x._accounts.Add("alice", enabled: false); x._server.Forced = ServerOutcome.NoAnswer; return null; }, "alice", "alice-pw"),
        };
        var seen = new List<string>();
        foreach (var (arrange, uun, password) in cases)
        {
            var rig = new LoginHandlerTests();
            var handler = arrange(rig);
            seen.Add(rig.Login(uun, password, handler).Message);
        }
        Assert.Equal(AllMessages.Order(), seen.Order());
    }

    [Fact]
    public void Nothing_secret_reaches_the_audit_log_on_any_path()
    {
        const string Password = "Tr0ub4dor&3-correct-horse";
        _server.Passwords["alice"] = Password;
        var handler = Handler();
        Login("alice", Password, handler);                               // create
        Login("alice", Password, handler);                               // refresh
        _server.Admins.Add("alice");
        Login("alice", Password, handler);                               // admin added
        _server.Forced = ServerOutcome.NoAnswer;
        Login("alice", Password, handler);                               // offline ok
        Login("alice", Password + "x", handler);                         // offline wrong
        _accounts.ThrowOn.Add("SetExpiry");
        _server.ForcedAnswer = null;
        Login("alice", Password, handler);                               // account error
        _accounts.ThrowOn.Clear();
        _server.Users.Remove("alice");
        Login("alice", Password, handler);                               // removed: disabled
        Assert.True(_audit.Events.Count >= 10);
        var text = _audit.AllText();
        Assert.DoesNotContain(Password, text, StringComparison.Ordinal);
        Assert.DoesNotContain("Tr0ub4dor", text, StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes(Password))[..12], text, StringComparison.Ordinal);
    }

    // ---- hardening: protected accounts, password convergence, offline scope, the last-admin guard ----

    [Fact]
    public void A_managed_account_made_force_local_is_refused_and_left_alone()
    {
        Login("alice", "alice-pw");
        _accounts.All["alice"].ForceLocal = true;
        var (calls, auths) = (_accounts.Calls.Count, _server.AuthCalls);
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Deny, r.Result);
        Assert.Equal(LoginHandler.Messages.Excluded, r.Message);
        Assert.True(_audit.Has(AuditKind.Deny, Reason.ForceLocal));
        Assert.Equal(auths, _server.AuthCalls);
        Assert.Equal(["Find"], _accounts.Calls.Skip(calls));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_built_in_account_is_refused_by_sid_whatever_its_name(bool managed)
    {
        _accounts.Add("alice", managed: managed, admin: true, builtIn: true); // e.g. the Administrator renamed "alice"
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Deny, r.Result);
        Assert.Equal(LoginHandler.Messages.Excluded, r.Message);
        Assert.True(_audit.Has(AuditKind.Deny, Reason.Excluded));
        Assert.Equal(0, _server.AuthCalls);
        Assert.Equal(0, _accounts.Mutations);
    }

    [Fact]
    public void Adoption_ignores_a_stale_stored_password_from_an_earlier_life()
    {
        const string Stale = "ABCDEFGHJKLMNPQRabcdefgh23456789";
        _accounts.Add("alice", managed: false).Password = "theirs";
        _secrets.LocalPasswords["alice"] = Stale;
        var r = Login("alice", "alice-pw", consent: true);
        Assert.Equal(ReplyResult.Ok, r.Result);
        var a = _accounts.All["alice"];
        Assert.NotEqual("theirs", a.Password);
        Assert.NotEqual(Stale, a.Password);
        Assert.Equal(a.Password, r.LocalPassword);
        Assert.Equal(a.Password, _secrets.LocalPasswords["alice"]);
    }

    /// <summary>SAM names are case-insensitive: a pre-existing "Alice" is adopted, and known, as alice.</summary>
    [Fact]
    public void A_mixed_case_pre_existing_account_is_adopted_as_the_user()
    {
        _accounts.Add("Alice", managed: false).Password = "theirs";
        var r = Login("alice", "alice-pw", consent: true);
        Assert.Equal(ReplyResult.Ok, r.Result);
        Assert.True(_accounts.All["alice"].Managed);
        Assert.Equal("alice", _accounts.Find("alice")!.Name);
        Assert.All(_audit.Events, e => Assert.Equal("alice", e.Uun));
    }

    [Fact]
    public void A_password_reset_by_hand_converges_back_at_the_next_online_sign_in()
    {
        Login("alice", "alice-pw");
        var stored = _secrets.LocalPasswords["alice"];
        _accounts.All["alice"].Password = "reset in lusrmgr";
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Ok, r.Result);
        Assert.Equal(stored, r.LocalPassword);
        Assert.Equal(stored, _accounts.All["alice"].Password);
        Assert.False(_audit.Has(AuditKind.PasswordSet)); // re-applied, not replaced
    }

    [Fact]
    public void Offline_never_signs_in_an_unmanaged_account()
    {
        _accounts.Add("alice", managed: false); // adoption is on by default
        _secrets.Verifiers["alice"] = FakeSeal.Verifier("alice-pw"); // leftovers from an earlier life of the name
        _secrets.LocalPasswords["alice"] = "ABCDEFGHJKLMNPQRabcdefgh23456789";
        _server.Forced = ServerOutcome.NoAnswer;
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Deny, r.Result);
        Assert.Equal(LoginHandler.Messages.OfflineNoAccount, r.Message);
        Assert.False(_audit.Has(AuditKind.AllowOffline));
        Assert.Empty(_secrets.Calls);
    }

    [Theory]
    [InlineData("")]
    [InlineData("short")]
    [InlineData("ABCDEFGHJKLMNPQRabcdefgh2345678 ")]  // 32 characters, one outside the alphabet
    [InlineData("ABCDEFGHJKLMNPQRabcdefgh234567890")] // 33 characters
    public void An_unusable_stored_password_is_replaced_online(string bad)
    {
        Login("alice", "alice-pw");
        _secrets.LocalPasswords["alice"] = bad;
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Ok, r.Result);
        Assert.True(LocalPasswords.IsValid(r.LocalPassword));
        Assert.Equal(r.LocalPassword, _accounts.All["alice"].Password);
        Assert.Equal(r.LocalPassword, _secrets.LocalPasswords["alice"]);
        Assert.Equal("stored local secret unusable", Assert.Single(_audit.Events, e => e.Kind == AuditKind.Error).Detail);
        Assert.True(_audit.Has(AuditKind.PasswordSet));
        Assert.Contains(_secrets.IssuedPasswords, p => p.Length == bad.Length && p.All(c => c == '\0')); // zeroed
    }

    [Fact]
    public void An_unusable_stored_password_refuses_offline_sign_in()
    {
        SignInOnlineThenGoOffline();
        _secrets.LocalPasswords["alice"] = "not what the generator makes!";
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Deny, r.Result);
        Assert.Equal(LoginHandler.Messages.OfflineNoAccount, r.Message);
    }

    [Fact]
    public void A_negative_offline_failure_count_is_treated_as_locked()
    {
        SignInOnlineThenGoOffline();
        _secrets.Failures["alice"] = -5;
        var r = Login("alice", "alice-pw");
        Assert.Equal(LoginHandler.Messages.OfflineLocked, r.Message);
    }

    [Fact]
    public void Online_sign_in_never_demotes_the_last_enabled_admin()
    {
        _accounts.Add("alice", admin: true);
        _server.ForcedAnswer = new ServerAnswer(ServerOutcome.Success, new UserFlags(true, false));
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Ok, r.Result);
        Assert.True(_accounts.All["alice"].Admin);
        Assert.True(_audit.Has(AuditKind.DemotionSkipped, Reason.LastAdmin));
        Assert.False(_audit.Has(AuditKind.AdminRemoved));
        Assert.DoesNotContain("SetAdmin", _accounts.Calls);
    }

    [Fact]
    public void Not_a_user_never_disables_the_last_enabled_admin_but_still_forgets_offline()
    {
        _accounts.Add("alice", admin: true);
        _secrets.Verifiers["alice"] = new byte[32];
        _server.ForcedAnswer = new ServerAnswer(ServerOutcome.Success, new UserFlags(false, false));
        var r = Login("alice", "alice-pw");
        Assert.Equal(LoginHandler.Messages.NotAuthorised, r.Message);
        Assert.True(_accounts.All["alice"].Enabled);
        Assert.False(_secrets.Verifiers.ContainsKey("alice"));
        Assert.True(_audit.Has(AuditKind.DisableSkipped, Reason.LastAdmin));
        Assert.DoesNotContain("SetEnabled", _accounts.Calls);
    }

    // ---- concurrency: the server round trip is outside the account lock; the decision is on fresh state ----

    [Fact]
    public void The_account_lock_is_free_while_the_server_is_asked()
    {
        var gate = new Lock();
        bool? freeMeanwhile = null;
        _server.OnAuthenticate = () =>
        {
            // Another thread tries the lock while this one is inside the server call.
            var probe = new Thread(() =>
            {
                freeMeanwhile = gate.TryEnter();
                if (freeMeanwhile == true) gate.Exit();
            });
            probe.Start();
            probe.Join();
        };
        var handler = new LoginHandler(_settings, _server, _accounts, _secrets, _audit, _clock, new RateLimiter(_clock), gate);
        Assert.Equal(ReplyResult.Ok, Login("alice", "alice-pw", handler).Result);
        Assert.True(freeMeanwhile);
    }

    [Fact]
    public async Task Two_sign_ins_ask_the_server_at_the_same_time()
    {
        using var both = new Barrier(2);
        var met = 0;
        _server.OnAuthenticate = () => { if (both.SignalAndWait(TimeSpan.FromSeconds(10))) Interlocked.Increment(ref met); };
        var handler = Handler();
        var a = Task.Run(() => Login("alice", "alice-pw", handler));
        var b = Task.Run(() => Login("bob", "bob-pw", handler));
        var results = await Task.WhenAll(a, b).WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Equal(2, met); // each was inside the server call while the other was too
        Assert.All(results, r => Assert.Equal(ReplyResult.Ok, r.Result));
    }

    [Fact]
    public void An_account_made_force_local_while_the_server_was_asked_is_refused_and_untouched()
    {
        _accounts.Add("alice");
        _server.OnAuthenticate = () => _accounts.All["alice"].ForceLocal = true;
        var r = Login("alice", "alice-pw");
        Assert.Equal(LoginHandler.Messages.Excluded, r.Message);
        Assert.Equal(0, _accounts.Mutations);
        Assert.Empty(_secrets.Verifiers);
    }

    [Fact]
    public void An_account_another_sign_in_created_meanwhile_is_synced_not_created_again()
    {
        _server.OnAuthenticate = () => _accounts.Add("alice");
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Ok, r.Result);
        Assert.DoesNotContain("Create", _accounts.Calls);
        Assert.Equal(r.LocalPassword, _accounts.All["alice"].Password);
    }

    [Fact]
    public void An_account_lookup_failure_after_the_server_answered_is_an_error()
    {
        _server.OnAuthenticate = () => _accounts.ThrowOn.Add("Find");
        var r = Login("alice", "alice-pw");
        Assert.Equal(ReplyResult.Error, r.Result);
        Assert.Equal(LoginHandler.Messages.AccountError, r.Message);
        Assert.Equal(0, _accounts.Mutations);
    }

    // ---- adoption never escalates or revives ----

    /// <summary>The last-admin guard would otherwise keep a non-admin directory user a local admin for good.</summary>
    [Fact]
    public void A_pre_existing_local_admin_is_not_adopted_by_a_non_admin_user()
    {
        _accounts.Add("alice", managed: false, admin: true).Password = "theirs"; // the PC's only admin
        foreach (var consent in new[] { false, true })
        {
            var r = Login("alice", "alice-pw", consent: consent);
            Assert.Equal(ReplyResult.Deny, r.Result);
            Assert.Equal(LoginHandler.Messages.NotManaged, r.Message);
        }
        Assert.False(_accounts.All["alice"].Managed);
        Assert.True(_accounts.All["alice"].Admin);
        Assert.Equal("theirs", _accounts.All["alice"].Password);
        Assert.Equal(0, _accounts.Mutations);
    }

    [Fact]
    public void A_pre_existing_local_admin_is_adopted_by_a_directory_admin()
    {
        _accounts.Add("bob", managed: false, admin: true).Password = "theirs";
        Assert.Equal(ReplyResult.Adopt, Login("bob", "bob-pw").Result);
        Assert.Equal(ReplyResult.Ok, Login("bob", "bob-pw", consent: true).Result);
        Assert.True(_accounts.All["bob"].Managed);
        Assert.True(_accounts.All["bob"].Admin);
    }

    [Fact]
    public void A_disabled_pre_existing_account_is_not_adopted()
    {
        _accounts.Add("alice", managed: false, enabled: false).Password = "theirs";
        var r = Login("alice", "alice-pw", consent: true);
        Assert.Equal(LoginHandler.Messages.NotManaged, r.Message);
        Assert.False(_accounts.All["alice"].Enabled);
        Assert.False(_accounts.All["alice"].Managed);
        Assert.Equal(0, _accounts.Mutations);
    }
}

public class ReconcilerTests
{
    private readonly FakeClock _clock = new();
    private readonly FakeServer _server = new();
    private readonly FakeAccounts _accounts = new();
    private readonly FakeSecrets _secrets = new();
    private readonly ListAudit _audit = new();

    private void Run(LoginSettings? settings = null) =>
        new Reconciler(settings ?? TestSettings.Create(), _server, _accounts, _secrets, _audit, _clock).Run();

    private string Summary() => _audit.Events.Last(e => e.Kind == AuditKind.CleanupRun).Detail!;

    // ---- managed accounts: removed users, admin sync ----

    [Fact]
    public void Removed_user_loses_the_offline_verifier_even_if_already_disabled()
    {
        _accounts.Add("alice");
        _accounts.Add("dave", enabled: false);
        _server.Users.Add("alice");
        _secrets.Verifiers["alice"] = new byte[32];
        _secrets.Verifiers["dave"] = new byte[32];
        Run();
        Assert.True(_secrets.Verifiers.ContainsKey("alice"));
        Assert.False(_secrets.Verifiers.ContainsKey("dave"));
    }

    [Fact]
    public void No_answer_keeps_every_verifier_and_changes_nothing()
    {
        _accounts.Add("dave");
        _secrets.Verifiers["dave"] = new byte[32];
        _server.StatusFails = true;
        Run();
        Assert.True(_secrets.Verifiers.ContainsKey("dave"));
        Assert.Equal(0, _accounts.Mutations);
        Assert.True(_audit.Has(AuditKind.CleanupSkipped, Reason.ServerError));
        Assert.False(_audit.Has(AuditKind.CleanupRun));
    }

    [Fact]
    public void Disables_managed_accounts_no_longer_users()
    {
        _accounts.Add("alice");
        _accounts.Add("dave", admin: true);
        _accounts.Add("backup", forceLocal: true, admin: true); // backstop admin, never touched
        _server.Users.Add("alice");
        Run();
        Assert.True(_accounts.All["alice"].Enabled);
        Assert.False(_accounts.All["dave"].Enabled);
        Assert.False(_accounts.All["dave"].Admin);
        Assert.True(_accounts.All["backup"].Enabled);
        Assert.True(_audit.Has(AuditKind.AccountDisabled, Reason.RemovedFromUsers));
        Assert.True(_audit.Has(AuditKind.AdminRemoved, Reason.RemovedFromUsers));
    }

    [Fact]
    public void Syncs_admins_both_ways()
    {
        _accounts.Add("alice");
        _accounts.Add("bob", admin: true);
        _accounts.Add("backup", forceLocal: true, admin: true); // so bob is never the last admin
        _server.Users.UnionWith(["alice", "bob"]);
        _server.Admins.Add("alice");
        Run();
        Assert.True(_accounts.All["alice"].Admin);
        Assert.False(_accounts.All["bob"].Admin);
        Assert.True(_audit.Has(AuditKind.AdminAdded, Reason.AdminSync));
        Assert.True(_audit.Has(AuditKind.AdminRemoved, Reason.AdminSync));
        Assert.True(_accounts.All["alice"].Enabled);
        Assert.True(_accounts.All["bob"].Enabled);
    }

    [Fact]
    public void Admin_without_user_is_not_admin()
    {
        _accounts.Add("alice");
        _accounts.Add("backup", forceLocal: true, admin: true);
        _server.StatusOverride = asked => new StatusSnapshot(new HashSet<string>(), asked.ToHashSet());
        Run();
        Assert.False(_accounts.All["alice"].Admin);
        Assert.False(_accounts.All["alice"].Enabled);
    }

    // ---- idle disable ----

    [Fact]
    public void Idle_managed_user_is_disabled()
    {
        _accounts.Add("alice", lastLogon: _clock.UtcNow.AddDays(-40));
        _accounts.Add("kiosk", forceLocal: true, lastLogon: _clock.UtcNow); // the device is in use today
        _server.Users.Add("alice");
        Run();
        Assert.False(_accounts.All["alice"].Enabled);
        Assert.False(_secrets.Verifiers.ContainsKey("alice"));
        Assert.True(_audit.Has(AuditKind.AccountDisabled, Reason.Idle));
        Assert.Equal("1 subjects, 1 changes", Summary());
    }

    [Theory]
    [InlineData(-40, 30, false)]  // idle 40d, threshold 30d: disabled
    [InlineData(-29, 30, true)]   // used 29d ago: kept
    [InlineData(-31, 30, false)]
    [InlineData(-30, 30, false)]  // exactly at the threshold: disabled
    [InlineData(-400, 0, true)]   // idle disable off: kept
    public void Idle_threshold(int lastLogonDays, int idleDays, bool stillEnabled)
    {
        _accounts.Add("alice", lastLogon: _clock.UtcNow.AddDays(lastLogonDays));
        _accounts.Add("kiosk", forceLocal: true, lastLogon: _clock.UtcNow); // the device is in use today
        _server.Users.Add("alice");
        Run(TestSettings.Create() with { IdleDisableDays = idleDays });
        Assert.Equal(stillEnabled, _accounts.All["alice"].Enabled);
    }

    [Fact]
    public void A_user_that_never_logged_on_is_not_idle_reaped()
    {
        _accounts.Add("alice", lastLogon: null);
        _server.Users.Add("alice");
        Run();
        Assert.True(_accounts.All["alice"].Enabled);
    }

    [Fact]
    public void An_already_disabled_idle_account_is_not_touched_again()
    {
        _accounts.Add("alice", enabled: false, lastLogon: _clock.UtcNow.AddDays(-99));
        _server.Users.Add("alice");
        Run();
        Assert.Equal(0, _accounts.Mutations);
        Assert.Equal("1 subjects, 0 changes", Summary());
    }

    // ---- lockdown of unmanaged, unprotected accounts ----

    [Fact]
    public void Lockdown_dry_run_reports_but_disables_nothing()
    {
        _accounts.Add("stranger", managed: false);
        Run(); // LockdownEnforce is off by default
        Assert.True(_accounts.All["stranger"].Enabled);
        Assert.Equal(0, _accounts.Mutations);
        Assert.True(_audit.Has(AuditKind.WouldDisable, Reason.Lockdown));
    }

    [Fact]
    public void Lockdown_armed_disables_an_account_unknown_to_ldap()
    {
        _accounts.Add("stranger", managed: false);
        _accounts.Add("backup", forceLocal: true, admin: true);
        Run(TestSettings.Create() with { LockdownEnforce = true });
        Assert.False(_accounts.All["stranger"].Enabled);
        Assert.True(_audit.Has(AuditKind.AccountDisabled, Reason.Lockdown));
        Assert.False(_audit.Has(AuditKind.WouldDisable));
    }

    [Fact]
    public void Lockdown_leaves_an_unmanaged_account_known_to_ldap_alone()
    {
        _accounts.Add("alice", managed: false); // a valid UUN the server knows: adopted at next sign-in
        _server.Users.Add("alice");
        Run(TestSettings.Create() with { LockdownEnforce = true });
        Assert.True(_accounts.All["alice"].Enabled);
        Assert.Equal(0, _accounts.Mutations);
        Assert.Contains("alice", Assert.Single(_server.StatusRequests));
    }

    [Fact]
    public void Lockdown_disables_an_account_whose_name_cannot_be_an_ldap_user()
    {
        _accounts.Add("has space", managed: false); // not a valid UUN: never asked about, cannot be a user
        _accounts.Add("o.brien", managed: false);
        _accounts.Add("backup", forceLocal: true, admin: true);
        Run(TestSettings.Create() with { LockdownEnforce = true });
        Assert.False(_accounts.All["has space"].Enabled);
        Assert.False(_accounts.All["o.brien"].Enabled);
        Assert.Empty(_server.StatusRequests); // no valid-UUN subjects to ask about
        Assert.DoesNotContain("SetEnabled", _accounts.Calls); // only ever through the lockdown call
    }

    /// <summary>SAM names are case-insensitive: "Alice" is the user alice, asked about and left alone.</summary>
    [Fact]
    public void Lockdown_leaves_a_mixed_case_account_of_a_known_user_alone()
    {
        _accounts.Add("Alice", managed: false);
        _server.Users.Add("alice");
        Run(TestSettings.Create() with { LockdownEnforce = true });
        Assert.True(_accounts.All["Alice"].Enabled);
        Assert.Equal(["alice"], Assert.Single(_server.StatusRequests));
        Assert.False(_audit.Has(AuditKind.WouldDisable));
    }

    [Fact]
    public void An_already_disabled_stranger_is_not_touched_under_lockdown()
    {
        _accounts.Add("stranger", managed: false, enabled: false);
        Run(TestSettings.Create() with { LockdownEnforce = true });
        Assert.Equal(0, _accounts.Mutations);
        Assert.False(_audit.Has(AuditKind.WouldDisable));
    }

    [Fact]
    public void A_lockdown_no_answer_changes_nothing()
    {
        _accounts.Add("alice", managed: false); // valid UUN forces a status read
        _accounts.Add("stranger", managed: false);
        _server.StatusFails = true;
        Run(TestSettings.Create() with { LockdownEnforce = true });
        Assert.True(_accounts.All["stranger"].Enabled);
        Assert.Equal(0, _accounts.Mutations);
        Assert.True(_audit.Has(AuditKind.CleanupSkipped, Reason.ServerError));
    }

    // ---- never touches protected accounts ----

    [Fact]
    public void Leaves_excluded_and_force_local_accounts_alone()
    {
        _accounts.Add("someone", managed: false, forceLocal: true);
        _accounts.Add("breakglass"); // excluded by TestSettings
        _accounts.Add("administrator", admin: true);
        Run(TestSettings.Create() with { LockdownEnforce = true });
        Assert.True(_accounts.All["someone"].Enabled);
        Assert.True(_accounts.All["breakglass"].Enabled);
        Assert.True(_accounts.All["administrator"].Admin);
        Assert.Empty(_server.StatusRequests);
        Assert.Equal("0 subjects, 0 changes", Summary());
    }

    // ---- last-admin invariant ----

    [Fact]
    public void The_last_enabled_admin_is_never_disabled()
    {
        _accounts.Add("alice", admin: true, lastLogon: _clock.UtcNow.AddDays(-99)); // idle, and the only admin
        _accounts.Add("kiosk", forceLocal: true, lastLogon: _clock.UtcNow);
        _server.Users.Add("alice");
        Run();
        Assert.True(_accounts.All["alice"].Enabled);
        Assert.True(_accounts.All["alice"].Admin); // nor demoted: the server no longer says admin, but it is the last
        Assert.True(_audit.Has(AuditKind.DisableSkipped, Reason.LastAdmin));
        Assert.True(_audit.Has(AuditKind.DemotionSkipped, Reason.LastAdmin));
        Assert.False(_audit.Has(AuditKind.AccountDisabled));
        Assert.False(_audit.Has(AuditKind.AdminRemoved));
    }

    /// <summary>The guard used to decline the disable, then demote the account in the same pass: no admin left.</summary>
    [Fact]
    public void A_removed_last_admin_stays_enabled_and_admin_but_loses_offline_sign_in()
    {
        _accounts.Add("alice", admin: true);
        _secrets.Verifiers["alice"] = new byte[32];
        Run(); // alice is no longer a user at all
        Assert.True(_accounts.All["alice"].Enabled);
        Assert.True(_accounts.All["alice"].Admin);
        Assert.False(_secrets.Verifiers.ContainsKey("alice"));
        Assert.True(_audit.Has(AuditKind.DisableSkipped, Reason.LastAdmin));
        Assert.True(_audit.Has(AuditKind.DemotionSkipped, Reason.LastAdmin));
    }

    [Fact]
    public void A_protected_backup_admin_lets_the_last_managed_admin_be_disabled()
    {
        _accounts.Add("alice", admin: true, lastLogon: _clock.UtcNow.AddDays(-99));
        _accounts.Add("backup", forceLocal: true, admin: true, lastLogon: _clock.UtcNow); // the backstop, in use
        _server.Users.Add("alice");
        Run();
        Assert.False(_accounts.All["alice"].Enabled);
        Assert.True(_audit.Has(AuditKind.AccountDisabled, Reason.Idle));
    }

    [Fact]
    public void With_two_managed_admins_removed_one_is_kept_as_the_backstop()
    {
        _accounts.Add("alice", admin: true);
        _accounts.Add("bob", admin: true);
        // Neither is a user any more: one disable must be declined so an enabled admin remains.
        Run(TestSettings.Create() with { LockdownEnforce = true });
        var enabled = new[] { "alice", "bob" }.Where(n => _accounts.All[n].Enabled).ToList();
        var kept = Assert.Single(enabled);
        Assert.True(_accounts.All[kept].Admin); // the backstop keeps its admin rights too
        Assert.True(_audit.Has(AuditKind.DisableSkipped, Reason.LastAdmin));
    }

    // ---- framing, batching, failure handling ----

    [Fact]
    public void No_subjects_makes_no_server_call()
    {
        _accounts.Add("breakglass"); // excluded
        _accounts.Add("backup", forceLocal: true);
        Run();
        Assert.Empty(_server.StatusRequests);
        Assert.Equal("0 subjects, 0 changes", Summary());
    }

    [Fact]
    public void Listing_failure_is_skipped_without_a_server_call()
    {
        _accounts.Add("alice");
        _accounts.ThrowOn.Add("ListAll");
        Run();
        Assert.Empty(_server.StatusRequests);
        var e = Assert.Single(_audit.Events);
        Assert.Equal(new AuditEvent(AuditKind.CleanupSkipped, "-", Reason.AccountError, "ListAll failed"), e);
    }

    [Fact]
    public void A_failure_on_one_account_does_not_stop_the_others()
    {
        _accounts.Add("alice");
        _accounts.Add("bob");
        _accounts.Add("carol");
        _accounts.ThrowFor.Add("bob");
        Run(); // none are users: all would be disabled
        Assert.False(_accounts.All["alice"].Enabled);
        Assert.True(_accounts.All["bob"].Enabled);
        Assert.False(_accounts.All["carol"].Enabled);
        var e = Assert.Single(_audit.Events, e => e.Kind == AuditKind.Error);
        Assert.Equal("bob", e.Uun);
        Assert.Equal(Reason.AccountError, e.Reason);
    }

    [Theory]
    [InlineData("SetEnabled")]
    [InlineData("SetAdmin")]
    public void Each_operation_failure_is_audited(string op)
    {
        _accounts.Add("alice", admin: true);
        _accounts.Add("backup", forceLocal: true, admin: true);
        _accounts.ThrowOn.Add(op);
        Run();
        Assert.Equal($"{op} failed", Assert.Single(_audit.Events, e => e.Kind == AuditKind.Error).Detail);
    }

    public static TheoryData<bool, bool, bool, bool, bool, bool> Table()
    {
        var data = new TheoryData<bool, bool, bool, bool, bool, bool>();
        foreach (var enabled in new[] { false, true })
            foreach (var admin in new[] { false, true })
                foreach (var user in new[] { false, true })
                    foreach (var serverAdmin in new[] { false, true })
                        data.Add(enabled, admin, user, serverAdmin, enabled && !user, user && serverAdmin);
        return data;
    }

    /// <summary>
    /// Every combination of local (enabled, admin) and server (user, admin) for a managed account, with a
    /// force-local backstop present so the last-admin guard never interferes: disabled iff no longer a user;
    /// admin iff user and admin. Never enables anyone (only an online sign-in does).
    /// </summary>
    [Theory]
    [MemberData(nameof(Table))]
    public void Managed_decision_table(bool enabled, bool admin, bool user, bool serverAdmin, bool disables, bool adminAfter)
    {
        _accounts.Add("alice", enabled: enabled, admin: admin);
        _accounts.Add("backup", forceLocal: true, admin: true, enabled: true);
        if (user) _server.Users.Add("alice");
        if (serverAdmin) _server.Admins.Add("alice");
        Run();
        var a = _accounts.All["alice"];
        Assert.Equal(enabled && !disables, a.Enabled);
        Assert.Equal(adminAfter, a.Admin);
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(99, 1)]
    [InlineData(100, 1)]
    [InlineData(101, 2)]
    [InlineData(250, 3)]
    public void Many_accounts_are_asked_about_in_batches(int count, int requests)
    {
        var names = Enumerable.Range(0, count).Select(i => $"u{i:D4}").ToList();
        foreach (var n in names) _accounts.Add(n);
        _server.Users.UnionWith(names);
        Run();
        Assert.Equal(requests, _server.StatusRequests.Count);
        Assert.All(_server.StatusRequests, r => Assert.InRange(r.Length, 1, ServerMessages.MaxStatusUuns));
        Assert.Equal(names.Order(), _server.StatusRequests.SelectMany(r => r).Order());
        Assert.All(_accounts.All.Values, a => Assert.True(a.Enabled));
        Assert.Equal(0, _accounts.Mutations);
    }

    [Fact]
    public void A_failed_batch_changes_nothing_at_all()
    {
        var names = Enumerable.Range(0, 150).Select(i => $"u{i:D4}").ToList();
        foreach (var n in names) _accounts.Add(n);
        var calls = 0;
        _server.StatusOverride = asked => ++calls == 2 ? null : new StatusSnapshot(new HashSet<string>(), new HashSet<string>());
        Run();
        Assert.Equal(0, _accounts.Mutations);
        Assert.True(_audit.Has(AuditKind.CleanupSkipped, Reason.ServerError));
    }

    // ---- hardening: the two-phase pass, a wrong clock, protected accounts, independent steps ----

    private Reconciler Reconciler(LoginSettings? settings = null) =>
        new(settings ?? TestSettings.Create(), _server, _accounts, _secrets, _audit, _clock);

    [Fact]
    public void An_account_that_appears_between_read_and_apply_waits_for_the_next_pass()
    {
        _accounts.Add("alice");
        var r = Reconciler();
        var plan = r.Read()!;
        _accounts.Add("dave");                          // created by a sign-in while the server was being asked
        r.Apply(plan);
        Assert.True(_accounts.All["dave"].Enabled);     // not asked about, so not "not a user"
        Assert.False(_accounts.All["alice"].Enabled);   // asked about, and not a user
        Assert.Equal(["alice"], Assert.Single(_server.StatusRequests));
    }

    [Fact]
    public void Read_with_no_answer_returns_no_plan_and_changes_nothing()
    {
        _accounts.Add("alice");
        _server.StatusFails = true;
        Assert.Null(Reconciler().Read());
        Assert.Equal(0, _accounts.Mutations);
    }

    [Fact]
    public void Apply_with_an_unreadable_account_list_changes_nothing()
    {
        _accounts.Add("alice");
        var r = Reconciler();
        var plan = r.Read()!;
        _accounts.ThrowOn.Add("ListAll");
        r.Apply(plan);
        Assert.Equal(0, _accounts.Mutations);
        Assert.True(_audit.Has(AuditKind.CleanupSkipped, Reason.AccountError));
    }

    [Fact]
    public void Apply_refuses_a_null_plan() => Assert.Throws<ArgumentNullException>(() => Reconciler().Apply(null!));

    /// <summary>A clock stepped a year forward at boot must not make every account idle at once.</summary>
    [Fact]
    public void A_clock_stepped_forward_does_not_idle_disable_everyone()
    {
        _accounts.Add("alice", lastLogon: _clock.UtcNow.AddDays(-1));
        _accounts.Add("bob", lastLogon: _clock.UtcNow.AddDays(-2));
        _server.Users.UnionWith(["alice", "bob"]);
        _clock.UtcNow = _clock.UtcNow.AddDays(365);
        Run();
        Assert.True(_accounts.All["alice"].Enabled);
        Assert.True(_accounts.All["bob"].Enabled);
        Assert.False(_audit.Has(AuditKind.AccountDisabled));
    }

    /// <summary>Idle is relative to the device's own use: a sole user back from a month away is not locked out.</summary>
    [Fact]
    public void The_only_user_of_a_device_left_switched_off_is_not_idle()
    {
        _accounts.Add("alice", lastLogon: _clock.UtcNow.AddDays(-45));
        _server.Users.Add("alice");
        Run();
        Assert.True(_accounts.All["alice"].Enabled);
    }

    [Fact]
    public void Idle_is_measured_against_the_most_recent_logon_on_the_device()
    {
        _accounts.Add("alice", lastLogon: _clock.UtcNow.AddDays(-50)); // 40 days before the newest logon: idle
        _accounts.Add("bob", lastLogon: _clock.UtcNow.AddDays(-10));   // newest; the device sat unused since
        _accounts.Add("carol", lastLogon: _clock.UtcNow.AddDays(-35)); // 25 days before it: not idle
        _server.Users.UnionWith(["alice", "bob", "carol"]);
        Run();
        Assert.False(_accounts.All["alice"].Enabled);
        Assert.True(_accounts.All["bob"].Enabled);
        Assert.True(_accounts.All["carol"].Enabled);
    }

    [Fact]
    public void A_logon_from_the_future_does_not_move_the_idle_reference_past_now()
    {
        _accounts.Add("alice", lastLogon: _clock.UtcNow.AddDays(-40));
        _accounts.Add("kiosk", forceLocal: true, lastLogon: _clock.UtcNow.AddDays(30)); // stamped by a wrong clock
        _server.Users.Add("alice");
        Run();
        Assert.False(_accounts.All["alice"].Enabled); // measured against now, not 30 days ahead
    }

    [Fact]
    public void Built_in_accounts_are_never_subjects_even_under_lockdown()
    {
        _accounts.Add("admin2", managed: false, admin: true, builtIn: true); // the Administrator, renamed
        _accounts.Add("gast", managed: false, builtIn: true);                // the Guest, localised
        Run(TestSettings.Create() with { LockdownEnforce = true });
        Assert.True(_accounts.All["admin2"].Enabled);
        Assert.True(_accounts.All["gast"].Enabled);
        Assert.Equal(0, _accounts.Mutations);
        Assert.Equal("0 subjects, 0 changes", Summary());
    }

    [Fact]
    public void Lockdown_never_disables_the_last_enabled_admin()
    {
        _accounts.Add("stranger", managed: false, admin: true);
        Run(TestSettings.Create() with { LockdownEnforce = true });
        Assert.True(_accounts.All["stranger"].Enabled);
        Assert.Equal("would have been: Lockdown",
            Assert.Single(_audit.Events, e => e.Kind == AuditKind.DisableSkipped).Detail);
    }

    [Fact]
    public void A_lockdown_disable_failure_is_audited_and_the_pass_goes_on()
    {
        _accounts.Add("stranger", managed: false);
        _accounts.Add("other", managed: false);
        _accounts.ThrowFor.Add("stranger");
        Run(TestSettings.Create() with { LockdownEnforce = true });
        Assert.True(_accounts.All["stranger"].Enabled);
        Assert.False(_accounts.All["other"].Enabled);
        Assert.True(_audit.Has(AuditKind.Error, Reason.AccountError));
    }

    [Theory]
    [InlineData("SetEnabled")]
    [InlineData("ClearVerifier")]
    public void A_removed_user_is_disabled_and_forgotten_independently(string op)
    {
        _accounts.Add("dave");
        _accounts.Add("backup", forceLocal: true, admin: true);
        _secrets.Verifiers["dave"] = new byte[32];
        (op == "SetEnabled" ? _accounts.ThrowOn : _secrets.ThrowOn).Add(op);
        Run();
        Assert.Equal(op == "SetEnabled", _accounts.All["dave"].Enabled);
        Assert.Equal(op == "ClearVerifier", _secrets.Verifiers.ContainsKey("dave"));
        Assert.Equal($"{op} failed", Assert.Single(_audit.Events, e => e.Kind == AuditKind.Error).Detail);
    }

    [Fact]
    public void Last_enabled_admin_needs_exactly_one_enabled_admin()
    {
        LocalAccount A(string n, bool admin = true, bool enabled = true) => new(n, true, enabled, admin, null);
        Assert.True(Weldap.Reconciler.IsLastEnabledAdmin([A("alice"), A("bob", admin: false)], "alice"));
        Assert.False(Weldap.Reconciler.IsLastEnabledAdmin([A("alice"), A("bob")], "alice"));
        Assert.False(Weldap.Reconciler.IsLastEnabledAdmin([A("alice"), A("bob")], "carol"));
        Assert.True(Weldap.Reconciler.IsLastEnabledAdmin([A("alice"), A("bob", enabled: false)], "alice"));
        Assert.False(Weldap.Reconciler.IsLastEnabledAdmin([A("bob")], "alice"));
        Assert.False(Weldap.Reconciler.IsLastEnabledAdmin([], "alice"));
    }

    /// <summary>The guard keeps a working local admin, not a removed WELDAP user nobody can sign in as.</summary>
    [Fact]
    public void Lockdown_keeps_the_usable_admin_not_a_removed_managed_one()
    {
        _accounts.Add("helpdesk", managed: false, admin: true); // listed first, as SAM may
        _accounts.Add("alice", admin: true);                    // managed, removed from the directory
        Run(TestSettings.Create() with { LockdownEnforce = true });
        Assert.True(_accounts.All["helpdesk"].Enabled);
        Assert.False(_accounts.All["alice"].Enabled);
        Assert.True(_audit.Has(AuditKind.DisableSkipped, Reason.LastAdmin));
    }
}
