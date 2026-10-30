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

    private Outcome Login(string uun, string password, LoginHandler? handler = null, Scenario scenario = Scenario.Logon)
    {
        using var request = ProtocolCodec.TryParseRequest(RequestBuilder.For(uun, password, scenario).Build())!;
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
        Assert.Equal(LoginHandler.Messages.RateLimited, r.Message);
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
    public void Unmanaged_local_account_is_never_taken_over(bool enabled)
    {
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
        using var request = new LoginRequest(Scenario.Logon, uun,
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
            ServerOutcome.Throttled => LoginHandler.Messages.RateLimited,
            ServerOutcome.Error => LoginHandler.Messages.ServerError,
            _ => LoginHandler.Messages.NotAuthorised,
        }, r.Message);
        Assert.DoesNotContain("SetVerifier", _secrets.Calls);
        Assert.DoesNotContain("Create", _accounts.Calls);
        Assert.DoesNotContain("SetPassword", _accounts.Calls);
        Assert.DoesNotContain("SetAdmin", _accounts.Calls);
        if (state == LocalState.None)
        {
            Assert.Empty(_accounts.All);
            return;
        }
        var disables = notUser && state is LocalState.Enabled or LocalState.EnabledAdmin;
        Assert.Equal(!disables && state != LocalState.Disabled, _accounts.All["alice"].Enabled);
        Assert.Equal(!disables, _secrets.Verifiers.ContainsKey("alice"));
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
        Assert.Equal(["Find", "Create", "SetExpiry", "EnsureUser"], _accounts.Calls);
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
        Assert.False(_audit.Has(AuditKind.AccountDisabled));
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
    public void Messages_are_the_expected_set() => Assert.Equal(13, AllMessages.Distinct().Count());

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
            (x => { x._accounts.Add("alice", managed: false); return null; }, "alice", "alice-pw"),
            (x =>
            {
                var h = x.Handler();
                for (var i = 0; i < RateLimiter.MaxFailures; i++) x.Login("alice", "nope", h);
                return h;
            }, "alice", "alice-pw"),
            (_ => null, "alice", "nope"),
            (_ => null, "carol", "carol-pw"),
            (x => { x._server.Forced = ServerOutcome.Error; return null; }, "alice", "alice-pw"),
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
}

public class ReconcilerTests
{
    private readonly FakeServer _server = new();
    private readonly FakeAccounts _accounts = new();
    private readonly FakeSecrets _secrets = new();
    private readonly ListAudit _audit = new();

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
    public void No_answer_keeps_every_verifier()
    {
        _accounts.Add("dave");
        _secrets.Verifiers["dave"] = new byte[32];
        _server.StatusFails = true;
        Run();
        Assert.True(_secrets.Verifiers.ContainsKey("dave"));
    }

    private void Run() => new Reconciler(TestSettings.Create(), _server, _accounts, _secrets, _audit).Run();

    private string Summary() => _audit.Events.Last(e => e.Kind == AuditKind.CleanupRun).Detail!;

    [Fact]
    public void Disables_accounts_no_longer_users()
    {
        _accounts.Add("alice");
        _accounts.Add("dave", admin: true);
        _server.Users.Add("alice");
        Run();
        Assert.True(_accounts.All["alice"].Enabled);
        Assert.False(_accounts.All["dave"].Enabled);
        Assert.False(_accounts.All["dave"].Admin);
        Assert.True(_audit.Has(AuditKind.AccountDisabled, Reason.RemovedFromUsers));
        Assert.True(_audit.Has(AuditKind.AdminRemoved, Reason.RemovedFromUsers));
        Assert.Equal("2 managed, 2 changes", Summary());
    }

    [Fact]
    public void Syncs_admins()
    {
        _accounts.Add("alice");
        _accounts.Add("bob", admin: true);
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
    public void Failed_read_changes_nothing()
    {
        _accounts.Add("alice");
        _accounts.Add("bob", admin: true);
        _server.StatusFails = true;
        Run();
        Assert.True(_accounts.All["alice"].Enabled);
        Assert.Equal(0, _accounts.Mutations);
        Assert.True(_audit.Has(AuditKind.CleanupSkipped, Reason.ServerError));
        Assert.False(_audit.Has(AuditKind.CleanupRun));
    }

    [Fact]
    public void Leaves_unmanaged_and_excluded_accounts_alone()
    {
        _accounts.Add("someone", managed: false);
        _accounts.Add("breakglass");
        _accounts.Add("administrator", admin: true);
        Run();
        Assert.True(_accounts.All["someone"].Enabled);
        Assert.True(_accounts.All["breakglass"].Enabled);
        Assert.True(_accounts.All["administrator"].Admin);
        Assert.Empty(_server.StatusRequests);
    }

    [Fact]
    public void Only_managed_valid_non_excluded_names_are_sent()
    {
        _accounts.Add("alice");
        _accounts.Add("bob", enabled: false);
        _accounts.Add("someone", managed: false);
        _accounts.Add("breakglass");
        _accounts.Add("guest");
        _accounts.Add("Mixed");
        _accounts.Add("has space");
        _accounts.Add("waytoolongforauunname1");
        _accounts.Add("x$");
        Run();
        var asked = Assert.Single(_server.StatusRequests);
        Assert.Equal(["alice", "bob"], asked.Order());
        Assert.Equal(0, _accounts.Calls.Count(c => c != "ListManaged" && c != "SetEnabled"));
        Assert.True(_accounts.All["Mixed"].Enabled);
        Assert.True(_accounts.All["has space"].Enabled);
    }

    [Fact]
    public void No_managed_accounts_makes_no_server_call()
    {
        _accounts.Add("someone", managed: false);
        Run();
        Assert.Empty(_server.StatusRequests);
        Assert.Equal("0 managed, 0 changes", Summary());
    }

    [Fact]
    public void Listing_failure_is_skipped_without_a_server_call()
    {
        _accounts.Add("alice");
        _accounts.ThrowOn.Add("ListManaged");
        Run();
        Assert.Empty(_server.StatusRequests);
        var e = Assert.Single(_audit.Events);
        Assert.Equal(new AuditEvent(AuditKind.CleanupSkipped, "-", Reason.AccountError, "ListManaged failed"), e);
    }

    [Fact]
    public void A_failure_on_one_account_does_not_stop_the_others()
    {
        _accounts.Add("alice");
        _accounts.Add("bob");
        _accounts.Add("carol");
        _accounts.ThrowFor.Add("bob");
        Run();
        Assert.False(_accounts.All["alice"].Enabled);
        Assert.True(_accounts.All["bob"].Enabled);
        Assert.False(_accounts.All["carol"].Enabled);
        var e = Assert.Single(_audit.Events, e => e.Kind == AuditKind.Error);
        Assert.Equal("bob", e.Uun);
        Assert.Equal(Reason.AccountError, e.Reason);
        Assert.Equal("3 managed, 2 changes", Summary());
    }

    [Theory]
    [InlineData("SetEnabled")]
    [InlineData("SetAdmin")]
    public void Each_operation_failure_is_audited(string op)
    {
        _accounts.Add("alice", admin: true);
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
    /// Every combination of local (enabled, admin) and server (user, admin): disabled iff no longer a user;
    /// admin iff user and admin. Never enables anyone (only an online sign-in does).
    /// </summary>
    [Theory]
    [MemberData(nameof(Table))]
    public void Decision_table(bool enabled, bool admin, bool user, bool serverAdmin, bool disables, bool adminAfter)
    {
        _accounts.Add("alice", enabled: enabled, admin: admin);
        if (user) _server.Users.Add("alice");
        if (serverAdmin) _server.Admins.Add("alice");
        Run();
        var a = _accounts.All["alice"];
        Assert.Equal(enabled && !disables, a.Enabled);
        Assert.Equal(adminAfter, a.Admin);
        var changes = (disables ? 1 : 0) + (admin != adminAfter ? 1 : 0);
        Assert.Equal(changes, _accounts.Mutations);
        Assert.Equal($"1 managed, {changes} changes", Summary());
    }

    [Fact]
    public void Admin_without_user_is_not_admin()
    {
        _accounts.Add("alice");
        _server.StatusOverride = _ => new StatusSnapshot(new HashSet<string>(), new HashSet<string> { "alice" });
        Run();
        Assert.False(_accounts.All["alice"].Admin);
        Assert.False(_accounts.All["alice"].Enabled);
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
        // Every account is still a user: none may be disabled because it fell outside one request.
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
}
