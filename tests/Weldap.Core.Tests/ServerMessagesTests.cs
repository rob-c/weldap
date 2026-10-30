using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Xunit;

namespace Weldap.Tests;

public class ServerRequestTests
{
    private static readonly SealedPassword Sample = new(
        "k1",
        [0x04, .. Enumerable.Range(1, 64).Select(i => (byte)i)],
        [.. Enumerable.Range(0, 40).Select(i => (byte)(0xF0 + i % 16))], // base64 with '+' and '/'
        1793320000,
        [.. Enumerable.Range(200, 16).Select(i => (byte)i)]);

    private static JsonElement Json(byte[] body) => JsonDocument.Parse(body).RootElement;

    [Theory]
    [InlineData(Scenario.Logon, "logon")]
    [InlineData(Scenario.Unlock, "unlock")]
    public void Auth_request_shape(Scenario scenario, string scenarioText)
    {
        var root = Json(ServerMessages.Auth("alice", scenario, Sample));
        Assert.Equal(["op", "v", "uun", "scenario", "kid", "enc", "ct", "ts", "rid"], root.EnumerateObject().Select(p => p.Name));
        Assert.Equal("auth", root.GetProperty("op").GetString());
        Assert.Equal(JsonValueKind.Number, root.GetProperty("v").ValueKind);
        Assert.Equal(1, root.GetProperty("v").GetInt32());
        Assert.Equal("alice", root.GetProperty("uun").GetString());
        Assert.Equal(scenarioText, root.GetProperty("scenario").GetString());
        Assert.Equal("k1", root.GetProperty("kid").GetString());
        Assert.Equal(Sample.Enc, Convert.FromBase64String(root.GetProperty("enc").GetString()!));
        Assert.Equal(Sample.Ct, Convert.FromBase64String(root.GetProperty("ct").GetString()!));
        Assert.Equal(Convert.ToBase64String(Sample.Ct), root.GetProperty("ct").GetString());
        Assert.Equal(JsonValueKind.Number, root.GetProperty("ts").ValueKind);
        Assert.Equal(1793320000, root.GetProperty("ts").GetInt64());
        Assert.Equal(Sample.Rid, Convert.FromBase64String(root.GetProperty("rid").GetString()!));
    }

    [Fact]
    public void Auth_request_exact_bytes()
    {
        var s = new SealedPassword("k-2", [4, 0, 0], [0, 0, 0], 7, [0, 0, 0, 0, 0, 0]);
        Assert.Equal(
            """{"op":"auth","v":1,"uun":"bob","scenario":"unlock","kid":"k-2","enc":"BAAA","ct":"AAAA","ts":7,"rid":"AAAAAAAA"}""",
            Encoding.UTF8.GetString(ServerMessages.Auth("bob", Scenario.Unlock, s)));
    }

    [Theory]
    [InlineData(1L)]
    [InlineData(1793320000L)]
    [InlineData(long.MaxValue)]
    public void Auth_request_timestamps_are_exact_integers(long ts)
    {
        var root = Json(ServerMessages.Auth("alice", Scenario.Logon, Sample with { Ts = ts }));
        Assert.Equal(ts, root.GetProperty("ts").GetInt64());
        Assert.Equal(ts.ToString(System.Globalization.CultureInfo.InvariantCulture), root.GetProperty("ts").GetRawText());
    }

    [Fact]
    public void Auth_request_never_carries_a_verifier_or_password()
    {
        var text = Encoding.UTF8.GetString(ServerMessages.Auth("alice", Scenario.Logon, Sample));
        Assert.DoesNotContain("verifier", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Strings_are_escaped_not_injected()
    {
        var root = Json(ServerMessages.Auth("a\",\"op\":\"status", Scenario.Logon, Sample with { Kid = "\"}" }));
        Assert.Equal("auth", root.GetProperty("op").GetString());
        Assert.Equal("a\",\"op\":\"status", root.GetProperty("uun").GetString());
        Assert.Equal(9, root.EnumerateObject().Count());
    }

    [Fact]
    public void Status_request_exact_bytes() =>
        Assert.Equal("""{"op":"status","v":1,"uuns":["alice","bob"]}""",
            Encoding.UTF8.GetString(ServerMessages.Status(["alice", "bob"])));

    [Theory]
    [InlineData(0, 0)]
    [InlineData(1, 1)]
    [InlineData(99, 99)]
    [InlineData(100, 100)]
    [InlineData(101, 100)]
    [InlineData(250, 100)]
    public void Status_request_asks_about_at_most_100(int count, int expected)
    {
        var uuns = Enumerable.Range(0, count).Select(i => $"u{i}").ToList();
        var root = Json(ServerMessages.Status(uuns));
        Assert.Equal(["op", "v", "uuns"], root.EnumerateObject().Select(p => p.Name));
        Assert.Equal("status", root.GetProperty("op").GetString());
        Assert.Equal(1, root.GetProperty("v").GetInt32());
        Assert.Equal(uuns.Take(expected), root.GetProperty("uuns").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(100, ServerMessages.MaxStatusUuns);
    }
}

public class AuthReplyTests
{
    private static ServerAnswer Parse(string json) => ServerMessages.ParseAuthReply(Encoding.UTF8.GetBytes(json));

    public static TheoryData<string, ServerOutcome, bool?, bool?> Replies() => new()
    {
        { """{"v":1,"result":"ok","user":true,"admin":false}""", ServerOutcome.Success, true, false },
        { """{"v":1,"result":"ok","user":true,"admin":true}""", ServerOutcome.Success, true, true },
        { """{"v":1,"result":"ok","user":false,"admin":false}""", ServerOutcome.Success, false, false },
        // An admin who is not a user is not an admin.
        { """{"v":1,"result":"ok","user":false,"admin":true}""", ServerOutcome.Success, false, false },
        { """{"admin":true,"user":true,"result":"ok","v":1}""", ServerOutcome.Success, true, true },
        { """{"v":1,"result":"ok","user":true,"admin":false,"displayName":"Alice"}""", ServerOutcome.Success, true, false },
        { """ {"v":1, "result":"ok", "user":true, "admin":true} """, ServerOutcome.Success, true, true },
        { """{"v":1,"result":"ok","user":true}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"ok","admin":true}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"ok"}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"ok","user":"true","admin":false}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"ok","user":1,"admin":false}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"ok","user":null,"admin":false}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"ok","user":true,"admin":"false"}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"ok","user":true,"admin":0}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"ok","user":[true],"admin":false}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"ok","user":{},"admin":false}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"invalid"}""", ServerOutcome.InvalidCredentials, null, null },
        { """{"v":1,"result":"invalid","user":true,"admin":true}""", ServerOutcome.InvalidCredentials, null, null },
        { """{"v":1,"result":"throttled"}""", ServerOutcome.Throttled, null, null },
        { """{"v":1,"result":"unavailable"}""", ServerOutcome.NoAnswer, null, null },
        { """{"v":1,"result":"unavailable","user":true,"admin":true}""", ServerOutcome.NoAnswer, null, null },
        { """{"v":1,"result":"denied"}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"error"}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"OK","user":true,"admin":true}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"ok ","user":true,"admin":true}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"Invalid"}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":""}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":null}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":1}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":["ok"],"user":true,"admin":true}""", ServerOutcome.Error, null, null },
        { """{"v":1}""", ServerOutcome.Error, null, null },
        { """{"v":1,"Result":"ok","user":true,"admin":true}""", ServerOutcome.Error, null, null },
        // Version
        { """{"result":"ok","user":true,"admin":true}""", ServerOutcome.Error, null, null },
        { """{"v":2,"result":"ok","user":true,"admin":true}""", ServerOutcome.Error, null, null },
        { """{"v":0,"result":"ok","user":true,"admin":true}""", ServerOutcome.Error, null, null },
        { """{"v":-1,"result":"ok","user":true,"admin":true}""", ServerOutcome.Error, null, null },
        { """{"v":"1","result":"ok","user":true,"admin":true}""", ServerOutcome.Error, null, null },
        { """{"v":true,"result":"ok","user":true,"admin":true}""", ServerOutcome.Error, null, null },
        { """{"v":null,"result":"ok","user":true,"admin":true}""", ServerOutcome.Error, null, null },
        { """{"v":1.5,"result":"ok","user":true,"admin":true}""", ServerOutcome.Error, null, null },
        { """{"v":4294967297,"result":"ok","user":true,"admin":true}""", ServerOutcome.Error, null, null },
        { """{"v":1e999,"result":"ok","user":true,"admin":true}""", ServerOutcome.Error, null, null },
        // Not an object / not JSON
        { "[]", ServerOutcome.Error, null, null },
        { """[{"v":1,"result":"ok","user":true,"admin":true}]""", ServerOutcome.Error, null, null },
        { "\"ok\"", ServerOutcome.Error, null, null },
        { "1", ServerOutcome.Error, null, null },
        { "true", ServerOutcome.Error, null, null },
        { "null", ServerOutcome.Error, null, null },
        { "", ServerOutcome.Error, null, null },
        { " ", ServerOutcome.Error, null, null },
        { "{", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"ok","user":true,"admin":true""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"ok","user":true,"admin":true}x""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"ok","user":true,"admin":true}{}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"ok","user":true,"admin":true,}""", ServerOutcome.Error, null, null },
        { """{"v":1,/*c*/"result":"ok","user":true,"admin":true}""", ServerOutcome.Error, null, null },
        { """{v:1,result:"ok",user:true,admin:true}""", ServerOutcome.Error, null, null },
        { """{'v':1,'result':'ok','user':true,'admin':true}""", ServerOutcome.Error, null, null },
        { "not json", ServerOutcome.Error, null, null },
        // Duplicate members: never resolved in favour of either copy.
        { """{"v":1,"result":"invalid","result":"ok","user":true,"admin":true}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"ok","result":"invalid","user":true,"admin":true}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"ok","user":false,"user":true,"admin":true}""", ServerOutcome.Error, null, null },
        { """{"v":1,"result":"ok","user":true,"admin":false,"admin":true}""", ServerOutcome.Error, null, null },
        { """{"v":2,"v":1,"result":"ok","user":true,"admin":true}""", ServerOutcome.Error, null, null },
    };

    [Theory]
    [MemberData(nameof(Replies))]
    public void Parses(string json, ServerOutcome outcome, bool? user, bool? admin)
    {
        var answer = Parse(json);
        Assert.Equal(outcome, answer.Outcome);
        if (user is null)
        {
            Assert.Null(answer.User);
        }
        else
        {
            Assert.Equal(new UserFlags(user.Value, admin!.Value), answer.User);
        }
    }

    [Theory]
    [InlineData(new byte[] { 0xFF, 0xFE, 0x7B, 0x00 })]
    [InlineData(new byte[] { 0xEF, 0xBB, 0xBF })]
    [InlineData(new byte[] { 0x00 })]
    [InlineData(new byte[] { 0xC3, 0x28 })]
    [InlineData(new byte[0])]
    public void Garbage_bytes_are_an_error(byte[] reply) => Assert.Equal(ServerOutcome.Error, ServerMessages.ParseAuthReply(reply).Outcome);

    [Fact]
    public void Deep_nesting_is_an_error_not_an_exception()
    {
        var json = "{\"v\":1,\"result\":\"ok\",\"user\":true,\"admin\":true,\"x\":" + new string('[', 200) + new string(']', 200) + "}";
        Assert.Equal(ServerOutcome.Error, Parse(json).Outcome);
    }

    [Fact]
    public void Random_bytes_never_throw()
    {
        var rng = new Random(7);
        for (var i = 0; i < 2000; i++)
        {
            var b = new byte[rng.Next(0, 80)];
            rng.NextBytes(b);
            var answer = ServerMessages.ParseAuthReply(b);
            Assert.NotEqual(ServerOutcome.Success, answer.Outcome);
        }
    }

    [Theory]
    [InlineData("""{"v":1,"result":"throttled"}""", "server: throttled")]
    [InlineData("""{"v":1,"result":"unavailable"}""", "server: back end unavailable")]
    [InlineData("""{"v":1,"result":"denied"}""", "server: account refused")]
    [InlineData("""{"v":1,"result":"error"}""", "server: error")]
    [InlineData("""{"v":1,"result":"what"}""", "server: error")]
    [InlineData("""{"v":2,"result":"ok"}""", "server: malformed reply")]
    [InlineData("[]", "server: malformed reply")]
    [InlineData("{", "server: malformed reply")]
    public void Details_are_fixed_strings(string json, string detail) => Assert.Equal(detail, Parse(json).Detail);

    [Fact]
    public void Reply_text_never_reaches_the_detail()
    {
        // Details end up in the event log: nothing the server sends is copied into them.
        foreach (var result in new[] { "ok", "invalid", "throttled", "unavailable", "denied", "error", "SECRET" })
        {
            var answer = Parse($$"""{"v":1,"result":"{{result}}","msg":"SECRET"}""");
            Assert.DoesNotContain("SECRET", answer.Detail ?? "", StringComparison.Ordinal);
        }
    }
}

public class StatusReplyTests
{
    private static readonly string[] Asked = ["alice", "bob", "carol"];

    private static StatusSnapshot? Parse(string json, IReadOnlyCollection<string>? asked = null) =>
        ServerMessages.ParseStatusReply(Encoding.UTF8.GetBytes(json), asked ?? Asked);

    [Fact]
    public void Parses_users_and_admins()
    {
        var s = Parse("""{"v":1,"result":"ok","users":["alice","bob"],"admins":["bob"]}""")!;
        Assert.Equal(["alice", "bob"], s.Users.Order());
        Assert.Equal(["bob"], s.Admins);
    }

    [Theory]
    [InlineData("""{"v":1,"result":"ok","users":[],"admins":[]}""", "", "")]
    [InlineData("""{"v":1,"result":"ok","users":["alice","alice"],"admins":[]}""", "alice", "")]
    [InlineData("""{"v":1,"result":"ok","users":["carol"],"admins":["bob"]}""", "carol", "bob")] // admin-not-user is kept; callers mask it
    [InlineData("""{"admins":["alice"],"users":["alice"],"result":"ok","v":1}""", "alice", "alice")]
    [InlineData("""{"v":1,"result":"ok","users":["alice"],"admins":[],"extra":1}""", "alice", "")]
    public void Accepts(string json, string users, string admins)
    {
        var s = Parse(json)!;
        Assert.Equal(users, string.Join(",", s.Users.Order()));
        Assert.Equal(admins, string.Join(",", s.Admins.Order()));
    }

    [Theory]
    [InlineData("""{"v":1,"result":"ok","users":["dave"],"admins":[]}""")]
    [InlineData("""{"v":1,"result":"ok","users":[],"admins":["dave"]}""")]
    [InlineData("""{"v":1,"result":"ok","users":["alice","dave"],"admins":[]}""")]
    [InlineData("""{"v":1,"result":"ok","users":["Alice"],"admins":[]}""")]
    [InlineData("""{"v":1,"result":"ok","users":["alice "],"admins":[]}""")]
    [InlineData("""{"v":1,"result":"ok","users":[""],"admins":[]}""")]
    [InlineData("""{"v":1,"result":"ok","users":[1],"admins":[]}""")]
    [InlineData("""{"v":1,"result":"ok","users":[null],"admins":[]}""")]
    [InlineData("""{"v":1,"result":"ok","users":["alice",null],"admins":[]}""")]
    [InlineData("""{"v":1,"result":"ok","users":[["alice"]],"admins":[]}""")]
    [InlineData("""{"v":1,"result":"ok","users":"alice","admins":[]}""")]
    [InlineData("""{"v":1,"result":"ok","users":{"alice":true},"admins":[]}""")]
    [InlineData("""{"v":1,"result":"ok","users":null,"admins":[]}""")]
    [InlineData("""{"v":1,"result":"ok","users":[],"admins":null}""")]
    [InlineData("""{"v":1,"result":"ok","admins":[]}""")]
    [InlineData("""{"v":1,"result":"ok","users":[]}""")]
    [InlineData("""{"v":1,"result":"ok"}""")]
    [InlineData("""{"v":1,"result":"error"}""")]
    [InlineData("""{"v":1,"result":"unavailable","users":[],"admins":[]}""")]
    [InlineData("""{"v":1,"result":"throttled","users":[],"admins":[]}""")]
    [InlineData("""{"v":1,"users":[],"admins":[]}""")]
    [InlineData("""{"v":2,"result":"ok","users":[],"admins":[]}""")]
    [InlineData("""{"result":"ok","users":[],"admins":[]}""")]
    [InlineData("""{"v":"1","result":"ok","users":[],"admins":[]}""")]
    [InlineData("""[{"v":1,"result":"ok","users":[],"admins":[]}]""")]
    [InlineData("null")]
    [InlineData("")]
    [InlineData("{")]
    [InlineData("""{"v":1,"result":"ok","users":[],"admins":[]} x""")]
    [InlineData("""{"v":1,"result":"ok","users":["alice"],"users":[],"admins":[]}""")]
    [InlineData("""{"v":1,"result":"ok","users":[],"users":["alice"],"admins":[]}""")]
    public void Rejects(string json) => Assert.Null(Parse(json));

    [Fact]
    public void Nothing_asked_means_no_names_may_come_back()
    {
        Assert.NotNull(Parse("""{"v":1,"result":"ok","users":[],"admins":[]}""", []));
        Assert.Null(Parse("""{"v":1,"result":"ok","users":["alice"],"admins":[]}""", []));
    }

    [Fact]
    public void Random_bytes_never_throw()
    {
        var rng = new Random(11);
        for (var i = 0; i < 2000; i++)
        {
            var b = new byte[rng.Next(0, 80)];
            rng.NextBytes(b);
            Assert.Null(ServerMessages.ParseStatusReply(b, Asked));
        }
    }
}

public class PinTests
{
    private static X509Certificate2 SelfSigned(AsymmetricAlgorithm key, string cn = "weldap.test")
    {
        var name = new X500DistinguishedName($"CN={cn}");
        var req = key switch
        {
            ECDsa ec => new CertificateRequest(name, ec, HashAlgorithmName.SHA256),
            RSA rsa => new CertificateRequest(name, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            _ => throw new ArgumentException("unsupported key type", nameof(key)),
        };
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    private static string SpkiPin(AsymmetricAlgorithm key) =>
        Convert.ToBase64String(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));

    [Fact]
    public void Pin_is_sha256_of_the_spki_for_ec_keys()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert = SelfSigned(key);
        Assert.Equal(SpkiPin(key), ServerMessages.Pin(cert));
        Assert.True(SettingsText.IsPin(ServerMessages.Pin(cert)));
    }

    [Fact]
    public void Pin_is_sha256_of_the_spki_for_rsa_keys()
    {
        using var key = RSA.Create(2048);
        using var cert = SelfSigned(key);
        Assert.Equal(SpkiPin(key), ServerMessages.Pin(cert));
    }

    [Fact]
    public void A_reissued_certificate_for_the_same_key_still_matches()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var a = SelfSigned(key, "one");
        using var b = SelfSigned(key, "two");
        Assert.NotEqual(a.RawData, b.RawData);
        Assert.True(ServerMessages.MatchesPin(b, [ServerMessages.Pin(a)]));
    }

    [Fact]
    public void Base_class_certificate_works()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert = SelfSigned(key);
        using X509Certificate plain = X509CertificateLoader.LoadCertificate(cert.RawData);
        Assert.True(ServerMessages.MatchesPin(plain, [SpkiPin(key)]));
    }

    public static TheoryData<string> Cases() => ["only", "second", "last-of-three", "none", "empty", "other-key", "lower-case",
        "upper-case", "trailing-space", "leading-space", "cert-hash", "hex", "truncated", "prefix-of-longer", "sha1"];

    [Theory]
    [MemberData(nameof(Cases))]
    public void MatchesPin(string @case)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert = SelfSigned(key);
        var pin = SpkiPin(key);
        var spki = key.ExportSubjectPublicKeyInfo();
        var hasLower = pin.Any(char.IsAsciiLetterLower);
        var hasUpper = pin.Any(char.IsAsciiLetterUpper);
#pragma warning disable CA5350 // SHA-1 here is the wrong pin form under test, not a use of SHA-1
        var sha1 = Convert.ToBase64String(SHA1.HashData(spki));
#pragma warning restore CA5350
        var (pins, expected) = @case switch
        {
            "only" => (new[] { pin }, true),
            "second" => (new[] { SpkiPin(other), pin }, true),
            "last-of-three" => (new[] { TestSettings.Pin, SpkiPin(other), pin }, true),
            "none" => (new[] { TestSettings.Pin }, false),
            "empty" => (Array.Empty<string>(), false),
            "other-key" => (new[] { SpkiPin(other) }, false),
            "lower-case" => (new[] { pin.ToLowerInvariant() }, !hasUpper),
            "upper-case" => (new[] { pin.ToUpperInvariant() }, !hasLower),
            "trailing-space" => (new[] { pin + " " }, false),
            "leading-space" => (new[] { " " + pin }, false),
            "cert-hash" => (new[] { Convert.ToBase64String(SHA256.HashData(cert.RawData)) }, false),
            "hex" => (new[] { Convert.ToHexString(SHA256.HashData(spki)) }, false),
            "truncated" => (new[] { pin[..43] }, false),
            "prefix-of-longer" => (new[] { pin + "AAAA" }, false),
            "sha1" => (new[] { sha1 }, false),
            _ => throw new ArgumentException(@case, nameof(@case)),
        };
        Assert.Equal(expected, ServerMessages.MatchesPin(cert, pins));
    }
}
