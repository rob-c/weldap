using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Weldap.Tests;

internal sealed class FakeClock : IClock
{
    public DateTimeOffset UtcNow { get; set; } = new(2026, 10, 29, 12, 0, 0, TimeSpan.Zero);
}

internal sealed class ListAudit : IAudit
{
    public List<AuditEvent> Events { get; } = [];
    public void Write(AuditEvent e) => Events.Add(e);
    public bool Has(AuditKind kind, Reason? reason = null) =>
        Events.Any(e => e.Kind == kind && (reason is null || e.Reason == reason));

    /// <summary>Every string an audit sink could ever print: for scanning for secrets.</summary>
    public string AllText() =>
        string.Join("\n", Events.Select(e => $"{e} | {(int)e.Kind} | {e.Uun} | {e.Reason} | {e.Detail}"));
}

/// <summary>
/// Test stand-ins for the sealing done in the credential provider and opened by the server. The fake
/// "ciphertext" is the UTF-8 password plus a 16-byte tag, so its length obeys the real bounds (17..272).
/// </summary>
internal static class FakeSeal
{
    public static byte[] Seal(string password)
    {
        var pw = Encoding.UTF8.GetBytes(password);
        return [.. pw, .. Tag(pw)];
    }

    public static string? Open(byte[] ct)
    {
        if (ct.Length <= Protocol.TagBytes) return null;
        var pw = ct.AsSpan(0, ct.Length - Protocol.TagBytes).ToArray();
        return ct.AsSpan(ct.Length - Protocol.TagBytes).SequenceEqual(Tag(pw)) ? Encoding.UTF8.GetString(pw) : null;
    }

    public static byte[] Verifier(string password) => SHA256.HashData(Encoding.UTF8.GetBytes("verifier:" + password));

    private static byte[] Tag(byte[] pw) => SHA256.HashData([.. "tag:"u8, .. pw])[..Protocol.TagBytes];
}

/// <summary>
/// Builds a binary v3 pipe request as the credential provider does. Every field can be overridden, including
/// the length prefixes (to lie about the content that follows) and trailing bytes.
/// </summary>
internal sealed record RequestBuilder
{
    public byte Version { get; init; } = Protocol.Version;
    /// <summary>The raw flags byte (position 1): bit0 scenario-unlock, bit1 consent. Tests set it directly.</summary>
    public byte Scenario { get; init; }
    public byte[] Uun { get; init; } = "alice"u8.ToArray();
    public byte[] Kid { get; init; } = "k1"u8.ToArray();
    public byte[] Enc { get; init; } = DefaultEnc();
    public byte[] Ct { get; init; } = FakeSeal.Seal("alice-pw");
    public long Ts { get; init; } = 1793320000;
    public byte[] Rid { get; init; } = [.. Enumerable.Range(100, Protocol.RidBytes).Select(i => (byte)i)];
    public byte[] Verifier { get; init; } = FakeSeal.Verifier("alice-pw");
    public byte[] Trailing { get; init; } = [];
    public int? UunLen { get; init; }
    public int? KidLen { get; init; }
    public int? CtLen { get; init; }

    public static RequestBuilder For(string uun, string password, Scenario scenario = Weldap.Scenario.Logon) => new()
    {
        Uun = Encoding.ASCII.GetBytes(uun),
        Scenario = (byte)scenario,
        Ct = FakeSeal.Seal(password),
        Verifier = FakeSeal.Verifier(password),
    };

    public static byte[] DefaultEnc()
    {
        var enc = Enumerable.Range(0, Protocol.EncBytes).Select(i => (byte)(i * 7 + 1)).ToArray();
        enc[0] = 0x04;
        return enc;
    }

    // Offsets of each field in the built request.
    public const int VersionAt = 0;
    public const int ScenarioAt = 1;
    public const int UunLenAt = 2;
    public const int UunAt = 3;
    public int KidLenAt => UunAt + Uun.Length;
    public int KidAt => KidLenAt + 1;
    public int EncAt => KidAt + Kid.Length;
    public int CtLenAt => EncAt + Enc.Length;
    public int CtAt => CtLenAt + 2;
    public int TsAt => CtAt + Ct.Length;
    public int RidAt => TsAt + 8;
    public int VerifierAt => RidAt + Rid.Length;
    public int End => VerifierAt + Verifier.Length;

    public byte[] Build()
    {
        var b = new List<byte> { Version, Scenario, (byte)(UunLen ?? Uun.Length) };
        b.AddRange(Uun);
        b.Add((byte)(KidLen ?? Kid.Length));
        b.AddRange(Kid);
        b.AddRange(Enc);
        var u16 = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(u16, (ushort)(CtLen ?? Ct.Length));
        b.AddRange(u16);
        b.AddRange(Ct);
        var i64 = new byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(i64, Ts);
        b.AddRange(i64);
        b.AddRange(Rid);
        b.AddRange(Verifier);
        b.AddRange(Trailing);
        return [.. b];
    }
}

/// <summary>
/// An independent reading of the v3 request layout (PROTOCOL.md), written differently from the codec on purpose:
/// the fuzz tests check the codec accepts exactly what this accepts, with the same fields.
/// </summary>
internal static class SpecParser
{
    public sealed record Parsed(Scenario Scenario, bool Consent, string Uun, string Kid, byte[] Enc, byte[] Ct, long Ts, byte[] Rid, byte[] Verifier);

    public static Parsed? Parse(byte[] m)
    {
        if (m.Length is < 1 or > 4096) return null;
        using var r = new BinaryReader(new MemoryStream(m));
        try
        {
            if (r.ReadByte() != 3) return null;
            var flags = r.ReadByte();
            if ((flags & ~0x03) != 0) return null;
            var consent = (flags & 0x02) != 0;
            var uunLen = r.ReadByte();
            if (uunLen is < 1 or > 20) return null;
            var uun = Exactly(r, uunLen);
            if (uun.Any(c => c is < 33 or > 126)) return null;
            var kidLen = r.ReadByte();
            if (kidLen is < 1 or > 32) return null;
            var kid = Exactly(r, kidLen);
            if (!kid.All(c => "abcdefghijklmnopqrstuvwxyz0123456789-".Contains((char)c, StringComparison.Ordinal))) return null;
            var enc = Exactly(r, 65);
            if (enc[0] != 4) return null;
            var ctLen = r.ReadUInt16(); // BinaryReader is little-endian
            if (ctLen is < 17 or > 272) return null;
            var ct = Exactly(r, ctLen);
            var ts = r.ReadInt64();
            if (ts < 1) return null;
            var rid = Exactly(r, 16);
            var verifier = Exactly(r, 32);
            if (r.BaseStream.Position != m.Length) return null;
            return new Parsed((flags & 0x01) != 0 ? Scenario.Unlock : Scenario.Logon, consent, Encoding.ASCII.GetString(uun),
                Encoding.ASCII.GetString(kid), enc, ct, ts, rid, verifier);
        }
        catch (EndOfStreamException)
        {
            return null;
        }
    }

    private static byte[] Exactly(BinaryReader r, int n)
    {
        var b = r.ReadBytes(n);
        return b.Length == n ? b : throw new EndOfStreamException();
    }
}

/// <summary>Plays the WELDAP server: opens the fake seal and answers with flags, as server.rs does.</summary>
internal sealed class FakeServer : IWeldapServer
{
    public Dictionary<string, string> Passwords { get; } = new();
    public HashSet<string> Users { get; } = [];
    public HashSet<string> Admins { get; } = [];
    public ServerAnswer? ForcedAnswer { get; set; }
    /// <summary>Runs while the "server" is being asked (the window in which other threads may change things).</summary>
    public Action? OnAuthenticate { get; set; }
    public bool StatusFails { get; set; }
    public Func<IReadOnlyCollection<string>, StatusSnapshot?>? StatusOverride { get; set; }
    public int AuthCalls { get; private set; }
    public string? LastUun { get; private set; }
    public Scenario? LastScenario { get; private set; }
    public SealedPassword? LastSealed { get; private set; }
    public List<string[]> StatusRequests { get; } = [];

    public ServerOutcome Forced
    {
        set => ForcedAnswer = new ServerAnswer(value, null, "forced");
    }

    public ServerAnswer Authenticate(string uun, Scenario scenario, SealedPassword sealedPassword)
    {
        AuthCalls++;
        OnAuthenticate?.Invoke();
        LastUun = uun;
        LastScenario = scenario;
        LastSealed = sealedPassword;
        if (ForcedAnswer is { } forced) return forced;
        if (!Passwords.TryGetValue(uun, out var expected) || FakeSeal.Open(sealedPassword.Ct) != expected)
            return new ServerAnswer(ServerOutcome.InvalidCredentials);
        return new ServerAnswer(ServerOutcome.Success, new UserFlags(Users.Contains(uun), Admins.Contains(uun)));
    }

    public StatusSnapshot? ReadStatus(IReadOnlyCollection<string> uuns)
    {
        StatusRequests.Add([.. uuns]);
        if (StatusOverride is { } f) return f(uuns);
        if (StatusFails) return null;
        // Like the server: users and admins are subsets of what was asked.
        return new StatusSnapshot(uuns.Where(Users.Contains).ToHashSet(), uuns.Where(Admins.Contains).ToHashSet());
    }
}

internal sealed class FakeAccounts : ILocalAccounts
{
    public sealed class Acct
    {
        public required string Name { get; init; }
        public bool Managed { get; set; } = true;
        public bool Enabled { get; set; } = true;
        public bool Admin { get; set; }
        public bool User { get; set; } = true;
        public bool ForceLocal { get; set; }
        public bool BuiltIn { get; set; }
        public string Password { get; set; } = "";
        public DateTimeOffset? Expires { get; set; }
        public DateTimeOffset? LastLogon { get; set; }
    }

    public Dictionary<string, Acct> All { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> Calls { get; } = [];
    /// <summary>Operation names ("Find", "Create", ...) that throw LocalAccountException.</summary>
    public HashSet<string> ThrowOn { get; } = [];
    /// <summary>Account names whose mutations throw LocalAccountException.</summary>
    public HashSet<string> ThrowFor { get; } = [];
    public bool Throw { get; set; }

    public int Mutations => Calls.Count(c => c is not ("Find" or "ListAll"));

    public Acct Add(string name, bool managed = true, bool enabled = true, bool admin = false,
        DateTimeOffset? expires = null, bool forceLocal = false, DateTimeOffset? lastLogon = null, bool builtIn = false) =>
        All[name] = new Acct
        {
            Name = name,
            Managed = managed,
            Enabled = enabled,
            Admin = admin,
            Expires = expires,
            ForceLocal = forceLocal,
            LastLogon = lastLogon,
            BuiltIn = builtIn,
        };

    private void Op(string op, string? name = null)
    {
        Calls.Add(op);
        if (Throw || ThrowOn.Contains(op) || (name is not null && ThrowFor.Contains(name)))
            throw new LocalAccountException($"{op} failed", 5);
    }

    // Like the shell (LocalAccounts): names come back lower case, whatever their SAM spelling.
    private static LocalAccount Snapshot(Acct a) =>
        new(a.Name.ToLowerInvariant(), a.Managed, a.Enabled, a.Admin, a.Expires, a.ForceLocal, a.LastLogon, a.BuiltIn);

    // Like the shell: SR-7, the mutators touch managed accounts only, and nothing ever touches a protected one.
    private Acct Managed(string name) =>
        All[name] is { Managed: true } a ? a : throw new LocalAccountException($"{name} is not managed; refusing to change it");

    private Acct Unprotected(string name) =>
        All[name] is { ForceLocal: false, BuiltIn: false } a ? a : throw new LocalAccountException($"{name} is protected");

    public LocalAccount? Find(string name)
    {
        Op("Find");
        return All.TryGetValue(name, out var a) ? Snapshot(a) : null;
    }

    public IReadOnlyList<LocalAccount> ListAll()
    {
        Op("ListAll");
        return All.Values.Select(Snapshot).ToList();
    }

    public void Create(string name, ReadOnlySpan<char> password)
    {
        Op("Create", name);
        All[name] = new Acct { Name = name, Password = password.ToString() };
    }

    public void Adopt(string name)
    {
        Op("Adopt", name);
        var a = Unprotected(name);
        a.Managed = true;
        a.User = true;
    }

    public void SetPassword(string name, ReadOnlySpan<char> password)
    {
        Op("SetPassword", name);
        Managed(name).Password = password.ToString();
    }

    public void SetEnabled(string name, bool enabled)
    {
        Op("SetEnabled", name);
        Managed(name).Enabled = enabled;
    }

    public void SetExpiry(string name, DateTimeOffset? expires)
    {
        Op("SetExpiry", name);
        Managed(name).Expires = expires;
    }

    public void SetAdmin(string name, bool admin)
    {
        Op("SetAdmin", name);
        Managed(name).Admin = admin;
    }

    public void EnsureUser(string name)
    {
        Op("EnsureUser", name);
        Managed(name).User = true;
    }

    public void DisableUnmanaged(string name)
    {
        Op("DisableUnmanaged", name);
        var a = Unprotected(name);
        if (a.Managed) throw new LocalAccountException($"{name} is managed");
        a.Enabled = false;
    }

    public void SetForceLocal(string name, bool forceLocal)
    {
        Op("SetForceLocal", name);
        All[name].ForceLocal = forceLocal;
    }
}

internal sealed class FakeSecrets : ISecretStore
{
    public Dictionary<string, string> LocalPasswords { get; } = new();
    public Dictionary<string, byte[]> Verifiers { get; } = new();
    public Dictionary<string, int> Failures { get; } = new();
    public List<string> Calls { get; } = [];
    /// <summary>Operation names ("GetVerifier", ...) that throw LocalAccountException.</summary>
    public HashSet<string> ThrowOn { get; } = [];
    /// <summary>Buffers handed out, so tests can check the caller zeroed them.</summary>
    public List<byte[]> IssuedVerifiers { get; } = [];
    public List<char[]> IssuedPasswords { get; } = [];

    private void Op(string op)
    {
        Calls.Add(op);
        if (ThrowOn.Contains(op)) throw new LocalAccountException($"{op} failed", 13);
    }

    public char[]? GetLocalPassword(string uun)
    {
        Op("GetLocalPassword");
        if (!LocalPasswords.TryGetValue(uun, out var p)) return null;
        var copy = p.ToCharArray();
        IssuedPasswords.Add(copy);
        return copy;
    }

    public void SetLocalPassword(string uun, ReadOnlySpan<char> password)
    {
        Op("SetLocalPassword");
        LocalPasswords[uun] = password.ToString();
    }

    public byte[]? GetVerifier(string uun)
    {
        Op("GetVerifier");
        if (!Verifiers.TryGetValue(uun, out var v)) return null;
        var copy = (byte[])v.Clone();
        IssuedVerifiers.Add(copy);
        return copy;
    }

    public void SetVerifier(string uun, ReadOnlySpan<byte> verifier)
    {
        Op("SetVerifier");
        Verifiers[uun] = verifier.ToArray();
    }

    public void ClearVerifier(string uun)
    {
        Op("ClearVerifier");
        Verifiers.Remove(uun);
    }

    public int GetOfflineFailures(string uun)
    {
        Op("GetOfflineFailures");
        return Failures.GetValueOrDefault(uun);
    }

    public void SetOfflineFailures(string uun, int count)
    {
        Op("SetOfflineFailures");
        Failures[uun] = count;
    }
}

internal static class TestSettings
{
    /// <summary>A well-formed pin (base64 of 32 bytes).</summary>
    public const string Pin = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    public static LoginSettings Create(int maxOfflineDays = 180) => new()
    {
        ServerHost = "weldap.example.test",
        ServerPins = [Pin],
        ExcludedAccounts = ["breakglass"],
        MaxOfflineDays = maxOfflineDays,
    };
}
