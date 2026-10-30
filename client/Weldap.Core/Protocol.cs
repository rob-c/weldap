using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Weldap;

// Pipe protocol v3: a fixed binary layout (PROTOCOL.md), mirrored in client/Weldap.Shared/WeldapProtocol.h.
// The password never crosses the pipe: the credential provider sends it sealed to the WELDAP server, plus the
// offline verifier (PBKDF2 of the password), and gets back the account's random local password on success.
public static class Protocol
{
    public const string PipeName = "weldap";
    public const byte Version = 3;
    public const int MaxMessageBytes = 4096;
    public const int MaxMessageChars = 200;
    public const int VerifierBytes = 32;
    public const int EncBytes = 65;
    public const int RidBytes = 16;
    public const int TagBytes = 16;
    public const int MaxPasswordUtf8 = 256;
    public const int MaxKidChars = 32;
}

public enum Scenario { Logon, Unlock }

public enum ReplyResult : byte { Ok = 0, Deny = 1, Error = 2 }

public enum SignInMode { Online, Offline }

/// <summary>A reply. On success it carries the local account password in a pinned buffer that Dispose zeroes.</summary>
public sealed class LoginReply : IDisposable
{
    private LoginReply(ReplyResult result, SignInMode mode, string message, char[]? localPassword)
    {
        Result = result;
        Mode = mode;
        Message = message;
        LocalPassword = localPassword;
    }

    public ReplyResult Result { get; }
    /// <summary>Online vs offline sign-in. Meaningful only when <see cref="Result"/> is <see cref="ReplyResult.Ok"/>:
    /// the Deny/Error factories always set Online, and <c>EncodeReply</c> writes the mode byte only in the Ok case.</summary>
    public SignInMode Mode { get; }
    public string Message { get; }
    public char[]? LocalPassword { get; }

    /// <summary>Takes ownership of <paramref name="localPassword"/> (pinned).</summary>
    public static LoginReply Ok(SignInMode mode, char[] localPassword) => new(ReplyResult.Ok, mode, "", localPassword);
    public static LoginReply Deny(string message) => new(ReplyResult.Deny, SignInMode.Online, message, null);
    public static LoginReply Error(string message) => new(ReplyResult.Error, SignInMode.Online, message, null);

    public void Dispose()
    {
        if (LocalPassword is not null) CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(LocalPassword.AsSpan()));
    }
}

/// <summary>A parsed request. The verifier lives in a pinned buffer that Dispose zeroes.</summary>
public sealed class LoginRequest : IDisposable
{
    private readonly byte[] _verifier;

    internal LoginRequest(Scenario scenario, string uun, SealedPassword sealedPassword, byte[] verifier)
    {
        Scenario = scenario;
        Uun = uun;
        Sealed = sealedPassword;
        _verifier = verifier;
    }

    public Scenario Scenario { get; }
    public string Uun { get; }
    public SealedPassword Sealed { get; }
    public ReadOnlySpan<byte> Verifier => _verifier;

    public void Dispose() => CryptographicOperations.ZeroMemory(_verifier);
}

public static class ProtocolCodec
{
    private static bool IsKid(ReadOnlySpan<byte> s)
    {
        foreach (var c in s)
            if (c is not ((>= (byte)'a' and <= (byte)'z') or (>= (byte)'0' and <= (byte)'9') or (byte)'-')) return false;
        return true;
    }

    /// <summary>
    /// Strict parse of a request:
    /// version(1)=3 scenario(1)∈{0,1} uunLen(1)∈1..20 uun kidLen(1)∈1..32 kid enc(65) ctLen(u16 LE)∈17..272 ct
    /// ts(u64 LE)&gt;0 rid(16) verifier(32), and nothing after. Returns null for anything else (the caller drops
    /// the connection). The UUN is only checked for printable ASCII here; the handler applies the UUN rule.
    /// </summary>
    public static LoginRequest? TryParseRequest(ReadOnlySpan<byte> m)
    {
        if (m.Length is 0 or > Protocol.MaxMessageBytes || m[0] != Protocol.Version || m.Length < 3) return null;
        if (m[1] > 1) return null;
        var scenario = m[1] == 1 ? Scenario.Unlock : Scenario.Logon;
        var at = 2;

        bool Take(ReadOnlySpan<byte> src, int n, out ReadOnlySpan<byte> field)
        {
            field = default;
            if (n < 0 || at + n > src.Length) return false;
            field = src.Slice(at, n);
            at += n;
            return true;
        }

        if (!Take(m, 1, out var f) || f[0] is 0 or > 20 || !Take(m, f[0], out var uun)) return null;
        foreach (var c in uun) if (c is < 0x21 or > 0x7E) return null;
        if (!Take(m, 1, out f) || f[0] is 0 or > Protocol.MaxKidChars || !Take(m, f[0], out var kid) || !IsKid(kid)) return null;
        if (!Take(m, Protocol.EncBytes, out var enc) || enc[0] != 0x04) return null;
        if (!Take(m, 2, out f)) return null;
        var ctLen = BinaryPrimitives.ReadUInt16LittleEndian(f);
        if (ctLen is <= Protocol.TagBytes or > Protocol.TagBytes + Protocol.MaxPasswordUtf8 || !Take(m, ctLen, out var ct)) return null;
        if (!Take(m, 8, out f)) return null;
        var ts = BinaryPrimitives.ReadInt64LittleEndian(f);
        if (ts <= 0 || !Take(m, Protocol.RidBytes, out var rid) || !Take(m, Protocol.VerifierBytes, out var v)) return null;
        if (at != m.Length) return null; // trailing bytes

        var verifier = GC.AllocateArray<byte>(Protocol.VerifierBytes, pinned: true);
        v.CopyTo(verifier);
        return new LoginRequest(scenario, Encoding.ASCII.GetString(uun),
            new SealedPassword(Encoding.ASCII.GetString(kid), enc.ToArray(), ct.ToArray(), ts, rid.ToArray()), verifier);
    }

    /// <summary>
    /// Encodes a reply into a pinned buffer the caller zeroes after sending (it may hold the local password):
    /// version(1)=3 result(1) mode(1) msgLen(1) message(UTF-16LE, msgLen units) pwLen(1) password(ASCII).
    /// </summary>
    public static byte[] EncodeReply(LoginReply reply) => EncodeReply(reply, n => GC.AllocateArray<byte>(n, pinned: true));

    internal static byte[] EncodeReply(LoginReply reply, Func<int, byte[]> allocate)
    {
        var message = reply.Message.AsSpan(0, Math.Min(reply.Message.Length, Protocol.MaxMessageChars));
        if (message.Length < reply.Message.Length && char.IsHighSurrogate(message[^1])) message = message[..^1]; // never half a pair
        var ok = reply.Result == ReplyResult.Ok;
        var password = ok ? reply.LocalPassword ?? [] : [];
        if (ok && password.Length is 0 or > 64) throw new InvalidOperationException("local password length");

        var buffer = allocate(5 + 2 * message.Length + password.Length);
        buffer[0] = Protocol.Version;
        buffer[1] = (byte)reply.Result;
        buffer[2] = (byte)(ok && reply.Mode == SignInMode.Offline ? 1 : 0);
        buffer[3] = (byte)message.Length;
        MemoryMarshal.AsBytes(message).CopyTo(buffer.AsSpan(4)); // UTF-16LE on every Windows architecture
        var at = 4 + 2 * message.Length;
        buffer[at++] = (byte)password.Length;
        foreach (var c in password)
        {
            if (!LocalPasswords.IsAllowed(c))
            {
                CryptographicOperations.ZeroMemory(buffer);
                throw new InvalidOperationException("local password character outside the generator alphabet");
            }
            buffer[at++] = (byte)c;
        }
        return buffer;
    }

    /// <summary>Reads one length-prefixed frame into a pinned buffer, or null if the frame is invalid.</summary>
    public static async Task<byte[]?> ReadFrameAsync(Stream stream, CancellationToken ct)
    {
        var header = new byte[4];
        if (!await ReadExactlyOrEofAsync(stream, header, ct).ConfigureAwait(false)) return null;
        var length = BinaryPrimitives.ReadUInt32LittleEndian(header);
        if (length is 0 or > Protocol.MaxMessageBytes) return null;

        var body = GC.AllocateArray<byte>((int)length, pinned: true);
        if (!await ReadExactlyOrEofAsync(stream, body, ct).ConfigureAwait(false))
        {
            CryptographicOperations.ZeroMemory(body);
            return null;
        }
        return body;
    }

    /// <summary>Writes the length prefix and the payload separately: no combined copy of the payload.</summary>
    public static async Task WriteFrameAsync(Stream stream, byte[] payload, CancellationToken ct)
    {
        var header = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(header, (uint)payload.Length);
        await stream.WriteAsync(header, ct).ConfigureAwait(false);
        await stream.WriteAsync(payload, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    private static async Task<bool> ReadExactlyOrEofAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        try
        {
            await stream.ReadExactlyAsync(buffer, ct).ConfigureAwait(false);
            return true;
        }
        catch (EndOfStreamException)
        {
            return false;
        }
    }
}

/// <summary>Random local account passwords: 32 printable ASCII characters, all four character classes.</summary>
public static class LocalPasswords
{
    private const string Upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const string Lower = "abcdefghijkmnopqrstuvwxyz";
    private const string Digits = "23456789";
    private const string Symbols = "!#%+-.:=?@^_~";
    private const string All = Upper + Lower + Digits + Symbols;
    public const int Length = 32;

    public static bool IsAllowed(char c) => All.Contains(c, StringComparison.Ordinal);

    /// <summary>A pinned buffer the caller zeroes.</summary>
    public static char[] Generate()
    {
        var pw = GC.AllocateArray<char>(Length, pinned: true);
        pw[0] = Upper[RandomNumberGenerator.GetInt32(Upper.Length)];
        pw[1] = Lower[RandomNumberGenerator.GetInt32(Lower.Length)];
        pw[2] = Digits[RandomNumberGenerator.GetInt32(Digits.Length)];
        pw[3] = Symbols[RandomNumberGenerator.GetInt32(Symbols.Length)];
        for (var i = 4; i < Length; i++) pw[i] = All[RandomNumberGenerator.GetInt32(All.Length)];
        // Shuffle so the class positions are not fixed.
        for (var i = Length - 1; i > 0; i--)
        {
            var j = RandomNumberGenerator.GetInt32(i + 1);
            (pw[i], pw[j]) = (pw[j], pw[i]);
        }
        return pw;
    }
}
