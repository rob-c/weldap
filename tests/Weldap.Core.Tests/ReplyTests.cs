using System.Text;
using Xunit;

namespace Weldap.Tests;

/// <summary>ProtocolCodec.EncodeReply and LoginReply: the bytes the credential provider gets back.</summary>
public class ReplyTests
{
    private const string Pw32 = "ABCDEFGHJKLMNPQRabcdefgh23456789";

    private static byte[] Encode(LoginReply reply) => ProtocolCodec.EncodeReply(reply);

    [Theory]
    [InlineData(SignInMode.Online, 0)]
    [InlineData(SignInMode.Offline, 1)]
    public void Ok_reply_exact_layout(SignInMode mode, byte modeByte)
    {
        using var reply = LoginReply.Ok(mode, Pw32.ToCharArray());
        byte[] expected = [3, 0, modeByte, 0, 32, .. Encoding.ASCII.GetBytes(Pw32)];
        Assert.Equal(expected, Encode(reply));
    }

    [Fact]
    public void Deny_reply_exact_layout()
    {
        using var reply = LoginReply.Deny("No.");
        Assert.Equal(new byte[] { 3, 1, 0, 3, (byte)'N', 0, (byte)'o', 0, (byte)'.', 0, 0 }, Encode(reply));
    }

    [Fact]
    public void Error_reply_exact_layout()
    {
        using var reply = LoginReply.Error("E");
        Assert.Equal(new byte[] { 3, 2, 0, 1, (byte)'E', 0, 0 }, Encode(reply));
    }

    [Theory]
    [InlineData(ReplyResult.Deny)]
    [InlineData(ReplyResult.Error)]
    public void Empty_message_is_allowed(ReplyResult result)
    {
        using var reply = result == ReplyResult.Deny ? LoginReply.Deny("") : LoginReply.Error("");
        Assert.Equal(new byte[] { 3, (byte)result, 0, 0, 0 }, Encode(reply));
    }

    [Fact]
    public void Ok_reply_has_an_empty_message()
    {
        using var reply = LoginReply.Ok(SignInMode.Online, Pw32.ToCharArray());
        Assert.Equal("", reply.Message);
        Assert.Equal(0, Encode(reply)[3]);
    }

    [Theory]
    [InlineData(ReplyResult.Deny)]
    [InlineData(ReplyResult.Error)]
    public void Deny_and_error_carry_no_password_and_online_mode(ReplyResult result)
    {
        using var reply = result == ReplyResult.Deny ? LoginReply.Deny("m") : LoginReply.Error("m");
        Assert.Null(reply.LocalPassword);
        Assert.Equal(SignInMode.Online, reply.Mode);
        var bytes = Encode(reply);
        Assert.Equal(0, bytes[2]);
        Assert.Equal(0, bytes[^1]);
        Assert.Equal(4 + 2 + 1, bytes.Length);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(1, 1)]
    [InlineData(199, 199)]
    [InlineData(200, 200)]
    [InlineData(201, 200)]
    [InlineData(255, 200)]
    [InlineData(256, 200)]
    [InlineData(300, 200)]
    [InlineData(10_000, 200)]
    public void Message_is_truncated_at_200_units(int length, int expected)
    {
        var message = string.Concat(Enumerable.Range(0, length).Select(i => (char)('a' + i % 26)));
        using var reply = LoginReply.Deny(message);
        var bytes = Encode(reply);
        Assert.Equal(expected, bytes[3]);
        Assert.Equal(5 + 2 * expected, bytes.Length);
        Assert.Equal(message[..expected], Encoding.Unicode.GetString(bytes, 4, 2 * expected));
    }

    [Theory]
    [InlineData("é")]
    [InlineData("Ünïcødé — “quotes”")]
    [InlineData("日本語のメッセージ")]
    [InlineData("Ω≈ç√∫")]
    [InlineData("😀")]
    [InlineData("a😀b👍🏽c")]
    [InlineData("\0inner nul\0")]
    public void Message_is_utf16le(string message)
    {
        using var reply = LoginReply.Error(message);
        var bytes = Encode(reply);
        Assert.Equal(message.Length, bytes[3]);
        Assert.Equal(Encoding.Unicode.GetBytes(message), bytes[4..^1]);
        Assert.Equal(0, bytes[^1]);
    }

    [Theory]
    [InlineData(199, 199)] // the pair would straddle the limit: dropped whole
    [InlineData(198, 200)] // the pair ends exactly at the limit: kept
    [InlineData(197, 199)] // 197 + pair = 199 fits; next pair would straddle: dropped
    public void Truncation_never_splits_a_surrogate_pair(int prefix, int expected)
    {
        var message = new string('x', prefix) + string.Concat(Enumerable.Repeat("😀", 10));
        using var reply = LoginReply.Deny(message);
        var bytes = Encode(reply);
        Assert.Equal(expected, bytes[3]);
        var text = Encoding.Unicode.GetString(bytes, 4, 2 * expected);
        Assert.False(char.IsHighSurrogate(text[^1]));
        Assert.Equal(message[..expected], text);
        // Strict decoding would throw on half a pair.
        Assert.Equal(text, new UnicodeEncoding(false, false, throwOnInvalidBytes: true).GetString(bytes, 4, 2 * expected));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(32)]
    [InlineData(63)]
    [InlineData(64)]
    public void Password_lengths_1_to_64_are_encoded(int length)
    {
        var pw = string.Concat(Enumerable.Range(0, length).Select(i => Pw32[i % Pw32.Length]));
        using var reply = LoginReply.Ok(SignInMode.Online, pw.ToCharArray());
        var bytes = Encode(reply);
        Assert.Equal(length, bytes[4]);
        Assert.Equal(pw, Encoding.ASCII.GetString(bytes, 5, length));
        Assert.Equal(5 + length, bytes.Length);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65)]
    [InlineData(100)]
    [InlineData(255)]
    [InlineData(256)]
    public void Password_length_outside_1_to_64_throws_before_allocating(int length)
    {
        var allocations = 0;
        using var reply = LoginReply.Ok(SignInMode.Online, Enumerable.Repeat('A', length).ToArray());
        Assert.Throws<InvalidOperationException>(() => ProtocolCodec.EncodeReply(reply, n => { allocations++; return new byte[n]; }));
        Assert.Equal(0, allocations);
        Assert.Throws<InvalidOperationException>(() => Encode(reply));
    }

    public static TheoryData<char, int> ForbiddenPasswordChars()
    {
        var data = new TheoryData<char, int>();
        foreach (var c in "\"\\ \0'$&<>`|/O0Il1\u00e9\u03a9\u00a0\u200b\n\r\t")
            foreach (var at in new[] { 0, 15, 31 })
                data.Add(c, at);
        return data;
    }

    /// <summary>A character outside the generator alphabet: throw, and the buffer it was written into is zeroed.</summary>
    [Theory]
    [MemberData(nameof(ForbiddenPasswordChars))]
    public void Password_char_outside_the_alphabet_throws_and_zeroes_the_buffer(char bad, int at)
    {
        var pw = Pw32.ToCharArray();
        pw[at] = bad;
        using var reply = LoginReply.Ok(SignInMode.Offline, pw);
        byte[]? buffer = null;
        Assert.Throws<InvalidOperationException>(() => ProtocolCodec.EncodeReply(reply, n => buffer = new byte[n]));
        Assert.NotNull(buffer);
        Assert.All(buffer, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Ok_reply_without_a_password_throws()
    {
        // Unreachable through LoginReply.Ok's signature, but the encoder must not trust that.
        using var reply = LoginReply.Ok(SignInMode.Online, null!);
        Assert.Throws<InvalidOperationException>(() => Encode(reply));
    }

    [Fact]
    public void Encoder_writes_into_the_buffer_it_returns()
    {
        using var reply = LoginReply.Ok(SignInMode.Online, Pw32.ToCharArray());
        byte[]? buffer = null;
        var result = ProtocolCodec.EncodeReply(reply, n => buffer = new byte[n]);
        Assert.Same(buffer, result);
    }

    [Fact]
    public void Dispose_zeroes_the_local_password()
    {
        var pw = LocalPasswords.Generate();
        LoginReply.Ok(SignInMode.Online, pw).Dispose();
        Assert.All(pw, c => Assert.Equal('\0', c));
    }

    [Fact]
    public void Dispose_of_deny_and_error_is_harmless()
    {
        LoginReply.Deny("x").Dispose();
        var e = LoginReply.Error("x");
        e.Dispose();
        e.Dispose();
        Assert.Equal("x", e.Message);
    }

    [Fact]
    public void Ok_takes_ownership_of_the_buffer()
    {
        var pw = Pw32.ToCharArray();
        using var reply = LoginReply.Ok(SignInMode.Offline, pw);
        Assert.Same(pw, reply.LocalPassword);
        Assert.Equal(ReplyResult.Ok, reply.Result);
        Assert.Equal(SignInMode.Offline, reply.Mode);
    }

    [Fact]
    public void Generated_passwords_always_encode()
    {
        for (var i = 0; i < 500; i++)
        {
            using var reply = LoginReply.Ok(SignInMode.Online, LocalPasswords.Generate());
            var bytes = Encode(reply);
            Assert.Equal(new string(reply.LocalPassword), Encoding.ASCII.GetString(bytes, 5, LocalPasswords.Length));
        }
    }
}
