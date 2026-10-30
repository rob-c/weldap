using System.Buffers.Binary;
using Xunit;

namespace Weldap.Tests;

/// <summary>
/// A programmable <see cref="Stream"/> standing in for the TLS stream to the server: it hands back a scripted
/// reply (optionally a byte at a time, optionally never finishing), can throw, and records everything written.
/// </summary>
internal sealed class ScriptedStream : Stream
{
    private readonly byte[] _reply;
    private readonly int _chunk;
    private int _read;

    public ScriptedStream(byte[] reply, int chunk = int.MaxValue)
    {
        _reply = reply;
        _chunk = chunk;
    }

    public MemoryStream Written { get; } = new();
    public bool Flushed { get; private set; }
    /// <summary>Reads never return and never end; the only way out is the deadline cancelling the token.</summary>
    public bool HangReads { get; init; }
    public bool HangWrites { get; init; }
    public Exception? ThrowOnRead { get; init; }
    public Exception? ThrowOnWrite { get; init; }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => _reply.Length;
    public override long Position { get => _read; set => throw new NotSupportedException(); }
    public override void Flush() => Flushed = true;
    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        Flushed = true;
        return Task.CompletedTask;
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (ThrowOnRead is not null) throw ThrowOnRead;
        if (HangReads) await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var n = Math.Min(Math.Min(_chunk, buffer.Length), _reply.Length - _read);
        _reply.AsSpan(_read, n).CopyTo(buffer.Span);
        _read += n;
        return n;
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (ThrowOnWrite is not null) throw ThrowOnWrite;
        if (HangWrites) await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        await Written.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
    }
}

public class ServerTransportTests
{
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(10);

    private static byte[] Frame(byte[] body)
    {
        var header = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(header, (uint)body.Length);
        return [.. header, .. body];
    }

    private static byte[] Frame(uint declaredLength, byte[] body)
    {
        var header = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(header, declaredLength);
        return [.. header, .. body];
    }

    private static Task<ServerReply> Exchange(Stream stream, byte[]? request = null, TimeSpan? deadline = null, CancellationToken ct = default) =>
        ServerTransport.ExchangeAsync(stream, request ?? "{\"op\":\"auth\"}"u8.ToArray(), deadline ?? Deadline, ct);

    [Fact]
    public async Task Good_reply_round_trips()
    {
        var body = "{\"v\":1,\"result\":\"ok\"}"u8.ToArray();
        var stream = new ScriptedStream(Frame(body));
        var result = await Exchange(stream);
        Assert.Equal(body, result.Reply);
        Assert.Equal("", result.Why);
    }

    [Fact]
    public async Task Request_is_framed_big_endian()
    {
        var request = new byte[0x0102];
        var stream = new ScriptedStream(Frame("{}"u8.ToArray()));
        await Exchange(stream, request);
        var written = stream.Written.ToArray();
        Assert.True(stream.Flushed);
        Assert.Equal(new byte[] { 0, 0, 1, 2 }, written[..4]); // big-endian, not little
        Assert.Equal(request.Length, written.Length - 4);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(7)]
    [InlineData(int.MaxValue)]
    public async Task Short_reads_are_reassembled(int chunk)
    {
        var body = "{\"v\":1,\"result\":\"invalid\"}"u8.ToArray();
        var result = await Exchange(new ScriptedStream(Frame(body), chunk));
        Assert.Equal(body, result.Reply);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Eof_in_the_header_is_no_answer(int headerBytes)
    {
        var result = await Exchange(new ScriptedStream(Frame("hello"u8.ToArray())[..headerBytes]));
        Assert.Null(result.Reply);
        Assert.Equal("server: connection closed", result.Why);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(9)]
    public async Task Eof_in_the_body_is_no_answer(int bodyBytes)
    {
        var truncated = Frame(10, new byte[bodyBytes]); // header says 10, fewer follow
        var result = await Exchange(new ScriptedStream(truncated));
        Assert.Null(result.Reply);
        Assert.Equal("server: connection closed", result.Why);
    }

    [Theory]
    [InlineData(0u, false)]
    [InlineData(1u, true)]
    [InlineData((uint)ServerTransport.MaxReplyBytes, true)]
    [InlineData((uint)ServerTransport.MaxReplyBytes + 1, false)]
    [InlineData(0x10000000u, false)]
    [InlineData(uint.MaxValue, false)]
    public async Task Reply_length_bounds(uint declared, bool accepted)
    {
        // Provide exactly as many body bytes as declared (capped so the test stays small) so only the length check decides.
        var provided = (int)Math.Min(declared, (uint)ServerTransport.MaxReplyBytes);
        var result = await Exchange(new ScriptedStream(Frame(declared, new byte[provided])));
        if (accepted)
        {
            Assert.NotNull(result.Reply);
            Assert.Equal(provided, result.Reply!.Length);
        }
        else
        {
            Assert.Null(result.Reply);
            Assert.Equal("server: bad reply length", result.Why);
        }
    }

    [Fact]
    public async Task Trailing_bytes_after_the_frame_are_ignored()
    {
        // A middlebox that injects bytes after the reply: we read exactly our frame and never see them.
        var body = "{\"v\":1,\"result\":\"ok\"}"u8.ToArray();
        var withGarbage = new ScriptedStream([.. Frame(body), 0xDE, 0xAD, 0xBE, 0xEF, .. new byte[500]]);
        var result = await Exchange(withGarbage);
        Assert.Equal(body, result.Reply);
    }

    [Fact]
    public async Task A_stuck_read_times_out()
    {
        var stream = new ScriptedStream([]) { HangReads = true };
        var result = await Exchange(stream, deadline: TimeSpan.FromMilliseconds(40));
        Assert.Null(result.Reply);
        Assert.Equal("server: timeout", result.Why);
    }

    [Fact]
    public async Task A_stuck_write_times_out()
    {
        var stream = new ScriptedStream([]) { HangWrites = true };
        var result = await Exchange(stream, deadline: TimeSpan.FromMilliseconds(40));
        Assert.Null(result.Reply);
        Assert.Equal("server: timeout", result.Why);
    }

    [Fact]
    public async Task A_dribble_past_the_deadline_times_out()
    {
        // The header arrives and one body byte, then the link goes quiet forever: the deadline, not an EOF, ends it.
        var result = await ServerTransport.ExchangeAsync(
            new HalfOpenStream(Frame(10_000, new byte[1])), "{}"u8.ToArray(), TimeSpan.FromMilliseconds(40), CancellationToken.None);
        Assert.Null(result.Reply);
        Assert.Equal("server: timeout", result.Why);
    }

    [Fact]
    public async Task An_io_error_is_no_answer()
    {
        var stream = new ScriptedStream([]) { ThrowOnRead = new IOException("connection reset") };
        var result = await Exchange(stream);
        Assert.Null(result.Reply);
        Assert.Equal("server: IOException", result.Why);
    }

    [Fact]
    public async Task A_write_error_is_no_answer()
    {
        var stream = new ScriptedStream([]) { ThrowOnWrite = new IOException("broken pipe") };
        var result = await Exchange(stream);
        Assert.Null(result.Reply);
        Assert.Equal("server: IOException", result.Why);
    }

    [Fact]
    public async Task Caller_cancellation_propagates_and_is_not_swallowed_as_an_answer()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var stream = new ScriptedStream([]) { HangReads = true };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ServerTransport.ExchangeAsync(stream, "{}"u8.ToArray(), Deadline, cts.Token));
    }

    [Fact]
    public async Task A_zero_deadline_means_no_timer()
    {
        var body = "{\"v\":1}"u8.ToArray();
        var result = await Exchange(new ScriptedStream(Frame(body)), deadline: TimeSpan.Zero);
        Assert.Equal(body, result.Reply);
    }

    [Fact]
    public async Task Null_arguments_throw()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            ServerTransport.ExchangeAsync(null!, [1], Deadline, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            ServerTransport.ExchangeAsync(new MemoryStream(), null!, Deadline, CancellationToken.None));
    }

    // ---- mapping to the login domain ----

    [Fact]
    public void Auth_mapping_parses_a_reply()
    {
        var reply = ServerReply.Ok("{\"v\":1,\"result\":\"ok\",\"user\":true,\"admin\":false}"u8.ToArray());
        var answer = ServerTransport.ToAuthAnswer(reply);
        Assert.Equal(ServerOutcome.Success, answer.Outcome);
        Assert.Equal(new UserFlags(true, false), answer.User);
    }

    [Theory]
    [InlineData("server: timeout")]
    [InlineData("server: connection closed")]
    [InlineData("tls: server key does not match the pin")]
    public void Auth_mapping_of_no_answer_keeps_the_reason(string why)
    {
        var answer = ServerTransport.ToAuthAnswer(ServerReply.NoAnswer(why));
        Assert.Equal(ServerOutcome.NoAnswer, answer.Outcome);
        Assert.Equal(why, answer.Detail);
        Assert.Null(answer.User);
    }

    [Fact]
    public void Status_mapping_parses_a_reply()
    {
        var reply = ServerReply.Ok("{\"v\":1,\"result\":\"ok\",\"users\":[\"alice\"],\"admins\":[]}"u8.ToArray());
        var snapshot = ServerTransport.ToStatus(reply, ["alice", "bob"]);
        Assert.NotNull(snapshot);
        Assert.Equal(["alice"], snapshot!.Users);
        Assert.Empty(snapshot.Admins);
    }

    [Fact]
    public void Status_mapping_of_no_answer_is_null() =>
        Assert.Null(ServerTransport.ToStatus(ServerReply.NoAnswer("server: timeout"), ["alice"]));

    [Fact]
    public void Server_reply_helpers()
    {
        Assert.Equal(new ServerReply(null, "x"), ServerReply.NoAnswer("x"));
        var body = new byte[] { 1 };
        Assert.Equal(new ServerReply(body, ""), ServerReply.Ok(body));
    }
}

/// <summary>Delivers a header then one body byte, and then hangs forever: exercises the deadline mid-body.</summary>
internal sealed class HalfOpenStream(byte[] data) : Stream
{
    private int _at;
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => data.Length;
    public override long Position { get => _at; set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => ValueTask.CompletedTask;

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_at >= data.Length) await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
        buffer.Span[0] = data[_at++];
        return 1;
    }
}
