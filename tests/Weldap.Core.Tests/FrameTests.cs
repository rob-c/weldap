using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Xunit;

namespace Weldap.Tests;

/// <summary>A stream that hands out at most <c>chunk</c> bytes per read and remembers every buffer it filled.</summary>
internal sealed class TrickleStream(byte[] data, int chunk = 1) : Stream
{
    private int _at;
    public List<byte[]> Buffers { get; } = [];
    public bool FailReads { get; init; }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => data.Length;
    public override long Position { get => _at; set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        if (FailReads) throw new IOException("pipe broken");
        var n = Math.Min(Math.Min(chunk, buffer.Length), data.Length - _at);
        data.AsSpan(_at, n).CopyTo(buffer);
        _at += n;
        return n;
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (MemoryMarshal.TryGetArray<byte>(buffer, out var segment) && !Buffers.Contains(segment.Array!)) Buffers.Add(segment.Array!);
        return ValueTask.FromResult(Read(buffer.Span));
    }
}

public class FrameTests
{
    private static byte[] Header(uint length)
    {
        var h = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(h, length);
        return h;
    }

    private static byte[] Body(int n) => [.. Enumerable.Range(0, n).Select(i => (byte)(i * 31 + 7))];

    private static Task<byte[]?> Read(Stream s) => ProtocolCodec.ReadFrameAsync(s, CancellationToken.None);

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(158)]
    [InlineData(451)]
    [InlineData(4095)]
    [InlineData(4096)]
    public async Task Frames_round_trip(int n)
    {
        var stream = new MemoryStream();
        await ProtocolCodec.WriteFrameAsync(stream, Body(n), CancellationToken.None);
        Assert.Equal(4 + n, stream.Length);
        stream.Position = 0;
        Assert.Equal(Body(n), await Read(stream));
        Assert.Equal(stream.Length, stream.Position);
    }

    [Theory]
    [InlineData(0, new byte[] { 0, 0, 0, 0 })]
    [InlineData(1, new byte[] { 1, 0, 0, 0 })]
    [InlineData(0x0102, new byte[] { 2, 1, 0, 0 })]
    [InlineData(4096, new byte[] { 0, 0x10, 0, 0 })]
    [InlineData(70000, new byte[] { 0x70, 0x11, 0x01, 0 })]
    public async Task Write_prefix_is_little_endian(int n, byte[] header)
    {
        var stream = new MemoryStream();
        await ProtocolCodec.WriteFrameAsync(stream, Body(n), CancellationToken.None);
        var written = stream.ToArray();
        Assert.Equal(header, written[..4]);
        Assert.Equal(Body(n), written[4..]);
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(4097u)]
    [InlineData(8192u)]
    [InlineData(0x7FFFFFFFu)]
    [InlineData(0x80000000u)]
    [InlineData(0xFFFFFFFFu)]
    public async Task Read_rejects_bad_lengths_without_reading_the_body(uint length)
    {
        var stream = new MemoryStream([.. Header(length), .. new byte[8192]]);
        Assert.Null(await Read(stream));
        Assert.Equal(4, stream.Position);
    }

    [Theory]
    [InlineData(1u)]
    [InlineData(4096u)]
    public async Task Read_accepts_lengths_at_the_bounds(uint length)
    {
        var body = Body((int)length);
        Assert.Equal(body, await Read(new MemoryStream([.. Header(length), .. body])));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Eof_inside_the_header_is_null(int bytes) =>
        Assert.Null(await Read(new MemoryStream(Header(10)[..bytes])));

    [Theory]
    [InlineData(10, 0)]
    [InlineData(10, 1)]
    [InlineData(10, 9)]
    [InlineData(4096, 4095)]
    [InlineData(4096, 0)]
    public async Task Eof_inside_the_body_is_null_and_the_partial_body_is_zeroed(int declared, int present)
    {
        var stream = new TrickleStream([.. Header((uint)declared), .. Body(present)], chunk: 3);
        Assert.Null(await Read(stream));
        var body = Assert.Single(stream.Buffers, b => b.Length == declared);
        Assert.All(body, b => Assert.Equal(0, b));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(7)]
    [InlineData(4096)]
    public async Task Short_reads_are_reassembled(int chunk)
    {
        var body = Body(300);
        Assert.Equal(body, await Read(new TrickleStream([.. Header(300), .. body], chunk)));
    }

    [Fact]
    public async Task Reads_exactly_one_frame()
    {
        var stream = new MemoryStream([.. Header(3), 1, 2, 3, .. Header(2), 9, 8]);
        Assert.Equal(new byte[] { 1, 2, 3 }, await Read(stream));
        Assert.Equal(new byte[] { 9, 8 }, await Read(stream));
        Assert.Null(await Read(stream));
    }

    [Fact]
    public async Task Io_errors_propagate()
    {
        // The pipe server treats IOException as "client went away"; it must not look like a valid empty frame.
        var stream = new TrickleStream([.. Header(3), 1, 2, 3]) { FailReads = true };
        await Assert.ThrowsAsync<IOException>(() => Read(stream));
    }

    [Fact]
    public async Task Cancellation_propagates()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ProtocolCodec.ReadFrameAsync(new TrickleStream([.. Header(3), 1, 2, 3]), cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ProtocolCodec.WriteFrameAsync(new MemoryStream(), [1], cts.Token));
    }

    [Fact]
    public async Task Writes_header_and_payload_without_a_combined_copy()
    {
        var stream = new RecordingStream();
        var payload = Body(10);
        await ProtocolCodec.WriteFrameAsync(stream, payload, CancellationToken.None);
        Assert.Equal(2, stream.Writes.Count);
        Assert.Equal(4, stream.Writes[0].Length);
        Assert.Same(payload, stream.Writes[1]);
        Assert.True(stream.Flushed);
    }

    private sealed class RecordingStream : MemoryStream
    {
        public List<byte[]> Writes { get; } = [];
        public bool Flushed { get; private set; }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (MemoryMarshal.TryGetArray(buffer, out var segment)) Writes.Add(segment.Array!);
            return base.WriteAsync(buffer, cancellationToken);
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            Flushed = true;
            return base.FlushAsync(cancellationToken);
        }
    }
}

public class LocalPasswordTests
{
    // Independent copy of the alphabet: no look-alikes (0 O 1 l I), nothing that needs quoting anywhere.
    private const string Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+-.:=?@^_~";

    public static TheoryData<char> Chars()
    {
        var data = new TheoryData<char>();
        for (var c = (char)0; c < 128; c++) data.Add(c);
        foreach (var c in new[] { '\u00a0', '\u00e9', '\u03a9', '\u0430', '\uff21', '\u200b', '\ufeff', '\uffff' }) data.Add(c);
        return data;
    }

    [Theory]
    [MemberData(nameof(Chars))]
    public void IsAllowed_table(char c) => Assert.Equal(Alphabet.Contains(c, StringComparison.Ordinal), LocalPasswords.IsAllowed(c));

    [Fact]
    public void Alphabet_has_70_distinct_printable_ascii_characters()
    {
        Assert.Equal(70, Alphabet.Distinct().Count());
        Assert.Equal(70, Enumerable.Range(0, 0x10000).Count(c => LocalPasswords.IsAllowed((char)c)));
    }

    private static readonly string[] Samples = [.. Enumerable.Range(0, 5000).Select(_ => new string(LocalPasswords.Generate()))];

    [Fact]
    public void Every_sample_is_32_allowed_characters() =>
        Assert.All(Samples, p =>
        {
            Assert.Equal(LocalPasswords.Length, p.Length);
            Assert.Equal(32, p.Length);
            Assert.All(p, c => Assert.True(LocalPasswords.IsAllowed(c)));
        });

    [Fact]
    public void Every_sample_has_all_four_classes() =>
        Assert.All(Samples, p =>
        {
            Assert.Contains(p, char.IsAsciiLetterUpper);
            Assert.Contains(p, char.IsAsciiLetterLower);
            Assert.Contains(p, char.IsAsciiDigit);
            Assert.Contains(p, c => !char.IsAsciiLetterOrDigit(c));
        });

    [Fact]
    public void Samples_are_unique() => Assert.Equal(Samples.Length, Samples.Distinct(StringComparer.Ordinal).Count());

    [Fact]
    public void Every_character_of_the_alphabet_occurs_at_a_plausible_rate()
    {
        var counts = Samples.SelectMany(p => p).GroupBy(c => c).ToDictionary(g => g.Key, g => g.Count());
        Assert.Equal(70, counts.Count);
        var mean = Samples.Length * 32.0 / 70;
        // Loose bounds: catches a broken generator (stuck, biased to one class), not subtle bias.
        Assert.All(counts.Values, n => Assert.InRange(n, mean * 0.5, mean * 1.7));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(31)]
    public void The_class_positions_are_shuffled(int position)
    {
        var classes = Samples.Select(p => p[position] switch
        {
            _ when char.IsAsciiLetterUpper(p[position]) => 0,
            _ when char.IsAsciiLetterLower(p[position]) => 1,
            _ when char.IsAsciiDigit(p[position]) => 2,
            _ => 3,
        }).Distinct().Count();
        Assert.Equal(4, classes);
    }

    [Fact]
    public void Each_call_returns_a_new_buffer()
    {
        var a = LocalPasswords.Generate();
        var b = LocalPasswords.Generate();
        Assert.NotSame(a, b);
        Array.Clear(a);
        Assert.DoesNotContain('\0', b);
    }
}
