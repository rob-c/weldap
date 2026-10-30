using System.Buffers.Binary;
using System.Text;
using Xunit;

namespace Weldap.Tests;

/// <summary>ProtocolCodec.TryParseRequest: the service's only parser of input from another process.</summary>
public class RequestParseTests
{
    private static readonly RequestBuilder Valid = new();
    private static readonly byte[] ValidBytes = Valid.Build();

    /// <summary>Largest legal request: every variable field at its maximum.</summary>
    private static readonly RequestBuilder Max = new()
    {
        Uun = Enumerable.Repeat((byte)'z', 20).ToArray(),
        Kid = Enumerable.Repeat((byte)'-', 32).ToArray(),
        Ct = Enumerable.Repeat((byte)0xEE, 272).ToArray(),
        Ts = long.MaxValue,
    };

    private static LoginRequest? Parse(byte[] m) => ProtocolCodec.TryParseRequest(m);

    private static void AssertSame(SpecParser.Parsed expected, LoginRequest actual)
    {
        Assert.Equal(expected.Scenario, actual.Scenario);
        Assert.Equal(expected.Uun, actual.Uun);
        Assert.Equal(expected.Kid, actual.Sealed.Kid);
        Assert.Equal(expected.Enc, actual.Sealed.Enc);
        Assert.Equal(expected.Ct, actual.Sealed.Ct);
        Assert.Equal(expected.Ts, actual.Sealed.Ts);
        Assert.Equal(expected.Rid, actual.Sealed.Rid);
        Assert.Equal(expected.Verifier, actual.Verifier.ToArray());
    }

    [Fact]
    public void Parses_valid_request()
    {
        using var r = Parse(ValidBytes)!;
        Assert.Equal(Scenario.Logon, r.Scenario);
        Assert.Equal("alice", r.Uun);
        Assert.Equal("k1", r.Sealed.Kid);
        Assert.Equal(Valid.Enc, r.Sealed.Enc);
        Assert.Equal(Valid.Ct, r.Sealed.Ct);
        Assert.Equal(1793320000, r.Sealed.Ts);
        Assert.Equal(Valid.Rid, r.Sealed.Rid);
        Assert.Equal(FakeSeal.Verifier("alice-pw"), r.Verifier.ToArray());
    }

    [Fact]
    public void Builder_layout_matches_the_documented_size() =>
        Assert.Equal(3 + 5 + 1 + 2 + 65 + 2 + 24 + 8 + 16 + 32, ValidBytes.Length);

    [Fact]
    public void Largest_legal_request_parses_and_fits_a_frame()
    {
        var bytes = Max.Build();
        Assert.Equal(3 + 20 + 1 + 32 + 65 + 2 + 272 + 8 + 16 + 32, bytes.Length);
        Assert.True(bytes.Length <= Protocol.MaxMessageBytes);
        using var r = Parse(bytes)!;
        Assert.Equal(new string('z', 20), r.Uun);
        Assert.Equal(long.MaxValue, r.Sealed.Ts);
    }

    [Theory]
    [InlineData(0, Scenario.Logon)]
    [InlineData(1, Scenario.Unlock)]
    public void Scenario_byte(byte value, Scenario expected)
    {
        using var r = Parse((Valid with { Scenario = value }).Build())!;
        Assert.Equal(expected, r.Scenario);
    }

    public static TheoryData<int> TruncationLengths() => [.. Enumerable.Range(0, ValidBytes.Length)];

    [Theory]
    [MemberData(nameof(TruncationLengths))]
    public void Every_truncation_is_rejected(int length) => Assert.Null(Parse(ValidBytes[..length]));

    [Fact]
    public void Every_truncation_of_the_largest_request_is_rejected()
    {
        var bytes = Max.Build();
        for (var n = 0; n < bytes.Length; n++) Assert.Null(Parse(bytes[..n]));
    }

    private enum Field { Version, Scenario, UunLen, Uun, KidLen, Kid, Enc0, Enc, CtLen, Ct, Ts, Rid, Verifier }

    private static Field FieldAt(int pos) => pos switch
    {
        _ when pos == RequestBuilder.VersionAt => Field.Version,
        _ when pos == RequestBuilder.ScenarioAt => Field.Scenario,
        _ when pos == RequestBuilder.UunLenAt => Field.UunLen,
        _ when pos < Valid.KidLenAt => Field.Uun,
        _ when pos == Valid.KidLenAt => Field.KidLen,
        _ when pos < Valid.EncAt => Field.Kid,
        _ when pos == Valid.EncAt => Field.Enc0,
        _ when pos < Valid.CtLenAt => Field.Enc,
        _ when pos < Valid.CtAt => Field.CtLen,
        _ when pos < Valid.TsAt => Field.Ct,
        _ when pos < Valid.RidAt => Field.Ts,
        _ when pos < Valid.VerifierAt => Field.Rid,
        _ => Field.Verifier,
    };

    public static TheoryData<int> BytePositions() => [.. Enumerable.Range(0, ValidBytes.Length)];

    /// <summary>
    /// Every value of every byte of a valid request: accepted exactly when the field rule allows it, and then
    /// parsed with the mutated value (cross-checked against the independent spec parser).
    /// </summary>
    [Theory]
    [MemberData(nameof(BytePositions))]
    public void Every_single_byte_mutation(int pos)
    {
        var field = FieldAt(pos);
        for (var value = 0; value < 256; value++)
        {
            var m = (byte[])ValidBytes.Clone();
            m[pos] = (byte)value;
            var expected = field switch
            {
                Field.Version => value == Protocol.Version,
                Field.Scenario => value <= 1,
                Field.UunLen or Field.KidLen or Field.CtLen => value == ValidBytes[pos],
                Field.Uun => value is >= 0x21 and <= 0x7E,
                Field.Kid => value is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-',
                Field.Enc0 => value == 0x04,
                Field.Ts => BinaryPrimitives.ReadInt64LittleEndian(m.AsSpan(Valid.TsAt)) > 0,
                _ => true,
            };
            var spec = SpecParser.Parse(m);
            Assert.Equal(expected, spec is not null); // the oracle agrees with the field rule
            using var actual = Parse(m);
            Assert.True(expected == (actual is not null), $"{field} @{pos} = 0x{value:x2}");
            if (actual is not null) AssertSame(spec!, actual);
        }
    }

    public static TheoryData<int, bool> UunLengths() => new()
    {
        { 0, false }, { 1, true }, { 2, true }, { 19, true }, { 20, true }, { 21, false }, { 32, false }, { 255, false },
    };

    [Theory]
    [MemberData(nameof(UunLengths))]
    public void Uun_length_bounds(int length, bool accepted)
    {
        var m = (Valid with { Uun = Enumerable.Repeat((byte)'a', length).ToArray() }).Build();
        using var r = Parse(m);
        Assert.Equal(accepted, r is not null);
        if (r is not null) Assert.Equal(length, r.Uun.Length);
    }

    public static TheoryData<int, bool> KidLengths() => new()
    {
        { 0, false }, { 1, true }, { 2, true }, { 31, true }, { 32, true }, { 33, false }, { 64, false }, { 255, false },
    };

    [Theory]
    [MemberData(nameof(KidLengths))]
    public void Kid_length_bounds(int length, bool accepted)
    {
        var m = (Valid with { Kid = Enumerable.Repeat((byte)'k', length).ToArray() }).Build();
        using var r = Parse(m);
        Assert.Equal(accepted, r is not null);
        if (r is not null) Assert.Equal(length, r.Sealed.Kid.Length);
    }

    public static TheoryData<int, bool> CtLengths() => new()
    {
        { 0, false }, { 1, false }, { 15, false }, { 16, false }, { 17, true }, { 18, true }, { 100, true },
        { 271, true }, { 272, true }, { 273, false }, { 300, false }, { 1024, false }, { 3500, false },
    };

    [Theory]
    [MemberData(nameof(CtLengths))]
    public void Ct_length_bounds(int length, bool accepted)
    {
        var m = (Valid with { Ct = Enumerable.Repeat((byte)0x5A, length).ToArray() }).Build();
        using var r = Parse(m);
        Assert.Equal(accepted, r is not null);
        if (r is not null) Assert.Equal(length, r.Sealed.Ct.Length);
    }

    [Theory]
    [InlineData(ushort.MaxValue)]
    [InlineData(0x8000)]
    [InlineData(0x0111)] // 273
    [InlineData(0x0100)] // 256: legal value, but more than the bytes present
    public void Ct_length_larger_than_the_data_is_rejected(int declared) =>
        Assert.Null(Parse((Valid with { CtLen = declared }).Build()));

    public static TheoryData<string, int> LengthLies()
    {
        var data = new TheoryData<string, int>();
        foreach (var field in new[] { "uun", "kid", "ct" })
            foreach (var delta in new[] { -3, -2, -1, 1, 2, 3 })
                data.Add(field, delta);
        return data;
    }

    /// <summary>A length prefix that disagrees with the content that follows never parses.</summary>
    [Theory]
    [MemberData(nameof(LengthLies))]
    public void Length_prefix_that_lies_is_rejected(string field, int delta)
    {
        var b = field switch
        {
            "uun" => Valid with { UunLen = Valid.Uun.Length + delta },
            "kid" => Valid with { KidLen = Valid.Kid.Length + delta },
            _ => Valid with { CtLen = Valid.Ct.Length + delta },
        };
        var m = b.Build();
        Assert.Null(SpecParser.Parse(m));
        Assert.Null(Parse(m));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(100)]
    [InlineData(4096 - 158)]
    public void Trailing_bytes_are_rejected(int extra)
    {
        Assert.Null(Parse((Valid with { Trailing = new byte[extra] }).Build()));
        Assert.Null(Parse((Valid with { Trailing = Enumerable.Repeat((byte)0xFF, extra).ToArray() }).Build()));
    }

    [Fact]
    public void A_second_request_appended_is_rejected() => Assert.Null(Parse([.. ValidBytes, .. ValidBytes]));

    [Theory]
    [InlineData(0L, false)]
    [InlineData(-1L, false)]
    [InlineData(long.MinValue, false)]
    [InlineData(-1793320000L, false)]
    [InlineData(1L, true)]
    [InlineData(1793320000L, true)]
    [InlineData(long.MaxValue, true)]
    public void Timestamp_must_be_positive(long ts, bool accepted)
    {
        using var r = Parse((Valid with { Ts = ts }).Build());
        Assert.Equal(accepted, r is not null);
        if (r is not null) Assert.Equal(ts, r.Sealed.Ts);
    }

    [Theory]
    [InlineData("a", true)]
    [InlineData("0", true)]
    [InlineData("-", true)]
    [InlineData("k-1", true)]
    [InlineData("2026-10-server-key", true)]
    [InlineData("abcdefghijklmnopqrstuvwxyz012345", true)]
    [InlineData("K1", false)]
    [InlineData("k_1", false)]
    [InlineData("k.1", false)]
    [InlineData("k 1", false)]
    [InlineData("k/1", false)]
    [InlineData("k\\1", false)]
    [InlineData("k\"1", false)]
    [InlineData("k\n", false)]
    [InlineData("k\0", false)]
    [InlineData("ké", false)]
    [InlineData("kа", false)] // Cyrillic a
    public void Kid_charset(string kid, bool accepted)
    {
        using var r = Parse((Valid with { Kid = Encoding.UTF8.GetBytes(kid) }).Build());
        Assert.Equal(accepted, r is not null);
        if (r is not null) Assert.Equal(kid, r.Sealed.Kid);
    }

    /// <summary>The codec only insists on printable ASCII; the handler then applies the UUN rule.</summary>
    [Theory]
    [InlineData("alice", true)]
    [InlineData("Alice", true)]
    [InlineData("a=b,ou=x", true)]
    [InlineData("!~", true)]
    [InlineData("a b", false)]
    [InlineData("a\tb", false)]
    [InlineData("alice\n", false)]
    [InlineData("a\0", false)]
    [InlineData("a\u007f", false)]
    [InlineData("alicé", false)]
    [InlineData("аlice", false)] // Cyrillic a
    public void Uun_must_be_printable_ascii(string uun, bool accepted)
    {
        using var r = Parse((Valid with { Uun = Encoding.UTF8.GetBytes(uun) }).Build());
        Assert.Equal(accepted, r is not null);
        if (r is not null) Assert.Equal(uun, r.Uun);
    }

    [Theory]
    [InlineData(0x00)]
    [InlineData(0x02)]
    [InlineData(0x03)]
    [InlineData(0x05)]
    [InlineData(0x06)]
    [InlineData(0x07)]
    [InlineData(0xFF)]
    public void Enc_must_be_an_uncompressed_point(byte first)
    {
        var enc = RequestBuilder.DefaultEnc();
        enc[0] = first;
        Assert.Null(Parse((Valid with { Enc = enc }).Build()));
    }

    [Theory]
    [InlineData(64)]
    [InlineData(66)]
    [InlineData(33)]
    public void Enc_of_the_wrong_size_is_rejected(int size)
    {
        var enc = new byte[size];
        enc[0] = 4;
        Assert.Null(Parse((Valid with { Enc = enc }).Build()));
    }

    [Theory]
    [InlineData(15)]
    [InlineData(17)]
    public void Rid_of_the_wrong_size_is_rejected(int size) =>
        Assert.Null(Parse((Valid with { Rid = new byte[size] }).Build()));

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]
    public void Verifier_of_the_wrong_size_is_rejected(int size) =>
        Assert.Null(Parse((Valid with { Verifier = new byte[size] }).Build()));

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    [InlineData(0xFF)]
    public void Wrong_version_is_rejected(byte version) =>
        Assert.Null(Parse((Valid with { Version = version }).Build()));

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(0x80)]
    [InlineData(0xFF)]
    public void Wrong_scenario_is_rejected(byte scenario) =>
        Assert.Null(Parse((Valid with { Scenario = scenario }).Build()));

    [Theory]
    [InlineData(new byte[0])]
    [InlineData(new byte[] { 3 })]
    [InlineData(new byte[] { 3, 0 })]
    [InlineData(new byte[] { 3, 0, 0 })]
    [InlineData(new byte[] { 3, 0, 1 })]
    [InlineData(new byte[] { 3, 0, 1, (byte)'a' })]
    [InlineData(new byte[] { 3, 0, 1, (byte)'a', 1, (byte)'k' })]
    public void Tiny_inputs_are_rejected(byte[] m) => Assert.Null(Parse(m));

    [Theory]
    [InlineData(4097)]
    [InlineData(8192)]
    [InlineData(65536)]
    [InlineData(1 << 20)]
    public void Oversize_input_is_rejected(int size)
    {
        var m = new byte[size];
        ValidBytes.CopyTo(m, 0);
        Assert.Null(Parse(m));
    }

    [Fact]
    public void Input_of_exactly_the_frame_limit_is_parsed_not_refused_up_front()
    {
        var m = (Valid with { Trailing = new byte[Protocol.MaxMessageBytes - ValidBytes.Length] }).Build();
        Assert.Equal(Protocol.MaxMessageBytes, m.Length);
        Assert.Null(Parse(m)); // refused for its trailing bytes, the same as any other request with them
    }

    public static TheoryData<int> Seeds(int count) => [.. Enumerable.Range(0, count)];

    /// <summary>Random well-formed requests round-trip through the builder and the codec, field for field.</summary>
    [Theory]
    [MemberData(nameof(Seeds), 40)]
    public void Random_valid_requests_round_trip(int seed)
    {
        var rng = new Random(seed);
        const string KidChars = "abcdefghijklmnopqrstuvwxyz0123456789-";
        for (var i = 0; i < 25; i++)
        {
            var enc = new byte[65];
            rng.NextBytes(enc);
            enc[0] = 4;
            var b = new RequestBuilder
            {
                Scenario = (byte)rng.Next(2),
                Uun = Enumerable.Range(0, rng.Next(1, 21)).Select(_ => (byte)rng.Next(0x21, 0x7F)).ToArray(),
                Kid = Enumerable.Range(0, rng.Next(1, 33)).Select(_ => (byte)KidChars[rng.Next(KidChars.Length)]).ToArray(),
                Enc = enc,
                Ct = RandomBytes(rng, rng.Next(17, 273)),
                Ts = rng.NextInt64(1, long.MaxValue),
                Rid = RandomBytes(rng, 16),
                Verifier = RandomBytes(rng, 32),
            };
            using var r = Parse(b.Build())!;
            Assert.Equal(b.Scenario == 1 ? Scenario.Unlock : Scenario.Logon, r.Scenario);
            Assert.Equal(Encoding.ASCII.GetString(b.Uun), r.Uun);
            Assert.Equal(Encoding.ASCII.GetString(b.Kid), r.Sealed.Kid);
            Assert.Equal(b.Enc, r.Sealed.Enc);
            Assert.Equal(b.Ct, r.Sealed.Ct);
            Assert.Equal(b.Ts, r.Sealed.Ts);
            Assert.Equal(b.Rid, r.Sealed.Rid);
            Assert.Equal(b.Verifier, r.Verifier.ToArray());
        }
    }

    private static byte[] RandomBytes(Random rng, int n)
    {
        var b = new byte[n];
        rng.NextBytes(b);
        return b;
    }

    private static byte[] Mutate(Random rng, byte[] seed)
    {
        var m = new List<byte>(seed);
        var edits = rng.Next(1, 5);
        for (var e = 0; e < edits; e++)
        {
            switch (rng.Next(8))
            {
                case 0 when m.Count > 0: // flip one bit
                    var i = rng.Next(m.Count);
                    m[i] ^= (byte)(1 << rng.Next(8));
                    break;
                case 1 when m.Count > 0: // overwrite with an interesting value
                    m[rng.Next(m.Count)] = new byte[] { 0, 1, 3, 4, 16, 17, 20, 21, 32, 33, 0x7F, 0x80, 0xFF }[rng.Next(13)];
                    break;
                case 2: // insert
                    m.Insert(rng.Next(m.Count + 1), (byte)rng.Next(256));
                    break;
                case 3 when m.Count > 0: // delete
                    m.RemoveAt(rng.Next(m.Count));
                    break;
                case 4: // truncate
                    m = m.Take(rng.Next(m.Count + 1)).ToList();
                    break;
                case 5 when m.Count > 8: // duplicate a chunk
                    var at = rng.Next(m.Count - 8);
                    m.InsertRange(rng.Next(m.Count), m.GetRange(at, rng.Next(1, 8)));
                    break;
                case 6: // append junk
                    m.AddRange(RandomBytes(rng, rng.Next(1, 10)));
                    break;
                default: // overwrite a run
                    if (m.Count > 0)
                    {
                        var start = rng.Next(m.Count);
                        for (var k = start; k < Math.Min(m.Count, start + rng.Next(1, 6)); k++) m[k] = (byte)rng.Next(256);
                    }
                    break;
            }
        }
        return [.. m];
    }

    /// <summary>
    /// Deterministic fuzz: random buffers and mutations of valid requests. The codec never throws and accepts
    /// exactly what the independent spec parser accepts, with the same fields.
    /// </summary>
    [Theory]
    [MemberData(nameof(Seeds), 50)]
    public void Fuzz_never_throws_and_matches_the_spec(int seed)
    {
        var rng = new Random(seed);
        var seeds = new[] { ValidBytes, Max.Build(), RequestBuilder.For("bob", "x", Scenario.Unlock).Build() };
        for (var i = 0; i < 400; i++)
        {
            var m = (i % 4) switch
            {
                0 => RandomBytes(rng, rng.Next(0, 600)),
                1 => [Protocol.Version, .. RandomBytes(rng, rng.Next(0, 500))],
                _ => Mutate(rng, seeds[rng.Next(seeds.Length)]),
            };
            var spec = SpecParser.Parse(m);
            using var actual = Parse(m);
            Assert.Equal(spec is not null, actual is not null);
            if (actual is null) continue;
            AssertSame(spec!, actual);
        }
    }

    [Fact]
    public void Fuzz_finds_both_outcomes()
    {
        // Guards the fuzz test against degenerating into "everything is rejected".
        var rng = new Random(12345);
        var accepted = 0;
        for (var i = 0; i < 2000; i++)
        {
            var m = Mutate(rng, ValidBytes);
            using var r = Parse(m);
            if (r is not null) accepted++;
        }
        Assert.InRange(accepted, 20, 1990);
    }

    [Fact]
    public void Request_holds_its_own_copies_of_the_frame()
    {
        // The pipe server zeroes the frame right after parsing.
        var m = (byte[])ValidBytes.Clone();
        using var r = Parse(m)!;
        Array.Clear(m);
        Assert.Equal("alice", r.Uun);
        Assert.Equal(Valid.Enc, r.Sealed.Enc);
        Assert.Equal(Valid.Ct, r.Sealed.Ct);
        Assert.Equal(Valid.Rid, r.Sealed.Rid);
        Assert.Equal(FakeSeal.Verifier("alice-pw"), r.Verifier.ToArray());
    }

    [Fact]
    public void Dispose_zeroes_the_verifier()
    {
        var r = Parse(ValidBytes)!;
        Assert.Contains(r.Verifier.ToArray(), b => b != 0);
        r.Dispose();
        Assert.All(r.Verifier.ToArray(), b => Assert.Equal(0, b));
        Assert.Equal(Protocol.VerifierBytes, r.Verifier.Length);
    }

    [Fact]
    public void Dispose_twice_is_harmless()
    {
        var r = Parse(ValidBytes)!;
        r.Dispose();
        r.Dispose();
        Assert.All(r.Verifier.ToArray(), b => Assert.Equal(0, b));
    }
}
