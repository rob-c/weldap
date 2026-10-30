using System.Security.Cryptography;
using Xunit;

namespace Weldap.Tests;

public class UunTests
{
    [Theory]
    [InlineData("alice")]
    [InlineData("a")]
    [InlineData("0")]
    [InlineData("s1234567")]
    [InlineData("12345678901234567890")]
    [InlineData("abcdefghijklmnopqrst")] // 20
    [InlineData("administrator")] // valid UUN; excluded separately
    public void Accepts(string uun) => Assert.True(Uun.IsValid(uun));

    [Theory]
    [InlineData("")]
    [InlineData("*")]
    [InlineData("a)")]
    [InlineData("a,ou=x")]
    [InlineData("a=b")]
    [InlineData("a\\b")]
    [InlineData("a b")]
    [InlineData(" alice")]
    [InlineData("alice ")]
    [InlineData("alice\n")]
    [InlineData("alice\r\n")]
    [InlineData("\nalice")]
    [InlineData("alice\0")]
    [InlineData("al\tice")]
    [InlineData("Alice")]
    [InlineData("ALICE")]
    [InlineData("aliCe")]
    [InlineData("abcdefghijklmnopqrstu")] // 21
    [InlineData("123456789012345678901")] // 21
    [InlineData("a-b")]
    [InlineData("a_b")]
    [InlineData("a.b")]
    [InlineData("a@b")]
    [InlineData("..")]
    [InlineData(null)]
    public void Rejects(string? uun) => Assert.False(Uun.IsValid(uun));

    private static string U(int codePoint) => char.ConvertFromUtf32(codePoint);

    public static TheoryData<string> Lookalikes() =>
    [
        U(0x0430) + "lice",          // Cyrillic a
        "b" + U(0x03BF) + "b",       // Greek omicron
        U(0xFF41) + "lice",          // fullwidth a
        "alic" + U(0x00E9),          // precomposed e-acute
        "alice" + U(0x0301),         // combining acute
        "al" + U(0x0131) + "ce",     // dotless i
        U(0x212A) + "en",            // Kelvin sign (folds to k case-insensitively)
        "s" + U(0x0663) + "4",       // Arabic-Indic digit three
        "s" + U(0x00B2),             // superscript two
        "s" + U(0xFF11),             // fullwidth digit one
        "alice" + U(0x200B),         // zero-width space
        U(0xFEFF) + "alice",         // byte-order mark
        "alice" + U(0x00A0),         // no-break space
        "alice" + U(0x2028),         // line separator
        "alice" + U(0x1F600),        // emoji (surrogate pair)
        "ﬁle",                       // fi ligature
    ];

    [Theory]
    [MemberData(nameof(Lookalikes))]
    public void Rejects_unicode_lookalikes(string uun) => Assert.False(Uun.IsValid(uun));

    [Fact]
    public void Single_characters_accepted_are_exactly_a_to_z_and_0_to_9()
    {
        for (var c = 0; c <= 0xFFFF; c++)
        {
            var expected = c is (>= 'a' and <= 'z') or (>= '0' and <= '9');
            Assert.True(expected == Uun.IsValid(((char)c).ToString()), $"U+{c:X4}");
        }
    }

    [Fact]
    public void Lengths_1_to_20_only()
    {
        for (var n = 0; n <= 64; n++) Assert.Equal(n is >= 1 and <= 20, Uun.IsValid(new string('x', n)));
    }
}

public class ExclusionTests
{
    [Theory]
    [InlineData("administrator")]
    [InlineData("Administrator")]
    [InlineData("ADMINISTRATOR")]
    [InlineData("guest")]
    [InlineData("Guest")]
    [InlineData("defaultaccount")]
    [InlineData("DefaultAccount")]
    [InlineData("wdagutilityaccount")]
    [InlineData("WDAGUtilityAccount")]
    [InlineData("breakglass")]
    [InlineData("BreakGlass")]
    public void Excluded(string uun) => Assert.True(TestSettings.Create().IsExcluded(uun));

    [Theory]
    [InlineData("alice")]
    [InlineData("admin")]
    [InlineData("administrators")]
    [InlineData("guests")]
    [InlineData("breakglass2")]
    [InlineData("")]
    public void Not_excluded(string uun) => Assert.False(TestSettings.Create().IsExcluded(uun));

    [Fact]
    public void Built_ins_apply_even_with_an_empty_list()
    {
        var s = TestSettings.Create() with { ExcludedAccounts = [] };
        Assert.All(LoginSettings.BuiltInExcluded, n => Assert.True(s.IsExcluded(n)));
        Assert.False(s.IsExcluded("breakglass"));
    }

    [Fact]
    public void Defaults()
    {
        var s = new LoginSettings { ServerHost = "h", ServerPins = [TestSettings.Pin] };
        Assert.Equal(636, s.ServerPort);
        Assert.Equal(180, s.MaxOfflineDays);
        Assert.Equal(10, s.OfflineMaxFailures);
        Assert.Empty(s.ExcludedAccounts);
    }
}

public class SettingsTextTests
{
    public static TheoryData<object?, string> Lists() => new()
    {
        { null, "" },
        { 42, "" },
        { new object(), "" },
        { "", "" },
        { "   ", "" },
        { "a", "a" },
        { "a,b", "a|b" },
        { "a;b", "a|b" },
        { "a[~]b", "a|b" },
        { "a[~]b[~]c", "a|b|c" },
        { " a , b ", "a|b" },
        { "a,,b", "a|b" },
        { ",a,", "a" },
        { "[~]", "" },
        { "a[~]", "a" },
        { "[~][~]a", "a" },
        { "a[~]b;c,d", "a|b|c|d" },
        { "a[ ~]b", "a[ ~]b" },
        { "a~b", "a~b" },
        { "a[~b", "a[~b" },
        { "a b", "a b" },
        { "\ta\t", "a" },
        { new[] { "a", "b" }, "a|b" },
        { new[] { "a", "b,c" }, "a|b|c" },
        { new[] { " ", "", "x" }, "x" },
        { new[] { "a[~]b", " c " }, "a|b|c" },
        { Array.Empty<string>(), "" },
    };

    [Theory]
    [MemberData(nameof(Lists))]
    public void SplitList(object? value, string expected) =>
        Assert.Equal(expected, string.Join("|", SettingsText.SplitList(value)));

    private static string B64(int bytes, byte fill = 0x5A) => Convert.ToBase64String(Enumerable.Repeat(fill, bytes).ToArray());

    public static TheoryData<string, bool> Pins() => new()
    {
        { TestSettings.Pin, true },
        { Convert.ToBase64String(SHA256.HashData("x"u8)), true },
        { B64(32, 0xFF), true },
        { B64(32, 0x00), true },
        { "", false },
        { TestSettings.Pin[..43], false },                 // padding missing
        { TestSettings.Pin + "=", false },                 // 45 chars
        { B64(33), false },                                // 44 chars, 33 bytes
        { B64(31), false },                                // 44 chars, 31 bytes
        { B64(20), false },                                // SHA-1
        { B64(48), false },                                // SHA-384
        { B64(64), false },                                // SHA-512
        { "!" + TestSettings.Pin[1..], false },
        { TestSettings.Pin.Replace('A', '-'), false },     // base64url
        { "_" + TestSettings.Pin[1..], false },            // base64url
        { " " + TestSettings.Pin[1..], false },
        { TestSettings.Pin[..20] + " " + TestSettings.Pin[21..], false },
        { TestSettings.Pin[..42] + "==", false },
        { TestSettings.Pin[..43] + "A", false },
        { "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9=", false }, // stray bits before the padding
        { "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh/=", false },
        { new string('=', 44), false },
        { Convert.ToHexString(SHA256.HashData("x"u8)), false }, // hex, not base64
    };

    [Theory]
    [MemberData(nameof(Pins))]
    public void IsPin(string pin, bool expected) => Assert.Equal(expected, SettingsText.IsPin(pin));

    private static LoginSettings Good => TestSettings.Create();

    [Fact]
    public void Validate_returns_the_same_settings()
    {
        var g = Good;
        Assert.Same(g, SettingsText.Validate(g));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(443)]
    [InlineData(636)]
    [InlineData(65535)]
    public void Validate_accepts_ports(int port) => SettingsText.Validate(Good with { ServerPort = port });

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(65536)]
    [InlineData(int.MinValue)]
    [InlineData(int.MaxValue)]
    public void Validate_rejects_ports(int port) =>
        Assert.Contains("ServerPort", Assert.Throws<InvalidOperationException>(() => SettingsText.Validate(Good with { ServerPort = port })).Message);

    public static TheoryData<string> GoodHosts() =>
    [
        "weldap.example.test", "localhost", "a", "10.0.0.1", "::1", "fe80::1", "2001:db8::42", "x-y.example", "UPPER.Example.COM",
        new string('a', 63) + "." + new string('b', 63) + "." + new string('c', 63) + "." + new string('d', 61), // 253
    ];

    [Theory]
    [MemberData(nameof(GoodHosts))]
    public void Validate_accepts_hosts(string host) => SettingsText.Validate(Good with { ServerHost = host });

    public static TheoryData<string> BadHosts() =>
    [
        "", " ", "a b", " weldap.test", "weldap.test ", "weldap/test", "http://weldap.test", "weldap.test/",
        "a\\b", "x_y.test", "weldap.test\n", "h\u00e9llo.test", "\u0430.test" /* Cyrillic a */, "weldap.test%25", "user@host",
        "[::1]", "host,other", "host;other", "*.test", "\0", new string('a', 254),
    ];

    [Theory]
    [MemberData(nameof(BadHosts))]
    public void Validate_rejects_hosts(string host) =>
        Assert.Contains("ServerHost", Assert.Throws<InvalidOperationException>(() => SettingsText.Validate(Good with { ServerHost = host })).Message);

    [Fact]
    public void Validate_requires_pins() =>
        Assert.Contains("not set", Assert.Throws<InvalidOperationException>(() => SettingsText.Validate(Good with { ServerPins = [] })).Message);

    [Theory]
    [InlineData("not-a-pin")]
    [InlineData("")]
    [InlineData("AAAA")]
    public void Validate_rejects_any_bad_pin(string bad)
    {
        Assert.Throws<InvalidOperationException>(() => SettingsText.Validate(Good with { ServerPins = [bad] }));
        Assert.Throws<InvalidOperationException>(() => SettingsText.Validate(Good with { ServerPins = [TestSettings.Pin, bad] }));
        Assert.Throws<InvalidOperationException>(() => SettingsText.Validate(Good with { ServerPins = [bad, TestSettings.Pin] }));
    }

    [Fact]
    public void Validate_accepts_several_pins() =>
        SettingsText.Validate(Good with { ServerPins = [TestSettings.Pin, B64(32, 1), B64(32, 2)] });

    [Fact]
    public void Pins_from_an_msi_property_validate()
    {
        var pins = SettingsText.SplitList(TestSettings.Pin + "[~]" + B64(32, 1));
        Assert.Equal(2, pins.Length);
        SettingsText.Validate(Good with { ServerPins = pins });
    }
}
