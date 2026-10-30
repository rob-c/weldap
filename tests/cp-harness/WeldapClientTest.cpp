// WELDAP credential provider: tests for the pipe client and the password sealer, built against the
// provider's own WeldapClient.cpp and WeldapSeal.cpp (see build.ps1).
//
//   WeldapClientTest selftest                                  unit, known-answer, adversarial and pipe tests
//   WeldapClientTest seal <public-b64> <aad> <password>        HPKE seal; host checks it with `weldap-probe open`
//   WeldapClientTest call <logon|unlock> <uun> <password|->   seal + real pipe exchange (prints no secrets);
//                                                              "-" reads the password from stdin
//
// selftest prints one PASS/FAIL line per check (SKIP for checks that cannot run here) and needs no
// configuration: the pipe tests run their own server thread on a private pipe name, and WeldapSealPassword is
// tested against a private, volatile registry tree mapped over HKEY_LOCAL_MACHINE for this process only
// (RegOverridePredefKey), so HKLM\SOFTWARE\WELDAP is never read or written. Reference values come from
// RFC 9180 / the CFRG HPKE test vectors, RFC 7914, and Python's hashlib/hmac + `cryptography` on the host.
// /analyze: C28285 is a syntax error inside the SDK's own SAL for CryptStringToBinaryW (wincrypt.h, SDK
// 10.0.26100), raised while the header is parsed, not a finding in this code; must precede the includes.
#pragma warning(disable: 28285)
#include "../../client/Weldap.CredentialProvider/WeldapClient.h"
#include "../../client/Weldap.CredentialProvider/WeldapSeal.h"
#include <bcrypt.h>
#include <wincrypt.h>
#include <sddl.h>
#include <aclapi.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <initializer_list>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

typedef std::vector<BYTE> Bytes;

// =============================================================================================
// Test plumbing
// =============================================================================================

static int g_passes = 0;
static int g_failures = 0;
static int g_skips = 0;

static void Check(bool f, _In_z_ _Printf_format_string_ const char *pszFormat, ...)
{
    char sz[600];
    va_list args;
    va_start(args, pszFormat);
    vsnprintf_s(sz, sizeof(sz), _TRUNCATE, pszFormat, args);
    va_end(args);
    printf("%s  %s\n", f ? "PASS" : "FAIL", sz);
    if (f)
    {
        g_passes++;
    }
    else
    {
        g_failures++;
    }
}

static void Skip(_In_z_ _Printf_format_string_ const char *pszFormat, ...)
{
    char sz[600];
    va_list args;
    va_start(args, pszFormat);
    vsnprintf_s(sz, sizeof(sz), _TRUNCATE, pszFormat, args);
    va_end(args);
    printf("SKIP  %s\n", sz);
    g_skips++;
}

static void Section(_In_z_ const char *pszName)
{
    printf("-- %s\n", pszName);
}

static int HexNibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static Bytes Hex(_In_z_ const char *psz)
{
    Bytes b;
    size_t n = strlen(psz);
    for (size_t i = 0; i + 1 < n; i += 2)
    {
        b.push_back(static_cast<BYTE>((HexNibble(psz[i]) << 4) | HexNibble(psz[i + 1])));
    }
    return b;
}

static Bytes Str(_In_z_ const char *psz)
{
    const BYTE *pb = reinterpret_cast<const BYTE *>(psz);
    return Bytes(pb, pb + strlen(psz));
}

static Bytes Rep(BYTE b, size_t n)
{
    return Bytes(n, b);
}

static Bytes Cat(std::initializer_list<Bytes> parts)
{
    Bytes r;
    for (const Bytes &p : parts)
    {
        r.insert(r.end(), p.begin(), p.end());
    }
    return r;
}

static Bytes Of(const BYTE *pb, size_t cb)
{
    return cb == 0 ? Bytes() : Bytes(pb, pb + cb);
}

static bool AllZero(const void *pv, size_t cb)
{
    const BYTE *pb = static_cast<const BYTE *>(pv);
    for (size_t i = 0; i < cb; i++)
    {
        if (pb[i] != 0) return false;
    }
    return true;
}

static Bytes Utf8(const std::wstring &s)
{
    if (s.empty()) return Bytes();
    int cb = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (cb <= 0) return Bytes();
    Bytes b(static_cast<size_t>(cb));
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), reinterpret_cast<char *>(b.data()), cb, nullptr, nullptr);
    return b;
}

// Independent base64 (RFC 4648, with padding) for building the expected AAD.
static std::string Base64Of(const Bytes &b)
{
    static const char c_rgch[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string s;
    size_t i = 0;
    for (; i + 3 <= b.size(); i += 3)
    {
        unsigned v = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
        s += c_rgch[(v >> 18) & 63]; s += c_rgch[(v >> 12) & 63]; s += c_rgch[(v >> 6) & 63]; s += c_rgch[v & 63];
    }
    if (b.size() - i == 1)
    {
        unsigned v = b[i] << 16;
        s += c_rgch[(v >> 18) & 63]; s += c_rgch[(v >> 12) & 63]; s += "==";
    }
    else if (b.size() - i == 2)
    {
        unsigned v = (b[i] << 16) | (b[i + 1] << 8);
        s += c_rgch[(v >> 18) & 63]; s += c_rgch[(v >> 12) & 63]; s += c_rgch[(v >> 6) & 63]; s += '=';
    }
    return s;
}

// Deterministic xorshift64 for the fuzz loops (same sequence on every run and architecture).
struct Rng
{
    unsigned long long s;
    unsigned long long Next()
    {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        return s;
    }
    unsigned Below(unsigned n)
    {
        return static_cast<unsigned>(Next() % n);
    }
    BYTE Byte()
    {
        return static_cast<BYTE>(Next() >> 24);
    }
};

// Places a buffer so that it ends exactly at a PAGE_NOACCESS page: any read or write past the end the code
// under test was given crashes the harness instead of passing silently.
class GuardedBuffer
{
public:
    GuardedBuffer()
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        m_cbPage = si.dwPageSize;
        m_pb = static_cast<BYTE *>(VirtualAlloc(nullptr, 3 * m_cbPage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        DWORD dwOld;
        if (m_pb != nullptr && !VirtualProtect(m_pb + 2 * m_cbPage, m_cbPage, PAGE_NOACCESS, &dwOld))
        {
            VirtualFree(m_pb, 0, MEM_RELEASE);
            m_pb = nullptr;
        }
    }
    ~GuardedBuffer()
    {
        if (m_pb != nullptr) VirtualFree(m_pb, 0, MEM_RELEASE);
    }
    GuardedBuffer(const GuardedBuffer &) = delete;
    GuardedBuffer &operator=(const GuardedBuffer &) = delete;

    bool Ok() const { return m_pb != nullptr; }
    size_t Capacity() const { return 2 * m_cbPage; }

    // Copies b so that its last byte is the last accessible byte; returns the start.
    BYTE *Place(const Bytes &b)
    {
        BYTE *p = m_pb + 2 * m_cbPage - b.size();
        if (!b.empty()) memcpy(p, b.data(), b.size());
        return p;
    }
    // cb writable bytes filled with bFill, ending at the guard page.
    BYTE *Space(size_t cb, BYTE bFill)
    {
        BYTE *p = m_pb + 2 * m_cbPage - cb;
        memset(p, bFill, cb);
        return p;
    }

private:
    BYTE *m_pb = nullptr;
    size_t m_cbPage = 0;
};

static GuardedBuffer *g_pGuard = nullptr;

// =============================================================================================
// Reference codec: an independent transcription of the v3 layouts in client/Weldap.Core/Protocol.cs
// (TryParseRequest / EncodeReply doc comments), used as the oracle for the C++ codec.
// =============================================================================================

struct REF_REQUEST
{
    int scenario;
    std::string uun, kid;
    Bytes enc, ct, rid, verifier;
    unsigned long long ts;
};

// Mirrors ProtocolCodec.TryParseRequest rule for rule.
static bool RefParseRequest(const Bytes &m, REF_REQUEST *pr)
{
    if (m.empty() || m.size() > 4096 || m[0] != 3 || m.size() < 3) return false;
    if (m[1] > 1) return false;
    size_t at = 2;
    auto take = [&](size_t n, Bytes *pField) -> bool {
        if (at + n > m.size()) return false;
        pField->assign(m.begin() + static_cast<ptrdiff_t>(at), m.begin() + static_cast<ptrdiff_t>(at + n));
        at += n;
        return true;
    };
    Bytes f, uun, kid;
    if (!take(1, &f) || f[0] == 0 || f[0] > 20 || !take(f[0], &uun)) return false;
    for (BYTE c : uun) if (c < 0x21 || c > 0x7E) return false;
    if (!take(1, &f) || f[0] == 0 || f[0] > 32 || !take(f[0], &kid)) return false;
    for (BYTE c : kid) if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
    if (!take(65, &pr->enc) || pr->enc[0] != 0x04) return false;
    if (!take(2, &f)) return false;
    unsigned ctLen = f[0] | (f[1] << 8);
    if (ctLen <= 16 || ctLen > 16 + 256 || !take(ctLen, &pr->ct)) return false;
    if (!take(8, &f)) return false;
    unsigned long long ts = 0;
    for (int i = 7; i >= 0; i--) ts = (ts << 8) | f[static_cast<size_t>(i)];
    if (static_cast<long long>(ts) <= 0) return false;
    if (!take(16, &pr->rid) || !take(32, &pr->verifier)) return false;
    if (at != m.size()) return false;
    pr->scenario = m[1];
    pr->uun.assign(uun.begin(), uun.end());
    pr->kid.assign(kid.begin(), kid.end());
    pr->ts = ts;
    return true;
}

// The request bytes for a WELDAP_SEALED, written out field by field from the documented layout.
static Bytes ExpectedRequest(bool fUnlock, const std::string &uun, const WELDAP_SEALED &s)
{
    size_t cchKid = strnlen(s.szKid, sizeof(s.szKid));
    Bytes m;
    m.push_back(0x03);
    m.push_back(fUnlock ? 0x01 : 0x00);
    m.push_back(static_cast<BYTE>(uun.size()));
    m.insert(m.end(), uun.begin(), uun.end());
    m.push_back(static_cast<BYTE>(cchKid));
    m.insert(m.end(), s.szKid, s.szKid + cchKid);
    m.insert(m.end(), s.rgbEnc, s.rgbEnc + sizeof(s.rgbEnc));
    m.push_back(static_cast<BYTE>(s.cbCt & 0xFF));
    m.push_back(static_cast<BYTE>((s.cbCt >> 8) & 0xFF));
    m.insert(m.end(), s.rgbCt, s.rgbCt + s.cbCt);
    unsigned long long ts = s.ts;
    for (int i = 0; i < 8; i++, ts >>= 8) m.push_back(static_cast<BYTE>(ts & 0xFF));
    m.insert(m.end(), s.rgbRid, s.rgbRid + sizeof(s.rgbRid));
    m.insert(m.end(), s.rgbVerifier, s.rgbVerifier + sizeof(s.rgbVerifier));
    return m;
}

struct REF_REPLY
{
    int result;
    bool fOffline;
    std::wstring message;   // exactly msgLen units (may contain U+0000)
    std::string password;
};

// Reply: version(1)=3 result(1) mode(1) msgLen(1) message(UTF-16LE) pwLen(1) password(ASCII), nothing after;
// result <= 2, mode <= 1, msgLen <= 200; ok: 1..64 bytes of 0x21..0x7E; deny/error: no password, mode 0.
static bool RefParseReply(_In_reads_bytes_opt_(cb) const BYTE *pb, size_t cb, REF_REPLY *pr)
{
    if (pb == nullptr || cb == 0 || cb > 4096) return false;
    size_t i = 0;
    auto avail = [&](size_t n) { return cb - i >= n; };
    if (!avail(4)) return false;
    BYTE ver = pb[0], result = pb[1], mode = pb[2], msgLen = pb[3];
    i = 4;
    if (ver != 3 || result > 2 || mode > 1 || msgLen > 200) return false;
    if (!avail(2u * msgLen)) return false;
    std::wstring message;
    for (size_t k = 0; k < msgLen; k++)
    {
        message += static_cast<wchar_t>(pb[i] | (pb[i + 1] << 8));
        i += 2;
    }
    if (!avail(1)) return false;
    BYTE pwLen = pb[i++];
    if (!avail(pwLen)) return false;
    std::string password(reinterpret_cast<const char *>(pb + i), pwLen);
    i += pwLen;
    if (i != cb) return false;
    if (result == 0)
    {
        if (pwLen < 1 || pwLen > 64) return false;
        for (char c : password) if (static_cast<BYTE>(c) < 0x21 || static_cast<BYTE>(c) > 0x7E) return false;
    }
    else if (pwLen != 0 || mode != 0)
    {
        return false;
    }
    pr->result = result;
    pr->fOffline = mode == 1;
    pr->message = message;
    pr->password = password;
    return true;
}

static Bytes ReplyBytes(BYTE ver, BYTE result, BYTE mode, const std::wstring &msg, const std::string &pw)
{
    Bytes b = { ver, result, mode, static_cast<BYTE>(msg.size()) };
    for (wchar_t c : msg)
    {
        b.push_back(static_cast<BYTE>(c & 0xFF));
        b.push_back(static_cast<BYTE>((c >> 8) & 0xFF));
    }
    b.push_back(static_cast<BYTE>(pw.size()));
    b.insert(b.end(), pw.begin(), pw.end());
    return b;
}

static bool IsZeroedError(const WELDAP_REPLY &r)
{
    WELDAP_REPLY z;
    ZeroMemory(&z, sizeof(z));
    z.result = WELDAP_RESULT_VALUE_ERROR;
    return memcmp(&r, &z, sizeof(r)) == 0;
}

// Field-by-field equality of the parser's output with the reference, including terminators and the
// untouched (zero) tails of both arrays.
static bool ReplyMatches(const WELDAP_REPLY &r, const REF_REPLY &ref)
{
    if (static_cast<int>(r.result) != ref.result || r.fOffline != ref.fOffline) return false;
    if (ref.message.size() > WELDAP_MAX_REPLY_MESSAGE_CHARS || ref.password.size() > WELDAP_MAX_LOCAL_PASSWORD_CHARS) return false;
    for (size_t i = 0; i <= WELDAP_MAX_REPLY_MESSAGE_CHARS; i++)
    {
        wchar_t want = i < ref.message.size() ? ref.message[i] : L'\0';
        if (r.message[i] != want) return false;
    }
    for (size_t i = 0; i <= WELDAP_MAX_LOCAL_PASSWORD_CHARS; i++)
    {
        wchar_t want = i < ref.password.size() ? static_cast<wchar_t>(static_cast<BYTE>(ref.password[i])) : L'\0';
        if (r.password[i] != want) return false;
    }
    return true;
}

// Parses b from a guarded copy with a poisoned output; *pfAccepted = parser verdict. True when the parser
// agrees with the reference (verdict and every field), and a rejection left the reply zeroed (result=error).
static bool ParseAgrees(const Bytes &b, bool *pfAccepted = nullptr, WELDAP_REPLY *pOut = nullptr)
{
    WELDAP_REPLY r;
    memset(&r, 0xA5, sizeof(r));
    const BYTE *pb = g_pGuard->Place(b);
    bool fOk = WeldapParseReply(pb, b.size(), &r);
    REF_REPLY ref;
    bool fRef = RefParseReply(pb, b.size(), &ref);
    if (pfAccepted) *pfAccepted = fOk;
    if (pOut) *pOut = r;
    bool f = (fOk == fRef) && (fOk ? ReplyMatches(r, ref) : IsZeroedError(r));
    SecureZeroMemory(&r, sizeof(r));
    return f;
}

static bool ParseRejects(const Bytes &b)
{
    bool fAccepted = true;
    return ParseAgrees(b, &fAccepted) && !fAccepted;
}

static bool ParseAccepts(const Bytes &b, WELDAP_RESULT result, bool fOffline, const std::wstring &msg, const std::string &pw)
{
    bool fAccepted = false;
    WELDAP_REPLY r;
    bool f = ParseAgrees(b, &fAccepted, &r) && fAccepted && r.result == result && r.fOffline == fOffline;
    f = f && wcsnlen(r.message, ARRAYSIZE(r.message)) <= msg.size() && wmemcmp(r.message, msg.data(), msg.size()) == 0 &&
        r.message[msg.size()] == L'\0';
    std::wstring wpw(pw.begin(), pw.end());
    f = f && wcscmp(r.password, wpw.c_str()) == 0;
    SecureZeroMemory(&r, sizeof(r));
    return f;
}

// =============================================================================================
// UUN normalisation
// =============================================================================================

static bool UunIs(const std::wstring &in, _In_opt_z_ PCWSTR pwzExpected)
{
    wchar_t out[WELDAP_MAX_UUN_CHARS + 2];
    wmemset(out, L'#', ARRAYSIZE(out));
    HRESULT hr = WeldapNormalizeUun(in.c_str(), out, WELDAP_MAX_UUN_CHARS + 1);
    if (out[WELDAP_MAX_UUN_CHARS + 1] != L'#') return false;   // wrote past cchOut
    if (pwzExpected == nullptr)
    {
        return hr == E_INVALIDARG && out[0] == L'\0';
    }
    return hr == S_OK && wcscmp(out, pwzExpected) == 0;
}

static void TestUun()
{
    Section("WeldapNormalizeUun");
    Check(UunIs(L"alice", L"alice"), "uun: plain lowercase kept");
    Check(UunIs(L"ALICE", L"alice"), "uun: uppercase folded");
    Check(UunIs(L"  Alice\t", L"alice"), "uun: trim + lowercase");
    Check(UunIs(L"\x3000" L"BOB1\x00A0", L"bob1"), "uun: Unicode whitespace trimmed");
    Check(UunIs(L"ABCDEFGHIJKLM", L"abcdefghijklm"), "uun: A-M fold to a-m");
    Check(UunIs(L"NOPQRSTUVWXYZ", L"nopqrstuvwxyz"), "uun: N-Z fold to n-z");
    Check(UunIs(L"0123456789", L"0123456789"), "uun: digits kept");
    Check(UunIs(L"MiXeD123cAsE", L"mixed123case"), "uun: mixed case");
    Check(UunIs(L"a", L"a"), "uun: 1 char ok");
    Check(UunIs(L"7", L"7"), "uun: single digit ok");
    Check(UunIs(L"abcdefghij012345678", L"abcdefghij012345678"), "uun: 19 chars ok");
    Check(UunIs(L"abcdefghij0123456789", L"abcdefghij0123456789"), "uun: 20 chars ok");
    Check(UunIs(L"abcdefghij01234567890", nullptr), "uun: 21 chars rejected");
    Check(UunIs(std::wstring(40, L'a'), nullptr), "uun: 40 chars rejected");
    Check(UunIs(std::wstring(100, L' ') + L"ABCDEFGHIJ0123456789" + std::wstring(100, L'\t'), L"abcdefghij0123456789"),
          "uun: 20 chars inside 200 chars of whitespace ok");
    Check(UunIs(std::wstring(100, L' ') + L"ABCDEFGHIJ01234567890" + std::wstring(100, L' '), nullptr),
          "uun: 21 chars inside whitespace rejected");
    Check(UunIs(L"", nullptr), "uun: empty rejected");
    Check(UunIs(L" ", nullptr), "uun: single space rejected");
    Check(UunIs(L" \t\r\n\x3000\x00A0 ", nullptr), "uun: whitespace only rejected");
    Check(UunIs(std::wstring(L"a") + std::wstring(4095, L' '), L"a"), "uun: 4096-char input (trailing spaces) ok");
    Check(UunIs(std::wstring(4096, L' ') + L"a", nullptr), "uun: input beyond 4096 chars not read (rejected)");

    // Exactly the set .NET's string.Trim() removes (char.IsWhiteSpace): each trimmed at both ends, and
    // rejected inside the name.
    static const struct { wchar_t c; const char *pszName; } c_rgTrim[] = {
        { 0x0009, "TAB" }, { 0x000A, "LF" }, { 0x000B, "VT" }, { 0x000C, "FF" }, { 0x000D, "CR" },
        { 0x0020, "SPACE" }, { 0x0085, "NEL" }, { 0x00A0, "NBSP" }, { 0x1680, "OGHAM SPACE" },
        { 0x2000, "EN QUAD" }, { 0x2001, "EM QUAD" }, { 0x2002, "EN SPACE" }, { 0x2003, "EM SPACE" },
        { 0x2004, "3-PER-EM" }, { 0x2005, "4-PER-EM" }, { 0x2006, "6-PER-EM" }, { 0x2007, "FIGURE SPACE" },
        { 0x2008, "PUNCTUATION SPACE" }, { 0x2009, "THIN SPACE" }, { 0x200A, "HAIR SPACE" },
        { 0x2028, "LINE SEPARATOR" }, { 0x2029, "PARAGRAPH SEPARATOR" }, { 0x202F, "NNBSP" },
        { 0x205F, "MMSP" }, { 0x3000, "IDEOGRAPHIC SPACE" },
    };
    for (const auto &t : c_rgTrim)
    {
        std::wstring s = std::wstring(1, t.c) + L"Alice9" + std::wstring(2, t.c);
        Check(UunIs(s, L"alice9"), "uun: U+%04X %s trimmed at both ends", static_cast<unsigned>(t.c), t.pszName);
    }
    for (const auto &t : c_rgTrim)
    {
        std::wstring s = std::wstring(L"al") + t.c + L"ice";
        Check(UunIs(s, nullptr), "uun: U+%04X %s inside the name rejected", static_cast<unsigned>(t.c), t.pszName);
    }
    // Look like whitespace but are not in the .NET set: not trimmed, so rejected (both ends must agree).
    static const wchar_t c_rgNotTrim[] = { 0x001C, 0x001D, 0x001E, 0x001F, 0x00AD, 0x180E, 0x200B, 0x200C,
                                           0x200D, 0x2060, 0xFEFF };
    for (wchar_t c : c_rgNotTrim)
    {
        bool f = UunIs(std::wstring(1, c) + L"bob", nullptr) && UunIs(std::wstring(L"bob") + c, nullptr);
        Check(f, "uun: U+%04X not trimmed (rejected leading and trailing)", static_cast<unsigned>(c));
    }
    // Every printable ASCII character outside [A-Za-z0-9] is rejected.
    for (wchar_t c = 0x20; c <= 0x7E; c++)
    {
        if ((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9')) continue;
        Check(UunIs(std::wstring(L"ab") + c + L"cd", nullptr), "uun: '%c' (0x%02X) inside rejected", static_cast<char>(c), static_cast<unsigned>(c));
    }
    static const wchar_t c_rgControl[] = { 0x0001, 0x0008, 0x000E, 0x001B, 0x007F, 0x0080, 0x009F };
    for (wchar_t c : c_rgControl)
    {
        Check(UunIs(std::wstring(L"ab") + c + L"cd", nullptr), "uun: control U+%04X rejected", static_cast<unsigned>(c));
    }
    // Non-ASCII letters and digits, including ones whose Unicode case mapping lands in ASCII.
    static const struct { wchar_t c; const char *pszName; } c_rgLookalike[] = {
        { 0x212A, "KELVIN SIGN (lowercases to k)" }, { 0x0130, "LATIN CAPITAL I WITH DOT (lowercases to i)" },
        { 0x0131, "DOTLESS i" }, { 0x017F, "LONG s (uppercases to S)" }, { 0xFF21, "FULLWIDTH A" },
        { 0xFF41, "FULLWIDTH a" }, { 0x00C9, "E ACUTE" }, { 0x00DF, "SHARP s" }, { 0x0410, "CYRILLIC A" },
        { 0x0430, "CYRILLIC a" }, { 0x0661, "ARABIC-INDIC ONE" }, { 0xFF10, "FULLWIDTH 0" },
        { 0x00B2, "SUPERSCRIPT 2" }, { 0x2160, "ROMAN NUMERAL ONE" },
    };
    for (const auto &t : c_rgLookalike)
    {
        Check(UunIs(std::wstring(L"x") + t.c + L"y", nullptr), "uun: U+%04X %s rejected", static_cast<unsigned>(t.c), t.pszName);
    }
    Check(UunIs(L"a\xD83D\xDE00", nullptr), "uun: surrogate pair (emoji) rejected");
    Check(UunIs(L"a\xD800", nullptr), "uun: lone high surrogate rejected");
    Check(UunIs(L"\xDC00z", nullptr), "uun: lone low surrogate rejected");

    // Buffers and arguments.
    {
        wchar_t out[8];
        wmemset(out, L'#', ARRAYSIZE(out));
        Check(WeldapNormalizeUun(L"alice", out, 0) == E_INVALIDARG && out[0] == L'#', "uun: cchOut 0 rejected, nothing written");
#pragma warning(suppress: 6387)   // deliberately null
        Check(WeldapNormalizeUun(L"alice", nullptr, 21) == E_INVALIDARG, "uun: null output rejected");
        Check(WeldapNormalizeUun(nullptr, out, ARRAYSIZE(out)) == E_INVALIDARG && out[0] == L'\0', "uun: null input rejected, output emptied");
        wmemset(out, L'#', ARRAYSIZE(out));
        Check(WeldapNormalizeUun(L"abc", out, 1) == E_INVALIDARG && out[0] == L'\0' && out[1] == L'#', "uun: cchOut 1 too small, only out[0] written");
        wmemset(out, L'#', ARRAYSIZE(out));
        Check(WeldapNormalizeUun(L"abc", out, 3) == E_INVALIDARG && out[0] == L'\0' && out[3] == L'#', "uun: cchOut == length (no room for NUL) rejected");
        wmemset(out, L'#', ARRAYSIZE(out));
        Check(WeldapNormalizeUun(L" ABC ", out, 4) == S_OK && wcscmp(out, L"abc") == 0 && out[4] == L'#', "uun: cchOut == length + 1 ok, nothing past it");
        wmemset(out, L'#', ARRAYSIZE(out));
        Check(WeldapNormalizeUun(L"abcdef!", out, ARRAYSIZE(out)) == E_INVALIDARG && out[0] == L'\0', "uun: late bad char empties output");
        wchar_t out21[WELDAP_MAX_UUN_CHARS + 1];
        Check(WeldapNormalizeUun(L"abcdefghij0123456789", out21, ARRAYSIZE(out21)) == S_OK && out21[20] == L'\0', "uun: 20 chars fit 21-char buffer exactly");
        Check(WeldapNormalizeUun(L"\0abc", out21, ARRAYSIZE(out21)) == E_INVALIDARG, "uun: leading NUL = empty, rejected");
        Check(WeldapNormalizeUun(L"ab\0!!", out21, ARRAYSIZE(out21)) == S_OK && wcscmp(out21, L"ab") == 0, "uun: stops at NUL");
    }
}

// =============================================================================================
// Request encoding
// =============================================================================================

static WELDAP_SEALED MakeSealed(_In_z_ const char *pszKid, ULONG cbCt, unsigned long long ts, BYTE bSeed)
{
    WELDAP_SEALED s;
    memset(&s, 0, sizeof(s));
    strncpy_s(s.szKid, pszKid, _TRUNCATE);
    s.rgbEnc[0] = 0x04;
    for (int i = 1; i < 65; i++) s.rgbEnc[i] = static_cast<BYTE>(bSeed + i);
    for (ULONG i = 0; i < cbCt && i < sizeof(s.rgbCt); i++) s.rgbCt[i] = static_cast<BYTE>(bSeed * 7 + i);
    s.cbCt = cbCt;
    s.ts = ts;
    for (int i = 0; i < 16; i++) s.rgbRid[i] = static_cast<BYTE>(0xA0 + i + bSeed);
    for (int i = 0; i < 32; i++) s.rgbVerifier[i] = static_cast<BYTE>((0xC0 + i) ^ bSeed);
    return s;
}

// Encodes into a guarded buffer of exactly cbOut bytes pre-filled with 0xEE.
static size_t EncodeGuarded(bool fUnlock, _In_opt_z_ PCWSTR pwzUun, _In_opt_ const WELDAP_SEALED *ps, size_t cbOut,
                            Bytes *pOut, bool *pfZeroed)
{
    BYTE *pb = g_pGuard->Space(cbOut, 0xEE);
#pragma warning(suppress: 6387)   // deliberately passing null arguments to test the checks
    size_t cb = WeldapEncodeRequest(fUnlock, pwzUun, ps, pb, cbOut);
    if (pOut) *pOut = Of(pb, cb <= cbOut ? cb : 0);
    if (pfZeroed) *pfZeroed = AllZero(pb, cbOut);
    return cb;
}

static bool EncodeFails(bool fUnlock, _In_opt_z_ PCWSTR pwzUun, _In_opt_ const WELDAP_SEALED *ps, size_t cbOut = 600)
{
    bool fZeroed = false;
    return EncodeGuarded(fUnlock, pwzUun, ps, cbOut, nullptr, &fZeroed) == 0 && fZeroed;
}

static void TestEncode()
{
    Section("WeldapEncodeRequest");
    // Literal expected bytes, written out by hand from the layout.
    {
        WELDAP_SEALED s;
        memset(&s, 0, sizeof(s));
        strcpy_s(s.szKid, "k");
        s.rgbEnc[0] = 0x04;
        memset(s.rgbEnc + 1, 0x11, 64);
        memset(s.rgbCt, 0x22, 17);
        s.cbCt = 17;
        s.ts = 0x0102030405060708ULL;
        memset(s.rgbRid, 0x33, 16);
        memset(s.rgbVerifier, 0x44, 32);
        Bytes want = Cat({ Hex("03" "00" "01" "61" "01" "6b" "04"), Rep(0x11, 64), Hex("1100"), Rep(0x22, 17),
                           Hex("0807060504030201"), Rep(0x33, 16), Rep(0x44, 32) });
        Bytes got;
        size_t cb = EncodeGuarded(false, L"a", &s, 600, &got, nullptr);
        Check(cb == 146 && got == want, "encode: literal logon/uun 'a'/kid 'k'/ct 17/ts 0x0102030405060708 (146 bytes)");

        strcpy_s(s.szKid, "k1-x");
        memset(s.rgbCt, 0x55, 272);
        s.cbCt = 272;
        s.ts = 1793320000ULL;
        want = Cat({ Hex("03" "01" "03" "626f62" "04" "6b312d78" "04"), Rep(0x11, 64), Hex("1001"), Rep(0x55, 272),
                     Hex("40e4e36a00000000"), Rep(0x33, 16), Rep(0x44, 32) });
        cb = EncodeGuarded(true, L"bob", &s, 600, &got, nullptr);
        Check(cb == 3 + 3 + 1 + 4 + 65 + 2 + 272 + 8 + 16 + 32 && got == want, "encode: literal unlock/uun 'bob'/kid 'k1-x'/ct 272 (ctLen 10 01)/ts 1793320000");
    }

    // Every combination of the extremes, checked against the field-by-field layout and the C# parser rules.
    static const char *c_rgUun[] = { "a", "abcdefghij0123456789" };
    static const PCWSTR c_rgwUun[] = { L"a", L"abcdefghij0123456789" };
    static const char *c_rgKid[] = { "k", "0123456789abcdefghijklmnopqrstu-" };
    static const ULONG c_rgCt[] = { 17, 272 };
    BYTE bSeed = 1;
    for (int u = 0; u < 2; u++)
    for (int iu = 0; iu < 2; iu++)
    for (int ik = 0; ik < 2; ik++)
    for (int ic = 0; ic < 2; ic++)
    {
        WELDAP_SEALED s = MakeSealed(c_rgKid[ik], c_rgCt[ic], 1793320000ULL + bSeed, bSeed);
        bSeed++;
        Bytes got;
        Bytes want = ExpectedRequest(u == 1, c_rgUun[iu], s);
        size_t cb = EncodeGuarded(u == 1, c_rgwUun[iu], &s, want.size(), &got, nullptr);
        Check(cb == want.size() && got == want, "encode: %s uun %zu kid %zu ct %lu -> %zu bytes, exact layout (buffer exactly sized)",
              u ? "unlock" : "logon", strlen(c_rgUun[iu]), strlen(c_rgKid[ik]), c_rgCt[ic], want.size());
        REF_REQUEST r;
        bool f = RefParseRequest(got, &r) && r.scenario == u && r.uun == c_rgUun[iu] && r.kid == c_rgKid[ik] &&
                 r.enc == Of(s.rgbEnc, 65) && r.ct == Of(s.rgbCt, s.cbCt) && r.ts == s.ts && r.rid == Of(s.rgbRid, 16) &&
                 r.verifier == Of(s.rgbVerifier, 32);
        Check(f, "encode: %s uun %zu kid %zu ct %lu accepted by the service's parse rules, fields round-trip",
              u ? "unlock" : "logon", strlen(c_rgUun[iu]), strlen(c_rgKid[ik]), c_rgCt[ic]);
    }

    // Timestamp: 8 bytes little-endian.
    {
        static const struct { unsigned long long ts; const char *pszHex; } c_rgTs[] = {
            { 1ULL, "0100000000000000" }, { 0xFFULL, "ff00000000000000" },
            { 0x100ULL, "0001000000000000" }, { 0x0102030405060708ULL, "0807060504030201" },
            { 0x7FFFFFFFFFFFFFFFULL, "ffffffffffffff7f" },
        };
        for (const auto &t : c_rgTs)
        {
            WELDAP_SEALED s = MakeSealed("k", 17, t.ts, 9);
            Bytes got;
            size_t cb = EncodeGuarded(false, L"u", &s, 600, &got, nullptr);
            // ts sits after version, scenario, uunLen, uun(1), kidLen, kid(1), enc(65), ctLen(2), ct(17).
            size_t at = 3 + 1 + 1 + 1 + 65 + 2 + 17;
            Check(cb == got.size() && cb >= at + 8 && Of(got.data() + at, 8) == Hex(t.pszHex), "encode: ts 0x%016llx little-endian", t.ts);
        }
        // The service's rules (Protocol.cs): ts 1..INT64_MAX, enc an uncompressed point, kid [a-z0-9-].
        for (unsigned long long ts : { 0ULL, 0x8000000000000000ULL, 0xFFFFFFFFFFFFFFFFULL })
        {
            WELDAP_SEALED s = MakeSealed("k", 17, ts, 9);
            Check(EncodeFails(false, L"u", &s), "encode: ts 0x%016llx refused (the service would drop it)", ts);
        }
        static const BYTE c_rgBadEnc0[] = { 0x00, 0x02, 0x03, 0x05, 0xFF };
        for (BYTE b : c_rgBadEnc0)
        {
            WELDAP_SEALED s = MakeSealed("k", 17, 1793320000ULL, 9);
            s.rgbEnc[0] = b;
            Check(EncodeFails(false, L"u", &s), "encode: enc[0]=0x%02x refused", b);
        }
        for (const char *kid : { "K1", "k_1", "k 1", "k.1", "k/1", "\x7f" })
        {
            WELDAP_SEALED s = MakeSealed(kid, 17, 1793320000ULL, 9);
            Check(EncodeFails(false, L"u", &s), "encode: kid \"%s\" refused", kid);
        }
    }

    // Exact buffer size, one byte short, and nothing written past cbOut (guard page).
    {
        WELDAP_SEALED s = MakeSealed("0123456789abcdefghijklmnopqrstuv", 272, 1793320000ULL, 3);
        size_t need = ExpectedRequest(true, "abcdefghij0123456789", s).size();
        Check(need == 451, "encode: largest request is 451 bytes");
        Bytes got;
        Check(EncodeGuarded(true, L"abcdefghij0123456789", &s, need, &got, nullptr) == need, "encode: largest request into exactly 451 bytes");
        Check(EncodeFails(true, L"abcdefghij0123456789", &s, need - 1), "encode: 450-byte buffer refused, buffer zeroed");
        Check(EncodeFails(true, L"abcdefghij0123456789", &s, 1), "encode: 1-byte buffer refused, buffer zeroed");
        WELDAP_SEALED smallest = MakeSealed("k", 17, 5, 3);
        size_t needSmall = ExpectedRequest(false, "a", smallest).size();
        Check(EncodeGuarded(false, L"a", &smallest, needSmall, &got, nullptr) == needSmall, "encode: smallest request (%zu bytes) into exact buffer", needSmall);
        Check(EncodeFails(false, L"a", &smallest, needSmall - 1), "encode: smallest request, one byte short refused, buffer zeroed");
        Check(WeldapEncodeRequest(false, L"a", &smallest, g_pGuard->Space(1, 0xEE), 0) == 0, "encode: cbOut 0 refused");
    }

    // Rejections: each must return 0 and leave the output all zero.
    WELDAP_SEALED s = MakeSealed("k1", 18, 1793320000ULL, 5);
    Check(EncodeFails(false, L"", &s), "encode: uun empty refused");
    Check(EncodeFails(false, L"abcdefghij01234567890", &s), "encode: uun 21 chars refused");
    Check(EncodeFails(false, std::wstring(255, L'a').c_str(), &s), "encode: uun 255 chars refused");
    static const struct { PCWSTR pwz; const char *pszName; } c_rgBadUun[] = {
        { L" ab", "leading space 0x20" }, { L"a b", "inner space" }, { L"ab ", "trailing space" },
        { L"a\x7F", "DEL 0x7F" }, { L"\x1F" L"a", "0x1F" }, { L"a\tb", "TAB" }, { L"a\x80", "0x80" },
        { L"\x00E9", "U+00E9" }, { L"a\x0100", "U+0100 (low byte 0x00)" }, { L"a\x0161", "U+0161 (low byte 'a')" },
        { L"\xFF21", "U+FF21" }, { L"a\xD83D\xDE00", "surrogate pair" }, { L"a\x2028", "U+2028" },
    };
    for (const auto &t : c_rgBadUun)
    {
        Check(EncodeFails(false, t.pwz, &s), "encode: uun with %s refused, buffer zeroed", t.pszName);
    }
    Bytes got;
    Check(EncodeGuarded(false, L"A!~z", &s, 600, &got, nullptr) == ExpectedRequest(false, "A!~z", s).size(),
          "encode: printable ASCII uun passed through (the service applies the UUN rule)");
    {
        WELDAP_SEALED bad = s;
        bad.szKid[0] = '\0';
        Check(EncodeFails(false, L"a", &bad), "encode: kid empty refused");
        memset(bad.szKid, 'a', sizeof(bad.szKid));   // 33 chars, no terminator
        Check(EncodeFails(false, L"a", &bad), "encode: kid 33 chars (unterminated) refused");
        bad = s;
        static const ULONG c_rgBadCt[] = { 0, 1, 16, 273, 274, 0x10000, 0xFFFFFFFF };
        for (ULONG cb : c_rgBadCt)
        {
            bad.cbCt = cb;
            Check(EncodeFails(false, L"a", &bad), "encode: cbCt %lu refused", cb);
        }
        bad.cbCt = 256;
        Check(EncodeGuarded(false, L"a", &bad, 600, &got, nullptr) == ExpectedRequest(false, "a", bad).size(), "encode: cbCt 256 ok");
    }
    Check(EncodeFails(false, nullptr, &s), "encode: null uun refused, buffer zeroed");
    Check(EncodeFails(false, L"a", nullptr), "encode: null sealed refused, buffer zeroed");
#pragma warning(suppress: 6387)   // deliberately null
    Check(WeldapEncodeRequest(false, L"a", &s, nullptr, 600) == 0, "encode: null output refused");

    // Fuzz: random field lengths and characters; success iff every field is in range, and then the exact layout.
    {
        Rng rng = { 0x243F6A8885A308D3ULL };
        int cOk = 0, cBad = 0, cWrong = 0;
        for (int iter = 0; iter < 4000; iter++)
        {
            WELDAP_SEALED f;
            memset(&f, 0, sizeof(f));
            unsigned cchKid = rng.Below(35);
            for (unsigned i = 0; i < cchKid && i < sizeof(f.szKid); i++) f.szKid[i] = static_cast<char>('a' + rng.Below(26));
            f.cbCt = rng.Below(8) == 0 ? static_cast<ULONG>(rng.Next()) : rng.Below(300);
            for (BYTE &b : f.rgbEnc) b = rng.Byte();
            if (rng.Below(8) != 0) f.rgbEnc[0] = 0x04;
            for (BYTE &b : f.rgbCt) b = rng.Byte();
            f.ts = rng.Below(8) == 0 ? rng.Next() : 1 + rng.Next() % 0x7FFFFFFFFFFFFFFFULL;
            for (BYTE &b : f.rgbRid) b = rng.Byte();
            for (BYTE &b : f.rgbVerifier) b = rng.Byte();
            unsigned cchUun = rng.Below(23);
            std::wstring uun;
            bool fUunOk = cchUun >= 1 && cchUun <= 20;
            for (unsigned i = 0; i < cchUun; i++)
            {
                wchar_t c = rng.Below(10) == 0 ? static_cast<wchar_t>(1 + rng.Below(0xFFFE)) : static_cast<wchar_t>(0x21 + rng.Below(94));
                if (c < 0x21 || c > 0x7E) fUunOk = false;
                uun += c;
            }
            bool fValid = fUunOk && cchKid >= 1 && cchKid <= 32 && f.cbCt > 16 && f.cbCt <= 272 && f.rgbEnc[0] == 0x04 &&
                          f.ts != 0 && f.ts <= 0x7FFFFFFFFFFFFFFFULL;
            size_t cbOut = rng.Below(4) == 0 ? rng.Below(460) : 600;
            Bytes out;
            bool fZeroed = false;
            bool fUnlock = rng.Below(2) == 1;
            size_t cb = EncodeGuarded(fUnlock, uun.c_str(), &f, cbOut, &out, &fZeroed);
            std::string uunA;
            for (wchar_t c : uun) uunA += static_cast<char>(c);
            if (fValid && cbOut >= ExpectedRequest(false, uunA, f).size())
            {
                Bytes want = ExpectedRequest(fUnlock, uunA, f);
                if (cb == want.size() && out == want) cOk++; else cWrong++;
            }
            else
            {
                if (cb == 0 && fZeroed) cBad++; else cWrong++;
            }
        }
        Check(cWrong == 0 && cOk > 500 && cBad > 500, "encode fuzz: 4000 random requests, %d encoded exactly, %d refused with zeroed buffer, %d wrong",
              cOk, cBad, cWrong);
    }
}

// =============================================================================================
// Reply parsing
// =============================================================================================

static const char c_szPw32[] = "Lp1!x9Qz-.:=?@^_~#%+AbCdEfGhJkMn";
static const char c_szPw64[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+-.:";
static_assert(sizeof(c_szPw32) == 33 && sizeof(c_szPw64) == 65, "fixture lengths");

static std::wstring Message200()
{
    // 200 UTF-16 units: ASCII, Latin-1, BMP and astral (surrogate pairs) characters.
    std::wstring s;
    while (s.size() < 196)
    {
        s += L"a\x00E9\x20AC\xD83D\xDE00";
    }
    s += L"\x4E2D\x6587Z!";
    s.resize(200);
    return s;
}

struct VALID_REPLY
{
    const char *pszName;
    Bytes b;
    WELDAP_RESULT result;
    bool fOffline;
    std::wstring msg;
    std::string pw;
};

static std::vector<VALID_REPLY> ValidReplies()
{
    std::vector<VALID_REPLY> v;
    auto add = [&](const char *pszName, WELDAP_RESULT r, bool fOffline, const std::wstring &msg, const std::string &pw) {
        v.push_back({ pszName, ReplyBytes(3, static_cast<BYTE>(r), fOffline ? 1 : 0, msg, pw), r, fOffline, msg, pw });
    };
    add("ok online, 32-char password", WELDAP_RESULT_VALUE_OK, false, L"", c_szPw32);
    add("ok offline, 1-char password", WELDAP_RESULT_VALUE_OK, true, L"", "!");
    add("ok online, 64-char password", WELDAP_RESULT_VALUE_OK, false, L"", c_szPw64);
    add("ok offline with a message", WELDAP_RESULT_VALUE_OK, true, L"Signed in offline", "~");
    add("deny, ASCII message", WELDAP_RESULT_VALUE_DENY, false, L"The username or password is incorrect.", "");
    add("deny, empty message (5 bytes)", WELDAP_RESULT_VALUE_DENY, false, L"", "");
    add("deny, 1-unit non-ASCII message", WELDAP_RESULT_VALUE_DENY, false, L"\x00E9", "");
    add("error, 200-unit message with surrogate pairs", WELDAP_RESULT_VALUE_ERROR, false, Message200(), "");
    add("error, empty message", WELDAP_RESULT_VALUE_ERROR, false, L"", "");
    add("deny, message of one surrogate pair", WELDAP_RESULT_VALUE_DENY, false, L"\xD83D\xDE00", "");
    return v;
}

static void TestParse()
{
    Section("WeldapParseReply");
    std::vector<VALID_REPLY> valid = ValidReplies();
    for (const VALID_REPLY &r : valid)
    {
        Check(ParseAccepts(r.b, r.result, r.fOffline, r.msg, r.pw), "parse: %s (%zu bytes) accepted, every field exact", r.pszName, r.b.size());
    }
    Check(valid[7].b.size() == 405, "parse: 200-unit message reply is 405 bytes");
    Check(ReplyBytes(3, 0, 0, Message200(), c_szPw64).size() == 469 &&
          ParseAccepts(ReplyBytes(3, 0, 0, Message200(), c_szPw64), WELDAP_RESULT_VALUE_OK, false, Message200(), c_szPw64),
          "parse: largest valid reply (469 bytes: ok, 200-unit message, 64-char password)");

    // Header fields out of range (everything else consistent).
    for (BYTE ver : std::initializer_list<BYTE>{ 0, 1, 2, 4, 0x13, 0x83, 0xFF })
    {
        Check(ParseRejects(ReplyBytes(ver, 1, 0, L"x", "")) && ParseRejects(ReplyBytes(ver, 0, 0, L"", "pw")), "parse: version %u rejected", static_cast<unsigned>(ver));
    }
    for (BYTE res : std::initializer_list<BYTE>{ 3, 4, 0x80, 0xFF })
    {
        Check(ParseRejects(ReplyBytes(3, res, 0, L"x", "")) && ParseRejects(ReplyBytes(3, res, 0, L"", "pw")), "parse: result %u rejected", static_cast<unsigned>(res));
    }
    for (BYTE mode : std::initializer_list<BYTE>{ 2, 3, 0x80, 0xFF })
    {
        Check(ParseRejects(ReplyBytes(3, 0, mode, L"", "pw")), "parse: mode %u on ok rejected", static_cast<unsigned>(mode));
    }
    Check(ParseRejects(ReplyBytes(3, 1, 1, L"no", "")), "parse: offline mode on deny rejected");
    Check(ParseRejects(ReplyBytes(3, 2, 1, L"no", "")), "parse: offline mode on error rejected");
    Check(ParseRejects(ReplyBytes(3, 1, 2, L"no", "")), "parse: mode 2 on deny rejected");
    Check(ParseRejects(ReplyBytes(3, 1, 0, std::wstring(201, L'm'), "")), "parse: message of 201 units rejected");
    Check(ParseRejects(ReplyBytes(3, 2, 0, std::wstring(255, L'm'), "")), "parse: message of 255 units rejected");
    Check(ParseRejects(ReplyBytes(3, 0, 0, std::wstring(201, L'm'), "pw")), "parse: ok with 201-unit message rejected");
    {
        Bytes b = ReplyBytes(3, 1, 0, L"123456789", "");
        b[3] = 10;   // claims one more unit than present
        Check(ParseRejects(b), "parse: msgLen one larger than the message rejected");
        b = ReplyBytes(3, 1, 0, L"1234567890", "");
        b[3] = 9;    // claims one fewer: the last unit's low byte becomes pwLen
        Check(ParseRejects(b), "parse: msgLen one smaller than the message rejected");
        b = ReplyBytes(3, 1, 0, L"", "");
        b.pop_back();
        Check(ParseRejects(b), "parse: 4-byte reply (no pwLen) rejected");
    }
    Check(ParseRejects(ReplyBytes(3, 0, 0, L"", "")), "parse: ok with empty password rejected");
    Check(ParseRejects(ReplyBytes(3, 0, 1, L"", "")), "parse: ok offline with empty password rejected");
    Check(ParseRejects(ReplyBytes(3, 0, 0, L"", std::string(65, 'P'))), "parse: ok with 65-char password rejected");
    Check(ParseRejects(ReplyBytes(3, 0, 0, L"", std::string(255, 'P'))), "parse: ok with 255-char password rejected");
    Check(ParseRejects(ReplyBytes(3, 1, 0, L"", "P")), "parse: deny carrying a 1-char password rejected");
    Check(ParseRejects(ReplyBytes(3, 1, 0, L"msg", std::string(64, 'P'))), "parse: deny carrying a 64-char password rejected");
    Check(ParseRejects(ReplyBytes(3, 2, 0, L"", "P")), "parse: error carrying a password rejected");
    {
        Bytes b = ReplyBytes(3, 0, 0, L"", std::string(64, 'P'));
        b.pop_back();
        Check(ParseRejects(b), "parse: pwLen 64 with 63 bytes present rejected");
    }
    // Password bytes.
    static const struct { BYTE b; size_t at; const char *pszWhere; } c_rgBadPw[] = {
        { 0x20, 0, "first" }, { 0x7F, 31, "last" }, { 0x00, 15, "middle" }, { 0x80, 5, "middle" }, { 0xFF, 0, "first" },
        { 0x09, 31, "last" }, { 0x0A, 1, "second" }, { 0x0D, 30, "second-to-last" }, { 0xC3, 3, "middle" },
    };
    for (const auto &t : c_rgBadPw)
    {
        std::string pw = c_szPw32;
        pw[t.at] = static_cast<char>(t.b);
        Check(ParseRejects(ReplyBytes(3, 0, 0, L"", pw)), "parse: password byte 0x%02X (%s) rejected", static_cast<unsigned>(t.b), t.pszWhere);
    }
    {
        int cAccepted = 0;
        bool fAgree = true;
        for (int c = 0; c < 256; c++)
        {
            bool fAccepted = false;
            fAgree = ParseAgrees(ReplyBytes(3, 0, 0, L"", std::string(1, static_cast<char>(c))), &fAccepted) && fAgree;
            cAccepted += fAccepted ? 1 : 0;
        }
        Check(fAgree && cAccepted == 94, "parse: of 256 one-byte passwords exactly the 94 in 0x21..0x7E accepted (%d)", cAccepted);
    }
    {
        // A bad last password byte after a 200-unit message: the message (already copied) must be wiped too.
        std::string pw = c_szPw64;
        pw[63] = 0x7F;
        Check(ParseRejects(ReplyBytes(3, 0, 0, Message200(), pw)), "parse: bad last password byte after 200-unit message, reply fully wiped");
    }

    // Trailing bytes, sizes, null.
    for (const VALID_REPLY &r : valid)
    {
        bool fAll = true;
        for (int c = 0; c < 256; c++)
        {
            Bytes b = r.b;
            b.push_back(static_cast<BYTE>(c));
            fAll = ParseRejects(b) && fAll;
        }
        Check(fAll, "parse: %s + any 1 trailing byte (256 values) rejected", r.pszName);
    }
    {
        Bytes b = Cat({ valid[5].b, Rep(0, 4096 - valid[5].b.size()) });
        Check(b.size() == 4096 && ParseRejects(b), "parse: valid reply zero-padded to 4096 bytes rejected");
        Bytes big = Cat({ valid[0].b, Rep(0, 4097 - valid[0].b.size()) });
        WELDAP_REPLY r;
        memset(&r, 0xA5, sizeof(r));
        Check(!WeldapParseReply(big.data(), big.size(), &r) && IsZeroedError(r), "parse: cb 4097 (> WELDAP_MAX_MESSAGE_BYTES) rejected");
        memset(&r, 0xA5, sizeof(r));
        const BYTE *pb = g_pGuard->Place(valid[0].b);
        Check(!WeldapParseReply(pb, static_cast<size_t>(-1), &r) && IsZeroedError(r), "parse: cb SIZE_MAX rejected without reading");
        memset(&r, 0xA5, sizeof(r));
        Check(!WeldapParseReply(pb, 0x80000000u, &r) && IsZeroedError(r), "parse: cb 2^31 rejected without reading");
        memset(&r, 0xA5, sizeof(r));
#pragma warning(suppress: 6387)   // deliberately null
        Check(!WeldapParseReply(nullptr, 0, &r) && IsZeroedError(r), "parse: nullptr, cb 0 rejected");
        memset(&r, 0xA5, sizeof(r));
#pragma warning(suppress: 6387)   // deliberately null
        Check(!WeldapParseReply(nullptr, 5, &r) && IsZeroedError(r), "parse: nullptr, cb 5 rejected");
        memset(&r, 0xA5, sizeof(r));
        Check(!WeldapParseReply(g_pGuard->Place(Bytes()), 0, &r) && IsZeroedError(r), "parse: empty buffer rejected");
    }

    // Every truncation of every valid reply (guard page right after the last byte given).
    for (const VALID_REPLY &r : valid)
    {
        bool fAll = true;
        for (size_t n = 0; n < r.b.size(); n++)
        {
            fAll = ParseRejects(Of(r.b.data(), n)) && fAll;
        }
        Check(fAll, "parse: %s, all %zu truncations rejected and zeroed", r.pszName, r.b.size());
    }

    // Every value of every header byte (version, result, mode, msgLen, pwLen) of every valid reply: the parser
    // agrees with the reference, and every rejection leaves the reply zeroed.
    static const char *c_rgHeader[] = { "version", "result", "mode", "msgLen", "pwLen" };
    for (const VALID_REPLY &r : valid)
    {
        size_t rgAt[] = { 0, 1, 2, 3, 4 + 2 * r.msg.size() };
        for (int h = 0; h < 5; h++)
        {
            bool fAll = true;
            int cAccepted = 0;
            for (int c = 0; c < 256; c++)
            {
                if (c == r.b[rgAt[h]]) continue;
                Bytes b = r.b;
                b[rgAt[h]] = static_cast<BYTE>(c);
                bool fAccepted = false;
                fAll = ParseAgrees(b, &fAccepted) && fAll;
                cAccepted += fAccepted ? 1 : 0;
            }
            Check(fAll, "parse: %s, 255 other %s values: parser == reference (%d still valid)", r.pszName, c_rgHeader[h], cAccepted);
        }
    }
    // Version byte specifically: no other value is ever accepted.
    {
        bool fAll = true;
        for (const VALID_REPLY &r : valid)
        for (int c = 0; c < 256; c++)
        {
            if (c == 3) continue;
            Bytes b = r.b;
            b[0] = static_cast<BYTE>(c);
            fAll = ParseRejects(b) && fAll;
        }
        Check(fAll, "parse: version byte != 3 rejected for all valid replies (2550 cases)");
    }
    // Every single-byte value at every position (header and body) of every valid reply.
    for (const VALID_REPLY &r : valid)
    {
        bool fAll = true;
        int cAccepted = 0, cTotal = 0;
        for (size_t at = 0; at < r.b.size(); at++)
        for (int c = 0; c < 256; c++)
        {
            if (c == r.b[at]) continue;
            Bytes b = r.b;
            b[at] = static_cast<BYTE>(c);
            bool fAccepted = false;
            fAll = ParseAgrees(b, &fAccepted) && fAll;
            cAccepted += fAccepted ? 1 : 0;
            cTotal++;
        }
        Check(fAll, "parse: %s, all %d single-byte substitutions: parser == reference (%d valid)", r.pszName, cTotal, cAccepted);
    }
}

// Re-encodes an accepted reply from the WELDAP_REPLY alone (msgLen taken from the input) and checks bounds.
static bool ReencodesConsistently(const Bytes &b, const WELDAP_REPLY &r)
{
    if (b.size() < 5) return false;
    size_t msgLen = b[3];
    if (r.result > WELDAP_RESULT_VALUE_ERROR || msgLen > WELDAP_MAX_REPLY_MESSAGE_CHARS) return false;
    if (r.message[msgLen] != L'\0' || r.message[WELDAP_MAX_REPLY_MESSAGE_CHARS] != L'\0') return false;
    size_t cchPw = wcsnlen(r.password, ARRAYSIZE(r.password));
    if (cchPw > WELDAP_MAX_LOCAL_PASSWORD_CHARS) return false;
    if (r.result == WELDAP_RESULT_VALUE_OK)
    {
        if (cchPw < 1) return false;
        for (size_t i = 0; i < cchPw; i++) if (r.password[i] < 0x21 || r.password[i] > 0x7E) return false;
    }
    else if (cchPw != 0 || r.fOffline || !AllZero(r.password, sizeof(r.password)))
    {
        return false;
    }
    std::wstring msg(r.message, msgLen);
    std::string pw;
    for (size_t i = 0; i < cchPw; i++) pw += static_cast<char>(r.password[i]);
    return ReplyBytes(3, static_cast<BYTE>(r.result), r.fOffline ? 1 : 0, msg, pw) == b;
}

static void FuzzParse()
{
    Section("WeldapParseReply fuzz");
    std::vector<VALID_REPLY> valid = ValidReplies();
    static const char *c_rgStrategy[] = { "random bytes", "structured replies", "mutated valid replies" };
    int cAcceptedAll = 0, cRejectedAll = 0;
    bool fReencode = true;
    for (int strategy = 0; strategy < 3; strategy++)
    {
        Rng rng = { 0x9E3779B97F4A7C15ULL + static_cast<unsigned long long>(strategy) };
        int cAccepted = 0, cRejected = 0, cDisagree = 0;
        const int c_iterations = 20000;
        for (int iter = 0; iter < c_iterations; iter++)
        {
            Bytes b;
            if (strategy == 0)
            {
                size_t n = rng.Below(4) == 0 ? rng.Below(600) : rng.Below(24);
                for (size_t i = 0; i < n; i++) b.push_back(rng.Byte());
                if (!b.empty() && rng.Below(2) == 0) b[0] = 3;
                if (b.size() > 1 && rng.Below(2) == 0) b[1] = static_cast<BYTE>(rng.Below(4));
                if (b.size() > 2 && rng.Below(2) == 0) b[2] = static_cast<BYTE>(rng.Below(3));
                if (b.size() > 3 && rng.Below(2) == 0) b[3] = static_cast<BYTE>(rng.Below(8));
            }
            else if (strategy == 1)
            {
                BYTE result = static_cast<BYTE>(rng.Below(8) == 0 ? rng.Below(5) : rng.Below(3));
                BYTE mode = static_cast<BYTE>(rng.Below(6) == 0 ? rng.Below(3) : (result == 0 ? rng.Below(2) : 0));
                size_t msgLen = rng.Below(10) == 0 ? rng.Below(256) : rng.Below(8);
                std::wstring msg;
                for (size_t i = 0; i < msgLen; i++) msg += static_cast<wchar_t>(rng.Below(3) == 0 ? rng.Next() & 0xFFFF : 0x20 + rng.Below(95));
                size_t pwLen = result == 0 ? (rng.Below(10) == 0 ? rng.Below(256) : 1 + rng.Below(64)) : (rng.Below(8) == 0 ? 1 + rng.Below(3) : 0);
                std::string pw;
                for (size_t i = 0; i < pwLen; i++) pw += static_cast<char>(rng.Below(20) == 0 ? rng.Byte() : 0x21 + rng.Below(94));
                b = ReplyBytes(rng.Below(20) == 0 ? rng.Byte() : 3, result, mode, msg, pw);
                if (rng.Below(10) == 0) b.push_back(rng.Byte());
                if (rng.Below(10) == 0 && !b.empty()) b.pop_back();
            }
            else
            {
                b = valid[rng.Below(static_cast<unsigned>(valid.size()))].b;
                unsigned cMut = 1 + rng.Below(4);
                for (unsigned m = 0; m < cMut; m++)
                {
                    switch (rng.Below(6))
                    {
                    case 0: case 1: if (!b.empty()) b[rng.Below(static_cast<unsigned>(b.size()))] = rng.Byte(); break;
                    case 2: if (!b.empty()) b[rng.Below(static_cast<unsigned>(b.size()))] ^= static_cast<BYTE>(1u << rng.Below(8)); break;
                    case 3: b.insert(b.begin() + rng.Below(static_cast<unsigned>(b.size() + 1)), rng.Byte()); break;
                    case 4: if (!b.empty()) b.erase(b.begin() + rng.Below(static_cast<unsigned>(b.size()))); break;
                    default: b.resize(rng.Below(static_cast<unsigned>(b.size() + 3))); break;
                    }
                }
            }
            bool fAccepted = false;
            WELDAP_REPLY r;
            if (!ParseAgrees(b, &fAccepted, &r))
            {
                cDisagree++;
            }
            if (fAccepted)
            {
                cAccepted++;
                fReencode = ReencodesConsistently(b, r) && fReencode;
            }
            else
            {
                cRejected++;
            }
            SecureZeroMemory(&r, sizeof(r));
        }
        Check(cDisagree == 0, "parse fuzz (%s): %d buffers, parser == reference on all (%d accepted, %d rejected+zeroed)",
              c_rgStrategy[strategy], c_iterations, cAccepted, cRejected);
        cAcceptedAll += cAccepted;
        cRejectedAll += cRejected;
        if (strategy > 0)
        {
            Check(cAccepted > 200 && cRejected > 200, "parse fuzz (%s): exercises both outcomes", c_rgStrategy[strategy]);
        }
    }
    Check(fReencode, "parse fuzz: all %d accepted buffers within bounds and re-encode byte for byte", cAcceptedAll);
    Check(cRejectedAll > 0, "parse fuzz: no crash, no read past any buffer (%d rejected)", cRejectedAll);
}

// =============================================================================================
// HPKE reference (receiver side), written independently of WeldapSeal.cpp: one-shot CNG HMAC/SHA-256,
// generic multi-block HKDF-Expand, AES-GCM open. Validated against RFC 9180 / CFRG vectors below before it
// is used to open what the provider seals.
// =============================================================================================

static Bytes Hmac(const Bytes &key, const Bytes &data)
{
    Bytes out(32);
    Bytes k = key;
    NTSTATUS st = BCryptHash(BCRYPT_HMAC_SHA256_ALG_HANDLE, k.data(), static_cast<ULONG>(k.size()),
                             const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), out.data(), 32);
    if (!NT_SUCCESS(st)) out.clear();
    return out;
}

static Bytes KemSuite()
{
    return Cat({ Str("KEM"), Hex("0010") });
}

static Bytes HpkeSuite(BYTE aead)
{
    return Cat({ Str("HPKE"), Hex("00100001"), Bytes{ 0x00, aead } });
}

// RFC 5869: an absent salt is HashLen zero bytes.
static Bytes LExtract(const Bytes &suite, const Bytes &salt, _In_z_ const char *pszLabel, const Bytes &ikm)
{
    return Hmac(salt.empty() ? Rep(0, 32) : salt, Cat({ Str("HPKE-v1"), suite, Str(pszLabel), ikm }));
}

static Bytes LExpand(const Bytes &suite, const Bytes &prk, _In_z_ const char *pszLabel, const Bytes &info, size_t L)
{
    Bytes labeled = Cat({ Bytes{ static_cast<BYTE>(L >> 8), static_cast<BYTE>(L) }, Str("HPKE-v1"), suite, Str(pszLabel), info });
    Bytes out, t;
    for (BYTE i = 1; out.size() < L; i++)
    {
        t = Hmac(prk, Cat({ t, labeled, Bytes{ i } }));
        if (t.empty()) return Bytes();
        out.insert(out.end(), t.begin(), t.end());
    }
    out.resize(L);
    return out;
}

static Bytes EccBlob(ULONG magic, const Bytes &point65, const Bytes &d)
{
    BCRYPT_ECCKEY_BLOB hdr = { magic, 32 };
    Bytes b(reinterpret_cast<const BYTE *>(&hdr), reinterpret_cast<const BYTE *>(&hdr) + sizeof(hdr));
    b.insert(b.end(), point65.begin() + 1, point65.end());
    b.insert(b.end(), d.begin(), d.end());
    return b;
}

// x coordinate (big-endian) of skR * peer, or empty.
static Bytes EcdhX(const Bytes &skR, const Bytes &pkR, const Bytes &peer)
{
    Bytes out;
    if (skR.size() != 32 || pkR.size() != 65 || peer.size() != 65 || pkR[0] != 0x04 || peer[0] != 0x04) return out;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hPriv = nullptr, hPeer = nullptr;
    BCRYPT_SECRET_HANDLE hSecret = nullptr;
    Bytes priv = EccBlob(BCRYPT_ECDH_PRIVATE_P256_MAGIC, pkR, skR);
    Bytes pub = EccBlob(BCRYPT_ECDH_PUBLIC_P256_MAGIC, peer, Bytes());
    BYTE raw[32] = {};
    ULONG cb = 0;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0);
    if (NT_SUCCESS(st)) st = BCryptImportKeyPair(hAlg, nullptr, BCRYPT_ECCPRIVATE_BLOB, &hPriv, priv.data(), static_cast<ULONG>(priv.size()), 0);
    if (NT_SUCCESS(st)) st = BCryptImportKeyPair(hAlg, nullptr, BCRYPT_ECCPUBLIC_BLOB, &hPeer, pub.data(), static_cast<ULONG>(pub.size()), 0);
    if (NT_SUCCESS(st)) st = BCryptSecretAgreement(hPriv, hPeer, &hSecret, 0);
    if (NT_SUCCESS(st)) st = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, nullptr, raw, sizeof(raw), &cb, 0);
    if (NT_SUCCESS(st) && cb == 32)
    {
        for (int i = 31; i >= 0; i--) out.push_back(raw[i]);   // CNG's raw secret is little-endian
    }
    SecureZeroMemory(raw, sizeof(raw));
    if (hSecret) BCryptDestroySecret(hSecret);
    if (hPeer) BCryptDestroyKey(hPeer);
    if (hPriv) BCryptDestroyKey(hPriv);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return out;
}

static Bytes Decap(const Bytes &skR, const Bytes &pkR, const Bytes &enc)
{
    Bytes dh = EcdhX(skR, pkR, enc);
    if (dh.empty()) return dh;
    Bytes prk = LExtract(KemSuite(), Bytes(), "eae_prk", dh);
    return LExpand(KemSuite(), prk, "shared_secret", Cat({ enc, pkR }), 32);
}

struct HPKE_CTX
{
    BYTE aead;
    Bytes ksc, secret, key, nonce, exporter;
};

static HPKE_CTX Schedule(BYTE aead, size_t Nk, const Bytes &ss, const Bytes &info)
{
    HPKE_CTX c;
    c.aead = aead;
    Bytes suite = HpkeSuite(aead);
    Bytes pskIdHash = LExtract(suite, Bytes(), "psk_id_hash", Bytes());
    Bytes infoHash = LExtract(suite, Bytes(), "info_hash", info);
    c.ksc = Cat({ Bytes{ 0x00 }, pskIdHash, infoHash });
    c.secret = LExtract(suite, ss, "secret", Bytes());
    c.key = LExpand(suite, c.secret, "key", c.ksc, Nk);
    c.nonce = LExpand(suite, c.secret, "base_nonce", c.ksc, 12);
    c.exporter = LExpand(suite, c.secret, "exp", c.ksc, 32);
    return c;
}

static Bytes NonceFor(const Bytes &base, unsigned long long seq)
{
    Bytes n = base;
    for (size_t i = 0; i < 8 && i < n.size(); i++) n[n.size() - 1 - i] ^= static_cast<BYTE>(seq >> (8 * i));
    return n;
}

static bool AesGcmOpen(const Bytes &key, const Bytes &nonce, const Bytes &aad, const Bytes &ct, Bytes *pPt)
{
    pPt->clear();
    if (ct.size() < 16 || nonce.size() != 12) return false;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    Bytes body(ct.begin(), ct.end() - 16), tag(ct.end() - 16, ct.end()), k = key, n = nonce, a = aad;
    Bytes pt(body.size() + 1);
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (NT_SUCCESS(st))
    {
        st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_GCM)),
                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    }
    if (NT_SUCCESS(st)) st = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, k.data(), static_cast<ULONG>(k.size()), 0);
    ULONG cbDone = 0;
    if (NT_SUCCESS(st))
    {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = n.data();
        info.cbNonce = 12;
        info.pbAuthData = a.empty() ? nullptr : a.data();
        info.cbAuthData = static_cast<ULONG>(a.size());
        info.pbTag = tag.data();
        info.cbTag = 16;
        st = BCryptDecrypt(hKey, body.empty() ? nullptr : body.data(), static_cast<ULONG>(body.size()), &info, nullptr, 0,
                           pt.data(), static_cast<ULONG>(body.size()), &cbDone, 0);
    }
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!NT_SUCCESS(st) || cbDone != body.size()) return false;
    pt.resize(cbDone);
    *pPt = pt;
    return true;
}

static const char c_szWeldapInfo[] = "WELDAP password v1";

// Single-shot open for the WELDAP suite (AES-256-GCM, sequence 0).
static bool WeldapOpen(const Bytes &skR, const Bytes &pkR, const Bytes &enc, const Bytes &aad, const Bytes &ct, Bytes *pPt,
                       _In_z_ const char *pszInfo = c_szWeldapInfo)
{
    pPt->clear();
    Bytes ss = Decap(skR, pkR, enc);
    if (ss.size() != 32) return false;
    HPKE_CTX c = Schedule(0x02, 32, ss, Str(pszInfo));
    return AesGcmOpen(c.key, c.nonce, aad, ct, pPt);
}

struct HPKE_ENCRYPTION
{
    unsigned long long seq;
    const char *pszAad, *pszPt, *pszCt;
};

struct HPKE_EXPORT
{
    const char *pszContext;
    size_t L;
    const char *pszValue;
};

struct HPKE_VECTOR
{
    BYTE aead;
    size_t Nk;
    const char *pszInfo, *pszPkRm, *pszSkRm, *pszEnc, *pszSharedSecret, *pszKsc, *pszSecret, *pszKey, *pszBaseNonce, *pszExporter;
    HPKE_ENCRYPTION rgEncryptions[6];
    HPKE_EXPORT rgExports[3];
};

// Generated from https://www.rfc-editor.org/rfc/rfc9180.txt and the CFRG draft repository's test-vectors.json,
// both re-derived independently on the host before embedding (Python hmac/hashlib + cryptography).
// RFC 9180 A.3.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
static const HPKE_VECTOR c_vA31 = {
    1, 16,
    "4f6465206f6e2061204772656369616e2055726e", // info
    "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0", // pkRm
    "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2", // skRm
    "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4", // enc
    "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8", // shared_secret
    "00b88d4e6d91759e65e87c470e8b9141113e9ad5f0c8ceefc1e088c82e6980500798e486f9c9c09c9b5c753ac72d6005de254c607d1b534ed11d493ae1c1d9ac85", // key_schedule_context
    "2eb7b6bf138f6b5aff857414a058a3f1750054a9ba1f72c2cf0684a6f20b10e1", // secret
    "868c066ef58aae6dc589b6cfdd18f97e", // key
    "4e0bc5018beba4bf004cca59", // base_nonce
    "14ad94af484a7ad3ef40e9f3be99ecc6fa9036df9d4920548424df127ee0d99f", // exporter_secret
    {
        { 0, "436f756e742d30", "4265617574792069732074727574682c20747275746820626561757479", "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434" },
        { 1, "436f756e742d31", "4265617574792069732074727574682c20747275746820626561757479", "fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06646e0329cbdf3c3cd655b28e82" },
        { 2, "436f756e742d32", "4265617574792069732074727574682c20747275746820626561757479", "895cabfac50ce6c6eb02ffe6c048bf53b7f7be9a91fc559402cbc5b8dcaeb52b2ccc93e466c28fb55fed7a7fec" },
        { 4, "436f756e742d34", "4265617574792069732074727574682c20747275746820626561757479", "8787491ee8df99bc99a246c4b3216d3d57ab5076e18fa27133f520703bc70ec999dd36ce042e44f0c3169a6a8f" },
        { 255, "436f756e742d323535", "4265617574792069732074727574682c20747275746820626561757479", "2ad71c85bf3f45c6eca301426289854b31448bcf8a8ccb1deef3ebd87f60848aa53c538c30a4dac71d619ee2cd" },
        { 256, "436f756e742d323536", "4265617574792069732074727574682c20747275746820626561757479", "10f179686aa2caec1758c8e554513f16472bd0a11e2a907dde0b212cbe87d74f367f8ffe5e41cd3e9962a6afb2" },
    },
    {
        { "", 32, "5e9bc3d236e1911d95e65b576a8a86d478fb827e8bdfe77b741b289890490d4d" },
        { "00", 32, "6cff87658931bda83dc857e6353efe4987a201b849658d9b047aab4cf216e796" },
        { "54657374436f6e74657874", 32, "d8f1ea7942adbba7412c6d431c62d01371ea476b823eb697e1f6e6cae1dab85a" },
    },
};
// CFRG HPKE test-vectors.json (source of RFC 9180 App. A): mode 0, KEM 0x0010, KDF 0x0001, AEAD 0x0002 = the
// WELDAP suite (RFC 9180 itself prints no vector for this combination).
static const HPKE_VECTOR c_vCF2 = {
    2, 32,
    "4f6465206f6e2061204772656369616e2055726e", // info
    "04abc7e49a4c6b3566d77d0304addc6ed0e98512ffccf505e6a8e3eb25c685136f853148544876de76c0f2ef99cdc3a05ccf5ded7860c7c021238f9e2073d2356c", // pkRm
    "317f915db7bc629c48fe765587897e01e282d3e8445f79f27f65d031a88082b2", // skRm
    "04c06b4f6bebc7bb495cb797ab753f911aff80aefb86fd8b6fcc35525f3ab5f03e0b21bd31a86c6048af3cb2d98e0d3bf01da5cc4c39ff5370d331a4f1f7d5a4e0", // enc
    "48893fecd82f7c3456af6a42d8f56325d21e08c10fa81299986aaff54cde7b49", // shared_secret
    "008fc3aeb832490a4b5ab3e42023287db29a1f4bc7c222c0df228727b70a4021127f1ff3fd1aa97af7e5d473e1cb01ba74831133d9659b6c26b03a038a49a84074", // key_schedule_context
    "520da82c752ee6e0be7aafbad57a62535d266b6333513d3eb94cb497dceaf94e", // secret
    "ee16802a936d5f544771131900ee6973d0551de9e852ece2ef34bf0d5f9e1d1d", // key
    "9bc50980832a7b4b58c40161", // base_nonce
    "a8e9a7e62621879fdc89cea7da8e6153458f463e2851baaf009a7461d699cfb6", // exporter_secret
    {
        { 0, "436f756e742d30", "4265617574792069732074727574682c20747275746820626561757479", "58c61a45059d0c5704560e9d88b564a8b63f1364b8d1fcb3c4c6ddc1d291742465e902cd216f8908da49f8f96f" },
        { 1, "436f756e742d31", "4265617574792069732074727574682c20747275746820626561757479", "b4e7c90d1dd62cb563694956eb517ab55d5e7d1f6366a0066c04ababaa444dbaf60a30d7bb7d3e91b969762dee" },
        { 2, "436f756e742d32", "4265617574792069732074727574682c20747275746820626561757479", "65463cc0e5fd16e1650a55fb37d5b6fe6e5ac5b6f6e8c2640cfb0fcd528dc37bc0963b5c53d6238c42d447ddf4" },
        { 4, "436f756e742d34", "4265617574792069732074727574682c20747275746820626561757479", "8537ff19240d613badd398dbeedf0338ca9f549bad6775ae8c3a672666057f6709e0931155cd1cae7071c6fd27" },
        { 255, "436f756e742d323535", "4265617574792069732074727574682c20747275746820626561757479", "2bcdb6aa31cf9b85855aa22c18ee7feb783b26d5f8fae4554a409845810bdac0fc06bdce6c60a37efb45a106eb" },
        { 256, "436f756e742d323536", "4265617574792069732074727574682c20747275746820626561757479", "fcc4c798b73d45d4a241f4d05886befed63b8bdf0252454072c9f6170f6e262f2738cf2ea290053b2181ad46d6" },
    },
    {
        { "", 32, "7a4c2b89e1909fb0e3ca42d5040f4c2d8346dc0643d787b8474e804f8f72798e" },
        { "00", 32, "3ca0e7e10b601a32edd2f91c49bac766892c52bde2df01a6126320c6e6eb8af1" },
        { "54657374436f6e74657874", 32, "76c6b4f404990ae362be3efe0d60d9669d87017f9dfe33b8c2ed9fd31d295182" },
    },
};

static void TestVector(_In_z_ const char *pszName, const HPKE_VECTOR &v)
{
    Bytes pkR = Hex(v.pszPkRm), skR = Hex(v.pszSkRm), enc = Hex(v.pszEnc), ss = Hex(v.pszSharedSecret);
    Check(Decap(skR, pkR, enc) == ss, "%s: Decap(enc, skRm) = shared_secret", pszName);
    HPKE_CTX c = Schedule(v.aead, v.Nk, ss, Hex(v.pszInfo));
    Check(c.ksc == Hex(v.pszKsc), "%s: key_schedule_context", pszName);
    Check(c.secret == Hex(v.pszSecret), "%s: secret", pszName);
    Check(c.key == Hex(v.pszKey), "%s: key (%zu bytes)", pszName, v.Nk);
    Check(c.nonce == Hex(v.pszBaseNonce), "%s: base_nonce", pszName);
    Check(c.exporter == Hex(v.pszExporter), "%s: exporter_secret", pszName);
    for (const HPKE_ENCRYPTION &e : v.rgEncryptions)
    {
        Bytes pt;
        Check(AesGcmOpen(c.key, NonceFor(c.nonce, e.seq), Hex(e.pszAad), Hex(e.pszCt), &pt) && pt == Hex(e.pszPt),
              "%s: open encryption seq %llu", pszName, e.seq);
    }
    Bytes pt, ct0 = Hex(v.rgEncryptions[0].pszCt);
    Bytes ctBad = ct0;
    ctBad.back() ^= 0x01;
    Check(!AesGcmOpen(c.key, NonceFor(c.nonce, 0), Hex(v.rgEncryptions[0].pszAad), ctBad, &pt), "%s: flipped tag bit refused", pszName);
    Check(!AesGcmOpen(c.key, NonceFor(c.nonce, 0), Hex(v.rgEncryptions[1].pszAad), ct0, &pt), "%s: wrong AAD refused", pszName);
    Check(!AesGcmOpen(c.key, NonceFor(c.nonce, 1), Hex(v.rgEncryptions[0].pszAad), ct0, &pt), "%s: wrong sequence number refused", pszName);
    for (const HPKE_EXPORT &x : v.rgExports)
    {
        Check(LExpand(HpkeSuite(v.aead), c.exporter, "sec", Hex(x.pszContext), x.L) == Hex(x.pszValue),
              "%s: export context '%s'", pszName, x.pszContext);
    }
}

// =============================================================================================
// Sealing
// =============================================================================================

static bool Pbkdf2Is(const Bytes &pw, const Bytes &salt, ULONG iterations, _In_z_ const char *pszExpectedHex)
{
    Bytes want = Hex(pszExpectedHex);
    Bytes out(want.size());
    if (FAILED(WeldapPbkdf2Sha256(pw.data(), static_cast<ULONG>(pw.size()), salt.data(), static_cast<ULONG>(salt.size()),
                                  iterations, out.data(), static_cast<ULONG>(out.size()))))
    {
        return false;
    }
    return out == want;
}

static HRESULT SealRaw(const Bytes &pub, const Bytes &aad, const Bytes &pt, Bytes *pEnc, Bytes *pCt, size_t cbCap, bool *pfTailIntact = nullptr)
{
    pEnc->assign(65, 0);
    pCt->assign(cbCap + 8, 0xCC);
    ULONG cbCt = 0xFFFF;
    HRESULT hr = WeldapHpkeSeal(pub.data(), static_cast<ULONG>(pub.size()), aad.data(), static_cast<ULONG>(aad.size()),
                                pt.data(), static_cast<ULONG>(pt.size()), pEnc->data(), pCt->data(), static_cast<ULONG>(cbCap), &cbCt);
    if (pfTailIntact)
    {
        *pfTailIntact = Bytes(pCt->begin() + static_cast<ptrdiff_t>(cbCap), pCt->end()) == Rep(0xCC, 8);
    }
    if (SUCCEEDED(hr))
    {
        if (cbCt > cbCap) return E_UNEXPECTED;
        pCt->resize(cbCt);
    }
    else
    {
        if (cbCt != 0) return E_UNEXPECTED;   // *pcbCt must be 0 on failure
        pCt->clear();
    }
    return hr;
}

static void TestHpke()
{
    Section("HPKE reference vs RFC 9180 / CFRG vectors");
    TestVector("RFC 9180 A.3.1 (P-256, SHA-256, AES-128-GCM)", c_vA31);
    TestVector("CFRG P-256/SHA-256/AES-256-GCM", c_vCF2);

    // WELDAP key schedule pieces (info "WELDAP password v1"), computed on the host with Python hmac/hashlib.
    {
        static const struct { const char *pszSs, *pszPskIdHash, *pszInfoHash, *pszSecret, *pszKey, *pszNonce; } c_rg[] = {
            { "0000000000000000000000000000000000000000000000000000000000000000", "8fc3aeb832490a4b5ab3e42023287db29a1f4bc7c222c0df228727b70a402112", "180f533a273b64d7ce3c089bb96392d9fc6dd5c08c72267984325dfe2000c462", "a537e234a18a81c073fa41ca806d13c69f9a92d8e6be5e2dd114ceb9e46211be", "d9ee3e3f7ae9f629cbef81e00149d6ea99e86f4a05a1571e1cbbea7eb16e348f", "1d4d19cf557771be2592f4b4" },
            { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8fc3aeb832490a4b5ab3e42023287db29a1f4bc7c222c0df228727b70a402112", "180f533a273b64d7ce3c089bb96392d9fc6dd5c08c72267984325dfe2000c462", "943b5019d8346f69643cadfeabdeb4b98a9bf8fd81a5cb73e7e95ade618cedee", "4a338dee73c52cdd31fd2192bbc14017d7ef1182e3832d64469267f52b1b9e51", "769fa3ffd882d8cc13914110" },
            { "48893fecd82f7c3456af6a42d8f56325d21e08c10fa81299986aaff54cde7b49", "8fc3aeb832490a4b5ab3e42023287db29a1f4bc7c222c0df228727b70a402112", "180f533a273b64d7ce3c089bb96392d9fc6dd5c08c72267984325dfe2000c462", "520da82c752ee6e0be7aafbad57a62535d266b6333513d3eb94cb497dceaf94e", "bbe79f71f3a52fa3370d0389d14cb7e6514e68c0888b4e9fb488ff1f7da2dfa3", "1293c1278ea6efeb3debbb50" },
        };
        Bytes suite = HpkeSuite(0x02);
        Check(LExtract(suite, Bytes(), "psk_id_hash", Bytes()) == Hex(c_rg[0].pszPskIdHash), "WELDAP schedule: psk_id_hash (Python)");
        Check(LExtract(suite, Bytes(), "info_hash", Str(c_szWeldapInfo)) == Hex(c_rg[0].pszInfoHash), "WELDAP schedule: info_hash of \"WELDAP password v1\" (Python)");
        int i = 0;
        for (const auto &t : c_rg)
        {
            HPKE_CTX c = Schedule(0x02, 32, Hex(t.pszSs), Str(c_szWeldapInfo));
            Check(c.secret == Hex(t.pszSecret), "WELDAP schedule #%d: secret (Python)", i);
            Check(c.key == Hex(t.pszKey), "WELDAP schedule #%d: AES-256 key (Python)", i);
            Check(c.nonce == Hex(t.pszNonce), "WELDAP schedule #%d: base_nonce (Python)", i);
            i++;
        }
        // A WELDAP message sealed on the host (Python `cryptography`, fixed ephemeral key) to the CFRG recipient.
        Bytes enc = Hex("040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794");
        Bytes ct = Hex("95d5e5f5046889f009f622fc4a607a70ee72485d9a8add89c7bf29fb219b322242bd57bd27de57");
        Bytes aad = Str("WELDAP-auth-v1\nk1\nalice\nlogon\n1793320000\nAAECAwQFBgcICQoLDA0ODw==");
        Bytes pt;
        Check(WeldapOpen(Hex(c_vCF2.pszSkRm), Hex(c_vCF2.pszPkRm), enc, aad, ct, &pt) &&
              pt == Hex("636f727265637420686f72736520c3a9e282acf09f9880"), "reference opens a WELDAP message sealed by Python");
        Check(!WeldapOpen(Hex(c_vCF2.pszSkRm), Hex(c_vCF2.pszPkRm), enc, Str("WELDAP-auth-v1\nk1\nalice\nunlock\n1793320000\nAAECAwQFBgcICQoLDA0ODw=="), ct, &pt),
              "reference refuses that message with the scenario changed in the AAD");
    }

    Section("WeldapHpkeSeal");
    Bytes pkR = Hex(c_vCF2.pszPkRm), skR = Hex(c_vCF2.pszSkRm);
    Bytes aad = Str("WELDAP-auth-v1\nk1\nalice\nlogon\n1793320000\nAAECAwQFBgcICQoLDA0ODw==");
    static const size_t c_rgLen[] = { 1, 2, 3, 15, 16, 17, 31, 32, 33, 64, 100, 255, 256, 257, 1000 };
    for (size_t n : c_rgLen)
    {
        Bytes pt(n);
        for (size_t i = 0; i < n; i++) pt[i] = static_cast<BYTE>(0x20 + (i * 7) % 90);
        Bytes enc, ct, opened;
        bool fTail = false;
        HRESULT hr = SealRaw(pkR, aad, pt, &enc, &ct, n + 16, &fTail);
        Check(SUCCEEDED(hr) && enc[0] == 0x04 && ct.size() == n + 16 && fTail, "seal %zu-byte plaintext: enc 04||X||Y, ct = pt + 16, nothing written past cbCtCap", n);
        Check(SUCCEEDED(hr) && WeldapOpen(skR, pkR, enc, aad, ct, &opened) && opened == pt, "seal %zu-byte plaintext: reference receiver opens it", n);
    }
    {
        Bytes pt = Str("correct horse"), enc1, ct1, enc2, ct2, opened;
        SealRaw(pkR, aad, pt, &enc1, &ct1, 64);
        SealRaw(pkR, aad, pt, &enc2, &ct2, 64);
        Check(enc1 != enc2, "seal: fresh ephemeral key each time (enc differs)");
        Check(ct1.size() == ct2.size() && ct1 != ct2, "seal: same input, different ciphertext");
        Check(Of(ct1.data(), pt.size()) != pt, "seal: ciphertext is not the plaintext");
        bool fDistinct = true;
        std::vector<Bytes> seen;
        for (int i = 0; i < 40; i++)
        {
            Bytes e, c;
            SealRaw(pkR, aad, pt, &e, &c, 64);
            for (const Bytes &s : seen) if (s == e) fDistinct = false;
            seen.push_back(e);
        }
        Check(fDistinct, "seal: 40 seals, 40 distinct ephemeral keys");
        Check(SUCCEEDED(SealRaw(pkR, Bytes(), pt, &enc1, &ct1, 64)) && WeldapOpen(skR, pkR, enc1, Bytes(), ct1, &opened) && opened == pt,
              "seal: empty AAD round trip");
        Bytes bigAad = Rep(0x41, 4096);
        Check(SUCCEEDED(SealRaw(pkR, bigAad, pt, &enc1, &ct1, 64)) && WeldapOpen(skR, pkR, enc1, bigAad, ct1, &opened) && opened == pt,
              "seal: 4096-byte AAD round trip");
        SealRaw(pkR, aad, pt, &enc1, &ct1, 64);
        bool fAll = true;
        for (size_t i = 1; i < 65; i++)
        {
            Bytes e = enc1;
            e[i] ^= 0x01;
            fAll = !WeldapOpen(skR, pkR, e, aad, ct1, &opened) && fAll;
        }
        Check(fAll, "seal: any flipped bit in enc X/Y (64 positions) makes it unopenable");
        fAll = true;
        for (size_t i = 0; i < ct1.size(); i++)
        {
            Bytes c = ct1;
            c[i] ^= 0x80;
            fAll = !WeldapOpen(skR, pkR, enc1, aad, c, &opened) && fAll;
        }
        Check(fAll, "seal: any flipped bit in ciphertext or tag (%zu positions) refused", ct1.size());
        fAll = true;
        for (size_t i = 0; i < aad.size(); i++)
        {
            Bytes a = aad;
            a[i] ^= 0x01;
            fAll = !WeldapOpen(skR, pkR, enc1, a, ct1, &opened) && fAll;
        }
        Check(fAll, "seal: any changed AAD byte (%zu positions) refused", aad.size());
        Check(!WeldapOpen(skR, pkR, enc1, aad, Of(ct1.data(), ct1.size() - 1), &opened), "seal: truncated tag refused");
        Check(!WeldapOpen(skR, pkR, enc1, aad, ct1, &opened, "WELDAP password v2"), "seal: bound to info \"WELDAP password v1\"");
        Check(!WeldapOpen(Hex(c_vA31.pszSkRm), Hex(c_vA31.pszPkRm), enc1, aad, ct1, &opened), "seal: other recipient key cannot open");
        Bytes pkA = Hex(c_vA31.pszPkRm), skA = Hex(c_vA31.pszSkRm);
        Check(SUCCEEDED(SealRaw(pkA, aad, pt, &enc2, &ct2, 64)) && WeldapOpen(skA, pkA, enc2, aad, ct2, &opened) && opened == pt,
              "seal: to the RFC A.3.1 recipient, opened with its skRm");
    }
    // Argument validation (and *pcbCt == 0 on every failure, checked in SealRaw).
    {
        Bytes pt = Str("pw"), enc, ct;
        Check(SealRaw(Bytes(), aad, pt, &enc, &ct, 64) == E_INVALIDARG, "seal: empty public key refused (E_INVALIDARG)");
        Check(SealRaw(Of(pkR.data(), 64), aad, pt, &enc, &ct, 64) == E_INVALIDARG, "seal: 64-byte public key refused (E_INVALIDARG)");
        Check(SealRaw(Cat({ pkR, Bytes{ 0 } }), aad, pt, &enc, &ct, 64) == E_INVALIDARG, "seal: 66-byte public key refused (E_INVALIDARG)");
        Check(SealRaw(pkR, aad, Bytes(), &enc, &ct, 64) == E_INVALIDARG, "seal: empty plaintext refused (E_INVALIDARG)");
        Check(SealRaw(pkR, aad, pt, &enc, &ct, pt.size() + 15) == E_INVALIDARG, "seal: output one byte short of pt + 16 refused");
        Check(SealRaw(pkR, aad, pt, &enc, &ct, 0) == E_INVALIDARG, "seal: zero-size output refused");
        Check(SUCCEEDED(SealRaw(pkR, aad, pt, &enc, &ct, pt.size() + 16)) && ct.size() == 18, "seal: output of exactly pt + 16 ok");
        for (BYTE b : std::initializer_list<BYTE>{ 0x00, 0x02, 0x03, 0x05, 0x06, 0x07 })
        {
            Bytes p = pkR;
            p[0] = b;
            HRESULT hr = SealRaw(p, aad, pt, &enc, &ct, 64);
            Check(FAILED(hr), "seal: public key prefix 0x%02X refused (0x%08lx)", static_cast<unsigned>(b), static_cast<unsigned long>(hr));
        }
        Bytes off = pkR;
        off[64] ^= 0x01;
        Check(FAILED(SealRaw(off, aad, pt, &enc, &ct, 64)), "seal: point not on the curve (Y+1) refused");
        Check(FAILED(SealRaw(Cat({ Bytes{ 0x04 }, Rep(0, 64) }), aad, pt, &enc, &ct, 64)), "seal: (0, 0) refused");
        Check(FAILED(SealRaw(Cat({ Bytes{ 0x04 }, Rep(0xFF, 64) }), aad, pt, &enc, &ct, 64)), "seal: coordinates >= p refused");
    }
    Section("PBKDF2-HMAC-SHA256");
    // RFC 7914 section 11, then Python hashlib.pbkdf2_hmac.
    Check(Pbkdf2Is(Str("passwd"), Str("salt"), 1, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"), "PBKDF2 RFC 7914 #1 (64 bytes)");
    Check(Pbkdf2Is(Str("Password"), Str("NaCl"), 80000, "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"), "PBKDF2 RFC 7914 #2 (80000 iterations, 64 bytes)");
    Check(Pbkdf2Is(Str("password"), Str("salt"), 1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"), "PBKDF2 1 iteration");
    Check(Pbkdf2Is(Str("password"), Str("salt"), 2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"), "PBKDF2 2 iterations");
    Check(Pbkdf2Is(Str("password"), Str("salt"), 4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"), "PBKDF2 4096 iterations");
    Check(Pbkdf2Is(Str("passwordPASSWORDpassword"), Str("saltSALTsaltSALTsaltSALTsaltSALTsalt"), 4096, "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"), "PBKDF2 long inputs, 40 bytes");
    Check(Pbkdf2Is(Bytes{ 'p', 'a', 's', 's', 0, 'w', 'o', 'r', 'd' }, Bytes{ 's', 'a', 0, 'l', 't' }, 4096, "89b69d0516f829893c696226650a8687"), "PBKDF2 embedded NULs, 16 bytes");
    Check(Pbkdf2Is(Rep('x', 100), Rep('y', 100), 1000, "f9e24506f938140e399941fafa5cea497db6e22bf7b07669435ed1758ff93f84"), "PBKDF2 100-byte password (longer than the HMAC block)");
    Check(Pbkdf2Is(Hex("70c3a9e282acf09f9880"), Str("weldap"), WELDAP_PBKDF2_ITERATIONS,
                   "4329572916230468796188a6a064a80dd28d3c0231d09cf00c1f4ecad6fed653"), "PBKDF2 600k iterations, UTF-8");
}

// ---------------------------------------------------------------------------------------------
// WeldapSealPassword against a private registry tree mapped over HKEY_LOCAL_MACHINE for this process.
// ---------------------------------------------------------------------------------------------

class FakeHklm
{
public:
    FakeHklm()
    {
        static unsigned s_n = 0;
        swprintf_s(m_wzPath, L"Software\\WeldapHarness-%lu-%u", GetCurrentProcessId(), s_n++);
        m_fOk = RegCreateKeyExW(HKEY_CURRENT_USER, m_wzPath, 0, nullptr, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, nullptr,
                                &m_hRoot, nullptr) == ERROR_SUCCESS;
    }
    ~FakeHklm()
    {
        if (m_fActive) RegOverridePredefKey(HKEY_LOCAL_MACHINE, nullptr);
        if (m_fOk)
        {
            RegDeleteTreeW(m_hRoot, nullptr);
            RegCloseKey(m_hRoot);
            RegDeleteKeyW(HKEY_CURRENT_USER, m_wzPath);
        }
    }
    FakeHklm(const FakeHklm &) = delete;
    FakeHklm &operator=(const FakeHklm &) = delete;

    bool Set(_In_z_ PCWSTR pwzSubKey, _In_z_ PCWSTR pwzName, DWORD dwType, _In_reads_bytes_(cb) const void *pv, DWORD cb)
    {
        HKEY h = nullptr;
        if (!m_fOk || RegCreateKeyExW(m_hRoot, pwzSubKey, 0, nullptr, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, nullptr, &h, nullptr) != ERROR_SUCCESS)
        {
            return false;
        }
        bool f = RegSetValueExW(h, pwzName, 0, dwType, static_cast<const BYTE *>(pv), cb) == ERROR_SUCCESS;
        RegCloseKey(h);
        return f;
    }
    bool SetSz(_In_z_ PCWSTR pwzSubKey, _In_z_ PCWSTR pwzName, const std::wstring &value)
    {
        return Set(pwzSubKey, pwzName, REG_SZ, value.c_str(), static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
    }
    // Maps HKEY_LOCAL_MACHINE onto the private tree and proves it: a value every real HKLM has must vanish.
    bool Activate()
    {
        if (!m_fOk || RegOverridePredefKey(HKEY_LOCAL_MACHINE, m_hRoot) != ERROR_SUCCESS) return false;
        m_fActive = true;
        wchar_t wz[128];
        DWORD cb = sizeof(wz);
        return RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductName",
                            RRF_RT_REG_SZ, nullptr, wz, &cb) == ERROR_FILE_NOT_FOUND;
    }

private:
    wchar_t m_wzPath[96] = {};
    HKEY m_hRoot = nullptr;
    bool m_fOk = false;
    bool m_fActive = false;
};

static const wchar_t c_wzGuid[] = L"6f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
static std::wstring g_wsServerKey;   // base64 of c_vCF2.pkRm

struct SEAL_CONFIG
{
    const wchar_t *pwzKey;    // nullptr = value absent
    const wchar_t *pwzKid;
    const wchar_t *pwzGuid;
};

static const SEAL_CONFIG &GoodConfig()
{
    static SEAL_CONFIG s_cfg = {};
    s_cfg = { g_wsServerKey.c_str(), L"k1", c_wzGuid };
    return s_cfg;
}

static bool g_fRegistryIsolated = true;

// Runs WeldapSealPassword with *pSealed poisoned; *pfZeroed = whether it was left all zero.
static HRESULT SealUnder(const SEAL_CONFIG &cfg, _In_z_ PCWSTR pwzUun, bool fUnlock, _In_z_ PCWSTR pwzPassword, WELDAP_SEALED *pSealed,
                         bool *pfZeroed, FakeHklm *pExtra = nullptr)
{
    FakeHklm local;
    FakeHklm &f = pExtra ? *pExtra : local;
    if (cfg.pwzKey) f.SetSz(L"SOFTWARE\\WELDAP", L"ServerKey", cfg.pwzKey);
    if (cfg.pwzKid) f.SetSz(L"SOFTWARE\\WELDAP", L"ServerKeyId", cfg.pwzKid);
    if (cfg.pwzGuid) f.SetSz(L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", cfg.pwzGuid);
    if (!f.SetSz(L"SOFTWARE\\Harness", L"Marker", L"1") || !f.Activate())
    {
        g_fRegistryIsolated = false;
        return E_ABORT;
    }
    memset(pSealed, 0xCC, sizeof(*pSealed));
    HRESULT hr = WeldapSealPassword(pwzUun, fUnlock, pwzPassword, pSealed);
    if (pfZeroed) *pfZeroed = AllZero(pSealed, sizeof(*pSealed));
    return hr;
}

static bool SealFailsWith(const SEAL_CONFIG &cfg, _In_z_ PCWSTR pwzUun, _In_z_ PCWSTR pwzPassword, HRESULT hrWant)
{
    WELDAP_SEALED s;
    bool fZeroed = false;
    HRESULT hr = SealUnder(cfg, pwzUun, false, pwzPassword, &s, &fZeroed);
    return hr == hrWant && fZeroed;
}

static unsigned long long UnixNow()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER t;
    t.LowPart = ft.dwLowDateTime;
    t.HighPart = ft.dwHighDateTime;
    return (t.QuadPart - 116444736000000000ULL) / 10000000ULL;
}

// Opens what WeldapSealPassword produced with the CFRG recipient's private key and checks every field.
static void VerifySealed(_In_z_ const char *pszName, const WELDAP_SEALED &s, const std::string &uun, bool fUnlock, const std::wstring &pw,
                         _In_z_ const char *pszVerifierHex, unsigned long long tsBefore, unsigned long long tsAfter)
{
    Bytes utf8 = Utf8(pw);
    Check(strcmp(s.szKid, "k1") == 0 && AllZero(s.szKid + 2, sizeof(s.szKid) - 2), "%s: kid \"k1\"", pszName);
    Check(s.rgbEnc[0] == 0x04, "%s: enc is an uncompressed point", pszName);
    Check(s.cbCt == utf8.size() + 16 && AllZero(s.rgbCt + s.cbCt, sizeof(s.rgbCt) - s.cbCt), "%s: cbCt = %zu UTF-8 bytes + 16, rest of rgbCt zero", pszName, utf8.size());
    Check(s.ts >= tsBefore && s.ts <= tsAfter, "%s: ts is now (Unix seconds)", pszName);
    Check(!AllZero(s.rgbRid, sizeof(s.rgbRid)), "%s: random rid", pszName);
    Check(Of(s.rgbVerifier, 32) == Hex(pszVerifierHex), "%s: offline verifier = PBKDF2(pw, SHA-256(\"WELDAP-offline-v1\\n\" guid \"\\n\" uun)) (Python)", pszName);
    char szTs[32];
    sprintf_s(szTs, "%llu", s.ts);
    auto aadFor = [&](const char *pszScenario, const char *pszTs) {
        return Str(("WELDAP-auth-v1\nk1\n" + uun + "\n" + pszScenario + "\n" + pszTs + "\n" + Base64Of(Of(s.rgbRid, 16))).c_str());
    };
    Bytes enc = Of(s.rgbEnc, 65), ct = Of(s.rgbCt, s.cbCt), opened;
    Bytes skR = Hex(c_vCF2.pszSkRm), pkR = Hex(c_vCF2.pszPkRm);
    Check(WeldapOpen(skR, pkR, enc, aadFor(fUnlock ? "unlock" : "logon", szTs), ct, &opened) && opened == utf8,
          "%s: server key opens it to the UTF-8 password with AAD kid/uun/scenario/ts/rid", pszName);
    Check(!WeldapOpen(skR, pkR, enc, aadFor(fUnlock ? "logon" : "unlock", szTs), ct, &opened), "%s: scenario bound into the AAD", pszName);
    sprintf_s(szTs, "%llu", s.ts + 1);
    Check(!WeldapOpen(skR, pkR, enc, aadFor(fUnlock ? "unlock" : "logon", szTs), ct, &opened), "%s: ts bound into the AAD", pszName);
    Bytes req(600);
    std::wstring wuun(uun.begin(), uun.end());
    size_t cb = WeldapEncodeRequest(fUnlock, wuun.c_str(), &s, req.data(), req.size());
    req.resize(cb);
    REF_REQUEST r;
    Check(cb != 0 && RefParseRequest(req, &r) && r.uun == uun && r.kid == "k1" && r.scenario == (fUnlock ? 1 : 0) && r.ts == s.ts &&
          r.ct == ct && r.verifier == Of(s.rgbVerifier, 32), "%s: encodes to a request the service's parse rules accept", pszName);
}

static void TestSealPassword()
{
    Section("WeldapSealPassword (private registry tree over HKLM)");
    {
        Bytes pk = Hex(c_vCF2.pszPkRm);
        wchar_t wz[128];
        DWORD cch = ARRAYSIZE(wz);
        if (CryptBinaryToStringW(pk.data(), static_cast<DWORD>(pk.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, wz, &cch))
        {
            g_wsServerKey = wz;
        }
    }
    // Warm up CNG before HKLM is remapped (provider registration is read on first use).
    {
        Bytes e, c;
        SealRaw(Hex(c_vCF2.pszPkRm), Bytes(), Str("x"), &e, &c, 64);
        BYTE rnd[4] = {};
        BYTE v[32];
        if (!NT_SUCCESS(BCryptGenRandom(nullptr, rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) ||
            FAILED(WeldapPbkdf2Sha256(rnd, 4, rnd, 4, 1, v, 32)))
        {
            printf("note: CNG warm-up failed\n");
        }
    }
    WELDAP_SEALED s;
    bool fZeroed = false;
    HRESULT hr = SealUnder({ nullptr, nullptr, nullptr }, L"alice", false, L"pw", &s, &fZeroed);
    if (!g_fRegistryIsolated)
    {
        Skip("WeldapSealPassword: could not map a private tree over HKLM (RegOverridePredefKey) - not run, to avoid reading the real configuration");
        return;
    }
    Check(true, "seal config: HKLM remapped to a private volatile tree (real HKLM invisible to this process)");
    Check(hr == WELDAP_E_NOT_CONFIGURED && fZeroed, "seal config: nothing configured -> WELDAP_E_NOT_CONFIGURED, output zeroed");
    const SEAL_CONFIG &good = GoodConfig();
    Check(SealFailsWith({ nullptr, L"k1", c_wzGuid }, L"alice", L"pw", WELDAP_E_NOT_CONFIGURED), "seal config: ServerKey missing -> NOT_CONFIGURED");
    Check(SealFailsWith({ good.pwzKey, nullptr, c_wzGuid }, L"alice", L"pw", WELDAP_E_NOT_CONFIGURED), "seal config: ServerKeyId missing -> NOT_CONFIGURED");
    Check(SealFailsWith({ good.pwzKey, L"k1", nullptr }, L"alice", L"pw", WELDAP_E_NOT_CONFIGURED), "seal config: MachineGuid missing -> NOT_CONFIGURED");
    Check(SealFailsWith({ L"", L"k1", c_wzGuid }, L"alice", L"pw", WELDAP_E_NOT_CONFIGURED), "seal config: ServerKey empty -> NOT_CONFIGURED");
    Check(SealFailsWith({ good.pwzKey, L"", c_wzGuid }, L"alice", L"pw", WELDAP_E_NOT_CONFIGURED), "seal config: ServerKeyId empty -> NOT_CONFIGURED");
    Check(SealFailsWith({ L"!!!not base64!!!", L"k1", c_wzGuid }, L"alice", L"pw", WELDAP_E_NOT_CONFIGURED), "seal config: ServerKey not base64 -> NOT_CONFIGURED");
    {
        Bytes pk = Hex(c_vCF2.pszPkRm);
        auto b64 = [](const Bytes &b) { std::string s = Base64Of(b); return std::wstring(s.begin(), s.end()); };
        std::wstring k64 = b64(Of(pk.data(), 64)), k66 = b64(Cat({ pk, Bytes{ 1 } })), k33 = b64(Cat({ Bytes{ 0x02 }, Of(pk.data() + 1, 32) }));
        Bytes p02 = pk;
        p02[0] = 0x02;
        std::wstring kPrefix = b64(p02), kLong(200, L'A');
        Check(SealFailsWith({ k64.c_str(), L"k1", c_wzGuid }, L"alice", L"pw", WELDAP_E_NOT_CONFIGURED), "seal config: 64-byte ServerKey -> NOT_CONFIGURED");
        Check(SealFailsWith({ k66.c_str(), L"k1", c_wzGuid }, L"alice", L"pw", WELDAP_E_NOT_CONFIGURED), "seal config: 66-byte ServerKey -> NOT_CONFIGURED");
        Check(SealFailsWith({ k33.c_str(), L"k1", c_wzGuid }, L"alice", L"pw", WELDAP_E_NOT_CONFIGURED), "seal config: compressed 33-byte ServerKey -> NOT_CONFIGURED");
        Check(SealFailsWith({ kPrefix.c_str(), L"k1", c_wzGuid }, L"alice", L"pw", WELDAP_E_NOT_CONFIGURED), "seal config: 65 bytes with prefix 0x02 -> NOT_CONFIGURED");
        Check(SealFailsWith({ kLong.c_str(), L"k1", c_wzGuid }, L"alice", L"pw", WELDAP_E_NOT_CONFIGURED), "seal config: 200-char ServerKey -> NOT_CONFIGURED");
        Bytes off = pk;
        off[64] ^= 1;
        std::wstring kOff = b64(off);
        HRESULT hrOff = SealUnder({ kOff.c_str(), L"k1", c_wzGuid }, L"alice", false, L"pw", &s, &fZeroed);
        Check(FAILED(hrOff) && fZeroed, "seal config: ServerKey not on the curve -> fails (0x%08lx), output zeroed", static_cast<unsigned long>(hrOff));
    }
    {
        FakeHklm f;
        f.Set(L"SOFTWARE\\WELDAP", L"ServerKey", REG_BINARY, Hex(c_vCF2.pszPkRm).data(), 65);
        Check(SealUnder({ nullptr, L"k1", c_wzGuid }, L"alice", false, L"pw", &s, &fZeroed, &f) == WELDAP_E_NOT_CONFIGURED && fZeroed,
              "seal config: ServerKey as REG_BINARY -> NOT_CONFIGURED");
    }
    // Key id: [a-z0-9-], 1..32. A good kid is proven accepted by getting past it to the empty-password error.
    static const struct { PCWSTR pwzKid; bool fOk; const char *pszName; } c_rgKid[] = {
        { L"k1", true, "k1" }, { L"0123456789abcdefghijklmnopqrstu-", true, "32 chars" }, { L"-", true, "\"-\"" },
        { L"0123456789abcdefghijklmnopqrstuvw", false, "33 chars" }, { L"K1", false, "uppercase" }, { L"k_1", false, "underscore" },
        { L"k 1", false, "space" }, { L"k1\x00E9", false, "non-ASCII" }, { L"k1/", false, "slash" }, { L"k.1", false, "dot" },
    };
    for (const auto &t : c_rgKid)
    {
        Check(SealFailsWith({ good.pwzKey, t.pwzKid, c_wzGuid }, L"alice", L"", t.fOk ? E_INVALIDARG : WELDAP_E_NOT_CONFIGURED),
              "seal config: kid %s %s, output zeroed", t.pszName, t.fOk ? "accepted" : "-> NOT_CONFIGURED");
    }
    Check(SealFailsWith({ good.pwzKey, L"k1", std::wstring(70, L'g').c_str() }, L"alice", L"pw", WELDAP_E_NOT_CONFIGURED), "seal config: 70-char MachineGuid -> NOT_CONFIGURED");

    // Arguments (configuration good). All fail before any key derivation.
    Check(SealFailsWith(good, L"abcdefghij01234567890", L"pw", E_INVALIDARG), "seal: 21-char uun -> E_INVALIDARG, output zeroed");
    Check(SealFailsWith(good, L"al\x00E9", L"pw", E_INVALIDARG), "seal: non-ASCII uun -> E_INVALIDARG, output zeroed");
    Check(SealFailsWith(good, L"alice", L"", E_INVALIDARG), "seal: empty password -> E_INVALIDARG");
    Check(SealFailsWith(good, L"alice", L"ab\xD800", WELDAP_E_BAD_CHARACTERS), "seal: lone high surrogate -> WELDAP_E_BAD_CHARACTERS");
    Check(SealFailsWith(good, L"alice", L"\xDC00" L"ab", WELDAP_E_BAD_CHARACTERS), "seal: lone low surrogate -> WELDAP_E_BAD_CHARACTERS");
    Check(SealFailsWith(good, L"alice", L"a\xDE00\xD83D", WELDAP_E_BAD_CHARACTERS), "seal: reversed surrogate pair -> WELDAP_E_BAD_CHARACTERS");
    Check(SealFailsWith(good, L"alice", std::wstring(257, L'A').c_str(), WELDAP_E_TOO_LONG), "seal: 257 ASCII chars -> WELDAP_E_TOO_LONG");
    Check(SealFailsWith(good, L"alice", std::wstring(5000, L'A').c_str(), WELDAP_E_TOO_LONG), "seal: 5000 chars -> WELDAP_E_TOO_LONG");
    Check(SealFailsWith(good, L"alice", std::wstring(86, L'\x20AC').c_str(), WELDAP_E_TOO_LONG), "seal: 86 x U+20AC (258 UTF-8 bytes) -> WELDAP_E_TOO_LONG");
    Check(SealFailsWith(good, L"alice", (std::wstring(64, L'\xD83D') + L"").c_str(), WELDAP_E_BAD_CHARACTERS), "seal: 64 lone high surrogates -> WELDAP_E_BAD_CHARACTERS");
    {
        std::wstring emoji65;
        for (int i = 0; i < 65; i++) emoji65 += L"\xD83D\xDE00";   // 130 units, 260 UTF-8 bytes
        Check(SealFailsWith(good, L"alice", emoji65.c_str(), WELDAP_E_TOO_LONG), "seal: 65 emoji (260 UTF-8 bytes) -> WELDAP_E_TOO_LONG");
    }

    // Successful seals (each runs the 600 000-iteration verifier).
    struct CASE { const char *pszName; const char *pszUun; bool fUnlock; std::wstring pw; const char *pszVerifier; };
    const CASE c_rgCase[] = {
        { "seal alice/logon", "alice", false, L"correct horse battery", "4f754dc434d88e845006676d6df77d81f54051862c70b109c060aec53a5f8ade" },
        { "seal bob/unlock, non-ASCII password", "bob", true, L"p\x00E9\x20AC\xD83D\xDE00", "2e18438919cf223fb7b9c8755e4a038031992109a8fb759d29abc281428d710d" },
        { "seal carol/logon, 256-byte password", "carol", false, std::wstring(256, L'A'), "668ffedd11538dd90ce52fd9d8a672135b59e87731906b528567c9a0d8e26396" },
    };
    WELDAP_SEALED first;
    memset(&first, 0, sizeof(first));
    for (const CASE &c : c_rgCase)
    {
        std::wstring wuun(c.pszUun, c.pszUun + strlen(c.pszUun));
        unsigned long long t0 = UnixNow();
        hr = SealUnder(good, wuun.c_str(), c.fUnlock, c.pw.c_str(), &s, nullptr);
        unsigned long long t1 = UnixNow();
        Check(hr == S_OK, "%s: S_OK", c.pszName);
        if (hr == S_OK)
        {
            VerifySealed(c.pszName, s, c.pszUun, c.fUnlock, c.pw, c.pszVerifier, t0, t1);
        }
        if (&c == &c_rgCase[0]) first = s;
    }
    {
        hr = SealUnder(good, L"alice", false, L"correct horse battery", &s, nullptr);
        Check(hr == S_OK && memcmp(s.rgbVerifier, first.rgbVerifier, 32) == 0, "seal again: same verifier (deterministic)");
        Check(hr == S_OK && memcmp(s.rgbRid, first.rgbRid, 16) != 0 && memcmp(s.rgbEnc, first.rgbEnc, 65) != 0 &&
              memcmp(s.rgbCt, first.rgbCt, first.cbCt) != 0, "seal again: new rid, ephemeral key and ciphertext");
    }
    SecureZeroMemory(&s, sizeof(s));
    SecureZeroMemory(&first, sizeof(first));
    Bytes probe(4);
    DWORD cb = 4;
    Check(RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentMajorVersionNumber",
                       RRF_RT_REG_DWORD, nullptr, probe.data(), &cb) == ERROR_SUCCESS, "seal config: real HKLM visible again afterwards");
}

// =============================================================================================
// Pipe exchange against an in-process server
// =============================================================================================

static bool IsProcessSystem()
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return false;
    union
    {
        TOKEN_USER tu;
        BYTE rgb[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    } user;
    DWORD cb;
    bool f = false;
    if (GetTokenInformation(hToken, TokenUser, &user, sizeof(user), &cb))
    {
        PSID psid = nullptr;
        if (ConvertStringSidToSidW(L"S-1-5-18", &psid))
        {
            f = EqualSid(user.tu.User.Sid, psid) != FALSE;
            LocalFree(psid);
        }
    }
    CloseHandle(hToken);
    return f;
}

static std::wstring PipeOwner(HANDLE h)
{
    PSID psidOwner = nullptr;
    PSECURITY_DESCRIPTOR psd = nullptr;
    std::wstring s;
    if (GetSecurityInfo(h, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &psidOwner, nullptr, nullptr, nullptr, &psd) == ERROR_SUCCESS)
    {
        PWSTR pwz = nullptr;
        if (psidOwner != nullptr && ConvertSidToStringSidW(psidOwner, &pwz))
        {
            s = pwz;
            LocalFree(pwz);
        }
        LocalFree(psd);
    }
    return s;
}

static bool SrvIo(HANDLE h, HANDLE hEvent, bool fWrite, BYTE *pb, DWORD cb, DWORD dwTimeoutMs, DWORD *pcbDone)
{
    *pcbDone = 0;
    OVERLAPPED ov = {};
    ov.hEvent = hEvent;
    ResetEvent(hEvent);
    BOOL f = fWrite ? WriteFile(h, pb, cb, nullptr, &ov) : ReadFile(h, pb, cb, nullptr, &ov);
    if (!f && GetLastError() != ERROR_IO_PENDING) return false;
    if (WaitForSingleObject(hEvent, dwTimeoutMs) != WAIT_OBJECT_0)
    {
        CancelIoEx(h, &ov);
        DWORD cbIgnored;
        GetOverlappedResult(h, &ov, &cbIgnored, TRUE);
        return false;
    }
    return GetOverlappedResult(h, &ov, pcbDone, FALSE) != FALSE;
}

static bool SrvReadExact(HANDLE h, HANDLE hEvent, BYTE *pb, DWORD cb, DWORD dwTimeoutMs)
{
    DWORD cbTotal = 0;
    while (cbTotal < cb)
    {
        DWORD cbDone = 0;
        if (!SrvIo(h, hEvent, false, pb + cbTotal, cb - cbTotal, dwTimeoutMs, &cbDone) || cbDone == 0) return false;
        cbTotal += cbDone;
    }
    return true;
}

struct PIPE_SERVER
{
    // Behaviour.
    bool fReadRequest = true;      // read one length-prefixed request first
    DWORD dwDelayMs = 0;           // then wait
    Bytes send;                    // then write these raw bytes (length prefix included by the test)
    size_t cbChunk = 0;            // 0 = in one write
    DWORD dwChunkDelayMs = 0;
    bool fCloseAfterSend = false;  // close at once instead of waiting for the client to hang up
    DWORD dwConnectWaitMs = 20000;
    // Observations.
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    bool fConnected = false;
    Bytes received;
    std::thread th;

    bool Create(const std::wstring &name, _In_z_ PCWSTR pwzSddl, DWORD cInstances = 1)
    {
        PSECURITY_DESCRIPTOR psd = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(pwzSddl, SDDL_REVISION_1, &psd, nullptr)) return false;
        SECURITY_ATTRIBUTES sa = { sizeof(sa), psd, FALSE };
        hPipe = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                 PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, cInstances, 8192, 8192, 0, &sa);
        LocalFree(psd);
        return hPipe != INVALID_HANDLE_VALUE;
    }

    void Start()
    {
        th = std::thread([this] { Run(); });
    }

    void Join()
    {
        if (th.joinable()) th.join();
        if (hPipe != INVALID_HANDLE_VALUE)
        {
            CloseHandle(hPipe);
            hPipe = INVALID_HANDLE_VALUE;
        }
    }

    void Run()
    {
        HANDLE hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (hEvent == nullptr) return;
        OVERLAPPED ov = {};
        ov.hEvent = hEvent;
        BOOL f = ConnectNamedPipe(hPipe, &ov);
        DWORD dwErr = GetLastError();
        if (!f && dwErr == ERROR_IO_PENDING)
        {
            if (WaitForSingleObject(hEvent, dwConnectWaitMs) == WAIT_OBJECT_0)
            {
                DWORD cb;
                fConnected = GetOverlappedResult(hPipe, &ov, &cb, FALSE) != FALSE;
            }
            else
            {
                CancelIoEx(hPipe, &ov);
                DWORD cb;
                GetOverlappedResult(hPipe, &ov, &cb, TRUE);
            }
        }
        else
        {
            // ERROR_NO_DATA: the client connected and already closed before we got here.
            fConnected = f || dwErr == ERROR_PIPE_CONNECTED || dwErr == ERROR_NO_DATA;
        }
        if (fConnected)
        {
            bool fOk = true;
            if (fReadRequest)
            {
                BYTE rgbLen[4];
                fOk = SrvReadExact(hPipe, hEvent, rgbLen, 4, 20000);
                if (fOk)
                {
                    received.insert(received.end(), rgbLen, rgbLen + 4);
                    DWORD cb = rgbLen[0] | (rgbLen[1] << 8) | (rgbLen[2] << 16) | (static_cast<DWORD>(rgbLen[3]) << 24);
                    if (cb <= 8192)
                    {
                        Bytes body(cb);
                        fOk = cb == 0 || SrvReadExact(hPipe, hEvent, body.data(), cb, 20000);
                        if (fOk) received.insert(received.end(), body.begin(), body.end());
                    }
                }
            }
            if (fOk && dwDelayMs) Sleep(dwDelayMs);
            for (size_t at = 0; fOk && at < send.size();)
            {
                size_t n = cbChunk ? min(cbChunk, send.size() - at) : send.size() - at;
                DWORD cbDone = 0;
                fOk = SrvIo(hPipe, hEvent, true, send.data() + at, static_cast<DWORD>(n), 20000, &cbDone) && cbDone == n;
                at += n;
                if (fOk && dwChunkDelayMs && at < send.size()) Sleep(dwChunkDelayMs);
            }
            if (!fCloseAfterSend)
            {
                // Drain until the client hangs up, recording anything else it writes.
                BYTE rgb[512];
                DWORD cbDone = 0;
                while (SrvIo(hPipe, hEvent, false, rgb, sizeof(rgb), 30000, &cbDone) && cbDone != 0)
                {
                    received.insert(received.end(), rgb, rgb + cbDone);
                }
            }
            else
            {
                FlushFileBuffers(hPipe);
            }
            DisconnectNamedPipe(hPipe);
        }
        CloseHandle(hEvent);
    }
};

static std::wstring UniquePipeName()
{
    static unsigned s_n = 0;
    wchar_t wz[96];
    swprintf_s(wz, L"\\\\.\\pipe\\weldap-harness-%lu-%u-%llu", GetCurrentProcessId(), s_n++, GetTickCount64());
    return wz;
}

struct CLIENT_RESULT
{
    WELDAP_CLIENT_STATUS status;
    WELDAP_REPLY reply;
    ULONGLONG ms;
};

static CLIENT_RESULT RunClient(const std::wstring &name, DWORD dwDeadlineMs, bool fUnlock, _In_z_ PCWSTR pwzUun, const WELDAP_SEALED &s)
{
    CLIENT_RESULT r;
    memset(&r.reply, 0xA5, sizeof(r.reply));
    ULONGLONG t0 = GetTickCount64();
    r.status = WeldapAuthenticateEx(name.c_str(), dwDeadlineMs, fUnlock, pwzUun, &s, &r.reply);
    r.ms = GetTickCount64() - t0;
    return r;
}

static Bytes Frame(const Bytes &body)
{
    DWORD cb = static_cast<DWORD>(body.size());
    return Cat({ Bytes{ static_cast<BYTE>(cb), static_cast<BYTE>(cb >> 8), static_cast<BYTE>(cb >> 16), static_cast<BYTE>(cb >> 24) }, body });
}

static const char *StatusName(WELDAP_CLIENT_STATUS s);

static const wchar_t c_wzSddlSystem[] = L"O:SYG:SYD:P(A;;GA;;;SY)";

// One scenario: server behaviour set by the caller, client run with the given deadline.
static CLIENT_RESULT PipeCase(PIPE_SERVER &srv, DWORD dwDeadlineMs, bool fUnlock = false, PCWSTR pwzUun = L"alice",
                              const WELDAP_SEALED *ps = nullptr, PCWSTR pwzSddl = c_wzSddlSystem, bool *pfCreated = nullptr)
{
    static const WELDAP_SEALED s_default = MakeSealed("k1", 40, 1793320000ULL, 7);
    std::wstring name = UniquePipeName();
    bool fCreated = srv.Create(name, pwzSddl);
    if (pfCreated) *pfCreated = fCreated;
    if (fCreated) srv.Start();
    CLIENT_RESULT r = RunClient(name, dwDeadlineMs, fUnlock, pwzUun, ps ? *ps : s_default);
    srv.Join();
    return r;
}

static void TestPipe()
{
    Section("WeldapAuthenticateEx against an in-process pipe server");
    bool fSystem = IsProcessSystem();
    const WELDAP_SEALED s = MakeSealed("k1", 40, 1793320000ULL, 7);
    Bytes okReply = ReplyBytes(3, 0, 0, L"", c_szPw32);

    // Pipes that do not exist / refuse us / are busy: independent of who we are.
    {
        CLIENT_RESULT r = RunClient(UniquePipeName(), 15000, false, L"alice", s);
        Check(r.status == WELDAP_STATUS_SERVICE_UNAVAILABLE && IsZeroedError(r.reply), "pipe missing -> SERVICE_UNAVAILABLE (%s), reply zeroed", StatusName(r.status));
        Check(r.ms >= 2900 && r.ms < 6000, "pipe missing: gives up after the ~3 s not-found grace, not the 15 s deadline (%llu ms)", r.ms);
        r = RunClient(UniquePipeName(), 700, false, L"alice", s);
        Check(r.status == WELDAP_STATUS_SERVICE_UNAVAILABLE && r.ms >= 600 && r.ms < 2500, "pipe missing, 700 ms deadline -> SERVICE_UNAVAILABLE within the deadline (%llu ms)", r.ms);
    }
    {
        PIPE_SERVER srv;
        srv.dwConnectWaitMs = 1500;
        bool fCreated = false;
        CLIENT_RESULT r = PipeCase(srv, 5000, false, L"alice", nullptr, L"O:SYG:SYD:P(D;;GA;;;SY)(A;;GA;;;BA)", &fCreated);
        Check(fCreated && r.status == WELDAP_STATUS_SERVICE_UNAVAILABLE && r.ms < 1500 && !srv.fConnected,
              "pipe denies us -> SERVICE_UNAVAILABLE at once, no retry until the deadline (%llu ms)", r.ms);
    }
    {
        std::wstring name = UniquePipeName();
        PIPE_SERVER srv;
        srv.fReadRequest = false;
        bool fCreated = srv.Create(name, c_wzSddlSystem, 1);
        if (fCreated) srv.Start();
        HANDLE hBlocker = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        CLIENT_RESULT r = RunClient(name, 1500, false, L"alice", s);
        if (hBlocker != INVALID_HANDLE_VALUE) CloseHandle(hBlocker);
        srv.Join();
        Check(fCreated && hBlocker != INVALID_HANDLE_VALUE && r.status == WELDAP_STATUS_SERVICE_UNAVAILABLE && r.ms >= 1400 && r.ms < 4000,
              "pipe busy (only instance taken) -> SERVICE_UNAVAILABLE at the 1.5 s deadline (%llu ms)", r.ms);
    }
    // Requests that cannot be encoded never touch the pipe.
    {
        WELDAP_SEALED bad = s;
        bad.cbCt = 0;
        PIPE_SERVER srv;
        srv.dwConnectWaitMs = 1000;
        CLIENT_RESULT r = PipeCase(srv, 5000, false, L"alice", &bad);
        Check(r.status == WELDAP_STATUS_BAD_REQUEST && !srv.fConnected && r.ms < 500 && IsZeroedError(r.reply),
              "bad sealed fields -> BAD_REQUEST, never connects, reply zeroed");
        PIPE_SERVER srv2;
        srv2.dwConnectWaitMs = 1000;
        r = PipeCase(srv2, 5000, false, L"al ice");
        Check(r.status == WELDAP_STATUS_BAD_REQUEST && !srv2.fConnected, "uun with a space -> BAD_REQUEST, never connects");
    }
    // Owner check: an honest non-SYSTEM owner. We run as SYSTEM, whose token may assign BUILTIN\Administrators
    // as owner; the server process is still SYSTEM, so only the pipe-owner half of the check is exercised.
    {
        std::wstring name = UniquePipeName();
        PIPE_SERVER srv;
        srv.fReadRequest = false;
        if (srv.Create(name, L"O:BAG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)"))
        {
            Check(PipeOwner(srv.hPipe) == L"S-1-5-32-544", "untrusted test pipe really is owned by BUILTIN\\Administrators");
            srv.Start();
            CLIENT_RESULT r = RunClient(name, 5000, false, L"alice", s);
            srv.Join();
            Check(r.status == WELDAP_STATUS_UNTRUSTED_SERVER && IsZeroedError(r.reply), "pipe owned by Administrators -> UNTRUSTED_SERVER (%s)", StatusName(r.status));
            Check(srv.fConnected && srv.received.empty(), "UNTRUSTED_SERVER: server saw the connection but not one byte (%zu)", srv.received.size());
            Check(r.ms < 2000, "UNTRUSTED_SERVER: immediate (%llu ms)", r.ms);
        }
        else
        {
            Skip("untrusted owner: cannot create a pipe owned by Administrators here (error %lu)", GetLastError());
        }
    }
    if (!fSystem)
    {
        Skip("pipe exchanges with a trusted server: the harness is not running as SYSTEM, so no pipe it creates can pass the client's SYSTEM checks");
        return;
    }
    {
        std::wstring name = UniquePipeName();
        PIPE_SERVER probe;
        if (probe.Create(name, c_wzSddlSystem))
        {
            Check(PipeOwner(probe.hPipe) == L"S-1-5-18", "trusted test pipe is owned by SYSTEM");
            CloseHandle(probe.hPipe);
            probe.hPipe = INVALID_HANDLE_VALUE;
        }
    }
    // Round trips.
    {
        PIPE_SERVER srv;
        srv.send = Frame(okReply);
        CLIENT_RESULT r = PipeCase(srv, 5000);
        Check(r.status == WELDAP_STATUS_REPLIED && r.reply.result == WELDAP_RESULT_VALUE_OK && !r.reply.fOffline &&
              wcscmp(r.reply.password, L"Lp1!x9Qz-.:=?@^_~#%+AbCdEfGhJkMn") == 0 && r.reply.message[0] == L'\0',
              "round trip: ok online, 32-char local password (%s)", StatusName(r.status));
        Bytes want = Frame(ExpectedRequest(false, "alice", s));
        Check(srv.received == want, "round trip: server received exactly the 4-byte LE length + encoded request (%zu bytes)", srv.received.size());
        REF_REQUEST rr;
        Check(srv.received.size() > 4 && RefParseRequest(Bytes(srv.received.begin() + 4, srv.received.end()), &rr) && rr.scenario == 0 && rr.uun == "alice",
              "round trip: request accepted by the service's parse rules");
        SecureZeroMemory(&r, sizeof(r));
    }
    {
        PIPE_SERVER srv;
        srv.send = Frame(ReplyBytes(3, 0, 1, L"", "~"));
        CLIENT_RESULT r = PipeCase(srv, 5000, true, L"bob");
        Check(r.status == WELDAP_STATUS_REPLIED && r.reply.result == WELDAP_RESULT_VALUE_OK && r.reply.fOffline && wcscmp(r.reply.password, L"~") == 0,
              "round trip: unlock, ok offline");
        Check(srv.received.size() > 6 && srv.received[5] == 1 && srv.received == Frame(ExpectedRequest(true, "bob", s)), "round trip: unlock scenario byte sent");
    }
    {
        PIPE_SERVER srv;
        srv.send = Frame(ReplyBytes(3, 1, 0, L"Nein, \x00E9\x20AC\xD83D\xDE00", ""));
        CLIENT_RESULT r = PipeCase(srv, 5000);
        Check(r.status == WELDAP_STATUS_REPLIED && r.reply.result == WELDAP_RESULT_VALUE_DENY && wcscmp(r.reply.message, L"Nein, \x00E9\x20AC\xD83D\xDE00") == 0 &&
              r.reply.password[0] == L'\0', "round trip: deny with a non-ASCII message");
    }
    {
        PIPE_SERVER srv;
        srv.send = Frame(ReplyBytes(3, 0, 0, Message200(), c_szPw64));
        CLIENT_RESULT r = PipeCase(srv, 5000);
        Check(r.status == WELDAP_STATUS_REPLIED && wcslen(r.reply.password) == 64 && wcsncmp(r.reply.message, Message200().c_str(), 200) == 0,
              "round trip: largest valid reply (469 bytes)");
        SecureZeroMemory(&r, sizeof(r));
    }
    {
        PIPE_SERVER srv;
        srv.send = Frame(ReplyBytes(3, 2, 0, L"Service error", ""));
        srv.cbChunk = 1;
        srv.dwChunkDelayMs = 3;
        CLIENT_RESULT r = PipeCase(srv, 8000);
        Check(r.status == WELDAP_STATUS_REPLIED && r.reply.result == WELDAP_RESULT_VALUE_ERROR && wcscmp(r.reply.message, L"Service error") == 0,
              "round trip: reply dribbled one byte at a time (%llu ms)", r.ms);
    }
    {
        PIPE_SERVER srv;
        srv.send = Frame(okReply);
        srv.dwDelayMs = 700;
        CLIENT_RESULT r = PipeCase(srv, 5000);
        Check(r.status == WELDAP_STATUS_REPLIED && r.ms >= 650, "round trip: server answers after 700 ms, inside the deadline (%llu ms)", r.ms);
    }
    {
        PIPE_SERVER srv;
        srv.send = Cat({ Frame(okReply), Rep(0x99, 10) });
        CLIENT_RESULT r = PipeCase(srv, 5000);
        Check(r.status == WELDAP_STATUS_REPLIED, "round trip: bytes after the framed reply are ignored, not parsed (%s)", StatusName(r.status));
    }
    // Timeouts.
    {
        PIPE_SERVER srv;   // reads the request, never answers
        CLIENT_RESULT r = PipeCase(srv, 1500);
        Check(r.status == WELDAP_STATUS_TIMEOUT && IsZeroedError(r.reply), "server never answers -> TIMEOUT (%s), reply zeroed", StatusName(r.status));
        Check(r.ms >= 1400 && r.ms < 4000, "server never answers: returns at the 1.5 s deadline (%llu ms)", r.ms);
        Check(srv.received == Frame(ExpectedRequest(false, "alice", s)), "server never answers: the request did arrive");
    }
    {
        PIPE_SERVER srv;
        srv.send = Bytes{ 20, 0, 0, 0 };   // length, then silence
        CLIENT_RESULT r = PipeCase(srv, 1500);
        Check(r.status == WELDAP_STATUS_TIMEOUT && r.ms < 4000, "length prefix then silence -> TIMEOUT (%s, %llu ms)", StatusName(r.status), r.ms);
    }
    {
        PIPE_SERVER srv;
        srv.send = Of(Frame(okReply).data(), 10);   // part of the body, then silence
        CLIENT_RESULT r = PipeCase(srv, 1500);
        Check(r.status == WELDAP_STATUS_TIMEOUT && IsZeroedError(r.reply), "partial body then silence -> TIMEOUT (%s), reply zeroed", StatusName(r.status));
    }
    {
        PIPE_SERVER srv;
        srv.send = Frame(okReply);
        srv.dwDelayMs = 2500;
        CLIENT_RESULT r = PipeCase(srv, 1000);
        Check(r.status == WELDAP_STATUS_TIMEOUT && r.ms < 2400 && IsZeroedError(r.reply), "reply after the deadline -> TIMEOUT, not used (%llu ms)", r.ms);
    }
    // Server hangs up early / bad framing.
    static const struct { const char *pszName; Bytes send; } c_rgEarly[] = {
        { "closes right after the request", Bytes() },
        { "closes after 2 bytes of the length", Bytes{ 0x10, 0x00 } },
        { "closes after the length", Bytes{ 0x10, 0x00, 0x00, 0x00 } },
        { "closes 3 bytes into a 5-byte body", Bytes{ 0x05, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00 } },
    };
    for (const auto &t : c_rgEarly)
    {
        PIPE_SERVER srv;
        srv.send = t.send;
        srv.fCloseAfterSend = true;
        CLIENT_RESULT r = PipeCase(srv, 5000);
        Check(r.status == WELDAP_STATUS_PROTOCOL_ERROR && r.ms < 2500 && IsZeroedError(r.reply), "server %s -> PROTOCOL_ERROR (%s, %llu ms)", t.pszName,
              StatusName(r.status), r.ms);
    }
    static const struct { const char *pszName; Bytes send; } c_rgFraming[] = {
        { "length 0", Bytes{ 0, 0, 0, 0 } },
        { "length 4097", Bytes{ 0x01, 0x10, 0x00, 0x00 } },
        { "length 65536", Bytes{ 0x00, 0x00, 0x01, 0x00 } },
        { "length 0x80000000", Bytes{ 0x00, 0x00, 0x00, 0x80 } },
        { "length 0xFFFFFFFF", Bytes{ 0xFF, 0xFF, 0xFF, 0xFF } },
    };
    for (const auto &t : c_rgFraming)
    {
        PIPE_SERVER srv;
        srv.send = Cat({ t.send, Rep(0x41, 64) });
        CLIENT_RESULT r = PipeCase(srv, 5000);
        Check(r.status == WELDAP_STATUS_PROTOCOL_ERROR && r.ms < 2500, "reply %s -> PROTOCOL_ERROR at once (%s, %llu ms)", t.pszName, StatusName(r.status), r.ms);
    }
    {
        PIPE_SERVER srv;
        srv.send = Frame(ReplyBytes(2, 1, 0, L"v2", ""));
        CLIENT_RESULT r = PipeCase(srv, 5000);
        Check(r.status == WELDAP_STATUS_PROTOCOL_ERROR && IsZeroedError(r.reply), "well-framed v2 reply -> PROTOCOL_ERROR");
        PIPE_SERVER srv2;
        std::string pw = c_szPw32;
        pw[31] = ' ';
        srv2.send = Frame(ReplyBytes(3, 0, 0, L"", pw));
        r = PipeCase(srv2, 5000);
        Check(r.status == WELDAP_STATUS_PROTOCOL_ERROR && IsZeroedError(r.reply), "ok reply with a bad password byte -> PROTOCOL_ERROR, no password left in the reply");
        PIPE_SERVER srv3;
        srv3.send = Frame(Cat({ okReply, Bytes{ 0 } }));
        r = PipeCase(srv3, 5000);
        Check(r.status == WELDAP_STATUS_PROTOCOL_ERROR && IsZeroedError(r.reply), "framed reply with a trailing byte -> PROTOCOL_ERROR");
    }
}

// =============================================================================================
// Modes
// =============================================================================================

static int SelfTest()
{
    GuardedBuffer guard;
    if (!guard.Ok())
    {
        printf("FAIL  could not allocate the guard pages\n");
        return 1;
    }
    g_pGuard = &guard;
    ULONGLONG t0 = GetTickCount64();
    TestUun();
    TestEncode();
    TestParse();
    FuzzParse();
    TestHpke();
    TestSealPassword();
    TestPipe();
    g_pGuard = nullptr;
    printf("checks: %d passed, %d failed, %d skipped (%llu ms)\n", g_passes, g_failures, g_skips, GetTickCount64() - t0);
    printf("%s (%d failure%s)\n", g_failures ? "FAILED" : "ALL PASSED", g_failures, g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}

static void PrintBase64(_In_z_ const char *pszLabel, _In_reads_bytes_(cb) const BYTE *pb, DWORD cb)
{
    char sz[1024];
    DWORD cch = sizeof(sz);
    if (CryptBinaryToStringA(pb, cb, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, sz, &cch))
    {
        printf("%s=%s\n", pszLabel, sz);
    }
}

// Seals <password> (UTF-16 -> UTF-8) with an explicit key and AAD, for the host-side interop check.
static int Seal(_In_z_ PCWSTR pwzPub, _In_z_ PCWSTR pwzAad, _In_z_ PCWSTR pwzPassword)
{
    BYTE pub[65];
    DWORD cbPub = sizeof(pub);
    if (!CryptStringToBinaryW(pwzPub, 0, CRYPT_STRING_BASE64, pub, &cbPub, nullptr, nullptr) || cbPub != 65)
    {
        printf("bad public key\n");
        return 2;
    }
    char aad[512] = {}, pw[1024] = {};
    int cbAad = WideCharToMultiByte(CP_UTF8, 0, pwzAad, -1, aad, sizeof(aad), nullptr, nullptr) - 1;
    int cbPw = WideCharToMultiByte(CP_UTF8, 0, pwzPassword, -1, pw, sizeof(pw), nullptr, nullptr) - 1;
    if (cbAad < 0 || cbPw < 0)
    {
        printf("bad argument\n");
        return 2;
    }
    // The command line can't carry a newline: "\n" in the AAD argument stands for one.
    int j = 0;
    for (int i = 0; i < cbAad; i++, j++)
    {
        if (aad[i] == '\\' && i + 1 < cbAad && aad[i + 1] == 'n') { aad[j] = '\n'; i++; } else { aad[j] = aad[i]; }
    }
    cbAad = j;
    BYTE enc[65], ct[1100];
    ULONG cbCt = 0;
    HRESULT hr = WeldapHpkeSeal(pub, 65, reinterpret_cast<BYTE *>(aad), static_cast<ULONG>(cbAad), reinterpret_cast<BYTE *>(pw),
                                static_cast<ULONG>(cbPw), enc, ct, sizeof(ct), &cbCt);
    SecureZeroMemory(pw, sizeof(pw));
    if (FAILED(hr))
    {
        printf("seal failed 0x%08lx\n", static_cast<unsigned long>(hr));
        return 1;
    }
    PrintBase64("enc", enc, 65);
    PrintBase64("ct", ct, cbCt);
    char hex[1100] = {};
    for (int i = 0; i < cbAad && 2 * i + 2 < static_cast<int>(sizeof(hex)); i++) sprintf_s(hex + 2 * i, 3, "%02x", static_cast<BYTE>(aad[i]));
    printf("aad_hex=%s\n", hex);
    return 0;
}

static const char *StatusName(WELDAP_CLIENT_STATUS s)
{
    switch (s)
    {
    case WELDAP_STATUS_REPLIED:             return "REPLIED";
    case WELDAP_STATUS_SERVICE_UNAVAILABLE: return "SERVICE_UNAVAILABLE";
    case WELDAP_STATUS_UNTRUSTED_SERVER:    return "UNTRUSTED_SERVER";
    case WELDAP_STATUS_TIMEOUT:             return "TIMEOUT";
    case WELDAP_STATUS_PROTOCOL_ERROR:      return "PROTOCOL_ERROR";
    case WELDAP_STATUS_BAD_REQUEST:         return "BAD_REQUEST";
    }
    return "?";
}

// Full path as the tile does it: seal (reads the server key from the registry) + pipe exchange.
static int Call(bool fUnlock, _In_z_ PCWSTR pwzUun, _In_z_ PCWSTR pwzPassword)
{
    wchar_t uun[WELDAP_MAX_UUN_CHARS + 1];
    if (FAILED(WeldapNormalizeUun(pwzUun, uun, ARRAYSIZE(uun))))
    {
        printf("status=INVALID_UUN\n");
        return 2;
    }
    // "-" = read the password from stdin (keeps it off the command line).
    wchar_t wzStdin[WELDAP_MAX_PASSWORD_CHARS + 2] = {};
    if (wcscmp(pwzPassword, L"-") == 0)
    {
        char line[1024] = {};
        if (fgets(line, sizeof(line), stdin) == nullptr)
        {
            printf("status=NO_PASSWORD\n");
            return 2;
        }
        line[strcspn(line, "\r\n")] = '\0';
        MultiByteToWideChar(CP_UTF8, 0, line, -1, wzStdin, ARRAYSIZE(wzStdin) - 1);
        SecureZeroMemory(line, sizeof(line));
        pwzPassword = wzStdin;
    }
    ULONGLONG t0 = GetTickCount64();
    WELDAP_SEALED sealed;
    HRESULT hr = WeldapSealPassword(uun, fUnlock, pwzPassword, &sealed);
    SecureZeroMemory(wzStdin, sizeof(wzStdin));
    ULONGLONG msSeal = GetTickCount64() - t0;
    if (FAILED(hr))
    {
        printf("status=SEAL_FAILED hr=0x%08lx\n", static_cast<unsigned long>(hr));
        return 1;
    }
    WELDAP_REPLY reply;
    WELDAP_CLIENT_STATUS st = WeldapAuthenticate(fUnlock, uun, &sealed, &reply);
    SecureZeroMemory(&sealed, sizeof(sealed));
    ULONGLONG ms = GetTickCount64() - t0;
    static const char *c_results[] = { "ok", "deny", "error" };
    printf("status=%s result=%s mode=%s local_password_chars=%zu seal_ms=%llu elapsed_ms=%llu\n", StatusName(st),
           st == WELDAP_STATUS_REPLIED && reply.result <= WELDAP_RESULT_VALUE_ERROR ? c_results[reply.result] : "-",
           st == WELDAP_STATUS_REPLIED && reply.result == WELDAP_RESULT_VALUE_OK ? (reply.fOffline ? "offline" : "online") : "-",
           wcsnlen(reply.password, ARRAYSIZE(reply.password)), msSeal, ms);
    char utf8[1024];
    if (WideCharToMultiByte(CP_UTF8, 0, reply.message, -1, utf8, sizeof(utf8), nullptr, nullptr) <= 0)
    {
        utf8[0] = '\0';
    }
    printf("message=%s\n", utf8);
    SecureZeroMemory(&reply, sizeof(reply));
    return 0;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc >= 2 && wcscmp(argv[1], L"selftest") == 0)
    {
        return SelfTest();
    }
    if (argc == 5 && wcscmp(argv[1], L"seal") == 0)
    {
        return Seal(argv[2], argv[3], argv[4]);
    }
    if (argc == 5 && wcscmp(argv[1], L"call") == 0)
    {
        return Call(wcscmp(argv[2], L"unlock") == 0, argv[3], argv[4]);
    }
    fwprintf(stderr, L"usage: WeldapClientTest selftest | seal <pub-b64> <aad> <password> | call <logon|unlock> <uun> <password>\n");
    return 2;
}
