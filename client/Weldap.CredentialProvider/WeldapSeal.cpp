// WELDAP: password sealing (see WeldapSeal.h). CNG only.

// /analyze: C28285 is a syntax error inside the SDK's own SAL for CryptStringToBinaryW (wincrypt.h,
// SAL_when(... CRYPT_STRING_BINARY), SDK 10.0.26100), not a finding in this code. It is raised while the
// header is parsed (windows.h pulls it in), so `#pragma warning(suppress)` on the call cannot reach it;
// hence a file-wide disable of that one warning, before the includes.
#pragma warning(disable: 28285)

#include "WeldapSeal.h"
#include <bcrypt.h>
#include <wincrypt.h>
#include <strsafe.h>
#include "../Weldap.Shared/WeldapProtocol.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

namespace
{
const BYTE c_rgbHpkeV1[] = { 'H', 'P', 'K', 'E', '-', 'v', '1' };
const BYTE c_rgbKemSuite[] = { 'K', 'E', 'M', 0x00, 0x10 };                                   // DHKEM(P-256, HKDF-SHA256)
const BYTE c_rgbHpkeSuite[] = { 'H', 'P', 'K', 'E', 0x00, 0x10, 0x00, 0x01, 0x00, 0x02 };    // + HKDF-SHA256, AES-256-GCM
const char c_szInfo[] = "WELDAP password v1";
const NTSTATUS c_ntsBad = static_cast<NTSTATUS>(0xC000000DL);   // STATUS_INVALID_PARAMETER

struct PART
{
    const BYTE *pb;
    ULONG cb;
};

PART Label(const char *psz)
{
    return { reinterpret_cast<const BYTE *>(psz), static_cast<ULONG>(strlen(psz)) };
}

// SHA-256 (pbKey == nullptr) or HMAC-SHA256 over the concatenation of parts.
HRESULT Digest(_In_opt_ const BYTE *pbKey, ULONG cbKey, const PART *rgParts, size_t cParts, _Out_writes_(32) BYTE *pbOut)
{
    static const BYTE c_rgbZeros[32] = {};
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS st;
    if (pbKey != nullptr)
    {
        if (cbKey == 0)
        {
            pbKey = c_rgbZeros;   // HMAC zero-pads short keys: an empty key equals 32 zero bytes
            cbKey = sizeof(c_rgbZeros);
        }
        st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (NT_SUCCESS(st)) st = BCryptCreateHash(hAlg, &hHash, nullptr, 0, const_cast<PUCHAR>(pbKey), cbKey, 0);
    }
    else
    {
        st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (NT_SUCCESS(st)) st = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    }
    for (size_t i = 0; NT_SUCCESS(st) && i < cParts; i++)
    {
        if (rgParts[i].cb != 0)
        {
            st = BCryptHashData(hHash, const_cast<PUCHAR>(rgParts[i].pb), rgParts[i].cb, 0);
        }
    }
    if (NT_SUCCESS(st)) st = BCryptFinishHash(hHash, pbOut, 32, 0);
    if (hHash != nullptr) BCryptDestroyHash(hHash);
    if (hAlg != nullptr) BCryptCloseAlgorithmProvider(hAlg, 0);
    return NT_SUCCESS(st) ? S_OK : HRESULT_FROM_NT(st);
}

// RFC 9180: LabeledExtract(salt, label, ikm) = Extract(salt, "HPKE-v1" || suite_id || label || ikm)
HRESULT LabeledExtract(const BYTE *pbSuite, ULONG cbSuite, const BYTE *pbSalt, ULONG cbSalt, const char *pszLabel,
                       const BYTE *pbIkm, ULONG cbIkm, _Out_writes_(32) BYTE *pbOut)
{
    PART rgParts[] = { { c_rgbHpkeV1, sizeof(c_rgbHpkeV1) }, { pbSuite, cbSuite }, Label(pszLabel), { pbIkm, cbIkm } };
    // Always HMAC: an empty salt is a non-null key of length 0, which Digest turns into 32 zero bytes.
    return Digest(pbSalt != nullptr ? pbSalt : c_rgbHpkeV1, pbSalt != nullptr ? cbSalt : 0, rgParts, ARRAYSIZE(rgParts), pbOut);
}

// LabeledExpand(prk, label, info, L) = Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info, L), L <= 32
HRESULT LabeledExpand(const BYTE *pbSuite, ULONG cbSuite, const BYTE *pbPrk, const char *pszLabel,
                      const BYTE *pbInfo, ULONG cbInfo, _Out_writes_(cbOut) BYTE *pbOut, ULONG cbOut)
{
    if (cbOut > 32)
    {
        return E_INVALIDARG;
    }
    BYTE rgbLen[2] = { static_cast<BYTE>(cbOut >> 8), static_cast<BYTE>(cbOut) };
    BYTE bCounter = 1;
    BYTE rgbT[32];
    PART rgParts[] = { { rgbLen, 2 }, { c_rgbHpkeV1, sizeof(c_rgbHpkeV1) }, { pbSuite, cbSuite }, Label(pszLabel),
                       { pbInfo, cbInfo }, { &bCounter, 1 } };
    HRESULT hr = Digest(pbPrk, 32, rgParts, ARRAYSIZE(rgParts), rgbT);
    if (SUCCEEDED(hr))
    {
        memcpy(pbOut, rgbT, cbOut);
    }
    SecureZeroMemory(rgbT, sizeof(rgbT));
    return hr;
}

// DHKEM(P-256) Encap's DH step: a fresh ephemeral key; enc = its public point, dh = x(skE * pkR).
HRESULT EcdhEphemeral(_In_reads_(65) const BYTE *pbPkR, _Out_writes_(65) BYTE *pbEnc, _Out_writes_(32) BYTE *pbDh)
{
    if (pbPkR[0] != 0x04)
    {
        return E_INVALIDARG;
    }
    struct
    {
        BCRYPT_ECCKEY_BLOB hdr;
        BYTE rgbXY[64];
    } blob = {};
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hEph = nullptr;
    BCRYPT_KEY_HANDLE hPeer = nullptr;
    BCRYPT_SECRET_HANDLE hSecret = nullptr;
    BYTE rgbRaw[32] = {};
    ULONG cb = 0;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0);
    if (NT_SUCCESS(st)) st = BCryptGenerateKeyPair(hAlg, &hEph, 256, 0);
    if (NT_SUCCESS(st)) st = BCryptFinalizeKeyPair(hEph, 0);
    if (NT_SUCCESS(st)) st = BCryptExportKey(hEph, nullptr, BCRYPT_ECCPUBLIC_BLOB, reinterpret_cast<PUCHAR>(&blob), sizeof(blob), &cb, 0);
    if (NT_SUCCESS(st) && (cb != sizeof(blob) || blob.hdr.cbKey != 32)) st = c_ntsBad;
    if (NT_SUCCESS(st))
    {
        pbEnc[0] = 0x04;
        memcpy(pbEnc + 1, blob.rgbXY, 64);
        blob.hdr.dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
        blob.hdr.cbKey = 32;
        memcpy(blob.rgbXY, pbPkR + 1, 64);
        st = BCryptImportKeyPair(hAlg, nullptr, BCRYPT_ECCPUBLIC_BLOB, &hPeer, reinterpret_cast<PUCHAR>(&blob), sizeof(blob), 0);
    }
    if (NT_SUCCESS(st)) st = BCryptSecretAgreement(hEph, hPeer, &hSecret, 0);
    if (NT_SUCCESS(st)) st = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, nullptr, rgbRaw, sizeof(rgbRaw), &cb, 0);
    if (NT_SUCCESS(st) && cb != 32) st = c_ntsBad;
    if (NT_SUCCESS(st))
    {
        for (int i = 0; i < 32; i++)
        {
            pbDh[i] = rgbRaw[31 - i];   // CNG returns the raw secret little-endian; HPKE wants big-endian x
        }
    }
    SecureZeroMemory(rgbRaw, sizeof(rgbRaw));
    if (hSecret != nullptr) BCryptDestroySecret(hSecret);
    if (hPeer != nullptr) BCryptDestroyKey(hPeer);
    if (hEph != nullptr) BCryptDestroyKey(hEph);   // the ephemeral private key never leaves CNG
    if (hAlg != nullptr) BCryptCloseAlgorithmProvider(hAlg, 0);
    return NT_SUCCESS(st) ? S_OK : HRESULT_FROM_NT(st);
}

HRESULT AesGcmSeal(_In_reads_(32) const BYTE *pbKey, _In_reads_(12) const BYTE *pbNonce, const BYTE *pbAad, ULONG cbAad,
                   const BYTE *pbPlain, ULONG cbPlain, _Out_writes_(cbPlain + 16) BYTE *pbOut)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (NT_SUCCESS(st))
    {
        st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_GCM)),
                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    }
    if (NT_SUCCESS(st)) st = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, const_cast<PUCHAR>(pbKey), 32, 0);
    if (NT_SUCCESS(st))
    {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = const_cast<PUCHAR>(pbNonce);
        info.cbNonce = 12;
        info.pbAuthData = const_cast<PUCHAR>(pbAad);
        info.cbAuthData = cbAad;
        info.pbTag = pbOut + cbPlain;
        info.cbTag = WELDAP_HPKE_TAG_BYTES;
        ULONG cbDone = 0;
        st = BCryptEncrypt(hKey, const_cast<PUCHAR>(pbPlain), cbPlain, &info, nullptr, 0, pbOut, cbPlain, &cbDone, 0);
        if (NT_SUCCESS(st) && cbDone != cbPlain) st = c_ntsBad;
    }
    if (hKey != nullptr) BCryptDestroyKey(hKey);
    if (hAlg != nullptr) BCryptCloseAlgorithmProvider(hAlg, 0);
    return NT_SUCCESS(st) ? S_OK : HRESULT_FROM_NT(st);
}

HRESULT Base64(const BYTE *pb, ULONG cb, _Out_writes_(cch) char *psz, DWORD cch)
{
    DWORD cchOut = cch;
    if (!CryptBinaryToStringA(pb, cb, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, psz, &cchOut))
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    return S_OK;
}

HRESULT RegString(HKEY hRoot, PCWSTR pwzKey, PCWSTR pwzValue, _Out_writes_(cch) PWSTR pwz, DWORD cch)
{
    DWORD cb = cch * sizeof(wchar_t);
    LSTATUS ls = RegGetValueW(hRoot, pwzKey, pwzValue, RRF_RT_REG_SZ, nullptr, pwz, &cb);
    return ls == ERROR_SUCCESS && pwz[0] != L'\0' ? S_OK : WELDAP_E_NOT_CONFIGURED;
}

// A locked, page-sized buffer for the UTF-8 password: never paged out, zeroed before release.
struct SECURE_PAGE
{
    BYTE *pb = nullptr;
    static const SIZE_T c_cb = 4096;
    SECURE_PAGE()
    {
        pb = static_cast<BYTE *>(VirtualAlloc(nullptr, c_cb, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (pb != nullptr) VirtualLock(pb, c_cb);
    }
    ~SECURE_PAGE()
    {
        if (pb != nullptr)
        {
            SecureZeroMemory(pb, c_cb);
            VirtualUnlock(pb, c_cb);
            VirtualFree(pb, 0, MEM_RELEASE);
        }
    }
    SECURE_PAGE(const SECURE_PAGE &) = delete;
    SECURE_PAGE &operator=(const SECURE_PAGE &) = delete;
};
} // namespace

HRESULT WeldapHpkeSeal(_In_reads_bytes_(cbPublic) const BYTE *pbPublic, ULONG cbPublic,
                       _In_reads_bytes_(cbAad) const BYTE *pbAad, ULONG cbAad,
                       _In_reads_bytes_(cbPlain) const BYTE *pbPlain, ULONG cbPlain,
                       _Out_writes_bytes_(WELDAP_HPKE_ENC_BYTES) BYTE *pbEnc,
                       _Out_writes_bytes_(cbCtCap) BYTE *pbCt, ULONG cbCtCap, _Out_ ULONG *pcbCt)
{
    *pcbCt = 0;
    if (cbPublic != WELDAP_HPKE_ENC_BYTES || cbPlain == 0 || cbCtCap < cbPlain + WELDAP_HPKE_TAG_BYTES)
    {
        return E_INVALIDARG;
    }
    BYTE rgbDh[32], rgbKemContext[2 * WELDAP_HPKE_ENC_BYTES], rgbEaePrk[32], rgbShared[32];
    BYTE rgbPskIdHash[32], rgbInfoHash[32], rgbKsc[65], rgbSecret[32], rgbKey[32], rgbNonce[12];

    HRESULT hr = EcdhEphemeral(pbPublic, pbEnc, rgbDh);
    if (SUCCEEDED(hr))
    {
        memcpy(rgbKemContext, pbEnc, WELDAP_HPKE_ENC_BYTES);
        memcpy(rgbKemContext + WELDAP_HPKE_ENC_BYTES, pbPublic, WELDAP_HPKE_ENC_BYTES);
        hr = LabeledExtract(c_rgbKemSuite, sizeof(c_rgbKemSuite), nullptr, 0, "eae_prk", rgbDh, sizeof(rgbDh), rgbEaePrk);
    }
    if (SUCCEEDED(hr)) hr = LabeledExpand(c_rgbKemSuite, sizeof(c_rgbKemSuite), rgbEaePrk, "shared_secret",
                                          rgbKemContext, sizeof(rgbKemContext), rgbShared, 32);
    // Key schedule, mode_base: psk and psk_id empty.
    if (SUCCEEDED(hr)) hr = LabeledExtract(c_rgbHpkeSuite, sizeof(c_rgbHpkeSuite), nullptr, 0, "psk_id_hash", nullptr, 0, rgbPskIdHash);
    if (SUCCEEDED(hr)) hr = LabeledExtract(c_rgbHpkeSuite, sizeof(c_rgbHpkeSuite), nullptr, 0, "info_hash",
                                           reinterpret_cast<const BYTE *>(c_szInfo), sizeof(c_szInfo) - 1, rgbInfoHash);
    if (SUCCEEDED(hr))
    {
        rgbKsc[0] = 0x00;
        memcpy(rgbKsc + 1, rgbPskIdHash, 32);
        memcpy(rgbKsc + 33, rgbInfoHash, 32);
        hr = LabeledExtract(c_rgbHpkeSuite, sizeof(c_rgbHpkeSuite), rgbShared, sizeof(rgbShared), "secret", nullptr, 0, rgbSecret);
    }
    if (SUCCEEDED(hr)) hr = LabeledExpand(c_rgbHpkeSuite, sizeof(c_rgbHpkeSuite), rgbSecret, "key", rgbKsc, sizeof(rgbKsc), rgbKey, 32);
    if (SUCCEEDED(hr)) hr = LabeledExpand(c_rgbHpkeSuite, sizeof(c_rgbHpkeSuite), rgbSecret, "base_nonce", rgbKsc, sizeof(rgbKsc), rgbNonce, 12);
    // Sequence number 0: nonce = base_nonce.
    if (SUCCEEDED(hr)) hr = AesGcmSeal(rgbKey, rgbNonce, pbAad, cbAad, pbPlain, cbPlain, pbCt);
    if (SUCCEEDED(hr)) *pcbCt = cbPlain + WELDAP_HPKE_TAG_BYTES;

    SecureZeroMemory(rgbDh, sizeof(rgbDh));
    SecureZeroMemory(rgbEaePrk, sizeof(rgbEaePrk));
    SecureZeroMemory(rgbShared, sizeof(rgbShared));
    SecureZeroMemory(rgbSecret, sizeof(rgbSecret));
    SecureZeroMemory(rgbKey, sizeof(rgbKey));
    SecureZeroMemory(rgbNonce, sizeof(rgbNonce));
    SecureZeroMemory(rgbKsc, sizeof(rgbKsc));
    return hr;
}

HRESULT WeldapPbkdf2Sha256(_In_reads_bytes_(cbPassword) const BYTE *pbPassword, ULONG cbPassword,
                           _In_reads_bytes_(cbSalt) const BYTE *pbSalt, ULONG cbSalt, ULONG iterations,
                           _Out_writes_bytes_(cbOut) BYTE *pbOut, ULONG cbOut)
{
    BCRYPT_ALG_HANDLE hPrf = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hPrf, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (NT_SUCCESS(st))
    {
        st = BCryptDeriveKeyPBKDF2(hPrf, const_cast<PUCHAR>(pbPassword), cbPassword, const_cast<PUCHAR>(pbSalt), cbSalt,
                                   iterations, pbOut, cbOut, 0);
    }
    if (hPrf != nullptr) BCryptCloseAlgorithmProvider(hPrf, 0);
    return NT_SUCCESS(st) ? S_OK : HRESULT_FROM_NT(st);
}

static HRESULT SealPassword(_In_ PCWSTR pwzUun, bool fUnlock, _In_ PCWSTR pwzPassword, _Out_ WELDAP_SEALED *pSealed)
{
    ZeroMemory(pSealed, sizeof(*pSealed));

    // Configuration: the server's public password key and its id (written by the MSI; admin-only key).
    wchar_t wzKey[128], wzKid[WELDAP_MAX_KID_CHARS + 1], wzGuid[64];
    HRESULT hr = RegString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WELDAP", L"ServerKey", wzKey, ARRAYSIZE(wzKey));
    if (SUCCEEDED(hr)) hr = RegString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WELDAP", L"ServerKeyId", wzKid, ARRAYSIZE(wzKid));
    if (SUCCEEDED(hr)) hr = RegString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", wzGuid, ARRAYSIZE(wzGuid));
    if (FAILED(hr))
    {
        return WELDAP_E_NOT_CONFIGURED;
    }
    BYTE rgbPublic[WELDAP_HPKE_ENC_BYTES];
    DWORD cbPublic = sizeof(rgbPublic);
    if (!CryptStringToBinaryW(wzKey, 0, CRYPT_STRING_BASE64, rgbPublic, &cbPublic, nullptr, nullptr) ||
        cbPublic != WELDAP_HPKE_ENC_BYTES || rgbPublic[0] != 0x04)
    {
        return WELDAP_E_NOT_CONFIGURED;
    }
    for (size_t i = 0; wzKid[i] != L'\0'; i++)
    {
        wchar_t c = wzKid[i];
        if (!((c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9') || c == L'-'))
        {
            return WELDAP_E_NOT_CONFIGURED;
        }
        pSealed->szKid[i] = static_cast<char>(c);
    }
    char szUun[WELDAP_MAX_UUN_CHARS + 1] = {};
    for (size_t i = 0; pwzUun[i] != L'\0'; i++)
    {
        if (i >= WELDAP_MAX_UUN_CHARS || pwzUun[i] > 0x7F)
        {
            return E_INVALIDARG;
        }
        szUun[i] = static_cast<char>(pwzUun[i]);
    }
    char szGuid[64] = {};
    for (size_t i = 0; wzGuid[i] != L'\0' && i < ARRAYSIZE(szGuid) - 1; i++)
    {
        szGuid[i] = static_cast<char>(wzGuid[i] & 0x7F);
    }

    // The password as UTF-8, in locked memory, for as short a time as possible.
    SECURE_PAGE page;
    if (page.pb == nullptr)
    {
        return E_OUTOFMEMORY;
    }
    int cchPassword = static_cast<int>(wcsnlen(pwzPassword, WELDAP_MAX_PASSWORD_CHARS + 1));
    int cbUtf8 = cchPassword == 0 ? 0 : WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, pwzPassword, cchPassword,
                                                            reinterpret_cast<char *>(page.pb), static_cast<int>(SECURE_PAGE::c_cb), nullptr, nullptr);
    if (cbUtf8 <= 0)
    {
        return cchPassword == 0 ? E_INVALIDARG : WELDAP_E_BAD_CHARACTERS;
    }
    if (static_cast<ULONG>(cbUtf8) > WELDAP_MAX_PASSWORD_UTF8)
    {
        return WELDAP_E_TOO_LONG;
    }

    // Request id and timestamp, then the AAD (which carries the request id in base64).
    if (!NT_SUCCESS(BCryptGenRandom(nullptr, pSealed->rgbRid, sizeof(pSealed->rgbRid), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
    {
        return E_FAIL;
    }
    char szRid[32];
    hr = Base64(pSealed->rgbRid, sizeof(pSealed->rgbRid), szRid, ARRAYSIZE(szRid));
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER t;
    t.LowPart = ft.dwLowDateTime;
    t.HighPart = ft.dwHighDateTime;
    pSealed->ts = (t.QuadPart - 116444736000000000ULL) / 10000000ULL;
    char szAad[256];
    if (SUCCEEDED(hr))
    {
        hr = StringCchPrintfA(szAad, ARRAYSIZE(szAad), "WELDAP-auth-v1\n%s\n%s\n%s\n%llu\n%s", pSealed->szKid, szUun,
                              fUnlock ? WELDAP_SCENARIO_UNLOCK : WELDAP_SCENARIO_LOGON, pSealed->ts, szRid);
    }

    // Seal to the server.
    if (SUCCEEDED(hr)) hr = WeldapHpkeSeal(rgbPublic, sizeof(rgbPublic), reinterpret_cast<const BYTE *>(szAad),
                                           static_cast<ULONG>(strlen(szAad)), page.pb, static_cast<ULONG>(cbUtf8),
                                           pSealed->rgbEnc, pSealed->rgbCt, sizeof(pSealed->rgbCt), &pSealed->cbCt);

    // Offline verifier.
    BYTE rgbSalt[32];
    if (SUCCEEDED(hr))
    {
        static const char c_szDomain[] = "WELDAP-offline-v1\n";
        static const char c_szNl[] = "\n";
        PART rgParts[] = { { reinterpret_cast<const BYTE *>(c_szDomain), sizeof(c_szDomain) - 1 },
                           { reinterpret_cast<const BYTE *>(szGuid), static_cast<ULONG>(strlen(szGuid)) },
                           { reinterpret_cast<const BYTE *>(c_szNl), 1 },
                           { reinterpret_cast<const BYTE *>(szUun), static_cast<ULONG>(strlen(szUun)) } };
        hr = Digest(nullptr, 0, rgParts, ARRAYSIZE(rgParts), rgbSalt);
    }
    if (SUCCEEDED(hr)) hr = WeldapPbkdf2Sha256(page.pb, static_cast<ULONG>(cbUtf8), rgbSalt, sizeof(rgbSalt),
                                               WELDAP_PBKDF2_ITERATIONS, pSealed->rgbVerifier, sizeof(pSealed->rgbVerifier));
    if (FAILED(hr))
    {
        SecureZeroMemory(pSealed, sizeof(*pSealed));
    }
    return hr;   // `page` (the UTF-8 password) is zeroed and released here
}

HRESULT WeldapSealPassword(_In_ PCWSTR pwzUun, bool fUnlock, _In_ PCWSTR pwzPassword, _Out_ WELDAP_SEALED *pSealed)
{
    HRESULT hr = SealPassword(pwzUun, fUnlock, pwzPassword, pSealed);
    if (FAILED(hr))
    {
        SecureZeroMemory(pSealed, sizeof(*pSealed));   // every failure path, including the early returns above
    }
    return hr;
}
