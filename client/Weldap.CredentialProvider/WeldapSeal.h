// WELDAP: sealing the password inside LogonUI, before it goes anywhere.
//
// HPKE (RFC 9180) base mode, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, to the WELDAP server's public
// password key (HKLM\SOFTWARE\WELDAP: ServerKey, ServerKeyId). Only the server holds the private key: the
// WELDAP service relays the ciphertext without being able to read it. The AAD binds the ciphertext to the key
// id, user, scenario, timestamp and a random request id (the server refuses stale or repeated ones):
//     "WELDAP-auth-v1\n" kid "\n" uun "\n" scenario "\n" ts "\n" rid
// Also computes the offline verifier, PBKDF2-HMAC-SHA256 of the password (600 000 iterations, 32 bytes) with
// salt SHA-256("WELDAP-offline-v1\n" MachineGuid "\n" uun): the service compares it when the server is out
// of reach, so Windows never needs the real password. Only CNG (bcrypt.dll); no network or account code.
#pragma once

#include <windows.h>

#define WELDAP_MAX_KID_CHARS        32u
#define WELDAP_MAX_PASSWORD_UTF8    256u      // the server's limit
#define WELDAP_VERIFIER_BYTES       32u
#define WELDAP_PBKDF2_ITERATIONS    600000u
#define WELDAP_HPKE_ENC_BYTES       65u       // uncompressed P-256 point
#define WELDAP_HPKE_TAG_BYTES       16u

#define WELDAP_RID_BYTES            16u

// Everything one attempt sends. No field holds the password.
struct WELDAP_SEALED
{
    char szKid[WELDAP_MAX_KID_CHARS + 1];                           // NUL-terminated [a-z0-9-]
    BYTE rgbEnc[WELDAP_HPKE_ENC_BYTES];
    BYTE rgbCt[WELDAP_MAX_PASSWORD_UTF8 + WELDAP_HPKE_TAG_BYTES];  // ciphertext || tag
    ULONG cbCt;
    unsigned long long ts;                                          // Unix seconds
    BYTE rgbRid[WELDAP_RID_BYTES];
    BYTE rgbVerifier[WELDAP_VERIFIER_BYTES];
};

// Failure codes the tile turns into messages.
#define WELDAP_E_NOT_CONFIGURED   HRESULT_FROM_WIN32(ERROR_NOT_FOUND)        // no server key on this PC
#define WELDAP_E_TOO_LONG         HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW)  // over 256 UTF-8 bytes
#define WELDAP_E_BAD_CHARACTERS   HRESULT_FROM_WIN32(ERROR_NO_UNICODE_TRANSLATION)

// Seals pwzPassword for pwzUun (already normalised). Zeroes every copy it makes; on failure *pSealed is zeroed.
HRESULT WeldapSealPassword(_In_ PCWSTR pwzUun, bool fUnlock, _In_ PCWSTR pwzPassword, _Out_ WELDAP_SEALED *pSealed);

// Building blocks, exposed for the harness's known-answer and interop tests.
HRESULT WeldapHpkeSeal(_In_reads_bytes_(cbPublic) const BYTE *pbPublic, ULONG cbPublic,
                       _In_reads_bytes_(cbAad) const BYTE *pbAad, ULONG cbAad,
                       _In_reads_bytes_(cbPlain) const BYTE *pbPlain, ULONG cbPlain,
                       _Out_writes_bytes_(WELDAP_HPKE_ENC_BYTES) BYTE *pbEnc,
                       _Out_writes_bytes_(cbCtCap) BYTE *pbCt, ULONG cbCtCap, _Out_ ULONG *pcbCt);
HRESULT WeldapPbkdf2Sha256(_In_reads_bytes_(cbPassword) const BYTE *pbPassword, ULONG cbPassword,
                           _In_reads_bytes_(cbSalt) const BYTE *pbSalt, ULONG cbSalt, ULONG iterations,
                           _Out_writes_bytes_(cbOut) BYTE *pbOut, ULONG cbOut);
