// WELDAP: pipe client for the credential provider.
//
// UUN normalisation, the binary request/reply codec and the named-pipe exchange with the
// WELDAP Service (see client/Weldap.Shared/PROTOCOL.md). No COM, no UI, no network or
// account code. The password itself never reaches this file: see WeldapSeal.h.
#pragma once

#include <windows.h>
#include "../Weldap.Shared/WeldapProtocol.h"
#include "WeldapSeal.h"

enum WELDAP_RESULT
{
    WELDAP_RESULT_VALUE_OK = WELDAP_RESULT_OK,
    WELDAP_RESULT_VALUE_DENY = WELDAP_RESULT_DENY,
    WELDAP_RESULT_VALUE_ERROR = WELDAP_RESULT_ERROR,
};

enum WELDAP_CLIENT_STATUS
{
    WELDAP_STATUS_REPLIED = 0,          // a well-formed reply arrived; see WELDAP_REPLY
    WELDAP_STATUS_SERVICE_UNAVAILABLE,  // no pipe / could not connect before the deadline
    WELDAP_STATUS_UNTRUSTED_SERVER,     // pipe server process is not SYSTEM: nothing was sent
    WELDAP_STATUS_TIMEOUT,              // connected, but write + reply did not finish before the deadline
    WELDAP_STATUS_PROTOCOL_ERROR,       // bad framing or malformed reply
    WELDAP_STATUS_BAD_REQUEST,          // the request could not be encoded (caller bug / invalid input)
};

struct WELDAP_REPLY
{
    WELDAP_RESULT result;
    bool fOffline;                                          // ok: signed in on the offline verifier
    wchar_t message[WELDAP_MAX_REPLY_MESSAGE_CHARS + 1];   // NUL-terminated
    // ok only: the account's random local password, what Windows logs on with. The caller SecureZeroMemory's
    // the whole reply as soon as the serialization is built.
    wchar_t password[WELDAP_MAX_LOCAL_PASSWORD_CHARS + 1];
};

// Trims leading/trailing whitespace and lowercases ASCII A-Z. Fails with E_INVALIDARG if the
// result is empty, longer than WELDAP_MAX_UUN_CHARS, or contains anything but [a-z0-9]
// (the service applies the same rule and is the authority; this only avoids sending junk).
HRESULT WeldapNormalizeUun(_In_opt_ PCWSTR pwzIn, _Out_writes_(cchOut) PWSTR pwzOut, size_t cchOut);

// Encodes the v3 binary request into pbOut: scenario, uun and the sealed fields (no password).
// Returns the byte count, or 0 on failure (buffer too small, bad field), with pbOut[0..cbOut) zeroed.
size_t WeldapEncodeRequest(bool fUnlock, _In_ PCWSTR pwzUun, _In_ const WELDAP_SEALED *pSealed,
                        _Out_writes_bytes_(cbOut) BYTE *pbOut, size_t cbOut);

// Strictly parses a v3 binary reply. Returns false if malformed: ok needs a password, deny/error must have
// none (and online mode).
bool WeldapParseReply(_In_reads_bytes_(cb) const BYTE *pb, size_t cb, _Out_ WELDAP_REPLY *pReply);

// Full exchange: connect (15 s overall deadline), verify the server is SYSTEM, send, read reply.
// pwzUun must already be normalised. pReply is only meaningful when WELDAP_STATUS_REPLIED.
WELDAP_CLIENT_STATUS WeldapAuthenticate(bool fUnlock, _In_ PCWSTR pwzUun, _In_ const WELDAP_SEALED *pSealed,
                                  _Out_ WELDAP_REPLY *pReply);

// Same, with the pipe name and deadline as parameters (for tests).
WELDAP_CLIENT_STATUS WeldapAuthenticateEx(_In_ PCWSTR pwzPipeName, DWORD dwDeadlineMs, bool fUnlock,
                                    _In_ PCWSTR pwzUun, _In_ const WELDAP_SEALED *pSealed,
                                    _Out_ WELDAP_REPLY *pReply);
