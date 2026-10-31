// WELDAP: pipe client for the credential provider. See WeldapClient.h and
// src/Weldap.Shared/PROTOCOL.md (the contract this file implements).

#include "WeldapClient.h"
#include <aclapi.h>
#include <sddl.h>
#include <wchar.h>
#include <strsafe.h>

#pragma comment(lib, "advapi32.lib")

// ---------------------------------------------------------------------------------------------
// UUN normalisation
// ---------------------------------------------------------------------------------------------

// The set .NET's char.IsWhiteSpace / string.Trim() uses, so both ends trim identically.
static bool IsTrimSpace(wchar_t c)
{
    return (c >= 0x0009 && c <= 0x000D) || c == 0x0020 || c == 0x0085 || c == 0x00A0 ||
           c == 0x1680 || (c >= 0x2000 && c <= 0x200A) || c == 0x2028 || c == 0x2029 ||
           c == 0x202F || c == 0x205F || c == 0x3000;
}

HRESULT WeldapNormalizeUun(_In_opt_ PCWSTR pwzIn, _Out_writes_(cchOut) PWSTR pwzOut, size_t cchOut)
{
    if (pwzOut == nullptr || cchOut == 0)
    {
        return E_INVALIDARG;
    }
    pwzOut[0] = L'\0';
    if (pwzIn == nullptr)
    {
        return E_INVALIDARG;
    }

    size_t cchIn = wcsnlen(pwzIn, 4096);
    size_t first = 0;
    while (first < cchIn && IsTrimSpace(pwzIn[first]))
    {
        first++;
    }
    size_t last = cchIn;
    while (last > first && IsTrimSpace(pwzIn[last - 1]))
    {
        last--;
    }
    size_t cch = last - first;
    if (cch == 0 || cch > WELDAP_MAX_UUN_CHARS || cch + 1 > cchOut)
    {
        return E_INVALIDARG;
    }
    // Built in a local buffer first (bounded by WELDAP_MAX_UUN_CHARS, which /analyze can prove), then copied:
    // pwzOut holds either the whole result or "".
    wchar_t wzUun[WELDAP_MAX_UUN_CHARS + 1];
    for (size_t i = 0; i < cch; i++)
    {
        wchar_t c = pwzIn[first + i];
        if (c >= L'A' && c <= L'Z')
        {
            c = static_cast<wchar_t>(c - L'A' + L'a');
        }
        if (!((c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9')))
        {
            return E_INVALIDARG;   // pwzOut[0] is already L'\0'
        }
        wzUun[i] = c;
    }
    wzUun[cch] = L'\0';
    return SUCCEEDED(StringCchCopyW(pwzOut, cchOut, wzUun)) ? S_OK : E_INVALIDARG;
}

// ---------------------------------------------------------------------------------------------
// Binary codec (PROTOCOL.md): little-endian, fixed field order, nothing optional.
// ---------------------------------------------------------------------------------------------

size_t WeldapEncodeRequest(bool fUnlock, _In_ PCWSTR pwzUun, _In_ const WELDAP_SEALED *pSealed,
                           _Out_writes_bytes_(cbOut) BYTE *pbOut, size_t cbOut)
{
    if (pwzUun == nullptr || pSealed == nullptr || pbOut == nullptr)
    {
        if (pbOut != nullptr)
        {
            SecureZeroMemory(pbOut, cbOut);   // on any failure the output is all zero
        }
        return 0;
    }
    size_t cchUun = wcsnlen(pwzUun, WELDAP_MAX_UUN_CHARS + 1);
    size_t cchKid = strnlen(pSealed->szKid, WELDAP_MAX_KID_CHARS + 1);
    ULONG cbCt = pSealed->cbCt;
    // Exactly the service's rules (Protocol.cs TryParseRequest): never send what it would drop.
    bool fKidOk = cchKid != 0 && cchKid <= WELDAP_MAX_KID_CHARS;
    for (size_t i = 0; fKidOk && i < cchKid; i++)
    {
        char c = pSealed->szKid[i];
        fKidOk = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
    }
    if (cchUun == 0 || cchUun > WELDAP_MAX_UUN_CHARS || !fKidOk || pSealed->rgbEnc[0] != 0x04 ||
        cbCt <= WELDAP_HPKE_TAG_BYTES || cbCt > sizeof(pSealed->rgbCt) || pSealed->ts == 0 ||
        pSealed->ts > 0x7FFFFFFFFFFFFFFFULL)
    {
        SecureZeroMemory(pbOut, cbOut);
        return 0;
    }
    size_t cb = 3 + cchUun + 1 + cchKid + WELDAP_HPKE_ENC_BYTES + 2 + cbCt + 8 + WELDAP_RID_BYTES + WELDAP_VERIFIER_BYTES;
    if (cb > cbOut)
    {
        SecureZeroMemory(pbOut, cbOut);
        return 0;
    }
    BYTE *p = pbOut;
    *p++ = WELDAP_PROTOCOL_VERSION;
    *p++ = fUnlock ? 1 : 0;
    *p++ = static_cast<BYTE>(cchUun);
    for (size_t i = 0; i < cchUun; i++)
    {
        if (pwzUun[i] < 0x21 || pwzUun[i] > 0x7E)
        {
            SecureZeroMemory(pbOut, cbOut);
            return 0;
        }
        *p++ = static_cast<BYTE>(pwzUun[i]);
    }
    *p++ = static_cast<BYTE>(cchKid);
    memcpy(p, pSealed->szKid, cchKid);                        p += cchKid;
    memcpy(p, pSealed->rgbEnc, WELDAP_HPKE_ENC_BYTES);        p += WELDAP_HPKE_ENC_BYTES;
    *p++ = static_cast<BYTE>(cbCt);
    *p++ = static_cast<BYTE>(cbCt >> 8);
    memcpy(p, pSealed->rgbCt, cbCt);                          p += cbCt;
    for (int i = 0; i < 8; i++)
    {
        *p++ = static_cast<BYTE>(pSealed->ts >> (8 * i));
    }
    memcpy(p, pSealed->rgbRid, WELDAP_RID_BYTES);             p += WELDAP_RID_BYTES;
    memcpy(p, pSealed->rgbVerifier, WELDAP_VERIFIER_BYTES);   p += WELDAP_VERIFIER_BYTES;
    return static_cast<size_t>(p - pbOut);
}

// Reply: version(1)=3 result(1) mode(1) msgLen(1) message(UTF-16LE, msgLen units) pwLen(1) password(ASCII).
// Exactly that many bytes; ok needs a password of 1..64 printable ASCII, deny/error must have none and mode 0.
bool WeldapParseReply(_In_reads_bytes_(cb) const BYTE *pb, size_t cb, _Out_ WELDAP_REPLY *pReply)
{
    ZeroMemory(pReply, sizeof(*pReply));
    pReply->result = WELDAP_RESULT_VALUE_ERROR;
    if (pb == nullptr || cb < 5 || cb > WELDAP_MAX_MESSAGE_BYTES || pb[0] != WELDAP_PROTOCOL_VERSION ||
        pb[1] > WELDAP_RESULT_ERROR || pb[2] > 1 || pb[3] > WELDAP_MAX_REPLY_MESSAGE_CHARS)
    {
        return false;
    }
    bool fOk = pb[1] == WELDAP_RESULT_OK;
    size_t cchMessage = pb[3];
    size_t at = 4 + 2 * cchMessage;   // pwLen
    if (cb <= at)
    {
        return false;
    }
    // C6385 false positive: cb > at is checked just above (so pb[at] is in bounds), but the analyzer does not
    // carry that symbolic bound from the branch to this read.
#pragma warning(suppress: 6385)
    size_t cchPassword = pb[at];
    at++;
    if (at + cchPassword != cb || (fOk ? (cchPassword == 0 || cchPassword > WELDAP_MAX_LOCAL_PASSWORD_CHARS)
                                       : (cchPassword != 0 || pb[2] != 0)))
    {
        return false;
    }
    // (The second bound is implied by the length checks above; spelled out so /analyze can prove the reads.)
    for (size_t i = 0; i < cchMessage && 5 + 2 * i < cb; i++)
    {
        pReply->message[i] = static_cast<wchar_t>(pb[4 + 2 * i] | (pb[5 + 2 * i] << 8));
    }
    for (size_t i = 0; i < cchPassword && at + i < cb; i++)
    {
        BYTE c = pb[at + i];
        if (c < 0x21 || c > 0x7E)
        {
            SecureZeroMemory(pReply, sizeof(*pReply));
            pReply->result = WELDAP_RESULT_VALUE_ERROR;
            return false;
        }
        pReply->password[i] = c;
    }
    pReply->result = static_cast<WELDAP_RESULT>(pb[1]);
    pReply->fOffline = pb[2] == 1;
    return true;
}

// ---------------------------------------------------------------------------------------------
// Pipe exchange
// ---------------------------------------------------------------------------------------------

namespace
{
// If the pipe does not exist at all (service stopped), keep retrying only this long: a running
// service re-creates its listening instance within milliseconds. Always bounded by the deadline.
const DWORD c_dwNotFoundGraceMs = 3000;

DWORD Remaining(ULONGLONG ullDeadline)
{
    ULONGLONG now = GetTickCount64();
    return now >= ullDeadline ? 0 : static_cast<DWORD>(ullDeadline - now);
}

enum IO_RESULT { IO_OK, IO_FAILED, IO_TIMEOUT };

IO_RESULT OverlappedIo(HANDLE hPipe, HANDLE hEvent, bool fWrite, BYTE *pb, DWORD cb,
                       ULONGLONG ullDeadline, DWORD *pcbDone)
{
    *pcbDone = 0;
    OVERLAPPED ov = {};
    ov.hEvent = hEvent;
    BOOL fOk = fWrite ? WriteFile(hPipe, pb, cb, nullptr, &ov) : ReadFile(hPipe, pb, cb, nullptr, &ov);
    if (!fOk && GetLastError() != ERROR_IO_PENDING)
    {
        return IO_FAILED;
    }
    if (WaitForSingleObject(hEvent, Remaining(ullDeadline)) != WAIT_OBJECT_0)
    {
        // Deadline: cancel and wait for the cancellation to land (ov is on our stack).
        CancelIoEx(hPipe, &ov);
        DWORD cbIgnored;
        GetOverlappedResult(hPipe, &ov, &cbIgnored, TRUE);
        return IO_TIMEOUT;
    }
    if (!GetOverlappedResult(hPipe, &ov, pcbDone, FALSE))
    {
        return IO_FAILED;
    }
    return IO_OK;
}

IO_RESULT TransferAll(HANDLE hPipe, HANDLE hEvent, bool fWrite, BYTE *pb, DWORD cb, ULONGLONG ullDeadline)
{
    DWORD cbTotal = 0;
    while (cbTotal < cb)
    {
        DWORD cbDone;
        IO_RESULT io = OverlappedIo(hPipe, hEvent, fWrite, pb + cbTotal, cb - cbTotal, ullDeadline, &cbDone);
        if (io != IO_OK)
        {
            return io;
        }
        if (cbDone == 0)
        {
            return IO_FAILED;   // peer closed
        }
        cbTotal += cbDone;
    }
    return IO_OK;
}

// PROTOCOL.md: before sending, the pipe server must be SYSTEM. Two checks, both must pass:
//  - the pipe object's owner is S-1-5-18. Only SYSTEM can create a pipe owned by SYSTEM (an
//    elevated admin's objects are owned by Administrators), and this can't go stale;
//  - the server process's token user is S-1-5-18. The server PID alone could be reused if a
//    squatter created the pipe and exited, hence the owner check above.
bool IsPipeServerSystem(HANDLE hPipe)
{
    PSID psidRequired = nullptr;
    if (!ConvertStringSidToSidW(WELDAP_REQUIRED_PEER_SID, &psidRequired))
    {
        return false;
    }

    bool fOwner = false;
    PSID psidOwner = nullptr;
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (GetSecurityInfo(hPipe, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION,
                        &psidOwner, nullptr, nullptr, nullptr, &psd) == ERROR_SUCCESS)
    {
        fOwner = psidOwner != nullptr && IsValidSid(psidOwner) && EqualSid(psidOwner, psidRequired);
        LocalFree(psd);
    }

    bool fProcess = false;
    ULONG pid = 0;
    if (fOwner && GetNamedPipeServerProcessId(hPipe, &pid) && pid != 0)
    {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess != nullptr)
        {
            HANDLE hToken;
            if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
            {
                union
                {
                    TOKEN_USER tu;
                    BYTE rgb[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
                } user;
                DWORD cb;
                if (GetTokenInformation(hToken, TokenUser, &user, sizeof(user), &cb))
                {
                    fProcess = IsValidSid(user.tu.User.Sid) && EqualSid(user.tu.User.Sid, psidRequired);
                }
                CloseHandle(hToken);
            }
            CloseHandle(hProcess);
        }
    }
    LocalFree(psidRequired);
    return fOwner && fProcess;
}

HANDLE ConnectPipe(PCWSTR pwzPipeName, ULONGLONG ullDeadline)
{
    ULONGLONG ullNotFoundUntil = GetTickCount64() + c_dwNotFoundGraceMs;
    for (;;)
    {
        // SECURITY_IDENTIFICATION: the server may identify, but never impersonate, LogonUI.
        HANDLE hPipe = CreateFileW(pwzPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                   FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                                   nullptr);
        if (hPipe != INVALID_HANDLE_VALUE)
        {
            return hPipe;
        }
        DWORD dwErr = GetLastError();
        DWORD dwLeft = Remaining(ullDeadline);
        if (dwLeft == 0)
        {
            return INVALID_HANDLE_VALUE;
        }
        if (dwErr == ERROR_PIPE_BUSY)
        {
            // Never pass 0 (= NMPWAIT_USE_DEFAULT_WAIT).
            WaitNamedPipeW(pwzPipeName, min(dwLeft, 1000ul));
        }
        else if (dwErr == ERROR_FILE_NOT_FOUND)
        {
            if (GetTickCount64() >= ullNotFoundUntil)
            {
                return INVALID_HANDLE_VALUE;
            }
            Sleep(min(dwLeft, 100ul));
        }
        else
        {
            return INVALID_HANDLE_VALUE;   // e.g. access denied: not our service
        }
    }
}

// Map a non-OK transfer result to a client status. Written once so the IO failure sites in Exchange cannot
// drift apart (a timeout stays a timeout; anything else is a generic protocol error).
WELDAP_CLIENT_STATUS IoToStatus(IO_RESULT io)
{
    return (io == IO_TIMEOUT) ? WELDAP_STATUS_TIMEOUT : WELDAP_STATUS_PROTOCOL_ERROR;
}

// The request/reply exchange over an already-connected, SYSTEM-verified pipe. rgbFrame carries the framed
// request in (4-byte length prefix + body) and is reused for the reply body; it is wiped once the request is
// on the wire. Taken as an array reference so /analyze keeps the exact buffer bound. Flat early-return control
// flow, in place of the former four-deep nest in WeldapAuthenticateEx.
WELDAP_CLIENT_STATUS Exchange(HANDLE hPipe, HANDLE hEvent, BYTE (&rgbFrame)[4 + WELDAP_MAX_MESSAGE_BYTES],
                              size_t cbBody, ULONGLONG ullDeadline, WELDAP_REPLY *pReply)
{
    IO_RESULT io = TransferAll(hPipe, hEvent, true, rgbFrame, static_cast<DWORD>(4 + cbBody), ullDeadline);
    SecureZeroMemory(rgbFrame, sizeof(rgbFrame));
    if (io != IO_OK)
    {
        return IoToStatus(io);
    }
    BYTE rgbLen[4];
    io = TransferAll(hPipe, hEvent, false, rgbLen, sizeof(rgbLen), ullDeadline);
    if (io != IO_OK)
    {
        return IoToStatus(io);
    }
    DWORD cbReply = rgbLen[0] | (rgbLen[1] << 8) | (rgbLen[2] << 16) | (static_cast<DWORD>(rgbLen[3]) << 24);
    if (cbReply < 1 || cbReply > WELDAP_MAX_MESSAGE_BYTES)
    {
        return WELDAP_STATUS_PROTOCOL_ERROR;
    }
    io = TransferAll(hPipe, hEvent, false, rgbFrame, cbReply, ullDeadline);
    if (io != IO_OK)
    {
        return IoToStatus(io);
    }
    return WeldapParseReply(rgbFrame, cbReply, pReply) ? WELDAP_STATUS_REPLIED : WELDAP_STATUS_PROTOCOL_ERROR;
}
} // namespace

WELDAP_CLIENT_STATUS WeldapAuthenticateEx(_In_ PCWSTR pwzPipeName, DWORD dwDeadlineMs, bool fUnlock,
                                    _In_ PCWSTR pwzUun, _In_ const WELDAP_SEALED *pSealed,
                                    _Out_ WELDAP_REPLY *pReply)
{
    ZeroMemory(pReply, sizeof(*pReply));
    pReply->result = WELDAP_RESULT_VALUE_ERROR;
    ULONGLONG ullDeadline = GetTickCount64() + dwDeadlineMs;

    // Frame = 4-byte little-endian length + the binary request (sealed password and offline verifier), then
    // reused for the reply (with the local password). Zeroed on every path.
    BYTE rgbFrame[4 + WELDAP_MAX_MESSAGE_BYTES];
    size_t cbBody = WeldapEncodeRequest(fUnlock, pwzUun, pSealed, rgbFrame + 4, WELDAP_MAX_MESSAGE_BYTES);
    if (cbBody == 0)
    {
        SecureZeroMemory(rgbFrame, sizeof(rgbFrame));
        return WELDAP_STATUS_BAD_REQUEST;
    }
    rgbFrame[0] = static_cast<BYTE>(cbBody);
    rgbFrame[1] = static_cast<BYTE>(cbBody >> 8);
    rgbFrame[2] = static_cast<BYTE>(cbBody >> 16);
    rgbFrame[3] = static_cast<BYTE>(cbBody >> 24);

    WELDAP_CLIENT_STATUS status;
    HANDLE hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE hPipe = (hEvent != nullptr) ? ConnectPipe(pwzPipeName, ullDeadline) : INVALID_HANDLE_VALUE;
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        status = WELDAP_STATUS_SERVICE_UNAVAILABLE;
    }
    else if (!IsPipeServerSystem(hPipe))
    {
        status = WELDAP_STATUS_UNTRUSTED_SERVER;   // nothing has been written
    }
    else
    {
        status = Exchange(hPipe, hEvent, rgbFrame, cbBody, ullDeadline, pReply);
    }

    SecureZeroMemory(rgbFrame, sizeof(rgbFrame));
    if (hPipe != INVALID_HANDLE_VALUE && hPipe != nullptr)
    {
        CloseHandle(hPipe);
    }
    if (hEvent != nullptr)
    {
        CloseHandle(hEvent);
    }
    if (status != WELDAP_STATUS_REPLIED)
    {
        SecureZeroMemory(pReply, sizeof(*pReply));
        pReply->result = WELDAP_RESULT_VALUE_ERROR;
    }
    return status;
}

WELDAP_CLIENT_STATUS WeldapAuthenticate(bool fUnlock, _In_ PCWSTR pwzUun, _In_ const WELDAP_SEALED *pSealed,
                                  _Out_ WELDAP_REPLY *pReply)
{
    return WeldapAuthenticateEx(WELDAP_PIPE_NAME, WELDAP_CLIENT_DEADLINE_MS, fUnlock, pwzUun, pSealed, pReply);
}
