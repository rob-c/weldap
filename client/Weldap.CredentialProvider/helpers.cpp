//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// Derived from the Microsoft Windows-classic-samples CredentialProvider V2 sample
// (https://github.com/microsoft/Windows-classic-samples, MIT License; full text in
// THIRD-PARTY-NOTICES.txt). Modified for WELDAP: unused helpers removed, password
// copies zeroed before they are freed.
//
// Helper functions for copying parameters and packaging the buffer
// for GetSerialization.


#include "helpers.h"
#include <intsafe.h>

//
// Copies the field descriptor pointed to by rcpfd into a buffer allocated
// using CoTaskMemAlloc. Returns that buffer in ppcpfd.
//
HRESULT FieldDescriptorCoAllocCopy(
    _In_ const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR &rcpfd,
    _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd
    )
{
    HRESULT hr;
    *ppcpfd = nullptr;
    DWORD cbStruct = sizeof(**ppcpfd);

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR *pcpfd = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(cbStruct);
    if (pcpfd)
    {
        pcpfd->dwFieldID = rcpfd.dwFieldID;
        pcpfd->cpft = rcpfd.cpft;
        pcpfd->guidFieldType = rcpfd.guidFieldType;

        if (rcpfd.pszLabel)
        {
            hr = SHStrDupW(rcpfd.pszLabel, &pcpfd->pszLabel);
        }
        else
        {
            pcpfd->pszLabel = nullptr;
            hr = S_OK;
        }
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    if (SUCCEEDED(hr))
    {
        *ppcpfd = pcpfd;
    }
    else
    {
        CoTaskMemFree(pcpfd);   
    }

    return hr;
}

//
// Copies rcpfd into the buffer pointed to by pcpfd. The caller is responsible for
// allocating pcpfd. This function uses CoTaskMemAlloc to allocate memory for
// pcpfd->pszLabel.
//
HRESULT FieldDescriptorCopy(
    _In_ const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR &rcpfd,
    _Out_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR *pcpfd
    )
{
    HRESULT hr;
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR cpfd;

    cpfd.dwFieldID = rcpfd.dwFieldID;
    cpfd.cpft = rcpfd.cpft;
    cpfd.guidFieldType = rcpfd.guidFieldType;

    if (rcpfd.pszLabel)
    {
        hr = SHStrDupW(rcpfd.pszLabel, &cpfd.pszLabel);
    }
    else
    {
        cpfd.pszLabel = nullptr;
        hr = S_OK;
    }

    if (SUCCEEDED(hr))
    {
        *pcpfd = cpfd;
    }

    return hr;
}

//
// This function copies the length of pwz and the pointer pwz into the UNICODE_STRING structure
// This function is intended for serializing a credential in GetSerialization only.
// Note that this function just makes a copy of the string pointer. It DOES NOT ALLOCATE storage!
// Be very, very sure that this is what you want, because it probably isn't outside of the
// exact GetSerialization call where the sample uses it.
//
HRESULT UnicodeStringInitWithString(
    _In_ PWSTR pwz,
    _Out_ UNICODE_STRING *pus
    )
{
    HRESULT hr;
    if (pwz)
    {
        size_t lenString = wcslen(pwz);
        USHORT usCharCount;
        hr = SizeTToUShort(lenString, &usCharCount);
        if (SUCCEEDED(hr))
        {
            USHORT usSize;
            hr = SizeTToUShort(sizeof(wchar_t), &usSize);
            if (SUCCEEDED(hr))
            {
                hr = UShortMult(usCharCount, usSize, &(pus->Length)); // Explicitly NOT including NULL terminator
                if (SUCCEEDED(hr))
                {
                    pus->MaximumLength = pus->Length;
                    pus->Buffer = pwz;
                    hr = S_OK;
                }
                else
                {
                    hr = HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);
                }
            }
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

//
// The following function is intended to be used ONLY with the Kerb*Pack functions.  It does
// no bounds-checking because its callers have precise requirements and are written to respect
// its limitations.
// You can read more about the UNICODE_STRING type at:
// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/secauthn/security/unicode_string.asp
//
static void _UnicodeStringPackedUnicodeStringCopy(
    __in const UNICODE_STRING& rus,
    __in PWSTR pwzBuffer,
    __out UNICODE_STRING *pus
    )
{
    pus->Length = rus.Length;
    pus->MaximumLength = rus.Length;
    pus->Buffer = pwzBuffer;

    CopyMemory(pus->Buffer, rus.Buffer, pus->Length);
}

//
// Initialize the members of a KERB_INTERACTIVE_UNLOCK_LOGON with weak references to the
// passed-in strings.  This is useful if you will later use KerbInteractiveUnlockLogonPack
// to serialize the structure.
//
// The password arrives already in CredProtect-encrypted form (see ProtectAndCopyPassword);
// the system accepts encrypted credentials for CPUS_LOGON and CPUS_UNLOCK_WORKSTATION, the only two
// scenarios this provider serves.
//
HRESULT KerbInteractiveUnlockLogonInit(
    _In_ PWSTR pwzDomain,
    _In_ PWSTR pwzUsername,
    _In_ PWSTR pwzPassword,
    _In_ CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _Out_ KERB_INTERACTIVE_UNLOCK_LOGON *pkiul
    )
{
    KERB_INTERACTIVE_UNLOCK_LOGON kiul;
    ZeroMemory(&kiul, sizeof(kiul));

    KERB_INTERACTIVE_LOGON *pkil = &kiul.Logon;

    // Note: this method uses custom logic to pack a KERB_INTERACTIVE_UNLOCK_LOGON with a
    // serialized credential.  We could replace the calls to UnicodeStringInitWithString
    // and KerbInteractiveUnlockLogonPack with a single call to CredPackAuthenticationBuffer,
    // but that API has a drawback: it returns a KERB_INTERACTIVE_UNLOCK_LOGON whose
    // MessageType is always KerbInteractiveLogon.
    //
    // If we only handled CPUS_LOGON, this drawback would not be a problem.  For
    // CPUS_UNLOCK_WORKSTATION, we could cast the output buffer of CredPackAuthenticationBuffer
    // to KERB_INTERACTIVE_UNLOCK_LOGON and modify the MessageType to KerbWorkstationUnlockLogon,
    // but such a cast would be unsupported -- the output format of CredPackAuthenticationBuffer
    // is not officially documented.

    // Initialize the UNICODE_STRINGS to share our username and password strings.
    HRESULT hr = UnicodeStringInitWithString(pwzDomain, &pkil->LogonDomainName);
    if (SUCCEEDED(hr))
    {
        hr = UnicodeStringInitWithString(pwzUsername, &pkil->UserName);
        if (SUCCEEDED(hr))
        {
            hr = UnicodeStringInitWithString(pwzPassword, &pkil->Password);
            if (SUCCEEDED(hr))
            {
                // Set a MessageType based on the usage scenario.
                switch (cpus)
                {
                case CPUS_UNLOCK_WORKSTATION:
                    pkil->MessageType = KerbWorkstationUnlockLogon;
                    hr = S_OK;
                    break;

                case CPUS_LOGON:
                    pkil->MessageType = KerbInteractiveLogon;
                    hr = S_OK;
                    break;

                // WELDAP: only logon and unlock reach this provider -- SetUsageScenario rejects every other
                // scenario (CredUI included) -- so anything else here is a programming error.
                default:
                    hr = E_FAIL;
                    break;
                }

                if (SUCCEEDED(hr))
                {
                    // KERB_INTERACTIVE_UNLOCK_LOGON is just a series of structures.  A
                    // flat copy will properly initialize the output parameter.
                    CopyMemory(pkiul, &kiul, sizeof(*pkiul));
                }
            }
        }
    }

    return hr;
}

//
// WinLogon and LSA consume "packed" KERB_INTERACTIVE_UNLOCK_LOGONs.  In these, the PWSTR members of each
// UNICODE_STRING are not actually pointers but byte offsets into the overall buffer represented
// by the packed KERB_INTERACTIVE_UNLOCK_LOGON.  For example:
//
// rkiulIn.Logon.LogonDomainName.Length = 14                                    -> Length is in bytes, not characters
// rkiulIn.Logon.LogonDomainName.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) -> LogonDomainName begins immediately
//                                                                              after the KERB_... struct in the buffer
// rkiulIn.Logon.UserName.Length = 10
// rkiulIn.Logon.UserName.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 14   -> UNICODE_STRINGS are NOT null-terminated
//
// rkiulIn.Logon.Password.Length = 16
// rkiulIn.Logon.Password.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 14 + 10
//
// There's more information on this at:
// http://msdn.microsoft.com/msdnmag/issues/05/06/SecurityBriefs/#void
//

HRESULT KerbInteractiveUnlockLogonPack(
    _In_ const KERB_INTERACTIVE_UNLOCK_LOGON &rkiulIn,
    _Outptr_result_bytebuffer_(*pcb) BYTE **prgb,
    _Out_ DWORD *pcb
    )
{
    HRESULT hr;

    const KERB_INTERACTIVE_LOGON *pkilIn = &rkiulIn.Logon;

    // alloc space for struct plus extra for the three strings
    DWORD cb = sizeof(rkiulIn) +
        pkilIn->LogonDomainName.Length +
        pkilIn->UserName.Length +
        pkilIn->Password.Length;

    KERB_INTERACTIVE_UNLOCK_LOGON *pkiulOut = (KERB_INTERACTIVE_UNLOCK_LOGON*)CoTaskMemAlloc(cb);
    if (pkiulOut)
    {
        // All of it, header padding included: LSA gets no stale bytes from LogonUI's heap (the strings below then
        // fill everything after the header).
        ZeroMemory(pkiulOut, cb);

        //
        // point pbBuffer at the beginning of the extra space
        //
        BYTE *pbBuffer = (BYTE*)pkiulOut + sizeof(*pkiulOut);

        //
        // set up the Logon structure within the KERB_INTERACTIVE_UNLOCK_LOGON
        //
        KERB_INTERACTIVE_LOGON *pkilOut = &pkiulOut->Logon;

        pkilOut->MessageType = pkilIn->MessageType;

        //
        // copy each string,
        // fix up appropriate buffer pointer to be offset,
        // advance buffer pointer over copied characters in extra space
        //
        _UnicodeStringPackedUnicodeStringCopy(pkilIn->LogonDomainName, (PWSTR)pbBuffer, &pkilOut->LogonDomainName);
        pkilOut->LogonDomainName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->LogonDomainName.Length;

        _UnicodeStringPackedUnicodeStringCopy(pkilIn->UserName, (PWSTR)pbBuffer, &pkilOut->UserName);
        pkilOut->UserName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->UserName.Length;

        _UnicodeStringPackedUnicodeStringCopy(pkilIn->Password, (PWSTR)pbBuffer, &pkilOut->Password);
        pkilOut->Password.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);

        *prgb = (BYTE*)pkiulOut;
        *pcb = cb;

        hr = S_OK;
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}

//
// Retrieves the 'negotiate' AuthPackage from the LSA. In this case, Kerberos
// For more information on auth packages see this msdn page:
// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/secauthn/security/msv1_0_lm20_logon.asp
//
HRESULT RetrieveNegotiateAuthPackage(_Out_ ULONG *pulAuthPackage)
{
    HRESULT hr;
    HANDLE hLsa;

    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (SUCCEEDED(HRESULT_FROM_NT(status)))
    {
        ULONG ulAuthPackage;
        LSA_STRING lsaszKerberosName = { sizeof(NEGOSSP_NAME_A) - 1, sizeof(NEGOSSP_NAME_A), const_cast<PCHAR>(NEGOSSP_NAME_A) };

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszKerberosName, &ulAuthPackage);
        if (SUCCEEDED(HRESULT_FROM_NT(status)))
        {
            *pulAuthPackage = ulAuthPackage;
            hr = S_OK;
        }
        else
        {
            hr = HRESULT_FROM_NT(status);
        }
        LsaDeregisterLogonProcess(hLsa);
    }
    else
    {
        hr = HRESULT_FROM_NT(status);
    }

    return hr;
}

// CredProtect-encrypts the local password into a CoTaskMem string the caller frees with CoTaskMemFreeSecureString.
// The service always supplies 1..64 characters (WeldapParseReply), so there is no empty case; the sample's
// CredUI and already-encrypted (Terminal Services) paths cannot reach this provider and are gone. CredProtectW
// declares its input non-const but only reads it, so the password is passed as it is: no extra plaintext copy.
HRESULT ProtectAndCopyPassword(_In_ PCWSTR pwzPassword, _Outptr_result_nullonfailure_ PWSTR *ppwzProtected)
{
    *ppwzProtected = nullptr;
    PWSTR pwz = const_cast<PWSTR>(pwzPassword);
    DWORD cchIn = static_cast<DWORD>(wcslen(pwz)) + 1;   // CredProtect counts the terminator
    // The first call only sizes the output: with no buffer it must fail with ERROR_INSUFFICIENT_BUFFER.
    DWORD cchProtected = 0;
    if (CredProtectW(FALSE, pwz, cchIn, nullptr, &cchProtected, nullptr))
    {
        return E_UNEXPECTED;
    }
    DWORD dwErr = GetLastError();
    if (dwErr != ERROR_INSUFFICIENT_BUFFER || cchProtected == 0)
    {
        return dwErr != ERROR_SUCCESS ? HRESULT_FROM_WIN32(dwErr) : E_UNEXPECTED;   // never S_OK without output
    }
    const DWORD cbProtected = cchProtected * sizeof(wchar_t);
    PWSTR pwzProtected = static_cast<PWSTR>(CoTaskMemAlloc(cbProtected));
    if (pwzProtected == nullptr)
    {
        return E_OUTOFMEMORY;
    }
    if (!CredProtectW(FALSE, pwz, cchIn, pwzProtected, &cchProtected, nullptr))
    {
        HRESULT hr = HRESULT_FROM_WIN32(GetLastError());
        SecureZeroMemory(pwzProtected, cbProtected);
        CoTaskMemFree(pwzProtected);
        return hr;
    }
    *ppwzProtected = pwzProtected;
    return S_OK;
}

//
// WELDAP: zero a CoTaskMem-allocated string before freeing it (password copies).
//
void CoTaskMemFreeSecureString(_In_opt_ PWSTR pwz)
{
    if (pwz != nullptr)
    {
        SecureZeroMemory(pwz, wcslen(pwz) * sizeof(*pwz));
        CoTaskMemFree(pwz);
    }
}
