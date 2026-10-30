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
// THIRD-PARTY-NOTICES.txt). Modified for WELDAP.
//

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include "WeldapCredential.h"
#include "WeldapClient.h"
#include "WeldapSeal.h"
#include "guid.h"

// Fixed short user-facing texts (the service's own message is preferred when it sends one).
static const wchar_t c_wzServiceUnavailable[] = L"Login service not available.";
static const wchar_t c_wzEnterUun[]           = L"Enter your username (letters and digits only).";
static const wchar_t c_wzEnterPassword[]      = L"Enter your password.";
static const wchar_t c_wzPasswordTooLong[]    = L"The password is too long.";
static const wchar_t c_wzBadCharacters[]      = L"The password contains characters that cannot be used.";
static const wchar_t c_wzDenied[]             = L"Sign-in was refused.";
static const wchar_t c_wzServiceError[]       = L"The login service reported an error.";
static const wchar_t c_wzInternalError[]      = L"Sign-in failed. Please try again.";
static const wchar_t c_wzNotConfigured[]      = L"This PC isn't set up for WELDAP sign-in. Contact IT.";

CWeldapCredential::CWeldapCredential():
    _cRef(1),
    _cpus(CPUS_INVALID),
    _pCredProvCredentialEvents(nullptr)
{
    DllAddRef();

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

CWeldapCredential::~CWeldapCredential()
{
    CoTaskMemFreeSecureString(_rgFieldStrings[PFI_PASSWORD]);
    _rgFieldStrings[PFI_PASSWORD] = nullptr;
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
        _pCredProvCredentialEvents = nullptr;
    }
    DllRelease();
}

// Deployment branding: HKLM\SOFTWARE\WELDAP\TileLabel (REG_SZ, up to 64 characters), written by the
// MSI. Only read here; missing, too long or empty falls back to the default.
static void GetTileLabel(_Out_writes_(cch) PWSTR pwz, size_t cch)
{
    StringCchCopyW(pwz, cch, L"WELDAP sign-in");
    wchar_t wz[65];
    DWORD cb = sizeof(wz);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WELDAP", L"TileLabel", RRF_RT_REG_SZ, nullptr, wz, &cb) == ERROR_SUCCESS
        && wz[0] != L'\0')
    {
        for (wchar_t *p = wz; *p != L'\0'; p++)
        {
            if (*p < 0x20 || *p == 0x7F)
            {
                *p = L' ';
            }
        }
        StringCchCopyW(pwz, cch, wz);
    }
}

// Initializes one credential with the field information passed in.
HRESULT CWeldapCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                   _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
                                   _In_ FIELD_STATE_PAIR const *rgfsp)
{
    HRESULT hr = S_OK;
    _cpus = cpus;

    // Copy the field descriptors for each field.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // Initialize the String value of all the fields.
    if (SUCCEEDED(hr))
    {
        wchar_t wzLabel[65];
        GetTileLabel(wzLabel, ARRAYSIZE(wzLabel));
        hr = SHStrDupW(wzLabel, &_rgFieldStrings[PFI_LABEL]);
        if (SUCCEEDED(hr))
        {
            hr = SHStrDupW(wzLabel, &_rgFieldStrings[PFI_LARGE_TEXT]);
        }
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[PFI_UUN]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[PFI_PASSWORD]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[PFI_SUBMIT_BUTTON]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[PFI_STATUS_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[PFI_TILEIMAGE]);
    }

    return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CWeldapCredential::Advise(_In_ ICredentialProviderCredentialEvents *pcpce)
{
    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
        _pCredProvCredentialEvents = nullptr;
    }
    if (pcpce == nullptr)
    {
        return E_INVALIDARG;
    }
    _pCredProvCredentialEvents = pcpce;
    _pCredProvCredentialEvents->AddRef();
    return S_OK;
}

// LogonUI calls this to tell us to release the callback.
HRESULT CWeldapCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

HRESULT CWeldapCredential::SetSelected(_Out_ BOOL *pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    return S_OK;
}

// The tile is no longer selected: wipe the password.
HRESULT CWeldapCredential::SetDeselected()
{
    _ClearPassword();
    return S_OK;
}

// Zeroes the stored password, replaces it with "" and tells LogonUI to clear the field.
void CWeldapCredential::_ClearPassword()
{
    CoTaskMemFreeSecureString(_rgFieldStrings[PFI_PASSWORD]);
    _rgFieldStrings[PFI_PASSWORD] = nullptr;
    if (SUCCEEDED(SHStrDupW(L"", &_rgFieldStrings[PFI_PASSWORD])) && _pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->SetFieldString(this, PFI_PASSWORD, _rgFieldStrings[PFI_PASSWORD]);
    }
}

void CWeldapCredential::_SetStatusText(_In_ PCWSTR pwz)
{
    PWSTR pwzCopy;
    if (SUCCEEDED(SHStrDupW(pwz, &pwzCopy)))
    {
        CoTaskMemFree(_rgFieldStrings[PFI_STATUS_TEXT]);
        _rgFieldStrings[PFI_STATUS_TEXT] = pwzCopy;
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, PFI_STATUS_TEXT, pwzCopy);
        }
    }
}

// Get info for a particular field of a tile.
HRESULT CWeldapCredential::GetFieldState(DWORD dwFieldID,
                                      _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
                                      _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis)
{
    HRESULT hr;

    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)))
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID
HRESULT CWeldapCredential::GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz)
{
    HRESULT hr;
    *ppwsz = nullptr;

    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && _rgFieldStrings[dwFieldID] != nullptr)
    {
        // Make a copy of the string and return that. The caller is responsible for freeing it.
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Get the image to show in the user tile
HRESULT CWeldapCredential::GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp)
{
    HRESULT hr;
    *phbmp = nullptr;

    if ((PFI_TILEIMAGE == dwFieldID))
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        if (hbmp != nullptr)
        {
            hr = S_OK;
            *phbmp = hbmp;
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// The submit button sits next to the password field.
HRESULT CWeldapCredential::GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo)
{
    HRESULT hr;

    if (PFI_SUBMIT_BUTTON == dwFieldID)
    {
        *pdwAdjacentTo = PFI_PASSWORD;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Called on each keystroke when a user types into an edit field.
HRESULT CWeldapCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
    HRESULT hr;

    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
        CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        PWSTR *ppwszStored = &_rgFieldStrings[dwFieldID];
        if (dwFieldID == PFI_PASSWORD)
        {
            CoTaskMemFreeSecureString(*ppwszStored);
        }
        else
        {
            CoTaskMemFree(*ppwszStored);
        }
        *ppwszStored = nullptr;
        hr = SHStrDupW(pwz != nullptr ? pwz : L"", ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// No checkboxes, combo boxes or command links on this tile.
HRESULT CWeldapCredential::GetCheckboxValue(DWORD /*dwFieldID*/, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel)
{
    *pbChecked = FALSE;
    *ppwszLabel = nullptr;
    return E_NOTIMPL;
}

HRESULT CWeldapCredential::SetCheckboxValue(DWORD /*dwFieldID*/, BOOL /*bChecked*/)
{
    return E_NOTIMPL;
}

HRESULT CWeldapCredential::GetComboBoxValueCount(DWORD /*dwFieldID*/, _Out_ DWORD *pcItems, _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem)
{
    *pcItems = 0;
    *pdwSelectedItem = 0;
    return E_NOTIMPL;
}

HRESULT CWeldapCredential::GetComboBoxValueAt(DWORD /*dwFieldID*/, DWORD /*dwItem*/, _Outptr_result_nullonfailure_ PWSTR *ppwszItem)
{
    *ppwszItem = nullptr;
    return E_NOTIMPL;
}

HRESULT CWeldapCredential::SetComboBoxSelectedValue(DWORD /*dwFieldID*/, DWORD /*dwSelectedItem*/)
{
    return E_NOTIMPL;
}

HRESULT CWeldapCredential::CommandLinkClicked(DWORD /*dwFieldID*/)
{
    return E_NOTIMPL;
}

// Packs a local logon for <computer name>\<uun> with the account's random local password from the service
// (KERB_INTERACTIVE_UNLOCK_LOGON for the Negotiate package): LSASS never sees the user's real password.
// Every temporary copy is zeroed before it is freed.
HRESULT CWeldapCredential::_BuildSerialization(_In_ PCWSTR pwzUun, _In_ PCWSTR pwzLocalPassword,
                                            _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs)
{
    ZeroMemory(pcpcs, sizeof(*pcpcs));

    wchar_t wzComputer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD cchComputer = ARRAYSIZE(wzComputer);
    if (!GetComputerNameW(wzComputer, &cchComputer))
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    wchar_t wzUun[WELDAP_MAX_UUN_CHARS + 1];
    HRESULT hr = StringCchCopyW(wzUun, ARRAYSIZE(wzUun), pwzUun);
    if (FAILED(hr))
    {
        return hr;
    }

    ULONG ulAuthPackage;
    hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
    if (FAILED(hr))
    {
        return hr;
    }

    PWSTR pwzProtectedPassword = nullptr;
    hr = ProtectIfNecessaryAndCopyPassword(pwzLocalPassword, _cpus, &pwzProtectedPassword);
    if (SUCCEEDED(hr))
    {
        // We use KERB_INTERACTIVE_UNLOCK_LOGON in both unlock and logon scenarios. It contains a
        // KERB_INTERACTIVE_LOGON to hold the creds plus a LUID that is filled in for us by Winlogon
        // as necessary.
        KERB_INTERACTIVE_UNLOCK_LOGON kiul;
        hr = KerbInteractiveUnlockLogonInit(wzComputer, wzUun, pwzProtectedPassword, _cpus, &kiul);
        if (SUCCEEDED(hr))
        {
            hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
            if (SUCCEEDED(hr))
            {
                pcpcs->ulAuthenticationPackage = ulAuthPackage;
                pcpcs->clsidCredentialProvider = CLSID_WeldapProvider;
            }
        }
        SecureZeroMemory(&kiul, sizeof(kiul));   // only pointers, but cheap
        CoTaskMemFreeSecureString(pwzProtectedPassword);
    }

    if (FAILED(hr))
    {
        if (pcpcs->rgbSerialization != nullptr)
        {
            SecureZeroMemory(pcpcs->rgbSerialization, pcpcs->cbSerialization);
            CoTaskMemFree(pcpcs->rgbSerialization);
        }
        ZeroMemory(pcpcs, sizeof(*pcpcs));
    }
    return hr;
}

// Copies the service's message for display: control characters become spaces; an empty or
// blank message is replaced by pwzFallback.
static void SanitizeMessage(_In_ PCWSTR pwzMessage, _In_ PCWSTR pwzFallback,
                            _Out_writes_(cchOut) PWSTR pwzOut, size_t cchOut)
{
    bool fAnyVisible = false;
    size_t i = 0;
    for (; pwzMessage[i] != L'\0' && i + 1 < cchOut; i++)
    {
        wchar_t c = pwzMessage[i];
        if (c < 0x20 || c == 0x7F)
        {
            c = L' ';
        }
        if (c != L' ')
        {
            fAnyVisible = true;
        }
        pwzOut[i] = c;
    }
    pwzOut[i] = L'\0';
    if (!fAnyVisible)
    {
        StringCchCopyW(pwzOut, cchOut, pwzFallback);
    }
}

// Checks the UUN + password with the WELDAP Service and, only on "ok" or "offline",
// returns the local logon serialization. Anything else: no serialization, message on the tile.
HRESULT CWeldapCredential::GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
                                         _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
                                         _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                         _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));

    wchar_t wzMessage[WELDAP_MAX_REPLY_MESSAGE_CHARS + 1];
    wzMessage[0] = L'\0';
    bool fSerialized = false;

    wchar_t wzUun[WELDAP_MAX_UUN_CHARS + 1];
    PCWSTR pwzPassword = _rgFieldStrings[PFI_PASSWORD] ? _rgFieldStrings[PFI_PASSWORD] : L"";
    size_t cchPassword = wcsnlen(pwzPassword, WELDAP_MAX_PASSWORD_CHARS + 1);

    if (FAILED(WeldapNormalizeUun(_rgFieldStrings[PFI_UUN], wzUun, ARRAYSIZE(wzUun))))
    {
        StringCchCopyW(wzMessage, ARRAYSIZE(wzMessage), c_wzEnterUun);
    }
    else if (cchPassword == 0)
    {
        StringCchCopyW(wzMessage, ARRAYSIZE(wzMessage), c_wzEnterPassword);
    }
    else if (cchPassword > WELDAP_MAX_PASSWORD_CHARS)
    {
        StringCchCopyW(wzMessage, ARRAYSIZE(wzMessage), c_wzPasswordTooLong);
    }
    else
    {
        // Seal first, then wipe the field: from here on the typed password exists only as ciphertext
        // (for the server) and as the PBKDF2 verifier (for offline sign-in).
        WELDAP_SEALED sealed;
        HRESULT hrSeal = WeldapSealPassword(wzUun, _cpus == CPUS_UNLOCK_WORKSTATION, pwzPassword, &sealed);
        _ClearPassword();
        if (FAILED(hrSeal))
        {
            StringCchCopyW(wzMessage, ARRAYSIZE(wzMessage),
                           hrSeal == WELDAP_E_NOT_CONFIGURED ? c_wzNotConfigured :
                           hrSeal == WELDAP_E_TOO_LONG ? c_wzPasswordTooLong :
                           hrSeal == WELDAP_E_BAD_CHARACTERS ? c_wzBadCharacters : c_wzInternalError);
        }
        else
        {
            WELDAP_REPLY reply;
            WELDAP_CLIENT_STATUS status = WeldapAuthenticate(_cpus == CPUS_UNLOCK_WORKSTATION, wzUun, &sealed, &reply);
            SecureZeroMemory(&sealed, sizeof(sealed));
            if (status == WELDAP_STATUS_REPLIED)
            {
                switch (reply.result)
                {
                case WELDAP_RESULT_VALUE_OK:
                    if (SUCCEEDED(_BuildSerialization(wzUun, reply.password, pcpcs)))
                    {
                        fSerialized = true;
                    }
                    else
                    {
                        StringCchCopyW(wzMessage, ARRAYSIZE(wzMessage), c_wzInternalError);
                    }
                    break;
                case WELDAP_RESULT_VALUE_DENY:
                    SanitizeMessage(reply.message, c_wzDenied, wzMessage, ARRAYSIZE(wzMessage));
                    break;
                default:
                    SanitizeMessage(reply.message, c_wzServiceError, wzMessage, ARRAYSIZE(wzMessage));
                    break;
                }
            }
            else if (status == WELDAP_STATUS_BAD_REQUEST)
            {
                StringCchCopyW(wzMessage, ARRAYSIZE(wzMessage), c_wzInternalError);
            }
            else
            {
                // Not running, not SYSTEM, timed out or malformed: all the same to the user.
                StringCchCopyW(wzMessage, ARRAYSIZE(wzMessage), c_wzServiceUnavailable);
            }
            SecureZeroMemory(&reply, sizeof(reply));   // includes the local password
        }
    }

    // The password field is wiped after every attempt (the serialization holds its own copy).
    _ClearPassword();

    if (fSerialized)
    {
        _SetStatusText(L"");
        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
    }
    else
    {
        _SetStatusText(wzMessage);
        if (SUCCEEDED(SHStrDupW(wzMessage, ppwszOptionalStatusText)))
        {
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
        }
        *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
    }
    return S_OK;
}

struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PCWSTR   pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS, L"Incorrect password or username.", CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"The account is disabled.", CPSI_WARNING },
};

// ReportResult lets us customise the message shown when Windows rejects the serialization
// (e.g. offline result and a wrong password).
HRESULT CWeldapCredential::ReportResult(NTSTATUS ntsStatus,
                                     NTSTATUS ntsSubstatus,
                                     _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                     _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    DWORD dwStatusInfo = (DWORD)-1;

    // Look for a match on status and substatus.
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
    {
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
        {
            dwStatusInfo = i;
            break;
        }
    }

    if ((DWORD)-1 != dwStatusInfo)
    {
        if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText)))
        {
            *pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
        }
    }

    // If we failed the logon, make sure the password field is empty.
    if (FAILED(HRESULT_FROM_NT(ntsStatus)))
    {
        _ClearPassword();
    }

    // Since nullptr is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    return S_OK;
}

// Enable the password reveal button and touch keyboard auto-invoke.
HRESULT CWeldapCredential::GetFieldOptions(DWORD dwFieldID,
                                        _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo)
{
    *pcpcfo = CPCFO_NONE;

    if (dwFieldID == PFI_PASSWORD)
    {
        *pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
    }
    else if (dwFieldID == PFI_TILEIMAGE)
    {
        *pcpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
    }

    return S_OK;
}
