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
// CWeldapCredential is the "WELDAP" tile: UUN + password, checked by the WELDAP Service
// over the named pipe before a local logon serialization is handed to LogonUI.

#pragma once

#include <windows.h>
#include <strsafe.h>
#include <shlguid.h>   // the CPFG_* field GUIDs used in common.h
#include "common.h"
#include "../Weldap.Shared/WeldapProtocol.h"   // WELDAP_MAX_UUN_CHARS
#include "dll.h"
#include "resource.h"

class CWeldapCredential : public ICredentialProviderCredential,
                       public ICredentialProviderCredentialWithFieldOptions
{
public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return InterlockedIncrement(&_cRef);
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        long cRef = InterlockedDecrement(&_cRef);
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    IFACEMETHODIMP QueryInterface(_In_ REFIID riid, _COM_Outptr_ void **ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(CWeldapCredential, ICredentialProviderCredential), // IID_ICredentialProviderCredential
            QITABENT(CWeldapCredential, ICredentialProviderCredentialWithFieldOptions), // IID_ICredentialProviderCredentialWithFieldOptions
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }
  public:
    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(_In_ ICredentialProviderCredentialEvents *pcpce);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP SetSelected(_Out_ BOOL *pbAutoLogon);
    IFACEMETHODIMP SetDeselected();

    IFACEMETHODIMP GetFieldState(DWORD dwFieldID,
                                 _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
                                 _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis);

    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo);

    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);

    IFACEMETHODIMP GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
                                    _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
                                    _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                    _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon);
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus,
                                NTSTATUS ntsSubstatus,
                                _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon);

    // ICredentialProviderCredentialWithFieldOptions
    IFACEMETHODIMP GetFieldOptions(DWORD dwFieldID,
                                   _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo);

  public:
    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                       _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
                       _In_ FIELD_STATE_PAIR const *rgfsp);
    CWeldapCredential();

  private:
    virtual ~CWeldapCredential();

    void _ClearPassword();
    void _SetStatusText(_In_ PCWSTR pwz);
    void _ShowConsent(_In_opt_ PCWSTR pwzOfferedUun);
    HRESULT _BuildSerialization(_In_ PCWSTR pwzUun, _In_ PCWSTR pwzLocalPassword,
                                _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs);

    long                                    _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO      _cpus;                                          // The usage scenario for which we were enumerated.
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR    _rgCredProvFieldDescriptors[PFI_NUM_FIELDS];    // An array holding the type and name of each field in the tile.
    FIELD_STATE_PAIR                        _rgFieldStatePairs[PFI_NUM_FIELDS];             // An array holding the state of each field in the tile.
    PWSTR                                   _rgFieldStrings[PFI_NUM_FIELDS];                // An array holding the string value of each field.
    ICredentialProviderCredentialEvents     *_pCredProvCredentialEvents;                    // Used to update fields.
    // Adoption consent (PROTOCOL.md). The offer is bound to the (normalised) name the service answered "adopt"
    // for: the Continue box is shown only then, can be ticked only while shown, is withdrawn when the name changes
    // to another one or the tile is deselected, and consent is sent only for that same name -- whatever order
    // LogonUI calls in, consent is only ever sent for the account the user was warned about.
    bool                                    _fConsent;
    wchar_t                                 _wzOfferedUun[WELDAP_MAX_UUN_CHARS + 1];   // "" = no offer
};
