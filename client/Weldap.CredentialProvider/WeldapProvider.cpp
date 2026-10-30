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
// CWeldapProvider implements ICredentialProvider, which is the main interface that LogonUI
// uses to decide which tiles to display. We show one "WELDAP" tile, on the logon and
// unlock screens only. This provider is not a filter and does not touch other providers,
// so the stock password tile is always there.

#include <initguid.h>
#include "WeldapProvider.h"
#include "WeldapCredential.h"
#include "guid.h"

CWeldapProvider::CWeldapProvider():
    _cRef(1),
    _pCredential(nullptr),
    _cpus(CPUS_INVALID)
{
    DllAddRef();
}

CWeldapProvider::~CWeldapProvider()
{
    if (_pCredential != nullptr)
    {
        _pCredential->Release();
        _pCredential = nullptr;
    }

    DllRelease();
}

// SetUsageScenario is the provider's cue that it's going to be asked for tiles
// in a subsequent call.
HRESULT CWeldapProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD /*dwFlags*/)
{
    HRESULT hr;

    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        _cpus = cpus;
        if (_pCredential != nullptr)
        {
            _pCredential->Release();
            _pCredential = nullptr;
        }
        _pCredential = new (std::nothrow) CWeldapCredential();
        if (_pCredential != nullptr)
        {
            hr = _pCredential->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs);
            if (FAILED(hr))
            {
                _pCredential->Release();
                _pCredential = nullptr;
            }
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
        break;

    default:
        // CPUS_CHANGE_PASSWORD, CPUS_CREDUI and anything else: not ours.
        hr = E_NOTIMPL;
        break;
    }

    return hr;
}

// We never take a serialization from elsewhere (remote logon, CredUI).
HRESULT CWeldapProvider::SetSerialization(
    _In_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const * /*pcpcs*/)
{
    return E_NOTIMPL;
}

HRESULT CWeldapProvider::Advise(
    _In_ ICredentialProviderEvents * /*pcpe*/,
    _In_ UINT_PTR /*upAdviseContext*/)
{
    return E_NOTIMPL;
}

HRESULT CWeldapProvider::UnAdvise()
{
    return E_NOTIMPL;
}

HRESULT CWeldapProvider::GetFieldDescriptorCount(
    _Out_ DWORD *pdwCount)
{
    *pdwCount = PFI_NUM_FIELDS;
    return S_OK;
}

// Gets the field descriptor for a particular field.
HRESULT CWeldapProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd)
{
    HRESULT hr;
    *ppcpfd = nullptr;

    // Verify dwIndex is a valid field.
    if ((dwIndex < PFI_NUM_FIELDS) && ppcpfd)
    {
        hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// One tile, never the default, never auto-logon: the stock tile stays the default.
HRESULT CWeldapProvider::GetCredentialCount(
    _Out_ DWORD *pdwCount,
    _Out_ DWORD *pdwDefault,
    _Out_ BOOL *pbAutoLogonWithDefault)
{
    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = FALSE;
    *pdwCount = (_pCredential != nullptr) ? 1 : 0;
    return S_OK;
}

// Returns the credential at the index specified by dwIndex.
HRESULT CWeldapProvider::GetCredentialAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ ICredentialProviderCredential **ppcpc)
{
    HRESULT hr = E_INVALIDARG;
    *ppcpc = nullptr;

    if ((dwIndex == 0) && ppcpc && _pCredential != nullptr)
    {
        hr = _pCredential->QueryInterface(IID_PPV_ARGS(ppcpc));
    }
    return hr;
}

// Boilerplate code to create our provider.
HRESULT CWeldapProvider_CreateInstance(_In_ REFIID riid, _COM_Outptr_ void **ppv)
{
    HRESULT hr;
    CWeldapProvider *pProvider = new (std::nothrow) CWeldapProvider();
    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        *ppv = nullptr;
        hr = E_OUTOFMEMORY;
    }
    return hr;
}
