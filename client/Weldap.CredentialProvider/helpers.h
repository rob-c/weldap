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

#pragma once

#pragma warning(push)
#pragma warning(disable: 28251)
#include <credentialprovider.h>
#include <ntsecapi.h>
#pragma warning(pop)

#define SECURITY_WIN32
#include <security.h>
#include <intsafe.h>

#include <windows.h>
#include <strsafe.h>

#pragma warning(push)
#pragma warning(disable: 4995)
#include <shlwapi.h>
#pragma warning(pop)

#pragma warning(push)
#pragma warning(disable: 28301)
#include <wincred.h>
#pragma warning(pop)

//makes a copy of a field descriptor using CoTaskMemAlloc
HRESULT FieldDescriptorCoAllocCopy(
    _In_ const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR &rcpfd,
    _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd
    );

//makes a copy of a field descriptor on the normal heap
HRESULT FieldDescriptorCopy(
    _In_ const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR &rcpfd,
    _Out_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR *pcpfd
    );

//creates a UNICODE_STRING from a NULL-terminated string
HRESULT UnicodeStringInitWithString(
    _In_ PWSTR pwz,
    _Out_ UNICODE_STRING *pus
    );

//initializes a KERB_INTERACTIVE_UNLOCK_LOGON with weak references to the provided credentials
HRESULT KerbInteractiveUnlockLogonInit(
    _In_ PWSTR pwzDomain,
    _In_ PWSTR pwzUsername,
    _In_ PWSTR pwzPassword,
    _In_ CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _Out_ KERB_INTERACTIVE_UNLOCK_LOGON *pkiul
    );

//packages the credentials into the buffer that the system expects
HRESULT KerbInteractiveUnlockLogonPack(
    _In_ const KERB_INTERACTIVE_UNLOCK_LOGON &rkiulIn,
    _Outptr_result_bytebuffer_(*pcb) BYTE **prgb,
    _Out_ DWORD *pcb
    );

//get the authentication package that will be used for our logon attempt
HRESULT RetrieveNegotiateAuthPackage(
    _Out_ ULONG *pulAuthPackage
    );

//encrypt the local password with CredProtect and copy it (an empty password is copied as-is)
HRESULT ProtectIfNecessaryAndCopyPassword(
    _In_ PCWSTR pwzPassword,
    _Outptr_result_nullonfailure_ PWSTR *ppwzProtectedPassword
    );

// WELDAP: zero a CoTaskMem-allocated string, then free it. Safe with nullptr.
void CoTaskMemFreeSecureString(_In_opt_ PWSTR pwz);
