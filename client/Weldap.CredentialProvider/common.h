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
// The fields of the WELDAP tile and which of them show in which state of LogonUI.

#pragma once
#include "helpers.h"

// The indexes of each of the fields in our tile. Display order follows the index.
enum WELDAP_FIELD_ID
{
    PFI_TILEIMAGE      = 0,
    PFI_LABEL          = 1,
    PFI_LARGE_TEXT     = 2,
    PFI_UUN            = 3,
    PFI_PASSWORD       = 4,
    PFI_SUBMIT_BUTTON  = 5,
    PFI_STATUS_TEXT    = 6,
    PFI_NUM_FIELDS     = 7,  // keep last: number of fields
};

// The first value indicates when the tile is displayed (selected, not selected)
// the second indicates things like whether the field is enabled, whether it has key focus, etc.
struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_BOTH,            CPFIS_NONE    },    // PFI_TILEIMAGE
    { CPFS_HIDDEN,                     CPFIS_NONE    },    // PFI_LABEL
    { CPFS_DISPLAY_IN_BOTH,            CPFIS_NONE    },    // PFI_LARGE_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_FOCUSED },    // PFI_UUN
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // PFI_PASSWORD
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // PFI_SUBMIT_BUTTON
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // PFI_STATUS_TEXT
};
static_assert(ARRAYSIZE(s_rgFieldStatePairs) == PFI_NUM_FIELDS, "field state table");

// Field descriptors for unlock and logon. For edit fields the label is the placeholder text.
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { PFI_TILEIMAGE,     CPFT_TILE_IMAGE,    const_cast<PWSTR>(L"Image"),     CPFG_CREDENTIAL_PROVIDER_LOGO  },
    { PFI_LABEL,         CPFT_SMALL_TEXT,    const_cast<PWSTR>(L"WELDAP"), CPFG_CREDENTIAL_PROVIDER_LABEL },
    { PFI_LARGE_TEXT,    CPFT_LARGE_TEXT,    const_cast<PWSTR>(L"WELDAP")                                 },
    { PFI_UUN,           CPFT_EDIT_TEXT,     const_cast<PWSTR>(L"Username")                                  },
    { PFI_PASSWORD,      CPFT_PASSWORD_TEXT, const_cast<PWSTR>(L"Password")                                  },
    { PFI_SUBMIT_BUTTON, CPFT_SUBMIT_BUTTON, const_cast<PWSTR>(L"Submit")                                    },
    { PFI_STATUS_TEXT,   CPFT_SMALL_TEXT,    const_cast<PWSTR>(L"Status")                                    },
};
static_assert(ARRAYSIZE(s_rgCredProvFieldDescriptors) == PFI_NUM_FIELDS, "field descriptor table");
