// WELDAP pipe protocol v3: constants shared with the C# service (client/Weldap.Core/Protocol.cs).
// Fixed binary layout, see PROTOCOL.md. The password never crosses the pipe (it is sealed to the server).
#pragma once

#define WELDAP_PIPE_NAME           L"\\\\.\\pipe\\weldap"
#define WELDAP_PROTOCOL_VERSION    3
#define WELDAP_MAX_MESSAGE_BYTES   4096u      // per direction, excluding the 4-byte length prefix
#define WELDAP_MAX_PASSWORD_CHARS  256u       // UTF-16 code units typed into the tile
#define WELDAP_MAX_UUN_CHARS       20u
#define WELDAP_MAX_LOCAL_PASSWORD_CHARS 64u   // the account's random local password in the reply
#define WELDAP_MAX_REPLY_MESSAGE_CHARS 200u   // UTF-16 code units
#define WELDAP_CLIENT_DEADLINE_MS  15000u     // connect + write + read, end to end (server + 3 s connect)

#define WELDAP_SCENARIO_LOGON      "logon"    // in the sealed AAD
#define WELDAP_SCENARIO_UNLOCK     "unlock"

// Request flags byte (position 1): scenario in bit0, adoption consent in bit1. Neither enters the sealed AAD;
// the server never sees them -- they steer the client/service pipe exchange only.
#define WELDAP_FLAG_SCENARIO_UNLOCK 0x01
#define WELDAP_FLAG_CONSENT         0x02

// Reply result byte.
#define WELDAP_RESULT_OK           0
#define WELDAP_RESULT_DENY         1
#define WELDAP_RESULT_ERROR        2
#define WELDAP_RESULT_ADOPT        3          // account can be adopted; show the warning, resubmit with consent

// Well-known SID both ends require of the other end's process token.
#define WELDAP_REQUIRED_PEER_SID   L"S-1-5-18"
