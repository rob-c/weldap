# WELDAP protocols (pipe v3, server v1)

The client (a Windows device) talks to exactly one thing: the WELDAP server. Everything about LDAP and 389 DS
lives behind the server and nowhere else. The user's password exists in plaintext only inside LogonUI (where
Windows collects it) and, for the length of one bind, inside the server (which must hand it to the directory).

```
client: LogonUI credential provider --pipe--> WELDAP service ==mTLS==> WELDAP server --LDAPS--> 389 DS
          seals the password (HPKE)          relays ciphertext,        opens it in locked memory,
          computes the offline verifier       cannot open it           binds as the user, zeroes it
```

## 1. Sealed password (credential provider -> server, end to end)

HPKE, RFC 9180, base mode: DHKEM(P-256, HKDF-SHA256) `0x0010`, HKDF-SHA256 `0x0001`, AES-256-GCM `0x0002`,
`info = "WELDAP password v1"`, one message (sequence 0). Recipient key: the server's password key
(`HKLM\SOFTWARE\WELDAP\ServerKey`, uncompressed point, base64; `ServerKeyId` names it). The private key
exists only in the server.

- Plaintext: the password as UTF-8, 1..256 bytes.
- AAD (ASCII, `\n`-separated): `WELDAP-auth-v1`, kid, uun, scenario, ts (Unix seconds), rid (base64 of 16 random
  bytes). Changing any of them makes the ciphertext unopenable.
- The server refuses a ts more than 120 s from its clock, and any rid it has already seen inside the window.

Offline verifier (computed in the same place, from the same UTF-8 bytes): PBKDF2-HMAC-SHA256, 600 000 iterations,
32 bytes, salt `SHA-256("WELDAP-offline-v1\n" + MachineGuid + "\n" + uun)`. Stored by the service only after the
server confirmed the password; compared (constant time) when the server gives no answer.

## 2. Pipe: credential provider <-> WELDAP service (binary, v3)

`\\.\pipe\weldap`, byte mode, 8 instances (the first with `FILE_FLAG_FIRST_PIPE_INSTANCE`; the DACL lets only SYSTEM
add one), served concurrently so several sessions signing in at once do not queue behind one another, `PIPE_REJECT_REMOTE_CLIENTS`, DACL
`D:P(D;;GA;;;NU)(A;;GA;;;SY)` (SYSTEM only, NETWORK denied; reads back as `FA`, file all access), owner SYSTEM. The server checks the client process
token is `S-1-5-18`; the client checks, before sending, that the pipe's owner and the server process token are
both `S-1-5-18`. One request, one reply, each framed as a 4-byte little-endian length and 1..4096 bytes. A fixed
binary layout (no JSON, no optional fields) keeps the parser in LogonUI a few dozen lines. Integers little-endian;
anything that does not match exactly is dropped, no reply.

Time budget, outermost first, so the service always answers before the tile gives up: the tile allows 15 s from
before it opens the pipe (`WELDAP_CLIENT_DEADLINE_MS`); the service serves a pipe client within 14 s; one server
round trip (connect, at most 3 s of it; TLS handshake; request; reply) is cut off after 9 s
(`LoginSettings.ServerBudgetSeconds`) and becomes "no answer".

Request (no password in it):

| bytes | field | rule |
| --- | --- | --- |
| 1 | version | 3 |
| 1 | flags | bit0 unlock (clear = logon), bit1 adoption consent; any other bit set = malformed |
| 1 + n | uun | n = 1..20, printable ASCII (the service then applies `[a-z0-9]{1,20}`) |
| 1 + k | kid | k = 1..32, `[a-z0-9-]` |
| 65 | enc | HPKE encapsulated key, uncompressed P-256 point (first byte 4) |
| 2 + c | ct | c = 17..272: ciphertext of the 1..256-byte UTF-8 password, then the 16-byte tag |
| 8 | ts | Unix seconds, > 0 |
| 16 | rid | random request id |
| 32 | verifier | offline verifier |

Reply:

| bytes | field | rule |
| --- | --- | --- |
| 1 | version | 3 |
| 1 | result | 0 ok, 1 deny, 2 error, 3 adopt |
| 1 | mode | 0 online, 1 offline (ok only); always sent, 0 unless ok+offline |
| 1 + 2m | message | m = 0..200 UTF-16LE code units, shown on the tile |
| 1 + p | password | ok: p = 1..64 printable ASCII, the account's local password; deny/error/adopt: p = 0 |

| result | mode | meaning | client does |
| --- | --- | --- | --- |
| ok | online | the server confirmed the password; the local account is in step | log on with `password` |
| ok | offline | no answer from the server; the verifier matched a managed, enabled, unexpired account | log on with `password` |
| deny | – | definite no (wrong password, not authorised, excluded, rate-limited, offline locked, ...) | show `message` |
| error | – | service-side failure | show `message` |
| adopt | – | the password is right, but the name is a pre-existing local account WELDAP does not manage; nothing has changed | show `message` (the warning) and a **Continue** box; a resubmit with it ticked sets the consent flag |

The offer is bound to the normalised name the service answered adopt for. The Continue box (`PFI_CONSENT`) can be
ticked only while it is shown; it is hidden and cleared when the username changes to another name (setting the same
name again keeps it), when the tile is deselected, and once the service answers a request with anything but adopt
(a submit the tile refuses itself, e.g. with no password, keeps it). The consent bit is sent only when the box is
ticked and the submitted name is the offered one, so consent is only ever sent for the account the user was warned
about, whatever order LogonUI calls in.

`password` is the account's local password: 32 random characters the service generated and keeps (machine-scope
DPAPI in `HKLM\SOFTWARE\WELDAP\Secret`; the key's SYSTEM-only ACL is the real protection). It is never the user's
password, so LSASS never holds the user's password and a password change at the server does not reset the local
account. The client zeroes the reply as soon as the serialization is built.

Logon serialization: `KERB_INTERACTIVE_UNLOCK_LOGON` for `Negotiate`, domain = computer name, user = uun,
password = the local password from the reply.

## 3. Service <-> WELDAP server (mutual TLS)

TLS 1.2/1.3 to `ServerHost:ServerPort`. The server is trusted by its key alone: the SHA-256 of its certificate's
SubjectPublicKeyInfo must be in `ServerPins` (no CA, no name check, so no certificate authority can stand in for
it). The service presents the newest valid `LocalMachine\My` certificate named `WELDAP device` that has its
private key (from `register-device.ps1`; key non-exportable, in the TPM when there is one). The server admits only
device-CA certificates not on its CRL. One request per connection, 4-byte **big-endian** length, JSON.

```json
{"op":"auth","v":1,"uun":"alice","scenario":"logon","kid":"k1","enc":"...","ct":"...","ts":1793320000,"rid":"..."}
-> {"v":1,"result":"ok","user":true,"admin":false}
 | {"v":1,"result":"invalid"|"denied"|"throttled"|"unavailable"|"error"}
{"op":"status","v":1,"uuns":["alice","bob"]}            (at most 100 per request: see below)
-> {"v":1,"result":"ok","users":["alice","bob"],"admins":["bob"]}   (subsets of the request)
```

`status` asks about every local account name on the device that can be a UUN, managed or not (excluded and
protected accounts aside), in batches of 100; the reconcile acts only if every batch was answered.

Two flags per user are all a client ever learns; `admin` counts only with `user`. `unavailable` (the server cannot
reach its directory), a refused handshake, any connection failure and the 9 s round-trip budget running out are the
only things the client treats as "no answer" (offline path).
