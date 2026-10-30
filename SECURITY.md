# Security policy

WELDAP sits on the Windows interactive-logon path and handles user passwords, so security
reports are taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.** Instead, use GitHub's private
vulnerability reporting for this repository: the **Security** tab → **Report a vulnerability**.
If that is unavailable to you, open a normal issue that says only "security report, please enable
private reporting" with no details, and a maintainer will follow up.

Please include, where you can: the component (client credential provider, client service, or
server), the version/commit, a description of the issue and its impact, and steps or a proof of
concept. We aim to acknowledge a report within a few days.

## Scope and threat model

The intended security properties — and their limits — are documented in
`client/Weldap.Shared/PROTOCOL.md` ("What protects the password") and `server/README.md`
("Hardening", "Known limits"), and summarised in `docs/REQUIREMENTS.md` (Security requirements).
In short:

- The user's directory password is sealed (HPKE) inside LogonUI to the server's key and is never
  seen by the client service, the pipe, LSASS, the local SAM, disk or the network.
- The server is the only LDAP client of the directory; the client learns only two flags per user.
- Clients authenticate to the server with a per-device certificate (mutual TLS) and trust the
  server by a pinned key, not a CA.

Reports that strengthen those properties, or that show a way to defeat them, are especially
welcome. Known, documented limits (for example: the server sees the password for the duration of
one LDAP bind; a stolen, powered-off device allows offline PBKDF2 guessing) are described in the
docs above and are not, by themselves, new vulnerabilities — but a way to widen them is.

## Supported versions

This is pre-1.0 software. Security fixes are made against the `main` branch; there are no
long-term support branches yet.
