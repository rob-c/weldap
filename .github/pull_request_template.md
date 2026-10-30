<!-- WELDAP handles passwords in the Windows logon path. Keep PRs small and the security reasoning explicit. -->

## What and why

<!-- What does this change, and why. Link any issue. -->

## Security reasoning

<!-- Anything touching the password path, the network surface, P/Invoke, the credential provider's imports,
     or logging needs a sentence on why it stays safe. "No change to the password path" is a fine answer. -->

## Checklist

- [ ] `tests/quality.sh` passes locally (paranoia, budget, protocol, shellcheck, client, server).
- [ ] New or changed behaviour comes with tests; the 100/100 coverage gates still hold.
- [ ] No secret can reach a log at any level (the `paranoia` gate enforces this — I did not work around it).
- [ ] No new network endpoint, P/Invoke, dependency, or credential-provider import without a note above on why.
- [ ] Windows-only changes were exercised in a VM (`tests/acceptance/run.sh`) where applicable, or noted as not yet.
