# Releasing WELDAP

A release is cut by pushing a version tag. Most of the work is automated by
[`.github/workflows/release.yml`](../.github/workflows/release.yml); the one piece that is not — the Windows
MSI — is spelled out at the end.

## What a release contains

| Artifact | Where | Built by |
| --- | --- | --- |
| Server container image | `ghcr.io/rob-c/weldap-server:<version>` (and `@sha256:…`) | release workflow |
| Build-provenance attestation for the image | GHCR, next to the image | release workflow |
| SBOMs — server image + client, SPDX and CycloneDX | GitHub release assets | release workflow |
| `IMAGE.txt` (image reference + verify command) | GitHub release assets | release workflow |
| Windows MSIs (`Weldap-x64.msi`, `Weldap-arm64.msi`) | GitHub release assets | **manual** (see below) |

The image is `linux/amd64`: the server runs only in its AlmaLinux 9 container.

## Cutting a release

1. **Bump the version.** Set the new version in `server/Cargo.toml` (the workflow refuses to release if the
   tag and the crate version disagree). Keep the client/provider versions in step if they changed, including the
   MSI's `ProductVersion` default in `installer/Weldap.wixproj` (see "The Windows MSI" below).
2. **Update the changelog.** Move the `[Unreleased]` items into a new `## [x.y.z] - YYYY-MM-DD` section and
   refresh the link refs at the bottom. The workflow lifts this section verbatim for the release body.
3. **Commit** on `main` and let CI go green.
4. **Tag and push:**

   ```sh
   git tag -a vX.Y.Z -m "WELDAP X.Y.Z — <one line>"
   git push origin vX.Y.Z
   ```

   The push triggers the release workflow. It builds and pushes the image, mints the provenance attestation,
   generates the SBOMs, creates the GitHub release from the changelog section, and uploads the assets.

### Re-running or backfilling

The workflow also has a manual trigger for an **existing** tag — use it to re-run a failed release, or to
backfill a tag that was pushed before this workflow existed (e.g. `v0.1.0`):

```sh
gh workflow run release.yml -f tag=vX.Y.Z
```

It checks out the named tag (never a branch head), so the artifact is always built from the tagged tree. If
the release already exists it only refreshes the assets.

## One-time GHCR setup

The first push creates the `weldap-server` package **private**. To let others pull it, make it public once in
the repo's *Packages* settings (or keep it private and grant pull access). The provenance attestation and the
SBOMs let a consumer verify exactly what they are pulling.

## Verifying a release

```sh
# Provenance: proves the image was built by this repo's release workflow from this source.
gh attestation verify oci://ghcr.io/rob-c/weldap-server@sha256:<digest> --owner rob-c

# SBOM: inspect the dependencies that went into the image or the client.
cat weldap-server.cdx.json | jq '.components[].purl'
```

Always pull the server image **by digest**, not by tag — the digest is in `IMAGE.txt` and in the attestation.

## The Windows MSI (manual)

The MSIs are not built in hosted CI: they need a Windows toolchain and the credential-provider DLL, which is
built and signed in the ARM64 build VM (`vm1`, see [README](../README.md)). Until a Windows runner is wired
up, build them there and attach them by hand:

1. **Set the MSI version.** `vm/provision/build-msi.ps1` takes `-ProductVersion X.Y.Z` (or `$env:WELDAP_VERSION`
   in the build VM's session; `vm/build-in-vm.sh` forwards `WELDAP_VERSION` from the host): pass the release
   version, and bump the `ProductVersion` default in `installer/Weldap.wixproj` to match ("Cutting a release",
   step 1). Without a version, `build-msi.ps1` stamps a dev build
   `<major>.<minor>.<days since 2026-01-01>` (major.minor from that default): Windows Installer compares the first
   three fields, so a stale dev MSI can never replace a newer build, and a rebuild on the same day upgrades in
   place. A release therefore bumps the **minor** version (0.2.0 is newer than any 0.1 dev build).
2. From the host, with the `WELDAP_SIGN_*` variables set (`docs/CONFIGURATION.md` §6), run `vm/build-in-vm.sh`:
   it builds both providers and both signed MSIs into `out/msi/Weldap-{x64,arm64}.msi`.
3. Verify each provider DLL's SHA-256 (`out/provider-{x64,ARM64}/WeldapCredentialProvider.dll`) matches the
   MSI-pinned `ProviderHash` (installed, the DLL is named `WeldapCredentialProvider-<first 12 hex of it>.dll`),
   then upload:

   ```sh
   gh release upload vX.Y.Z out/msi/Weldap-x64.msi out/msi/Weldap-arm64.msi --clobber
   ```

Keep the MSI's pinned provider hash in sync with the service's anti-tamper check — see
[`ARCHITECTURE.md`](ARCHITECTURE.md) ("if you change X do Y").
