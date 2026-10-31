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
| Windows MSI | GitHub release asset | **manual** (see below) |

The image is `linux/amd64`: the server runs only in its AlmaLinux 9 container.

## Cutting a release

1. **Bump the version.** Set the new version in `server/Cargo.toml` (the workflow refuses to release if the
   tag and the crate version disagree). Keep the client/provider versions in step if they changed.
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

The MSI is not built in hosted CI: it needs a Windows toolchain and the credential-provider DLL, which is
built and signed in the ARM64 build VM (`vm1`, see [README](../README.md)). Until a Windows runner is wired
up, build it there and attach it by hand:

1. In `vm1`, build the provider and the signed MSI as usual (`build.sh` / the packaging step).
2. From the host, verify the DLL hash matches the MSI-pinned value, then upload:

   ```sh
   gh release upload vX.Y.Z WeldapSetup-X.Y.Z.msi --clobber
   ```

Keep the MSI's pinned provider hash in sync with the service's anti-tamper check — see
[`ARCHITECTURE.md`](ARCHITECTURE.md) ("if you change X do Y").
