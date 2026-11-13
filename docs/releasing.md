# Releasing

How Dove releases are versioned, cut, signed and verified.

## Versioning

Semantic versioning, tags `vX.Y.Z`. While the major version is 0, a minor bump may change behaviour or
configuration; read the changelog.

- Patch: bug fixes and security fixes, no configuration changes.
- Minor: new features and additive changes (new tools, config keys with defaults, schema migrations).
- Major: breaking changes to the config file, the admin protocol, the tool contract or the on-disk format.
- Schema migrations never go down. A newer schema refuses an older binary, so a rollback is "restore the backup".
- Prereleases use `-rc.N` or `-beta.N` (`v0.2.0-rc.1`). They are marked as prerelease on GitHub and never move the
  `X.Y` and `latest` image tags or the "latest release" that `install.sh` and `dove upgrade` resolve.

## What a release contains

- `dove-<tag>-<target>.tar.gz` for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
  `x86_64-unknown-linux-musl` (static, for Alpine), `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`,
  `aarch64-apple-darwin`. Each holds `dove-<tag>-<target>/{dove,LICENSE,README.md}`. The `-gnu` assets must stay:
  `dove upgrade` of older binaries looks for them.
- `dove-<tag>-x86_64-pc-windows-msvc.zip` with `dove.exe`, only while the Windows release is switched on (below).
- `dove_<version>_amd64.deb` and `dove_<version>_arm64.deb` (cargo-deb, built from the gnu binaries): binary, hardened
  systemd unit, sysusers/tmpfiles snippets. The package creates `/etc/dove` (0750) and the service account, never
  secrets, and starts nothing.
- `SHA256SUMS` (archives and `.deb` files), and `SHA256SUMS.minisig`, a minisign signature over it with the trusted
  comment `dove <tag>`. The public key is committed at `deploy/release/minisign.pub` and embedded in `install.sh`,
  `install.ps1` and in `dove upgrade`.
- `install.sh` and `install.ps1`.
- GitHub build provenance attestations for the archives, the `.deb` files and the image.
- Image `ghcr.io/dominik-lenhart/dove` for linux/amd64 and linux/arm64, tags `X.Y.Z`, `X.Y` and `latest`,
  assembled from the release's gnu binaries (`deploy/Containerfile.release`).
- The Homebrew formula in `dominik-lenhart/homebrew-tap` (not a release asset, see below).

Linux gnu binaries are built on Ubuntu 22.04 (glibc 2.35), so they run on current distributions and in the distroless
Debian 12 image; the musl builds are static. macOS binaries target macOS 11 and later. `x86_64-apple-darwin` is
cross-compiled on the arm64 `macos-15` runner (the Intel runner took 21 of the 21 minutes of a release, the other
targets about 6). `aarch64-pc-windows-msvc` is not built: it needs the `windows-11-arm` runner and an arm64
OpenSSL/NASM setup nobody has tried yet.

## Build caches

Tag runs restore, and never save, the `rust-cache` caches that `release-cache.yml` saved on `main` (one cache per
target, key `release-<target>`, shared through `.github/actions/release-build`). That workflow runs on pushes to `main`
that change `Cargo.lock`, `rust-toolchain.toml` or the release build files, so the vendored OpenSSL/SQLCipher C build
is compiled once, not per release. On pull requests touching the same files it builds all targets without saving, so
a broken cross-compile shows up before release day. If a tag build is unexpectedly slow, check that the last run of
`Release cache` on `main` succeeded; caches unused for seven days are evicted, so run it by hand (re-run a past run)
after a quiet week.

## Homebrew tap

The `homebrew` job runs after the release exists, for stable tags only (prereleases never reach the tap). It renders
`deploy/homebrew/dove.rb.in` with `deploy/homebrew/render.sh` from the release's `SHA256SUMS`, refusing to continue
unless all four platforms are listed exactly once, and pushes `Formula/dove.rb` to `dominik-lenhart/homebrew-tap`
with a write deploy key. The formula is generated: change the template, never the tap. If the job fails the release
stays valid; fix the cause and re-run the job, or render by hand:

```sh
curl -fsSLO https://github.com/dominik-lenhart/dove/releases/download/vX.Y.Z/SHA256SUMS
sh deploy/homebrew/render.sh X.Y.Z SHA256SUMS > Formula/dove.rb    # in a clone of the tap, then commit and push
```

Setup (done once, already in place): an ed25519 deploy key with write access on the tap repository
(`gh repo deploy-key add <pub> -R dominik-lenhart/homebrew-tap --allow-write`) and its private half as the secret
`HOMEBREW_TAP_DEPLOY_KEY` of this repository. To rotate it, generate a new pair in a temporary directory, replace
both, delete the local files and the old deploy key.

## Windows release switch

The Windows zip is built only when `WINDOWS_RELEASE` in `release.yml` is `"true"`; it is on since 0.5.0-rc.1. Nothing
else depends on it: the other assets, the checksum count, signing, the `.deb` files, the image and the Homebrew job work
with or without the zip. The CI `windows` job is gating, and `Release cache` builds `x86_64-pc-windows-msvc`.

Every release with the switch on runs the `windows-smoke` job on a Windows runner after publishing: `install.ps1`
installs the release and `dove --version` must print it; `dove local init`, `dove local start`, the HTTP endpoint on
127.0.0.1 and `dove local stop` must work; and `dove upgrade --version <new>` must reach the release from the earlier
Windows release named in `UPGRADE_FROM` (skipped for that release itself). A failing smoke job does not withdraw the
release: delete the GitHub Release (and tag) by hand if the Windows build is broken, or ship a fix release.

## One-time setup

Generate a signing key without a password (the workflow cannot type one) and keep a copy offline:

```sh
minisign -G -W -p deploy/release/minisign.pub -s ~/dove-release.key
gh secret set MINISIGN_SECRET_KEY --repo dominik-lenhart/dove < ~/dove-release.key
```

The secret holds the whole key file. The committed public key `deploy/release/minisign.pub` must be the matching one,
and the same key string must be in `install.sh` (`PUBKEY`) and in the source of `dove upgrade`.

Repository settings: Actions enabled; no special workflow permissions (each job declares its own). The first image push
creates the GHCR package: set it to public under Packages and link it to the repository. Attestations on private
repositories need GitHub Enterprise, public repositories get them for free.

## Cutting a release

1. On `main` with green CI, set `version` in `Cargo.toml` (and refresh `Cargo.lock`: `cargo update -p dove-mcp`) and in
   `server.json` (`tests/packaging.rs` fails while they differ).
2. In `CHANGELOG.md` rename `## [Unreleased]` content into `## [X.Y.Z] - <date>`, add a fresh empty `## [Unreleased]`,
   and update the compare links at the bottom. The release notes are exactly this section.
3. Commit (`release: vX.Y.Z`), push, wait for CI.
4. Tag and push:
   ```sh
   git tag -s vX.Y.Z -m "dove vX.Y.Z"      # or -a if you do not sign tags
   git push origin vX.Y.Z
   ```
5. Watch the `Release` workflow. It fails at once if the tag is not `v` + the `Cargo.toml` version or the changelog has no
   section for it. It builds the archives and `.deb` packages, signs `SHA256SUMS`, verifies the signature against the committed public
   key, attests, creates the release, pushes the image and updates the Homebrew tap.
6. Verify the published artifacts (next section), then upgrade your own instance with `dove upgrade`.
7. Update the [MCP Registry](https://registry.modelcontextprotocol.io) entry: `mcp-publisher login github` (as the
   repository owner), then `mcp-publisher publish` in the repository root. It reads `server.json`.

A failed run before "Create the release" can be re-run from the Actions page. After the release exists, delete it
and the tag (`gh release delete vX.Y.Z --cleanup-tag`) before pushing the tag again, or cut the next patch version.

## Verifying a release by hand

```sh
tag=v0.1.0; target=x86_64-unknown-linux-gnu
base=https://github.com/dominik-lenhart/dove/releases/download/$tag
curl -fsSLO "$base/dove-$tag-$target.tar.gz" -O "$base/SHA256SUMS" -O "$base/SHA256SUMS.minisig"

# 1. signature over the checksum list (public key from this repository)
minisign -V -P RWQRx2ysvLhSBINGxR3uV9awNjRzHTcz6NUppfFhP2OBdhxTETjz+zGr -m SHA256SUMS
#    the trusted comment must read: dove v0.1.0

# 2. the archive against the list
sha256sum --ignore-missing -c SHA256SUMS            # macOS: shasum -a 256 -c SHA256SUMS 2>&1 | grep "$target"

# 3. build provenance (proves the archive was built by this repository's workflow)
gh attestation verify "dove-$tag-$target.tar.gz" --repo dominik-lenhart/dove
gh attestation verify oci://ghcr.io/dominik-lenhart/dove:0.1.0 --repo dominik-lenhart/dove
```

## Key rotation

1. Generate a new key pair (see One-time setup) under a new file name.
2. Ship a release that trusts both keys: add the new public key next to the old one in `install.sh` and in
   `dove upgrade`, keep signing with the old key. Users upgrade to it.
3. Replace the secret `MINISIGN_SECRET_KEY`, commit the new `deploy/release/minisign.pub`, remove the old key from
   `install.sh` and `dove upgrade` in the next release, which is now signed by the new key.
4. If the old key may be compromised, skip step 2's overlap: publish the new key through a channel users can check
   (a signed git tag and an announcement), mark the old releases as untrusted in the notes, and tell users to reinstall
   with `install.sh` from the new release, since `dove upgrade` on an old binary will reject the new signature.

## A bad release

- Do not move or re-upload a tag. Publish a fixed patch release instead; users upgrade with `dove upgrade`.
- Mark the bad release as a prerelease or delete it, so that "latest" resolves to the previous good one
  (`gh release edit vX.Y.Z --prerelease`, `gh release delete vX.Y.Z`). Deleting a release does not delete its image tags:
  remove them from Packages if the image is harmful, and move `latest` and `X.Y` back by re-tagging the previous digest
  (`docker buildx imagetools create -t ghcr.io/dominik-lenhart/dove:latest ghcr.io/dominik-lenhart/dove:<good>`).
- A bad migration cannot be undone by a rollback of the binary alone: operators restore their state backup (see the
  deployment guide, Upgrading). Say so in the notes.
- If the signing key leaked, follow the rotation steps and revoke the repository secret immediately.
