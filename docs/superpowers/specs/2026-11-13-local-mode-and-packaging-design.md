# Local mode, Windows, packaging and faster CI (design)

Status: approved by the owner on 2026-11-13 ("Windows is important for people who want Dove on their own computer;
not everybody has a VPS"). Target: v0.4.0.

## A. Local mode: Dove on your own computer (macOS, Linux, Windows)

Today Dove assumes a server: an HTTPS `public_url`, a reverse proxy or Tailscale, a systemd service user. Local mode
is the same binary running as the desktop user, for MCP hosts on the same machine (Claude Desktop, Claude Code,
Codex, Cursor, ...).

1. **Config.** `mode = "local"` (default `"server"`). In local mode `listen` must be a loopback address and
   `public_url` may be `http://127.0.0.1:<port>` or `http://localhost:<port>` (and nothing else over plain HTTP). Host
   header / DNS-rebinding checks stay: only the configured loopback origin is accepted. Google OAuth works with a
   `http://127.0.0.1:<port>/oauth/google/callback` redirect URI (Google allows loopback redirects); IMAP needs nothing.
   Remote web connectors (ChatGPT, claude.ai) cannot reach it; the docs say so.
2. **Paths.** Per-user defaults: config and data under the platform dirs (`~/.config/dove` + `~/.local/share/dove`
   on Linux, `~/Library/Application Support/Dove` on macOS, `%APPDATA%\Dove` / `%LOCALAPPDATA%\Dove` on Windows).
   Strict-mode checks keep working on Unix (owner = current user, no group/other bits). On Windows the check is: owner
   is the current user's SID and the DACL grants nothing to Everyone, Users, Authenticated Users or other user SIDs
   (Dove creates its directories with such a DACL).
3. **Secrets in local mode.** `dove local init` generates kek, pepper and index key. On Windows they are stored as
   DPAPI (CurrentUser) protected files; on macOS and Linux as 0600 files in the data dir (an OS keychain is a later
   option). Server mode keeps reading secret files exactly as today.
4. **Admin channel.** Unix: unchanged (Unix socket + `SO_PEERCRED`/`getpeereid` uid check). Windows: a named pipe
   `\\.\pipe\dove-admin-<user SID>` created with a DACL for the current user only, and every connection checked with
   `GetNamedPipeClientProcessId` → process token → `TokenUser` SID equal to the service's SID (the peer-uid check's
   Windows twin). No admin over HTTP, ever.
5. **Running it.** `dove local init` (config + secrets + data dir, prints next steps), `dove local start` (foreground),
   `dove local install` / `uninstall` registering a per-user autostart: launchd agent (macOS), `systemd --user` unit
   (Linux), Task Scheduler "at logon" task (Windows, no admin rights needed). `dove local status`. Then the usual
   `dove accounts connect-imap ...`, `dove clients create ...` and `dove mcp install --client claude-code|codex|claude-desktop`
   (add Claude Desktop's config file: `%APPDATA%\Claude\claude_desktop_config.json`, `~/Library/Application
   Support/Claude/claude_desktop_config.json`).
6. **Threat model, stated plainly in the docs.** On a personal computer the agent usually runs as the same OS user as
   Dove. Local mode still protects mail from remote callers and leaked/over-scoped tokens, keeps grants, audit and
   "no permanent delete", but an agent with a shell as the same user can read Dove's files and use its admin channel.
   For separation, run Dove on another machine or user (server mode). Dove never weakens server mode for this.
7. **Windows port scope.** Everything Unix-specific gets a `cfg(windows)` twin or is compiled out: admin socket
   (named pipe), peer check, file-mode checks (ACL check), `nix` usage (rlimits, user lookups: skip or Windows API),
   the client's credential store (`keyring` already supports Windows Credential Manager), the update notice's
   `O_NOFOLLOW` cache writes (Windows: `FILE_FLAG_OPEN_REPARSE_POINT` or refuse reparse points), `dove upgrade`
   (replacing a running `.exe`: rename the old file aside, move the new one in, delete the old one on next start).
   systemd, Tailscale setup and `serve` hardening warnings stay Unix-only where they make no sense.

## B. Packaging

- **Windows** `x86_64-pc-windows-msvc` (and `aarch64-pc-windows-msvc` if the vendored C deps build): `dove-<tag>-<target>.zip`
  with `dove.exe`, in `SHA256SUMS` and the minisign signature; `install.ps1` (verifies SHA-256, installs to
  `%LOCALAPPDATA%\Programs\Dove`, adds it to the user PATH). `dove upgrade` picks the `.zip`.
- **Static Linux** `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`. The `-gnu` assets stay (0.3.0's
  `dove upgrade` looks for them). `install.sh` picks musl on musl systems (Alpine) and gnu otherwise; `dove upgrade`
  keeps the libc it was built for.
- **Debian/Ubuntu** `.deb` (amd64, arm64) via `cargo-deb`: binary, systemd unit, sysusers/tmpfiles snippets,
  `/etc/dove` with 0750; postinst creates nothing secret and prints the next steps. Attached to the release.
- **Homebrew** tap `dominik-lenhart/homebrew-tap`, formula `dove` updated by the release workflow (deploy key on the
  tap repo, private key as a repo secret), installs the macOS and Linux binaries.

## C. Faster CI and releases

- Build `x86_64-apple-darwin` by cross-compiling on the arm64 `macos-15` runner (the Intel runner took 21 of the 21
  minutes; the other targets take ~6).
- `Swatinem/rust-cache` in the release builds (tag runs can restore caches saved on `main`), plus a cheap job on `main`
  that warms the release-profile caches only when `Cargo.lock` or the toolchain changes.
- CI: run the test job with the runner's cores (`--test-threads=4`), keep clippy/fmt/deny/gitleaks in parallel jobs,
  cancel superseded runs (`concurrency` with `cancel-in-progress` on branches, never on tags), skip the Rust jobs for
  docs-only changes (`paths-ignore` for `**.md`, `docs/**`).
- A Windows CI job (build + the test files that do not need Unix sockets or `sudo`), and a macOS check job only on
  release tags or when `src/**` changes, to keep the Windows/macOS code from rotting.
