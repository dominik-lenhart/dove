# Deployment guide

How to run your own Dove instance: one service on your server, your own Google Cloud project, your own proxy. There
is no hosted Dove and no shared client id (spec section 1).

Read [`README.md`](../README.md) first for what Dove protects and what it does not. Everything below uses example
values (`dove.example.com`, `info@example.com`); replace them. Status of this guide: the artifacts under `deploy/`
were checked as described in [What has been verified](#what-has-been-verified). None of it has run on a production
host against real Google yet.

Contents: [Requirements](#requirements) · [Install](#install) · [Google Cloud](#google-cloud-setup) ·
[Secrets](#secrets) · [Configuration](#configuration) · [Run](#run-the-service) · [Reverse proxy](#reverse-proxy) ·
[Connect mailboxes](#connect-mailboxes) · [Projects, clients, grants](#projects-clients-and-grants) ·
[Administration](#administration-access) · [Backup](#backup-and-restore) · [Upgrades](#upgrades-and-migrations) ·
[KEK rotation](#kek-rotation) · [Deleting data](#deleting-data-logical-versus-physical) ·
[Verified](#what-has-been-verified)

## Requirements

- A Linux host you control, one public DNS name for Dove (for example `dove.example.com`) and ports 80 and 443
  reachable for the proxy. Dove itself listens on `127.0.0.1` only.
- Memory: the reference profile is a 512 MiB limit for the service (spec 8.1a). The goal of under 256 MiB resident
  memory at steady state is provisional and not measured yet. A 1 GiB profile exists for larger workloads. Disk: the
  state store is small; the search index (not implemented yet, see the README status) will grow with mail volume.
- A Google account that owns a Google Cloud project, and 2-step verification on every mailbox you connect.
- For building: Rust 1.90 or newer, a C compiler, `perl` and `make` (SQLCipher and OpenSSL are vendored and built
  from source). Running needs none of them.
- Keep agents off this host, or at least off the service and operator accounts. See
  [Administration access](#administration-access).

## Install

There are no published release binaries yet (signed releases are a goal, spec 13a). Build from source.

### Binary with systemd

```sh
export PATH=$HOME/.cargo/bin:$PATH
cargo build --release --locked                 # on a shared host: CARGO_BUILD_JOBS=3 and a low priority
sudo install -m 0755 target/release/dove /usr/local/bin/dove
sudo install -m 0644 deploy/systemd/dove.service /etc/systemd/system/dove.service
sudo install -m 0644 deploy/systemd/dove.sysusers.conf /usr/lib/sysusers.d/dove.conf
sudo install -m 0644 deploy/systemd/dove.tmpfiles.conf /usr/lib/tmpfiles.d/dove.conf
sudo systemd-sysusers && sudo systemd-tmpfiles --create
```

This creates the system user `dove` (no shell, no password), `/etc/dove` (group `dove`, 0750) and
`/etc/dove/credentials` (root only, 0700). The unit creates `/var/lib/dove` (0700) and `/run/dove` (0750) itself.
Do not enable the service yet; create secrets and the configuration first.

### Container

```sh
docker build -f deploy/Containerfile -t dove-mcp:local .
```

The image is multi-stage, runs as UID/GID 65532, contains no shell, and works with `read_only: true`. Base images
are pinned by digest in `deploy/Containerfile`. The example [`deploy/compose.yaml`](../deploy/compose.yaml) runs Dove
and Caddy with `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, a 512 MiB limit and secrets as files. Podman
users can build the same file with `podman build -f deploy/Containerfile`; that path has not been tried.

## Google Cloud setup

Do this once, as the owner (spec section 9). Console names change; the intent is what matters.

1. Create a Google Cloud project under your own Google account, for example `dove-<owner>`.
2. Enable the **Gmail API**.
3. Google Auth Platform, Branding: app name, support email, no logo (a logo triggers brand verification).
4. Audience: user type **External** (needed for personal `@gmail.com` accounts and for Workspace domains other than
   the one that owns the project). Set the publishing status to **In production**. While the app is in **Testing**,
   Google expires refresh tokens after 7 days and Dove would stop working every week.
5. Data access: add the scopes `openid`, `email`, `https://www.googleapis.com/auth/gmail.readonly` and
   `https://www.googleapis.com/auth/gmail.compose`. Both Gmail scopes are classed as restricted. **Do not submit the
   app for verification.** A personal-use app stays unverified: when you connect a mailbox Google shows "Google
   hasn't verified this app" and you continue through **Advanced**. An unverified app is limited to 100 users over
   the project's lifetime, which is enough for about 25 mailboxes.
6. Credentials: create an OAuth client of type **Web application** with exactly one authorized redirect URI,
   `https://dove.example.com/oauth/google/callback`. Put the client id in `config.toml` and the client secret in a
   secret file (next section). Never commit either.
7. Google Workspace mailboxes: the domain admin may block unverified third-party apps. In the Admin console under
   Security, API controls, App access control, mark the OAuth client id as trusted for that domain.

**Not yet verified:** that an unverified production-status app obtains a long-lived refresh token for these
restricted scopes with a real account. The spec requires one manual check with a real account before release and
nothing here has done it. If Google refuses, spec section 9 lists the fallbacks: one Google Cloud project per
Workspace domain with user type Internal, or (phase 3) IMAP with an app password for personal accounts.

Refresh tokens can still stop working: unused for 6 months, the user changes their password (Gmail scopes are
revoked), the user removes access in their Google account, a Workspace admin policy, or too many tokens for one user
and client (the oldest is revoked). Dove marks such a mailbox `reauth_required`, sends one notification, and the
tools return `account_unavailable` until you run `dove accounts reconnect <alias>`.

## Secrets

Dove reads secrets only from files, never from environment variables. Each secret file must be a regular file
without any group or other permission bits (0400 or 0600), or the service refuses to start.

| File | Content | Notes |
| --- | --- | --- |
| `kek` | Key encryption key, one `<version> <base64 key>` line per version | Wraps the per-mailbox keys. Back it up separately and offline. |
| `pepper` | Keyed-hash secret for client tokens | Losing or changing it invalidates every client token (they are stored as keyed hashes only). |
| `index_key` | Key of the encrypted search index | The index is rebuildable; losing the key means a rebuild. |
| `google_client_secret` | The OAuth client secret from Google | Plain text, surrounding whitespace is trimmed. |

Generate the three keys locally (the command prints a line and talks to nothing):

```sh
sudo sh -c 'umask 077; for n in kek pepper index_key; do dove keys generate > /etc/dove/credentials/$n; done'
sudo sh -c 'umask 077; cat > /etc/dove/credentials/google_client_secret'    # paste the secret, then Ctrl-D
sudo chmod 0400 /etc/dove/credentials/*
```

`dove keys generate` prints a line such as `1 <44 base64 characters>`; `--version N` sets the version number (used for
[KEK rotation](#kek-rotation)). In the container deployment run it with the image:
`docker run --rm dove-mcp:local keys generate > secrets/kek`.

With systemd, the unit's `LoadCredential=` lines copy each file into `/run/credentials/dove.service/` (a private
in-memory directory readable by the service user only) at every start, which is why `config.toml` points there. To
keep the sources encrypted at rest, use `systemd-creds encrypt` with `LoadCredentialEncrypted=` instead; the service
sees the same plain files. In the container deployment, Compose mounts file secrets at `/run/secrets/<name>`; see
the header of `deploy/compose.yaml` for the ownership requirement (host files owned by 65532, mode 0400).

Back up `kek` and `pepper` offline and apart from any state backup. A state backup together with the KEK is
everything an attacker needs to read the stored Google refresh tokens.

## Configuration

Print the reference configuration and edit it:

```sh
dove config-example | sudo tee /etc/dove/config.toml
sudo chown root:dove /etc/dove/config.toml && sudo chmod 0640 /etc/dove/config.toml
```

The file holds no secrets. Unknown keys are rejected. Settings and defaults (from `src/config.rs`):

| Key | Default | Meaning |
| --- | --- | --- |
| `public_url` | required | `https://` origin without path, for example `https://dove.example.com`. Requests must carry this `Host`. |
| `listen` | `127.0.0.1:8787` | Must be a loopback address; Dove refuses others. |
| `data_dir` | required | Owned by the service user, mode 0700 (enforced). Holds `state.db` and the index. |
| `allowed_origins` | `[]` | Browser origins allowed to call `/mcp`. Leave empty unless you know you need it. |
| `allow_send` | `false` | Instance gate for `send_draft`. See [README](../README.md#compose-scope-and-sending-two-gates-and-what-they-mean). |
| `admin.socket_path` | `/run/dove/admin.sock` | Unix socket, mode 0660. |
| `admin.operator_uid` | required | The only non-root uid allowed to administer. Not the service user and not an agent's uid. |
| `google.client_id`, `google.client_secret_file` | required | From [Google Cloud setup](#google-cloud-setup). |
| `secrets.kek_file`, `pepper_file`, `index_key_file` | required | Paths of the secret files. |
| `limits.*` | see below | Request and upstream limits. |
| `audit.retention_days` | `180` | Audit retention. Prune with `dove audit prune`. |
| `notifier.webhook_url` | unset | HTTPS webhook (for example ntfy) for "mailbox needs re-authorization". Messages carry no mail content. |
| `index.*` | see below | Search index tuning (index not implemented yet). |

`limits` defaults: `body_bytes` 1 MiB, `client_requests_per_minute` 120, `client_burst` 40,
`client_sends_per_hour` 20, `upstream_total_inflight` 16, `upstream_per_mailbox` 4, `upstream_search_mailboxes` 8,
`upstream_request_timeout_secs` 10, `tool_call_timeout_secs` 30. `index` defaults: `poll_interval_secs` 60,
`sql_heap_limit_mib` 96, `page_cache_kib` 8192, `reader_connections` 3, `body_jobs` 2, `max_message_bytes` 25 MiB,
`max_body_chars` 200000.

The service refuses to start when: a secret file is readable by group or others, a secret file is missing (including
the KEK), `public_url` is not an HTTPS origin, `listen` is not loopback, the data directory is not mode 0700, or the
index self-check (SQLCipher, key, FTS5, in-memory temp storage) fails. It logs a warning if it runs as the operator
uid; run it as the dedicated service user.

## Run the service

systemd:

```sh
sudo systemctl enable --now dove
journalctl -u dove -f                      # JSON logs, no mail content
curl -fsS http://127.0.0.1:8787/healthz    # "ok" or "degraded" (a mailbox needs re-authorization)
```

The unit (`deploy/systemd/dove.service`) runs as `dove` with no capabilities, `NoNewPrivileges`,
`ProtectSystem=strict` with write access only to `/var/lib/dove` and `/run/dove`, `MemoryMax=512M` and
`CPUQuota=200%`, system-call and address-family filters, and secrets via `LoadCredential=`. For the 1 GiB profile set
`MemoryHigh=900M` and `MemoryMax=1G`. `TimeoutStopSec=15s`: the service drains in-flight requests for up to 10
seconds (spec 8.2) and the extra 5 seconds let it exit before systemd sends SIGKILL. Two directives are
deliberately absent: `PrivateUsers=` would make the kernel report the operator's uid as unmapped and break the admin
socket's peer check, and `PrivateNetwork=` would cut Google and the proxy off.

Container:

```sh
cp deploy/config.container.toml deploy/config.toml    # edit public_url, google.client_id, admin.operator_uid
mkdir -p deploy/secrets                               # create the four secret files here, then:
sudo chown 65532:65532 deploy/secrets/* && sudo chmod 0400 deploy/secrets/*
$EDITOR deploy/Caddyfile                              # replace dove.example.com with your hostname
docker compose -f deploy/compose.yaml up -d
```

Then run the checks below with `docker compose exec` (see the header of the compose file).

Check the installation with `dove doctor`. It reports: configuration, service user versus operator uid, data
directory mode, admin socket mode, `allow_send`, Google reachability, index encryption, audit chain and the TLS
reachability of the public URL. Fix every `ok: false` before connecting mailboxes.

## Reverse proxy

Dove must not be reachable except through a TLS proxy that forwards an explicit allowlist (spec 6.6). The routes
Dove serves publicly (spec 5.6, 6.6):

| Method and path | Purpose |
| --- | --- |
| `POST /mcp` | MCP endpoint, bearer token required |
| `GET /oauth/google/callback` | Google consent callback for `dove accounts connect` |
| `GET /.well-known/oauth-protected-resource` and `.../mcp` | OAuth discovery for MCP hosts |
| `GET /.well-known/oauth-authorization-server` | OAuth issuer metadata |
| `GET`, `POST /oauth/dove/authorize` | Approval page |
| `POST /oauth/dove/token`, `/oauth/dove/register`, `/oauth/dove/revoke` | OAuth token, registration, revocation |
| `POST /connect/redeem` | Invitation redemption for `dove login` |

The downstream OAuth routes and `/connect/redeem` are in the allowlist already, but Dove does not implement them yet
(README status); it answers 404 until step 4 of the plan lands.

`/healthz` is deliberately not forwarded: it reveals whether any mailbox needs re-authorization. Probe the loopback
address instead. The admin interface is a Unix socket and is not reachable over HTTP at all.

- **Caddy:** [`deploy/Caddyfile`](../deploy/Caddyfile). Automatic TLS (TLS 1.2 and newer), HSTS, a 1 MB body limit,
  404 for everything else. Install Caddy, copy the file to `/etc/caddy/Caddyfile`, change the hostname, `systemctl
  reload caddy`.
- **nginx:** [`deploy/nginx/dove.conf`](../deploy/nginx/dove.conf), the same allowlist as exact, case-sensitive
  method and path pairs. nginx does not obtain certificates itself.

Both configurations set `X-Forwarded-For` to the client address (replacing, not appending) and drop `X-Real-IP` and
`Forwarded`. Dove reads the last `X-Forwarded-For` entry when the connecting peer is loopback. If your proxy appends
instead of replacing, a client can forge its address, and IP-bound tokens and audit source IPs become meaningless.

Caddy's `path` matcher ignores case, so `/MCP` is forwarded; Dove matches routes exactly and answers 404. The nginx
file matches case-sensitively and answers 404 itself.

## Connect mailboxes

All admin commands talk to the Unix socket (`/run/dove/admin.sock`, override with `--socket` or
`DOVE_ADMIN_SOCKET`) and work only for the configured operator uid (or root).

```sh
dove accounts connect --alias work-info --email info@example.com
```

The command prints a Google link that is valid for 10 minutes. Open it, sign in as exactly that address, continue
through the "unverified app" warning (Advanced), and approve both Gmail permissions. Dove then checks that the
approving Google identity equals the address you gave, that both scopes were granted (Google lets users untick
them), and that a refresh token works, before it stores anything. Anything else is rejected without storing a
grant. The page that follows tells you to close the tab.

Other commands: `accounts list`, `accounts check [alias]` (refreshes a token and calls the profile endpoint),
`accounts reconnect <alias>` (replaces the grant only after the new one is verified), `accounts disable|enable
<alias>`, `accounts remove <alias>` (revokes at Google, deletes the grant and key locally, keeps audit history).

Aliases match `[a-z0-9-]{2,40}`.

## Projects, clients and grants

A **project** groups mailboxes. A **client token** belongs to one project and sees only the intersection of its
explicit grants and the project's current mailboxes.

```sh
dove projects create acme
dove projects add-account acme work-info
dove projects add-account acme work-billing

dove clients create support-agent --project acme \
    --grant work-info=read,draft --grant work-billing=read --expires 90d --allow-ip 203.0.113.0/24
```

`clients create` prints the token (`dove_` followed by 43 base64url characters) **once**. Store it in the agent's
secret store, not in a project file. Grants are explicit per mailbox, `draft` requires `read`, and `send`
requires both. Adding a mailbox to a project gives existing tokens no new access. Other commands:
`clients set-grants <name> --grant ...` (replaces the whole set atomically), `clients rotate <name>`,
`clients revoke <name>`, `clients show <name>`, `clients list`, `projects list|show|remove-account`. Changes take
effect on the next request, without a restart. `--expires` takes `90d`, `12h`, `30m`, `45s` or `2w`.

Connect an MCP host with the bearer token, for example (command taken from the spec, not yet tried against a real
host):

```sh
claude mcp add --transport http dove https://dove.example.com/mcp --header "Authorization: Bearer dove_..."
```

`dove clients invite` exists for the future `dove login` and OAuth approval flow (README status). Until that lands,
use `clients create` tokens.

A `send` grant is refused unless `allow_send = true` is set in `config.toml`; that file is deployment-owner
configuration, and neither MCP calls nor the CLI can change it. See the README before enabling it.

## Administration access

- The admin protocol is newline-delimited JSON over a Unix socket. The service checks `SO_PEERCRED` and accepts only
  the configured `admin.operator_uid` (and root). Agent bearer tokens never reach admin verbs; the `dove` binary
  itself carries no authority, so copying it elsewhere helps nobody.
- The socket directory `/run/dove` is mode 0750 and group `dove`; the socket is 0660. Add the operator account to
  the group `dove` so it can reach the socket: `sudo usermod -aG dove <operator>`. Do not add agent accounts.
- Keep the config, unit, binary, state, secrets and deploy credentials out of agent control (spec FR-C1). An agent's
  shell must have neither the operator uid nor the service uid, no `sudo`, no inherited admin SSH access and no
  access to a privileged container socket. Use a separate host or a restricted OS account for agents. A shell
  running as the operator cannot be told apart from the operator by any CLI.
- Container deployments: whoever can run `docker` can run admin commands via
  `docker compose exec --user <operator_uid>:65532 dove /usr/local/bin/dove ...`. Treat Docker socket access as
  operator-level.

## Backup and restore

What the state store (`/var/lib/dove/state.db`) holds: wrapped per-mailbox keys, encrypted refresh tokens, keyed
hashes of client tokens, projects, grants, own-draft records, send state and the hash-chained audit log (no mail
content). The search index (`index.db`) is derived data and is **not** backed up.

Daily encrypted backup of the state store only. Use SQLite's online backup so you get a consistent copy while the
service runs; never copy `state.db`, `state.db-wal` and `state.db-shm` with `cp`.

```sh
# run as the service user, because /var/lib/dove is 0700
sudo -u dove sqlite3 /var/lib/dove/state.db ".backup '/var/lib/dove/state-backup.db'"
sudo -u dove age -R /path/to/backup-recipients.txt -o /var/backups/dove/state-$(date +%F).db.age /var/lib/dove/state-backup.db
sudo -u dove rm /var/lib/dove/state-backup.db        # the plain copy must not stay on the host
```

`age` is one choice; any strong file encryption you already operate (for example GnuPG) works. Keep the backup
encryption key separate from the KEK. Ship the encrypted file off the host. Exclude `index.db`, any `-wal` and
`-shm` files, and temporary data from backups and from deployment artifacts. The `.backup` command itself was
checked on a freshly initialised scratch store; the `age` step and the off-host transfer are your setup and untested here.

Keep `kek` and `pepper` backups **offline and apart** from state backups. Without the KEK, a state backup cannot
decrypt any Google token; without the pepper, restored client tokens do not authenticate.

Restore:

1. Stop the service (`systemctl stop dove`).
2. Decrypt the backup to `/var/lib/dove/state.db`, owner `dove`, mode 0600; the directory stays 0700. Remove old
   `state.db-wal` and `state.db-shm` files.
3. Delete `index.db` and its `-wal` and `-shm` files. A restore **starts a fresh index** and does not claim coverage
   until it has caught up.
4. Put the matching `kek`, `pepper` and `index_key` back, in the same versions that were current when the backup was
   made (a backup wrapped under KEK version 1 needs that version 1 line, see [KEK rotation](#kek-rotation)).
5. Start the service, run `dove doctor`, `dove accounts check`, `dove audit verify`.

Test a restore on a scratch machine before you need it. The mailboxes' Google grants stay valid on Google's side
across a restore, but a mailbox removed after the backup comes back in Dove's state; run `accounts remove` again.

## Upgrades and migrations

Schema migrations are versioned and run at startup, each inside a transaction. A failed migration stops startup and
leaves the store untouched. There are no down-migrations: to roll back to an older binary, restore the state backup
you took before upgrading.

1. Back up the state store (previous section).
2. Install the new binary (`install -m 0755 ... /usr/local/bin/dove`) or build a new image.
3. `systemctl restart dove` (or `docker compose up -d`). Read the journal for migration errors.
4. `dove doctor`.

## KEK rotation

The KEK file is read-only to the service (a credential). Rotation re-wraps each mailbox key under a new KEK version
(plan assumption A8):

1. Append a new version line, keeping the old one:
   `sudo sh -c 'umask 077; dove keys generate --version 2 >> /etc/dove/credentials/kek'`
   (the new version must be the highest number).
2. Restart the service so it loads both versions.
3. `dove keys rotate`. It re-wraps every grant under the newest version and prints
   `versions_in_use` and `versions_safe_to_delete_from_kek_file`.
4. Remove the old version line from the file once it is safe, and restart.

The old KEK version stays necessary for any state backup taken before the rotation: keep the old line in your
offline KEK backup for as long as you may restore such a backup, or accept that those backups become unreadable.
A rotated-away KEK that is destroyed makes every older backup's grants unrecoverable, which is also the point.
Rotating the pepper is not supported: it would invalidate every client token. The index key can be replaced by
deleting the index files and rebuilding once the index exists.

## Deleting data: logical versus physical

`dove accounts remove <alias>` revokes the grant at Google (best effort), deletes the grant and the mailbox's key
from the current state, and purges derived index rows. It is logical removal of current state. What it does **not**
do:

- It does not erase earlier **state backups**: they still hold the wrapped key and encrypted grant. Delete them, or
  destroy the KEK versions they depend on.
- SQLite runs with `secure_delete` on, so freed pages in the database file are overwritten, but the write-ahead log,
  filesystem snapshots, copy-on-write filesystems and flash wear levelling can retain older bytes. To reclaim pages
  and truncate the log: stop the service, run `sqlite3 state.db "VACUUM; PRAGMA wal_checkpoint(TRUNCATE);"` as the
  service user, start it again. Even then, snapshots on the host or provider side are outside Dove's control. Do not
  rely on this as secure erasure.
- Revocation at Google independently ends the token's validity, which is the stronger guarantee for the Google
  side. If revocation failed, remove Dove's access in the Google account's security settings.
- The audit log keeps its history by design (alias, ids, result codes; no mail content). Pruning follows
  `audit.retention_days` or `dove audit prune`.

## What has been verified

Checked in this repository's work, with the tool named; "not verified" means nobody has run it.

| Artifact | Verified | Not verified |
| --- | --- | --- |
| `deploy/systemd/dove.service` | `systemd-analyze verify` (only warning: the binary was not installed on the check machine); `systemd-analyze security --offline` exposure 1.4 OK; the binary started with `LoadCredential`, `StateDirectory`, `RuntimeDirectory`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `ProtectProc`, `MemoryDenyWriteExecute`, `SystemCallFilter`, `RestrictAddressFamilies`, `NoNewPrivileges` and memory/task/file limits as a transient `systemd-run --user` unit: served `/healthz`, accepted `dove doctor` over the socket (Google reachable), stopped cleanly | Running as a system service with `User=dove`; `PrivateDevices`, `ProtectKernelTunables/Modules/Logs`, `ProtectClock`, `ProtectHostname`, `CapabilityBoundingSet=` (the user manager cannot apply them); sysusers and tmpfiles snippets |
| `deploy/Containerfile`, `compose.yaml` | Built with Docker 29; 66 MB image; `--version` and `config-example` run read-only with all capabilities dropped; the compose stack started read-only with `cap_drop: ALL`, `no-new-privileges`, 512 MiB limit, secrets from files, tmpfs socket directory; Caddy shared Dove's network namespace and proxied to the loopback listener; `dove doctor` worked via `exec --user <uid>:65532`, another uid was refused; `stop` exited 0 | Podman; a real TLS certificate; the 1 GiB profile; memory behaviour under load |
| `deploy/Caddyfile` | `caddy validate` (Caddy 2.11); every allowlisted method/path pair forwarded, other methods and paths 404 (including `/healthz`, `GET /mcp`, `/mcp/`, `//healthz`, `/mcp/%2e%2e/healthz`); forged `X-Forwarded-For`, `X-Real-IP`, `Forwarded` replaced or dropped; a 2 MB body got 413 | Automatic certificate issuance; chunked uploads at the proxy |
| `deploy/nginx/dove.conf` | `nginx -t` (1.30) with a throwaway certificate; same route matrix as Caddy, `/MCP` and `//mcp` get 404; 2 MB body got 413 | Certificate handling |
| `.github/workflows/ci.yml` | `actionlint`; YAML parse; the gitleaks container step run locally, clean on this repository and failing on a planted key; `cargo deny check` (0.20.2) passes | The workflow has not run on GitHub |
| Backup | `sqlite3 .backup` of a running, freshly initialised store gave an intact copy (`PRAGMA integrity_check` ok) | `age` encryption step, off-host transfer, a full restore drill |
