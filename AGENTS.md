# AGENTS.md

Guide for coding agents working on Dove. Keep it current: when you learn something durable about this repo
(a pitfall, a command that works, a decision), add it under "Learnings" in the same commit as the change.

## What this is

Dove is a self-hosted MCP server that gives AI agents token-scoped read/draft access to Gmail mailboxes.
Spec: `docs/spec.md`. Plan, status and assumptions: `docs/PLAN.md`. Rust, one package (`dove-mcp`), one binary
(`dove`) with service, local admin and remote client subcommands.

## Commands

The host is shared. Use `heavy` for full builds and the full test suite; keep jobs low.

```sh
export PATH=$HOME/.cargo/bin:$PATH
CARGO_BUILD_JOBS=3 heavy cargo build              # full build
CARGO_BUILD_JOBS=3 heavy cargo test -- --test-threads=2   # full suite
cargo test --lib vault::                          # one module, no heavy needed
cargo test --test <file>                          # one integration test file
cargo clippy --all-targets -- -D warnings
cargo fmt
```

## Layout

- `src/config.rs`, `src/secrets.rs`: config file, secret files, startup checks
- `src/vault.rs`: envelope encryption of Google refresh tokens
- `src/store/`: durable state store (SQLite WAL), migrations, repositories
- `src/audit.rs`: hash-chained audit log
- `src/admin/`: Unix socket admin protocol (server + CLI client)
- `src/policy.rs`: the single authorization decision point
- `src/gmail/`: outbound gateway (allowlist), token manager, typed Gmail operations, MIME/HTML handling
- `src/imap/`: IMAP/SMTP provider; `ops.rs` is the command allowlist and the only place that builds command strings
- `src/mcp/`: JSON-RPC / Streamable HTTP protocol layer; `src/tools/`: tool handlers
- `src/index/`: SQLCipher FTS5 index, sync engine, query compiler
- `src/client/`: remote client commands (login, search, mcp install, stdio bridge)
- `src/update/`: `dove upgrade` (signed GitHub Releases) and the daily new-version notice; CLI only
- `tests/`: integration tests against the fake Google server in `tests/support/`

## Security invariants (do not weaken)

- Agent tokens never reach admin verbs. Admin happens only over the Unix socket after a peer-uid check.
- Unknown and out-of-scope accounts/objects return the identical `not_found`.
- Every tool call goes through `policy::authorize` and produces exactly one audit record.
- No mail content, subjects, addresses, tokens or OAuth codes in logs or audit records.
- Outbound HTTP only through `gmail::gateway`, which enforces the exact method/path allowlist (spec 7.5).
- SQLite transactions never span an `.await` on network I/O. Blocking DB work runs in `spawn_blocking`.
- Secrets are read from files with strict modes, never from env vars.

## Conventions

- Errors to agents use the stable codes in `src/error.rs` (spec 5.4).
- Time is stored as unix seconds (i64, UTC). Wire format is RFC 3339. Exception: the index stores Gmail
  `internalDate` in milliseconds (PLAN A12) for exact ordering and ties.
- Tests: write the test, break the code on purpose to see it fail, then fix. No trivial tests.
- Commit after each verified change; only your own files. Message style: imperative, scoped (`vault: ...`).

## Learnings

- 2026-11-12: Rust toolchain lives in `~/.cargo/bin` (rustup, no system Rust). Crate versions are newer than
  older model knowledge (reqwest 0.13, rand 0.10, hmac 0.13/sha2 0.11 on digest 0.11, chacha20poly1305 0.11,
  rusqlite 0.42). Check APIs in `~/.cargo/registry/src/*/<crate>-<ver>/` instead of guessing.
- 2026-11-12: axum 0.8 rejects `Option<ConnectInfo<_>>` as an extractor; take the full `Request` and read
  `ConnectInfo` from its extensions. Streams with `buffered(n)` over closures that borrow locals need
  `let x = &x;` rebinding before the `move` closure, or rustc reports "FnOnce is not general enough".
- 2026-11-12: reqwest `.header()` appends; a test helper that sets defaults must build a `HeaderMap` with
  `insert` or overrides silently become duplicate headers (the server sees the first value).
- 2026-11-12: Mutation checks catch weak tests: a guard that is shadowed by a second check (e.g. stale revision vs
  human-owned draft, single-use state vs alias-exists) needs a test where only that guard can fire.
- 2026-11-12: `pkill -f <pattern>` inside a Bash tool call matches the tool's own shell; use `pgrep -af` and kill
  by PID.
- 2026-11-12: Gmail writes go through `Google::write`, which classifies failures once: not dispatched or 4xx is
  definitive (safe to retry), 5xx / lost response / unreadable body is `outcome_unknown`. Never classify by
  matching error message text.
- 2026-11-12: AC19 runs the real CLI as `nobody` (`cargo test --test agent_shell -- --ignored`, needs passwordless
  `sudo -n -u nobody`). On this dev host agent sessions run as uid 1000 with passwordless sudo, so a deployment
  here would give agents admin rights (operator uid or root). Production needs an agent uid that is neither the
  operator uid nor able to sudo.
- 2026-11-12: Do not set `PrivateUsers=` in the systemd unit: inside a user namespace `SO_PEERCRED` reports the
  operator uid as unmapped, and the admin socket's peer check rejects the operator. `systemd-analyze verify` only
  checks syntax; to test sandbox directives run the binary as `systemd-run --user` (the user manager cannot apply
  capability-dropping directives such as `PrivateDevices=`, so those stay untested there). `StateDirectoryMode=0700`
  is required, the service refuses any other data dir mode.
- 2026-11-12: Caddyfile named matchers with several conditions need the block form (`@x { method POST; path /mcp }`
  on separate lines). `@x method POST path /mcp` parses as extra method names and forwards every GET. Caddy `path`
  is case-insensitive and nginx `map` keys are too unless prefixed with `~`; always test the allowlist with a real
  proxy (docker `caddy:2`, `nginx:stable-alpine`), see docs/deployment.md.
- 2026-11-12: Compose ignores `uid`/`gid`/`mode` of file secrets outside Swarm; the host file itself must be owned by
  65532 with mode 0400, or Dove refuses to start. The distroless image has no shell: run admin commands with
  `docker compose exec --user <operator_uid>:65532 dove /usr/local/bin/dove ...`. Dove listens on loopback only, so
  Caddy joins its network namespace (`network_mode: service:dove`) and the ports are published on the dove service.
- 2026-11-12: The docker host is shared with production. For container tests use unique names (`dove-t-*`), never
  `docker system prune`, and remove only your own images and volumes.
- 2026-11-12: `cargo deny check` (deny.toml) passes only with two documented advisory ignores: RUSTSEC-2023-0071 (rsa)
  and RUSTSEC-2026-0387 (crypto-bigint), both pulled in by jsonwebtoken's `rust_crypto` backend. Dove only verifies
  RS256 signatures, so they do not apply; drop the ignores once jsonwebtoken updates. MPL-2.0 (the scraper/cssparser
  stack) and sqlcipher-src (WTFPL, blessing) are allowed explicitly. CI scans secrets with the gitleaks container
  image (no licence key needed), pinned by digest; locally: `docker run --rm -v $PWD:/repo ghcr.io/gitleaks/gitleaks:v8.30.1 dir /repo`.

- 2026-11-12: Edition 2024 reserves `gen`; name generation variables `gen_id`/`generation` (SQL column names are fine).
- 2026-11-12: Disk-full can be simulated on the index with `PRAGMA max_page_count = <current page_count>` on the
  writer connection (after `wal_checkpoint(TRUNCATE)`); writes then fail with SQLITE_FULL.
- 2026-11-12: The fake Google's page tokens are offsets. Deleting several already-listed messages between pages
  shifts later pages and makes enumeration skip messages (real Gmail tokens do not); avoid that in sync tests.
- 2026-11-12: Index jobs, purge, rebuild and sync-state creation serialize on a per-account lock; every write also
  re-checks the job's fence. Tests: `dove::index::sync::{sync_account, sync_steps}` run passes deterministically.
- 2026-11-12: Without ANALYZE data SQLite planned `m.id IN (SELECT msg FROM addrs ...)` as a scan of the whole
  mailbox partition; the fixed `sqlite_stat1` rows in index migration V2 fix that. If you add an index, add a stat row
  and extend the EXPLAIN QUERY PLAN assertions in `tests/search_contract.rs`.
- 2026-11-12: Timestamp ties are ordered by random fake message ids; tests must not assume which tied row comes first.
- 2026-11-12: The state store is one mutex-guarded connection, so concurrent HTTP requests serialize at the DB.
  An atomic guard (e.g. `UPDATE ... WHERE used_at IS NULL`) is then shadowed by the earlier read in the same
  transaction; test it directly with a stale view (see `invite::tests`) or the mutation survives.
- 2026-11-12: `cargo test --test a --lib foo::` applies the `foo::` filter to every target; run filtered lib
  tests and integration files in separate invocations when mutation-checking.
- 2026-11-12: The shared `CARGO_TARGET_DIR` holds one `target/debug/dove` for all worktrees; another agent's build
  can replace it between your build and test run. Tests that exec `CARGO_BIN_EXE_dove` (`tests/client_e2e.rs`)
  need a private target dir per worktree (the default `<worktree>/target` is private).
- 2026-11-12: Client tests run the binary with `env_clear()`, a temp HOME and
  `DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent/...` so the real keychain and config are never touched.
- 2026-11-12: The client address is resolved once in the HTTP guard (`http::client_ip`, PLAN A30) and read by handlers
  with `http::request_ip(&req)`; never parse `X-Forwarded-For` in a handler. Tests simulate a client address by
  sending `X-Forwarded-For` together with `X-Dove-Proxy-Auth: <app.proxy_secret>` (the test config sets a secret;
  `c.secrets.proxy_secret_file = None` gives the legacy behaviour).
- 2026-11-12: Approval-page checkboxes are `read.<account_id>`; e2e helpers translate positional `read.0` via
  `check_name` in `tests/oauth_e2e.rs`. The bundled SQLCipher has JSON1 (`json_each`, `json_extract`).
- 2026-11-12: When mutation-checking with `sed`, confirm the mutation applied (`grep -c`) before trusting a passing
  test; quoting `$` or `'` in patterns silently matches nothing.
- 2026-11-12: Canary checks must compare whole secrets (minus known `dove*_` prefixes). Cutting at the first `_`
  made random base64url secrets degenerate to 1-3 characters and caused a flaky "secret found in logs".
- 2026-11-12: There is no shared `fts` table any more (index V3): each generation has `fts_g<gen>`, created by
  `index::new_generation` and dropped only through `index::drop_generation` (bounded steps). Tests that count
  postings must iterate the `fts5` tables in `sqlite_schema`. Never build an FTS table name from anything but the
  integer generation id.
- 2026-11-12: serde never borrows through `Option<Cow<'a, str>>` (it copies even with `#[serde(borrow)]`); use a
  plain `Cow<'a, str>` with `#[serde(default)]` or `&'a str`. Memory claims are checked with the counting global
  allocator in `tests/ingest_memory.rs` (one test per binary, the counter is process-wide); its measurement test is
  `--ignored`. Do not build `--release` ad hoc: it is a full build and belongs under `heavy`.
- 2026-11-12: First real systemd install (systemd 259): `LoadCredential=` copies are 0440 root:root with an ACL for the
  service user, so a strict "no group bits" secret check rejects them; `secrets::secret_mode_ok` allows that one case
  (A44). Test unit directives with `sudo systemd-run --wait --pipe -p User=dove -p LoadCredential=...` before
  documenting them. Globs over root-only directories in docs must run inside `sudo sh -c '...'`.
- 2026-11-12: The IMAP/SMTP client is hand-written (`src/imap/`), not `async-imap`: it is small, uses the rustls,
  aws-lc-rs provider and platform verifier already in the tree through reqwest (no new crates), and lets outcome
  classification follow exactly where a write stopped (`ExecError::sent_all`, SMTP `data_terminator_sent`).
  Plaintext exists only as `ImapConnector::plaintext_for_tests()` (cfg `test`/`testing`). Tests use
  `tests/support/fake_imap.rs`: non-PEEK fetches set `\Seen` there, `fail_next_containing` targets one command
  (for example the body fetch), and `assert_only_allowlisted()` checks the command log.
- 2026-11-12: IMAP accounts (`accounts.provider = 'imap'`) keep their sealed password in `grants` (vault AAD kind
  `imap_password`, so `open_grant` fails on it): code that walks `grants` (remove, keys rotate) must branch on
  `provider`. `zeroize::Zeroizing`'s `Debug` prints the secret, so admin requests carry passwords as
  `admin::Password` (redacted `Debug`). Tests connect IMAP mailboxes with `Harness::imap_mailbox` (real
  `AccountsConnectImap` against `h.imap`); assign `h.imap = FakeImap::start_with(..)` before connecting to change
  server options. Connect errors name the step and server address only, never server text.
- 2026-11-12: Tools read messages through `mail::fetch_message` / `mail::list_labels`, which dispatch on
  `Mailbox.provider`; `read::Fetched.meta` is a typed `mail::MessageMeta`. Gmail-only paths that reach
  `TokenManager::access_token` with an IMAP account get `invalid_argument` (never the vault or Google). Extra MCP content
  items (the `get_attachment` resource) go in `ToolOutput.extra`; `Remote::call_tool` keeps them in `ToolResult.content`.
  IMAP `get_thread` takes `message_id` until the index can resolve derived thread ids. `tests/support/fake_imap.rs`
  takes UTF-8 folder names while `imap_folders.name` stores the wire name (modified UTF-7).
- 2026-11-12: IMAP index sync lives in `src/index/imap_sync.rs`; `sync::sync_steps` dispatches on `accounts.provider` (one
  scan per job, then pending batches, then publish). Rows key on the agent id `f<folder>-<uidvalidity>-<uid>`, so a
  folder is the key range `[f3-, f3.)` of `messages(gen, gmail_id)` (`-` sorts right before `.`; folder 31 is outside).
  Per-folder checkpoints are `imap_checkpoints` (index V4, WITHOUT ROWID: its `sqlite_stat1` row names the table itself
  as `idx`); `drop_generation_step` deletes them with the generation. Tests: connect enables indexing but creates no
  sync state and the harness runs no scheduler, so call `IndexEnable` and then `dove::index::imap_sync::sync_steps`.
- 2026-11-12: Without CONDSTORE (Strato) flags come from a bounded flags-only refresh per folder and scan (newest
  `RECENT_FLAGS` plus a rotating `ROTATE_FLAGS` window); deletions are detected by count (known UIDs below UIDNEXT vs
  `EXISTS` minus new) and only a mismatch costs a `UID SEARCH ALL`. Tests assert the command log for both paths.
- 2026-11-12: `imap::account::with_session` closures are higher-ranked over the session lifetime, so captures must be
  owned (`Arc<App>`, cloned ids). To keep partial results when the session fails (and is dropped), write them to an
  `Arc<Mutex<..>>` captured by the closure (see `imap_sync::hydrate`). IMAP folder names sit in plaintext in the state
  store (`imap_folders`), not in the index.
- 2026-11-12: `source:"gmail"` naming an IMAP mailbox is `invalid_argument`; without an account list IMAP mailboxes show
  up in `account_errors`. Index text operators are `terms`, `phrase`, `prefix` (there is no `contains`).
- 2026-11-12: IMAP drafts (`src/tools/drafts_imap.rs`): `own_drafts.message_id` is the `f<folder>-<uidvalidity>-<uid>`
  id (also the revision), `content_hash` the SHA-256 of the bytes the server returns after `APPEND` (never Dove's own
  bytes: servers rewrite). Ownership needs record + same Drafts folder id + UID present + hash match; anything else is
  `draft_conflict`. The previous UID is deleted only after the new revision is recorded, never after an unknown
  `APPEND`. `OwnDraftUid::new_for_drafts` has exactly one caller (`drafts_imap.rs`), enforced by a source scan in
  `tests/imap_drafts_e2e.rs`; its `deletions()` helper checks every `UID STORE`/`UID EXPUNGE` in the fake's log.
  Non-owned IMAP drafts use their message id as `draft_id`; `list_drafts` pages by UID (`page_token` = next upper bound).
- 2026-11-12: IMAP send: SMTP gets the draft's server bytes without `Bcc` (`mime::without_header`), envelope recipients
  from To/Cc/Bcc, envelope sender the account address. Only a lost reply after the final `.` is `send_unknown`; any
  SMTP refusal (code in `details.smtp_code`) returns the draft to `active`. After `sent` is recorded, Dove files the
  draft's bytes (Bcc kept) in Sent with `\Seen` unless `save_sent_copy` is false, then deletes its draft; both are best
  effort and reported once. SMTP framing always ends DATA with CRLF, so compare submitted bytes with that in mind.
  Test SMTP-only auth failures with `smtp_fail_next("AUTH", SmtpFault::Reply(535))` (IMAP keeps working).
- 2026-11-12: IMAP IDLE (`src/index/imap_idle.rs`): the supervisor and the scheduler are not started by the harness;
  tests start them with `dove::index::imap_idle::start(app)` / `dove::index::start(app)` and abort the handles.
  `app.index.idle.is_healthy(account_id)` tells whether a mailbox is idling. The fake server offers IDLE by default
  (`Opts { idle: false, .. }` to test polling, `idle_timeout` for a server BYE, `kick_idle()` for a silent drop) and
  counts `open_connections`, `max_open_connections` and `idling`. `ImapSession::idle_next` has no timeout and is
  cancel-safe (state lives in the session), so it can sit in `select!`; every other command is refused while idling.
- 2026-11-12: The harness's 3 s IMAP command timeout and 8 s tool deadline bound most stalls on their own; a test of a
  smaller budget (search freshness, 2 s) must raise both or the budget mutation survives. Freshness tests age
  `sync_state.last_success_at` instead of sleeping past the 5 s threshold.
- 2026-11-12: Draft attachments (`src/tools/compose.rs`, `mime::build_draft`): attachment leaves are written base64
  with an explicit `Content-Transfer-Encoding`, because mail-builder sends `text/*` bodies as 7bit/QP and turns bare
  LF into CRLF (a test needs a plain-ASCII LF-only text attachment to catch that). `ParsedMessage::is_draft_shape`
  (text/plain, or `multipart/mixed` = body + attachment leaves) is what update and `editable_by_dove` accept.
  Grants enforce `draft` ⇒ `read`, so "source without read" tests must use a mailbox the token is not granted.
  Sources are authorized in `compose::parse_attachments` / `readable_message` before the send-as lookup; tests check
  `google.requests()` and `imap.commands()` are empty right after the refused calls (clearing the log later hides a
  regression). `/mcp` authenticates before reading the body (`Limits::draft_body_bytes` for clients with draft).
  To scan audit rows as text, read cells as `rusqlite::types::Value` (`get_ref` Debug prints bytes).
- 2026-11-12: Build speed, measured: a cold `cargo build` in a fresh target dir takes about 3 min at 3 jobs and is
  dominated by the vendored OpenSSL/SQLCipher C build. sccache (enabled in `~/.cargo/config.toml`) caches the Rust
  crates across target dirs but not that C build (paths differ per `OUT_DIR`), so it saved only ~3 %. The dev profile
  uses `debug = "line-tables-only"` and no debug info for dependencies: a fresh target with all test binaries is
  ~5 GB. Old target dirs grow past 30 GB; `cargo clean` them now and then. Copying a target dir to seed a worktree
  is slower than building.
- 2026-11-12: IMAP response memory (`src/imap/session.rs`): `* SEARCH` / `* VANISHED` lines are parsed from bytes
  (never tokenized) and are the only lines allowed past `MAX_LINE` (up to `BIG_LINE`). Everything a command keeps goes
  into `Collected` and is charged to one budget (literal cap + `RETAINED`); flag/size FETCHes become `FetchedMeta` on
  arrival. VANISHED stays `UidRanges` (never expand a range; look known UIDs up in it). Session unit tests fake a
  server with `answering(bytes)` / `over_stream(io)`; a write failure can be injected with a wrapping `Io`.
- 2026-11-12: Upstream priorities: `ImapPool::with_session` is interactive, `with_session_prio(.., Background, ..)`
  (index sync) also takes the gateway's background slot. Tests exhaust it with
  `app.google.gateway().background_limit().acquire_many_owned(..)`. One IMAP sync scan or fetch batch is bounded by
  `index.imap_step_timeout_secs`; `Fault::Delay` on `EXAMINE` makes a scan slow without tripping the command timeout.
- 2026-11-12: IMAP thread ids hash root Message-ID + `mail::thread_subject` (PLAN A47); changing the formula needs an
  index migration that rebuilds IMAP generations (V5 pattern), since stored rows lack the References root. Every
  server-provided label (folder, keyword) goes through `mail::label_text`; agent-visible folder names come only from
  `utf7::display_name`.
- 2026-11-12: A shell wait loop `until ! pgrep -f "<cmd>"` matches its own command line and never ends; wait on cargo
  in the foreground instead. `cargo test --test a --test b` stops at the first failing binary, so a mutation run
  over several files can skip the test meant to catch it: run that file alone (or `--no-fail-fast`).
- 2026-11-12: Write tools (create/update/send draft) run detached (`tools::detached`) and must call `cx.commit()` right
  before their first side effect (send claim, APPEND, Gmail write); upstream writes use `cx.write_deadline()`, never
  `cx.deadline`. A new write tool needs both, or a call timeout can drop a dispatched write's record. Tests shrink the
  budget (`tool_call_timeout_secs = 4`) and raise `upstream_request_timeout_secs` so one `Fault::Delay` /
  `SmtpFault::Delay` outlives the call; Gmail write tests must raise the request timeout too, or the 3 s harness
  request timeout ends the write before any deadline does.
- 2026-11-13: Self-update (`src/update/`) trusts only `SHA256SUMS` signed by `deploy/release/minisign.pub` with the
  trusted comment `dove <tag>`. Tests pass a `update::Source` (bases, key, current version, target) pointing at a local
  fake server; there is no env override for the production URLs. Fixtures in `tests/fixtures/update/` are signed with
  a throwaway key whose secret was not kept: to change one, rebuild all with `build.py`, a new key (minisign in an
  `ubuntu:24.04` container) and replace `test.pub`. The tar crate's `Builder` refuses `..` paths, so traversal
  archives are made with Python's `tarfile`. A source scan in `tests/update_e2e.rs` keeps `serve` away from the
  updater. Dropping a tokio runtime waits for blocking tasks (a hanging DNS lookup), so `main` uses
  `shutdown_background()` when the notice check ran; try the notice in a pty with `script -qec "<cmd>" /dev/null`.
  The notice never runs privileged (euid 0, euid != uid, `SUDO_UID` set: `sudo -E` keeps the user's HOME), and its
  cache writes never follow symlinks (owned real dir, `O_EXCL|O_NOFOLLOW` temp file, rename onto the literal path).
- 2026-11-13: Sending identities live in `src/identity.rs` (tables `account_aliases`, `account_signatures`, migration
  `V_SEND_IDENTITIES`). The IMAP sender is checked twice, at `create_draft` (`dispatch_create`) and again in
  `drafts_imap::prepare_send`, where the From header decides the SMTP envelope sender (login address unless the alias
  has `envelope`). `from.email` is already lowercased there, so a mutation that drops the `to_lowercase` in
  `signature_for` survives (equivalent mutant). `update_draft` never signs; the signature goes in before the
  quote/forward join in `dispatch_create`. Admin audit rows for alias/signature verbs hold no address and no text.
- 2026-11-13: `src/tailscale.rs` is CLI-side only (the service never calls `tailscale`). `PUBLIC_PATHS` is the one list of
  public routes; `allowlists_do_not_drift` compares it with `deploy/Caddyfile`, `deploy/nginx/dove.conf` and the
  `.route(...)` literals in `src/http.rs`, `src/mcp.rs`, `src/oauth.rs`: a new route needs a line in all of them (and
  must be a string literal or `AUTHORIZE_PATH`). Tests fake `tailscale` with a shell script that keeps serve state in
  files (`tests/tailscale_e2e.rs`); write it once per process (writing an executable per test races with other tests'
  forks, ETXTBSY) and keep `/usr/bin:/bin` in the child's PATH (the script needs `cat`, `awk`). Never run the real
  `tailscale serve`/`funnel` here: the host's Tailscale serves other things (read-only `status --json` and
  `serve status --json` are fine). Real node JSON: `Self.DNSName` has a trailing dot, `CertDomains` empty means HTTPS
  is off, `Self.CapMap` has a `funnel` key when Funnel is allowed, serve state keys are `host:port`.

