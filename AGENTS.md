# AGENTS.md

Guide for coding agents working on Dove. Keep it current: when you learn something durable about this repo
(a pitfall, a command that works, a decision), add it under "Learnings" in the same commit as the change.
Notes about one particular machine or deployment (build wrappers, hostnames, ports, local users) go in
`AGENTS.local.md` instead: it is gitignored, so read it when it exists and never commit it.

## What this is

Dove is a self-hosted MCP server that gives AI agents token-scoped read/draft access to Gmail mailboxes.
Spec: `docs/spec.md`. Plan, status and assumptions: `docs/PLAN.md`. Rust, one package (`dove-mcp`), one binary
(`dove`) with service, local admin and remote client subcommands.

## Commands

```sh
cargo build                                       # full build
cargo test -- --test-threads=2                    # full suite
cargo test --lib vault::                          # one module
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
- `src/client/`: remote client commands (login, search, mcp install, stdio bridge, `watch` incl. `watch listen`)
- `src/update/`: `dove upgrade` (signed GitHub Releases) and the daily new-version notice; CLI only
- `src/requests/`: agent requests (scheduled sends approved on the admin socket): store, admin verbs, send worker
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
  `sudo -n -u nobody`). Production needs an agent uid that is neither the operator uid nor able to sudo: an agent
  running as the operator or with sudo has admin rights.
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
  `--ignored`. Do not build `--release` ad hoc: it is a full build.
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
  `tailscale serve`/`funnel` from tests or while developing: it changes the machine's Tailscale config (read-only
  `status --json` and `serve status --json` are fine). Real node JSON: `Self.DNSName` has a trailing dot, `CertDomains` empty means HTTPS
  is off, `Self.CapMap` has a `funnel` key when Funnel is allowed, serve state keys are `host:port`.

- 2026-11-13: Watches (`src/watch/`, `src/tools/watches.rs`): events come from one hook,
  `watch::messages_indexed`, called by `sync::commit_results` after its transaction with the ids that were new rows of
  the serving generation (both engines go through it, so IMAP polling and IDLE need nothing extra). Matching re-checks
  the serving generation in its own index read, then records events in a state-store transaction that re-checks the
  watch's liveness (`watch::end_reason`). Tests drive the clock through `watch::tick(app, now)` and
  `watch::sinks::deliver_due(app, now)`; the harness starts no watch worker. Webhook receivers in tests are plain HTTP
  on loopback, which only `gateway().allow_plain_http_sinks_for_tests()` (cfg `test`/`testing`) permits; call it
  before `SinksAdd`, and again plus `watch::sinks::reload_allowlist` after a harness restart. Index `received_at` is
  milliseconds but IMAP INTERNALDATE has second precision, so "newer than" comparisons against a thread baseline need
  `>=` for newly indexed mail (a reply can share the second). Fake Google's `MessageSpec.from` takes a bare address;
  `"Name <addr>"` is not parsed into the address.
- 2026-11-13: Grants: `Actions::parse` reads stored lists only (no presets); operator input goes through
  `Actions::parse_grant` (presets + actions) in `admin::ops::resolve_grants`, which also serves invitations. Narrowing
  uses `Actions::intersect`, which keeps the dependency rules. `list_accounts` hides `send` while `allow_send` is off,
  so tests of the send gate must read `client_mailboxes.actions`.
- 2026-11-13: Organize tools live in `src/tools/organize.rs`. IMAP `\Deleted` outside Drafts exists only as
  `ImapOp::UidStoreDeletedCopied(&[CopiedUid])`; `CopiedUid::confirmed_by_copyuid` is private to `session.rs` and called
  once in `move_uids` (source scan in `tests/imap_organize_e2e.rs`, whose `assert_expunges_only_copied_or_own` walks
  the command log). The fake IMAP server offers `MOVE` and `COPYUID` by default (`Opts { move_cap, copyuid }`); folders
  added after connect need a `list_labels` call before Dove knows them. Gmail organize tests drop `gmail.modify` from
  `accounts.granted_scopes` to simulate a pre-0.2 grant; the fake Google answers `messages.modify` with 400 for
  unknown label ids and TRASH (use `messages.trash`).
- 2026-11-13: A `buffered` stream over closures that borrow `ids` fails with "FnOnce is not general enough" even with
  rebinding when the future is returned from a generic `Fn`; collect `Pin<Box<dyn Future + Send + 'a>>` first, then
  `stream::iter(futs).buffered(n)` (see `organize::gmail_each`).
- 2026-11-13: Mail intelligence (index V6, `src/calendar.rs`, `src/attachment_text.rs`, `src/index/intel.rs`,
  `src/tools/{contacts,digest}.rs`). FTS5 tables cannot be altered: new generations have `(subject, body, att)`,
  old ones two columns and `generations.att_fts = 0`; query code must check `Target::att_fts` before naming `att`.
  Rows from before V6 have `category`/`att_complete` NULL = unknown, never "no": positive predicates skip them and
  `tools::search::field_coverage` reports the gap, so a test that fakes old rows sets them to NULL. A migration that
  rebuilds accounts (V5, V6 pattern) makes tests of an earlier step apply only that step (`MIGRATIONS[n]`).
- 2026-11-13: Attachment text is untrusted-input parsing with a CPU/memory budget: the hand-written ZIP reader never
  trusts declared sizes (inflate through `read_bounded`), the XML scanner expands no entities and searches `;` only
  13 bytes ahead (an unbounded `find(';')` was quadratic), PDF names are matched after `#XX` resolution and with the
  PDF whitespace set including NUL (`/Obj#53tm`, `/ObjStm\0` evaded a substring or `is_ascii_whitespace` check).
  lopdf's load cannot be interrupted, so every cap must act before it. Panic messages may quote document content:
  `guarded()` mutes the process-wide hook for the extracting thread only.
- 2026-11-13: SQLite plans: `addrs_name` must contain the selected column (`addr`) to be a covering scan, otherwise
  the planner reads the table through `addrs_addr`. The digest walks `messages_date` (range on `received_at`) and
  probes `labels` per row with a correlated `EXISTS`; the `IN (SELECT msg FROM labels ...)` form made it walk every
  INBOX label row. Plan assertions for both live in `tests/mail_intel_e2e.rs::contact_and_digest_queries_use_indexes`.
- 2026-11-13: Test fixtures for mail intelligence build raw MIME by hand (`MessageSpec.raw`) and ZIPs/PDFs in the test
  (`zip_entries`, lopdf builder), because mail-builder cannot set `List-Unsubscribe` or calendar parts. A search that
  names a granted but unindexed mailbox is `partial` ("indexing is not enabled"), so tests index every granted
  mailbox. Fake IMAP messages need `add_message_at(.., now)` for date windows (the default date is old).
- 2026-11-13: Gmail over IMAP (PLAN A57): `ImapSettings.gmail` is set once at connect (`X-GM-EXT-1` plus a `\All`
  folder) and the session learns it through `set_gmail` in `account::with_session_prio`; tools branch with
  `account::gmail_mode`. In Gmail mode only `Special::All | Junk | Trash` are scanned, labels come from `X-GM-LABELS`
  through `mail::message_labels`, and organize never reaches `expunge_copied` (the session refuses it, and refuses a
  move without `MOVE`). `imap_folders.special` has a CHECK constraint: a new special needs a migration that rebuilds
  the table (`V_GMAIL_IMAP`). The fake server's Gmail mode is `Opts { gmail: true, .. }` with `FakeImap::gmail_user`
  (INBOX, `[Gmail]/All Mail`, Spam, Trash, Sent Mail, Drafts, Important, labels `Work` and `Privat/Kunden`): `gm_add`
  places one message in All Mail and its label folders, `gm_relabel` changes its labels server side,
  `gm_uid`/`gm_folders`/`gm_flags` look it up, and
  `assert_gmail_deletes_only_in_drafts()` walks the command log (it also panics on any `UID COPY`).
- 2026-11-13: Restoring a mutated file with its old content keeps its old mtime, so cargo reuses the mutated build and
  the "fixed" run still fails (or a later mutant looks killed). `touch` the file after restoring it.
- 2026-11-13: CI's gitleaks scans the whole git history, and a fixed UUID literal such as `"request_key": "4b0c..."` trips
  its `generic-api-key` rule. Use `uuid::Uuid::new_v4()` in tests; a finding already in history needs a fingerprint line
  in `.gitleaksignore` (`<commit>:<file>:<rule>:<line>`). Check locally with the docker command above before pushing.
- 2026-11-13: Packaging lives in `deploy/` (`deb/`, `homebrew/`, `release/`) and `.github/workflows/release*.yml`. The Homebrew
  formula is generated (`deploy/homebrew/render.sh`, tested in `tests/packaging.rs`, which runs the real script) and pushed to
  `dominik-lenhart/homebrew-tap` by the `homebrew` release job with a write deploy key (secret `HOMEBREW_TAP_DEPLOY_KEY`); never
  edit the tap by hand. Workflow YAML check: `docker run --rm -v $PWD:/repo -w /repo rhysd/actionlint:latest`. The Windows release
  (`WINDOWS_RELEASE` in `release.yml`) and the Windows CI job (`continue-on-error`) stay gated until the Windows port is merged.
- 2026-11-13: Platform code (PLAN A58) lives in `src/platform/` (`mod.rs` private dirs/files and the strict check per OS,
  `paths.rs` local-mode paths, `windows.rs` SIDs, DACLs, DPAPI, pipe peer SIDs). Never call
  `std::os::unix` APIs outside `cfg(unix)`; use `platform::{restrict_file, restrict_dir, ensure_private_dir,
  write_private_new}`. Integration test files that need Unix sockets, modes or `sudo` start with `#![cfg(unix)]`.
  Type-check the Windows code here with the `dove-t-mingw:local` image (Ubuntu 24.04 + mingw-w64; rebuild it from
  `ubuntu:24.04` with `apt-get install gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 make perl` if it is gone), mounting
  `~/.rustup` and `~/.cargo`, `RUSTC_WRAPPER=` (sccache is not in the image) and a separate target dir:
  `heavy docker run --rm -u 1000:1000 -v ~/.rustup:/rustup -v ~/.cargo:/cargo -v $PWD:/src -w /src
  -e RUSTUP_HOME=/rustup -e CARGO_HOME=/cargo -e PATH=/cargo/bin:/usr/bin:/bin -e HOME=/tmp -e RUSTC_WRAPPER=
  -e CARGO_TARGET_DIR=/src/target/win-gnu -e CARGO_BUILD_JOBS=3 dove-t-mingw:local cargo clippy
  --target x86_64-pc-windows-gnu --all-targets -- -D warnings` (about 4 min cold). This compiles, it does not run:
  the `cfg(windows)` tests (DACLs, DPAPI, the admin pipe, replacing a running exe) only run on a Windows machine.
- 2026-11-13: Unix socket paths are limited to 103 bytes (macOS `sun_path`); the agent scratchpad paths are longer, so a
  manual local-mode run there fails to bind (`dove local init` now refuses such a `DOVE_LOCAL_HOME`). Use a short
  directory such as `/tmp/dl-<id>` for manual runs, set `DOVE_LOCAL_HOME` for every command, and remove it afterwards.
  `dove local install` writes the real `~/.config/systemd/user/dove.service` of the user running it; always `dove local uninstall`
  after trying it.
- 2026-11-13: The client's loopback owner check (`client::loopback`, P1) runs before every credential it sends to a
  plain-http loopback server; tests that serve such a server must run it in the test process (same uid). A test helper
  started as `sudo -n -u nobody <cmd>` survives `kill_on_drop` (only `sudo` dies) and keeps inherited pipes open, which
  hangs `cargo test | grep`: give it its own timeout and `stderr(Stdio::null())`. To undo a mutation, never
  `git checkout <file>` on a file with uncommitted work; reverse the edit and `touch` it.
- 2026-11-13: `sqlite3_interrupt` (`InterruptHandle::interrupt`) is a no-op while no statement runs, so a timer that fires
  before the first statement starts loses the deadline and the query runs unbounded (seen on the Windows CI runner, where
  opening a SQLCipher connection outlasted a 100 ms deadline). `Index::read` enforces deadlines with a progress handler
  on the reader's own thread (rusqlite feature `hooks`). Tests of a deadline use a bounded query so a regression fails
  instead of hanging the runner.
- 2026-11-13: nginx/Angie `set_real_ip_from` / `real_ip_header` set in the `http {}` context by another site (Cloudflare's
  `CF-Connecting-IP` on a shared host) also rewrite `$remote_addr` for Dove's server blocks, which feeds the address
  allowlist, the rate limit key and the `X-Forwarded-For` Dove trusts. Both nginx templates override it in the server
  block (`set_real_ip_from 192.0.2.1/32`) and log to their own query-free `access_log`; test such proxy behaviour in a
  throwaway `nginx:stable-alpine` container with an http-level `real_ip_header` and a request carrying the header.
- 2026-11-13: Third-party crates log through the `log` bridge, and the content parsers quote untrusted input (lopdf
  printed whole PDF font dictionaries, ~1,100 warnings a day in production). `logging::LOG_TARGETS` is an allowlist
  (Dove plus the transport stack) applied after `DOVE_LOG`; never add a crate that parses mail or attachments.
  `tests/log_targets.rs` triggers real lopdf and html5ever warnings and checks none reach the log.
- 2026-11-13: Every `ToolDef` declares `mail_content`. For those tools `mcp::call_tool` adds `untrusted_content_notice`
  (`tools::UNTRUSTED_NOTICE`) to `structuredContent` and their `outputSchema`, and wraps the legacy JSON text item (no
  `MCP-Protocol-Version` counts as 2025-03-26) in the envelope. A new tool that returns mail text needs
  `mail_content: true`, an enveloped `text`, and a line in `mail_content_is_marked_untrusted_in_every_protocol_version`
  (`tests/mail_intel_e2e.rs`). Tests that compare a mail tool's whole `structuredContent` must include the notice.
- 2026-11-13: OAuth hardening: a dynamically registered client never gets a 303 before approval (errors and denial render
  a page); pre-registered clients keep RFC 6749 error redirects. The approval page asks for `confirm_redirect` when a
  dynamic client's redirect is not `oauth::known_redirect` (HTTPS on `KNOWN_REDIRECT_HOSTS`, exact host, or loopback).
  `tests/oauth_e2e.rs`'s `REDIRECT` is a known host on purpose; tests of unknown destinations use `with_redirect`.
  `/connect/redeem` checks the invitation's `--allow-ip`; the approval page does not (A34: the browser is not the host).
- 2026-11-13: Failed bearer auth on `/mcp` draws from a per-address bucket (`limits.auth_failures_per_minute`), charged
  only after a failed lookup; a valid token is never refused by it, because Claude's and ChatGPT's egress addresses
  are shared with anyone holding an API key (a pre-lookup check let strangers lock the owner out). Loopback and unknown
  addresses are exempt because behind Tailscale Serve or in local mode they stand for every caller. Tests simulate addresses with `X-Forwarded-For` plus
  `X-Dove-Proxy-Auth`.
- 2026-11-13: Security review fixes. Organize writes spend `limits.client_organize_per_hour` (messages, per client):
  `organize::Budget::take` reserves before the first write, `settle` refunds failed ids, or everything when the call
  failed before `cx.commit()`; `RateLimiter::take_hourly`/`refund` take several tokens at once. Tests shrink it with
  `Harness::start_with(|c| c.limits.client_organize_per_hour = 5)`. Moving out of Spam/Junk needs `delete` (Gmail
  `SPAM` label, IMAP `organize::is_junk`, Gmail-over-IMAP `\Junk`). Trash/Junk names live in `imap::connect`
  (`TRASH_NAMES`, `JUNK_NAMES`, compared with `same_name`, Unicode case) and word stems (`TRASH_STEMS`, `JUNK_STEMS`)
  count only for the `delete` gate. Named folder lookup (`folder_by_label`, `imap_target`) is still ASCII-case only.
- 2026-11-13: Sinks belong to a project and their URL is sealed (`sink_url`, store migration 7). A migration that needs
  the vault cannot be SQL only: add nullable columns in SQL and finish in `App::new` (`watch::sinks::seal_legacy_urls`).
  Never rebuild a table that others reference with ON DELETE actions (`DROP TABLE` runs them; `V_GMAIL_IMAP` could
  only because nothing references `imap_folders`). Tests add sinks with `add_sink_to(h, name, project, url)`; a test
  of an earlier migration pins its index (`n = 6`) instead of `MIGRATIONS.len()`.
- 2026-11-13: `tests/packaging.rs` runs the real `install.sh` with fake `curl`/`wget`/`minisign` (written once per
  process) in a PATH of symlinked system tools, so no network and no real minisign are needed. There is no PowerShell
  on the host; `docker run --rm mcr.microsoft.com/powershell:latest pwsh -NoProfile -File <script>` checks an
  `install.ps1` expression quickly (the image is cached locally).
- 2026-11-13: SQLite flattens a subquery or CTE into its user and copies the column expression into every place that
  uses it; `EXPLAIN QUERY PLAN` then lists one `CORRELATED SCALAR SUBQUERY` per copy. A per-row correlated check used
  in several aggregates (the thread view's `from_self`) goes in an `AS MATERIALIZED` CTE so it runs once per row;
  assert the count of the lookup lines in the plan test. `query::Scope` carries `selves` (own addresses per account
  id); `from_self` and `group_by:"thread"` refuse to compile without an entry for every target, so a new caller that
  passes an empty map gets `invalid_argument`, not a silently wrong answer.
- 2026-11-13: Coverage exceptions (`src/tools/coverage.rs`, PLAN A62) are built only there; search, digest and contacts
  must not hand-write exception JSON. `pending` has no date, so a query's `received_at` range cannot exclude pending
  rows; `attempts = 0` rows are "queued", only `attempts > 0` are retries, and a retry cannot run before the next
  sync pass (`next_retry_at` = later of `next_attempt_at` and `sync_state.next_run_at`). Tests move those times with
  `UPDATE pending/sync_state` and compare against the stored values, not wall-clock guesses. The tool-description text
  about `resolves` is the `coverage_note!` macro in `src/tools/mod.rs`.
- 2026-11-13: Secret redaction (PLAN A60, `src/redact.rs`) applies only at the output step through
  `ToolCx::redact_table` / `redact_objects`; a new list or overview tool with subjects or snippets must call one of
  them, targeted reads must not. Test fixtures that look like keys (`ghp_…`, PEM headers, `API key: …`) trip CI's
  gitleaks: build them at run time (`format!("gh{}", "p_…")`) and check with the docker command above.
- 2026-11-14: Organize budget refunds (PLAN A63): an id is refunded only as `Outcome::Failed` with a code other than
  `outcome_unknown`; use `Outcome::Spent` when a write for that id took effect before the failure. IMAP writes must be
  classified like `move_uids`/`append` (`ExecError::sent_all` true = `OutcomeUnknown`); `simple()` drops that
  distinction and is for reads and Drafts housekeeping only (organize STOREs go through `write_simple` /
  `stores_then_fetch`). Fake faults: IMAP `Fault::No` (refused, refunded), `Fault::DropAfterApply` (applied, reply
  lost), `fail_next_containing("UID STORE", "-FLAGS", ..)` for the second STORE; Gmail `Fault::Status(503, ..)` is
  `outcome_unknown`, 4xx is definitive. Budget tests probe what is left with `n + 1` then `n` unknown ids.
- 2026-11-14: `AdminRequest` is `deny_unknown_fields`, and the CLI and the service can briefly be different versions
  (new binary installed, service not restarted). A new optional request field must be `Option<_>` with
  `#[serde(default, skip_serializing_if = "Option::is_none")]` so the older service still parses requests that do not
  use it; tests construct `AdminRequest` literals in many files, so a new field touches all of them.
- 2026-11-14: Client install and update (PLAN A67): the server binary stays root-owned on purpose, the client uses a
  user-level install (`install.sh` without sudo). `update::is_homebrew_install` canonicalizes and looks for the path
  components `Cellar/dove`; test it with a temp dir holding `Cellar/dove/<ver>/bin/dove` and a `bin/dove` symlink
  (`brew_layout` in `tests/update_e2e.rs`). `notice_text`/`notice_line` take the upgrade command as a parameter,
  production passes `update::upgrade_command()`. `tests/packaging.rs` runs `install.sh` through `InstallEnv`
  (`$SHELL`, default directory, dir on `PATH`); `InstallRun` keeps its temp dir alive, because a dropped `TempDir`
  deletes what the test wants to inspect. The user-install test skips itself as root (the default dir is then
  `/usr/local/bin`), so the root branch of install.sh's closing hint is not covered.
- 2026-11-14: To wake an agent on new mail, use `dove watch listen` (`src/client/watch.rs`), not webhooks into the agent
  host: it pulls `list_watch_events` (one event per request, so the cursor is saved after each), runs a fixed command
  with only `DOVE_*` ids in its environment, skips existing events on the first start, retries up to `--max-attempts`
  and holds a `File::try_lock` lock per profile. Pin it to a session with `claude -p --resume <id> --fork-session`
  (prompt after `--`, since `--allowedTools` is variadic). Tests run the real binary in
  `tests/client_e2e.rs::watch_listen_runs_the_command_once_per_event_with_ids_only`; generate events there with
  `index::sync::sync_account` after `IndexEnable`. Never build the prompt from mail content.
- 2026-11-14: Several messages of one mailbox are read with `mail::fetch_many` (IMAP: one session, one `EXAMINE` and
  one metadata `UID FETCH` per folder, then `fetch_raw_sized` per message; Gmail: `upstream_per_mailbox` concurrency).
  Do not loop over `fetch_message` for a list: on IMAP each call is its own pool checkout, credential load and four
  commands. `get_message` with `refs`/`message_ids` runs through `batch::run`; never add a second response budget.
  Read-path tests count commands in `h.imap.commands()` (`EXAMINE`, `BODY.PEEK[]`, `(UID RFC822.SIZE)`) and requests
  in `h.google.requests()`.
- 2026-11-14: `no_reply_by` (PLAN A70) decides replies through `watch::first_reply` and `watch::Baseline`: `>=` the
  baseline instant minus the stored `baseline_ids`, own mail by `watch::is_own` (owner addresses or the `SENT` label).
  To test the deadline path on its own, let the sync hook end the watch, set the row back to `active`
  (`reopen` in `tests/watch_no_reply_e2e.rs`) and `tick` past `deadline + NO_REPLY_GRACE_SECS`. IMAP same-second
  cases put both messages at the same `add_message_at` second. Gmail mailboxes have no Dove aliases
  (`AccountsAliasAdd` refuses them); fake a send-as follow-up with any address plus the `SENT` label.
- 2026-11-14: Argument errors (PLAN A68): raise `ToolError::invalid_at(path, text)`, never `invalid("'x' ...")`, so the message
  starts with the path and `details.field` feeds the audit (`~invalid=<path>` via `ToolError::audit_field`, which drops
  anything that is not a plain lowercase path). Build the path from the tool's own structure, never from caller text, and
  never echo a value into it. New leniency goes in `tools::lenient::normalize` (argument level) or `index::query::parse_*`
  (value level) and only where the reading is unique; add the case to `tests/search_contract.rs`
  (`search_accepts_arguments_that_have_one_reading`) and keep the not-found scope tests green. When mutation-checking from a
  script, set `PATH` with explicit absolute directories (`~` is not expanded inside a joined PATH string): a missing
  `cargo` makes every mutant look killed.
- 2026-11-14: Requests (`src/requests/`, PLAN A71): the worker sends only through `drafts::send_core` with
  `SendAuth::Approved` and an approved revision; never add a second send path. Tests drive it with
  `dove::requests::worker::tick(h.app(), t)` (the harness starts no worker) and `Harness::restart` runs its
  `recover_after_restart`. `unless_reply` needs an index synced within 10 minutes of the tick time, so those tests use
  `send_at = now + 60`, not hours ahead. `IndexDisable` purges the index at once, which shadows the `index_enabled`
  checks; test the flag alone with `UPDATE accounts SET index_enabled = 0`. The note is sealed with the request id as
  vault scope and is the only free text in the tables; keep ids, times and codes everywhere else.
- 2026-11-14: A sync that ends `ready` can still leave messages in the index's `pending` retry queue (a failed fetch;
  thread unknown) while `last_success_at` advances, so "the index shows no reply" needs `pending` empty for the serving
  generation (`requests::worker::reply_condition`). Make a fetch fail with `fail_next("GET", "/messages/<id>", ..)` or
  IMAP `fail_next_containing("UID FETCH", "UID FETCH <uid> (UID BODY.PEEK[])", Fault::Bad)`, and make the retry due with
  `UPDATE pending SET next_attempt_at = 0`. `create_draft` does not derive reply recipients and the fake Google sends a
  draft without any, but SMTP refuses it: IMAP reply fixtures need an explicit `to`. A test of the request worker's claim
  guard must keep the request `approved` (another item still open), or `close_if_finished` plus the claim's
  request-status check hide the mutation.
