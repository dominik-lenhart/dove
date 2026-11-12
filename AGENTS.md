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
- `src/mcp/`: JSON-RPC / Streamable HTTP protocol layer; `src/tools/`: tool handlers
- `src/index/`: SQLCipher FTS5 index, sync engine, query compiler
- `src/client/`: remote client commands (login, search, mcp install, stdio bridge)
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
