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
- Time is stored as unix seconds (i64, UTC). Wire format is RFC 3339.
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
