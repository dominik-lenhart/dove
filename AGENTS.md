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
- 2026-11-12: The state store is one mutex-guarded connection, so concurrent HTTP requests serialize at the DB.
  An atomic guard (e.g. `UPDATE ... WHERE used_at IS NULL`) is then shadowed by the earlier read in the same
  transaction; test it directly with a stale view (see `invite::tests`) or the mutation survives.
- 2026-11-12: `cargo test --test a --lib foo::` applies the `foo::` filter to every target; run filtered lib
  tests and integration files in separate invocations when mutation-checking.
- 2026-11-12: The shared `CARGO_TARGET_DIR` holds one `target/debug/dove` for all worktrees; another agent's build
  can replace it between your build and test run. Tests that exec `CARGO_BIN_EXE_dove` (`tests/client_e2e.rs`)
  need a private target dir, e.g. `CARGO_TARGET_DIR=/home/dominik/projects/.dove-worktrees/target-onboarding`.
- 2026-11-12: Client tests run the binary with `env_clear()`, a temp HOME and
  `DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent/...` so the real keychain and config are never touched.
