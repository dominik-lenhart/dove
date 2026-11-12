# Implementation plan (v1)

Source of truth: [`docs/spec.md`](spec.md) (draft 0.5, 12 Nov 2026). This file tracks order, status and the
assumptions taken while implementing. Status markers: `[x]` done and verified through its normal interface,
`[~]` partially done, `[ ]` open. "Unverified" means not yet proven against real Gmail, Apple Mail, ChatGPT/Claude
hosts or reference hardware.

## Steps

1. Foundation
   - [x] Cargo package `dove-mcp`, binary `dove`, module layout (spec 7.8)
   - [x] Config file + startup checks: secret file modes, HTTPS public URL, KEK present (8.4, AC15)
   - [x] Vault: per-account DEK, KEK wrap, XChaCha20-Poly1305 with AAD (6.4, AC8)
   - [x] State store: SQLite WAL, versioned migrations in one transaction (7.2, 10)
   - [x] SQLCipher/FTS5/temp-store startup self-check for the index (7.9)
   - [x] Audit log with hash chain, `audit verify|tail|search`, retention pruning (6.7, AC16)
   - [x] Admin socket with peer-credential check; projects/clients/grants CLI (FR-C1, FR-P*, AC19)
   - [x] Client tokens: `dove_` + 32 bytes, HMAC-SHA-256 pepper lookup, rotate/revoke/expiry/IP (6.4, AC11)
2. Google + MCP core
   - [x] Outbound gateway with exact method/path allowlist and fixed origins (7.5)
   - [x] Connect/reconnect flow: pending state, PKCE, ID-token validation, scope + identity checks (7.3, AC7)
   - [x] Token manager: single-flight refresh, `invalid_grant` -> `reauth_required` + one notification (AC10)
   - [x] MCP Streamable HTTP (stateless), Host/Origin checks, bearer auth before MCP (7.1, AC13)
   - [x] Tools: list_accounts, list_labels, get_message, get_thread, list_drafts, get_draft
   - [x] Untrusted content envelope, HTML-to-text, invisible Unicode removal (6.5, AC12)
   - [x] create_draft (idempotent request_key), update_draft (revision check, per-draft lock) (5.3, AC4, AC6, AC18)
   - Unverified: real Google consent screen, real Gmail draft round-trips, Apple Mail editing a Dove draft. All
     step-2 evidence is against the fake Google server in `tests/support/fake_google.rs`.
3. Index + sync
   - [x] Encrypted index DB, generations, backfill with durable progress, history polling, expiry rebuild (7.9)
     (`src/index/`, `tests/index_sync.rs`: arrival/label/deletion during backfill, history expiry, interrupted pass
     before checkpoint, retry records, rate-limit backoff, disk full)
   - [x] `dove index enable|disable|status|rebuild`, purge + cursor invalidation, fenced jobs
   - [x] Typed query compiler -> parameterized SQL, coverage reporting (5.3, AC17, AC20) (`src/index/query.rs`,
     `tests/search_contract.rs`; hot paths checked with EXPLAIN QUERY PLAN)
   - Unverified: index build time, query latency and RSS (8.1, 8.1a) are not measured; the planner statistics
     describe an assumed 250k-message / 10-mailbox index, not a measured one. Real Gmail history/paging behaviour.
4. Contracts
   - [x] Projections, keyset cursors (15 min TTL, bounded), count_only, live Gmail route (search_messages only;
     batch_read is separate)
   - [x] batch_read with budgets (AC21; `tests/batch_e2e.rs`)
   - [x] send_draft behind instance gate + send grant + ownership, at-most-once (6.3, AC3; `tests/send_e2e.rs`)
   - [x] Client onboarding: invitations, `dove login`, remote CLI commands, `mcp install`, `mcp stdio` (5.6, AC22
     local part). Guide: `docs/onboarding.md`.
     - [x] `dove clients invite` (admin socket): 256-bit `dovei_` secret, hash only, single use, 10 min, `all`
       expanded once, POST `/connect/redeem` rate-limited and atomic (`tests/invite_e2e.rs`)
     - [x] `src/client/`: `login` (invitation from prompt/stdin only, `--token-stdin`), profiles, OS credential store
       or explicit 0600 `--secret-file`, `status`, `logout [--revoke]`, `search`, `message get`, `thread get`,
       `draft create|get|update|send`, `batch`, `mcp install` (Claude Code, Codex), `mcp stdio`, `connect-info`,
       `doctor --profile`; no path to the admin socket (`tests/client_e2e.rs`, runs the real binary)
     - [x] Log/audit/store canary for all onboarding and OAuth secrets (`tests/onboarding_logs.rs`)
     - Unverified: real Claude Code and Codex reading the generated entries, macOS Keychain and Windows Credential
       Manager (only the "no store available" path runs here), the 60 s setup target on clean machines, signed
       release binaries for all platforms. `search` and `batch` depend on tools still being built in parallel.
   - [x] Downstream OAuth AS for ChatGPT/Claude (5.6, AC23 server side): PRM (both paths), RFC 8414 metadata,
     approval page with invitation + narrowing + CSRF, S256 PKCE, exact redirect, resource binding, single-use codes,
     rotating refresh with reuse detection, DCR (bounded, rate-limited, no authority), RFC 7009 revocation,
     pre-registered clients in config (`tests/oauth_e2e.rs`). Unverified: real ChatGPT and Claude hosts (AC23);
     host versions/settings are not recorded because no real host was available.
5. Hardening
   - [~] Fake Google server integration suite covering AC1-AC21 (done: AC1, AC2, AC4, AC6, AC7, AC10, AC12, AC13,
     AC16, AC18 in `tests/mcp_e2e.rs`, `tests/connect_e2e.rs`; AC14, AC17 and AC20 except the log canary in
     `tests/search_contract.rs`, `tests/index_sync.rs`; AC3 `send_e2e`, AC8/AC9 `hygiene_e2e`, AC19 `agent_shell`,
     AC21 `batch_e2e`)
   - [~] Restart/crash recovery tests, log canary test (AC8, AC9 in `tests/hygiene_e2e.rs`; restart cases in
     `send_e2e`, `connect_e2e`, `mcp_e2e`, `index_sync`, graceful shutdown in `shutdown_e2e`)
   - [ ] Benchmarks (8.1) with synthetic 250k corpus, RSS measurement
   - [~] Deployment: systemd unit, container, Caddy allowlist, backup docs, SECURITY.md, README (files written:
     `deploy/` (systemd, Containerfile, compose, Caddyfile, nginx), `docs/deployment.md`, `README.md`, `SECURITY.md`,
     CI workflow with `deny.toml` and secret scan. Verified: syntax and sandbox start of the unit as a user unit,
     local container build and compose run, Caddy and nginx route matrices on stock images, actionlint, gitleaks,
     cargo-deny. Unverified: system-level unit with `User=dove`, a production host with real TLS and Google, Podman,
     the `age` backup step and a restore drill, the CI run on GitHub. Open for the owner: `SECURITY.md` contact
     placeholder, licence file (A7))

## Assumptions and decisions

- A1. The user referred to spec v0.4; the attached file is labelled draft 0.5. The attached text is implemented.
- A2. MCP protocol layer is a small hand-written stateless Streamable HTTP implementation in `src/mcp/` instead of
  `rmcp`. Reason: the spec needs auth, Host/Origin checks and per-token tool lists before any MCP processing, plus
  stable error shapes; a ~500 line JSON-RPC layer is easier to audit (G7) than tracking rmcp 3.x internals. The layer
  sits behind one module boundary, so switching to rmcp later is a contained change.
- A3. rusqlite links one SQLite library per binary, so SQLCipher is used for both stores. The durable state store is
  opened without a key (plain SQLite format, secrets inside are envelope-encrypted per 6.4); the index is keyed.
- A4. Google origins are fixed constants in the production binary. Tests inject a fake upstream through the library
  API; there is no config switch that redirects upstream traffic.
- A5. Admin protocol is newline-delimited JSON over a Unix socket (`0660`, group = operator group). The server
  verifies `SO_PEERCRED` uid against `admin.operator_uid` (or root). The CLI binary carries no authority.
- A6. The service process is the only writer to the state store; admin commands mutate state through the socket.
- A8. KEK rotation: the KEK file is read-only to the service (systemd credential). The operator appends a new
  `<version> <key>` line (`dove keys generate --version N`), restarts, runs `dove keys rotate` to re-wrap every grant
  under the newest version, then deletes the old line. `keys rotate` reports which versions are still referenced.
- A9. Admin actions are audited in the same transaction as their state change; failed actions get a separate
  `error` record, so every admin request yields exactly one record.
- A10. Index sync state (generations, checkpoints, retry records) lives in the index DB, not the state store: it is
  derived and rebuildable. The operator's choice (`accounts.index_enabled`) stays in the state store and is
  authoritative; the scheduler reconciles the two (creates missing state, purges state of disabled accounts).
- A11. Backfill lists `messages` newest-first and indexes each page before listing the next, so the first page is the
  bounded recent-mail priority pass. A generation is published once enumeration is done, every candidate was tried
  once and history since the captured id is reconciled; messages that still fail stay as retry records and keep
  coverage `partial` until indexed.
- A12. Addresses are normalized by trimming and lowercasing the whole address (local part included), at ingest and
  lookup. `received_at` is stored as Gmail internalDate in milliseconds (wire format keeps ms precision).
- A13. Unparseable or oversized MIME is indexed from Gmail metadata only (labels, dates, size, snippet) with
  `meta_complete = 0`; queries that filter/project/order on MIME-derived fields then report partial coverage.
- A14. The index ships fixed `sqlite_stat1` rows (index migration V2) for an assumed large index, and Dove never
  runs ANALYZE, so plans do not flip with index size. Multi-mailbox newest-first pages walk `messages_recent` in
  order (gen index disabled with unary `+`); single-mailbox and count queries use the gen-prefixed indexes. Both are
  tunables to revisit with the 8.1 benchmark.
- A15. `search_messages` details: `alias:ID` qualifies label/thread_id/message_id values to one mailbox (unknown or
  out-of-scope alias = `not_found`); text predicates are re-tokenized like unicode61 and emitted as quoted FTS
  literals; `prefix` needs at least 2 characters (`query_too_broad` otherwise); `gmail_query` is limited to 1024
  characters without control characters; the text rendering is the compact JSON result inside the untrusted-content
  envelope. Coverage `exceptions` list per mailbox `stage` (`not_indexed`, `pending`, `backfill`, `rebuilding`,
  `stale`, `ready`) with a reason; `account_errors` list unavailable mailboxes. Cursors are not single use: a page
  can be fetched again until the cursor expires or is evicted.
- A17. The OAuth authorization server is hand-written in `src/oauth.rs` on reviewed primitives (sha2 for PKCE,
  HMAC-pepper token hashes, `subtle` constant-time compares, `url` parsing, OS RNG). `oxide-auth` 0.6 (with an
  axum 0.8 frontend) was considered: it has no resource indicators (RFC 8707), dynamic registration (RFC 7591),
  revocation (RFC 7009) or refresh-family reuse detection, and its registrar/authorizer/issuer traits are exactly
  where Dove's security logic lives (invitation consumption, connection-bound families, SQLite transactions), so
  it would add a dependency without removing the code that needs review. Every guard has a mutation-checked test.
- A18. Authority comes only from invitations. One approval creates one `kind = 'oauth'` connection; its code and
  token family point at that connection (`family_id = connection_id`), so no migration was needed. Tokens carry
  no grants, which is why refresh cannot broaden the intersection. Scope is a single informational `mail`;
  unknown requested scopes are ignored, never granted.
- A19. A missing `resource` parameter at authorize binds to `<public_url>/mcp` (the only resource); any other
  value is `invalid_target`. Access tokens are accepted on `/mcp` only for that resource.
- A20. Refresh rotation is strict: reuse of a rotated refresh token, or of a used code, revokes the connection
  and all its tokens (and bumps `auth_epoch`). There is no grace window, so a host that refreshes twice in
  parallel loses the connection and needs a new invitation. Rotation also retires older access tokens.
- A21. Approval-page state (pending requests, CSRF token, browser-binding cookie `__Host-dove_authz`) lives in
  memory, bounded to 10 000 requests (20 per source IP, GET rate-limited per IP) for 10 minutes. A restart only
  makes the user start the sign-in again.
- A22. Dynamic registration accepts public clients only (`token_endpoint_auth_method = none`), 1-5 redirect URIs,
  HTTPS or loopback HTTP; custom schemes and Client ID Metadata Documents are unsupported and fail explicitly.
  Registrations are capped (`oauth.max_dynamic_clients`, unused ones pruned after 24 h) and limited per IP per
  hour. Pre-registered (optionally confidential) clients are configured in `[[oauth.clients]]` with a secret file.
- A23. Removing a mailbox from a project cancels the project's open invitations, so a re-add cannot resurrect
  rights through an old invitation. Accounts deleted before redemption are dropped from the invitation.
- A24. Client profiles live in `$DOVE_CONFIG_DIR`, else `$XDG_CONFIG_HOME/dove`, else `~/.config/dove`
  (`%APPDATA%\dove` on Windows) as `profiles.toml` (0600): server origin, connection name, credential reference
  (`keyring` or `file:<path>`). Server URLs must be HTTPS; plain HTTP is accepted only for loopback hosts.
- A25. The OS credential store is `keyring` 4 (Keychain, Windows Credential Manager, Secret Service). `login`
  probes it before redeeming; when it is unavailable it stops and asks for `--secret-file`, so the invitation is
  not consumed by a failed attempt.
- A26. `mcp install` targets `~/.claude.json` / `.mcp.json` (`mcpServers`, honours `CLAUDE_CONFIG_DIR`) and
  `~/.codex/config.toml` / `.codex/config.toml` (`mcp_servers`, honours `CODEX_HOME`). JSON is re-emitted with
  two-space indentation, key order and all values kept (checked by re-reading before the atomic rename); TOML is
  edited with `toml_edit`, keeping comments. Symlinked config files are written through to their target.
  The entry names `dove-<profile>`. Host-side behaviour is unverified.
- A27. `mcp stdio` retries only connect errors (the request never reached the server); anything that may have
  reached the server is not replayed. Cancellation drops the local request and its response; the stateless server
  has no cancel channel, so already dispatched upstream work may still finish.
- A28. `dove doctor --profile <p>` runs the remote client checks and never opens the admin socket; plain
  `dove doctor` stays the operator check.
- A29. `tools/list` declares `securitySchemes: [{type: oauth2, scopes: [mail]}]` per tool for hosts that read it
  (ChatGPT apps); unverified.
- A7. Licence is a placeholder (Apache-2.0) until the owner decides (spec 13.7).
- A16. batch_read: budgets are assigned in input order (deterministic). Items that do not fit return
  `budget_exceeded` with a smaller-request hint instead of a continuation token. The wire budget counts the
  structured result plus the text rendering. Legacy text-only clients get the structured result serialized as
  compact JSON (spec 5.3); mail content stays in its own JSON fields there instead of the text envelope.
- A40. Full-text postings live in one contentless FTS5 table per generation (`fts_g<id>`, name derived only from
  the integer id). A text predicate is a `UNION ALL` of MATCH over the eligible generations' tables only, so its
  work never depends on other accounts' postings (spec 7.9). Generation ids come from `meta.gen_seq` and are never
  reused. Index migration V3 cannot move the old shared table's postings (contentless), so it starts a rebuild for
  every account: an active generation keeps serving metadata while the stage is `rebuilding` (coverage partial),
  a half-built one is abandoned. Generations that no sync state references (retired, replaced, purged, abandoned)
  are dropped in bounded transactions: derived rows and retry records in chunks of 2,000, then the FTS `_data`
  blocks in chunks of 256, then the near-empty FTS table. Each step re-checks that the generation is unreferenced;
  the scheduler collects leftovers of interrupted drops. Purge no longer runs FTS 'optimize': the postings go with
  the dropped table (secure_delete zeroes the freed pages). Searches never take the writer lock (the schema is
  migrated once on its own connection), so long writes delay other writers only.
- A41. Gmail response bodies are streamed with a byte cap (gateway `read_capped`): a declared length over the cap
  is refused unread, a streamed body stops at the cap. Over the cap is `TooLarge` for reads (`budget_exceeded` to
  agents, never retried, never partially parsed) and `outcome_unknown` for writes. General cap 40 MiB (a 25 MiB
  message for the read tools); index body jobs cap at `4/3 * index.max_message_bytes + 64 KiB`. A message over it
  is indexed from a `format=minimal` answer only (`meta_complete = body_complete = 0`). The size is not checked
  before the raw fetch: messages.list carries no sizes and a minimal pre-fetch would cost the same quota as the raw
  fetch for every message. The raw text is decoded in place in the downloaded buffer, so a job holds about 4/3 of
  the message: measured peak heap of the parse path (counting allocator, `tests/ingest_memory.rs`, attachment-heavy
  messages) 11.5 MiB for 8.6 MB, 22.4 MiB for 17.2 MB and 29.3 MiB for 22.6 MB raw. `index.max_message_bytes`
  therefore defaults to 22 MiB (was 25) to keep a body job within the 32 MiB of spec 8.1a; RSS was not measured.
- A42. Cursors: at most 100 live cursors per client inside the global 1,000 / 8 MiB caps; a client at its share
  evicts its own oldest cursor. batch_read charges a resumed cursor the page limit stored with it.
- A43. Sync: a job takes its cancel token before the account lock, so a disable that lands while it waits cancels
  it. A history pass checkpoints at the history id of its first history.list page; later pages may report a newer
  mailbox id than the records they list, and records past the first page's id are replayed next pass (idempotent).
