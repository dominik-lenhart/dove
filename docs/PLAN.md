# Implementation plan (v1)

Source of truth: [`docs/spec.md`](spec.md) (draft 0.5, 12 Nov 2026). This file tracks order, status and the
assumptions taken while implementing. Status markers: `[x]` done and verified through its normal interface,
`[~]` partially done, `[ ]` open. "Unverified" means not yet proven against real Gmail, Apple Mail, ChatGPT/Claude
hosts or reference hardware.

## Steps

1. Foundation
   - [ ] Cargo package `dove-mcp`, binary `dove`, module layout (spec 7.8)
   - [ ] Config file + startup checks: secret file modes, HTTPS public URL, KEK present (8.4, AC15)
   - [ ] Vault: per-account DEK, KEK wrap, XChaCha20-Poly1305 with AAD (6.4, AC8)
   - [ ] State store: SQLite WAL, versioned migrations in one transaction (7.2, 10)
   - [ ] SQLCipher/FTS5/temp-store startup self-check for the index (7.9)
   - [ ] Audit log with hash chain, `audit verify|tail|search`, retention pruning (6.7, AC16)
   - [ ] Admin socket with peer-credential check; projects/clients/grants CLI (FR-C1, FR-P*, AC19)
   - [ ] Client tokens: `dove_` + 32 bytes, HMAC-SHA-256 pepper lookup, rotate/revoke/expiry/IP (6.4, AC11)
2. Google + MCP core
   - [ ] Outbound gateway with exact method/path allowlist and fixed origins (7.5)
   - [ ] Connect/reconnect flow: pending state, PKCE, ID-token validation, scope + identity checks (7.3, AC7)
   - [ ] Token manager: single-flight refresh, `invalid_grant` -> `reauth_required` + one notification (AC10)
   - [ ] MCP Streamable HTTP (stateless), Host/Origin checks, bearer auth before MCP (7.1, AC13)
   - [ ] Tools: list_accounts, list_labels, get_message, get_thread, list_drafts, get_draft
   - [ ] Untrusted content envelope, HTML-to-text, invisible Unicode removal (6.5, AC12)
   - [ ] create_draft (idempotent request_key), update_draft (revision check, per-draft lock) (5.3, AC4, AC6, AC18)
3. Index + sync
   - [ ] Encrypted index DB, generations, backfill with durable progress, history polling, expiry rebuild (7.9)
   - [ ] `dove index enable|disable|status|rebuild`, purge + cursor invalidation
   - [ ] Typed query compiler -> parameterized SQL, coverage reporting (5.3, AC17, AC20)
4. Contracts
   - [ ] Projections, keyset cursors (15 min TTL, bounded), count_only, live Gmail route
   - [ ] batch_read with budgets (AC21)
   - [ ] send_draft behind instance gate + send grant + ownership, at-most-once (6.3, AC3)
   - [ ] Client onboarding: invitations, `dove login`, remote CLI commands, `mcp install`, `mcp stdio` (5.6, AC22)
   - [ ] Downstream OAuth AS for ChatGPT/Claude (5.6, AC23)
5. Hardening
   - [ ] Fake Google server integration suite covering AC1-AC21
   - [ ] Restart/crash recovery tests, log canary test
   - [ ] Benchmarks (8.1) with synthetic 250k corpus, RSS measurement
   - [ ] Deployment: systemd unit, container, Caddy allowlist, backup docs, SECURITY.md, README

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
- A7. Licence is a placeholder (Apache-2.0) until the owner decides (spec 13.7).
