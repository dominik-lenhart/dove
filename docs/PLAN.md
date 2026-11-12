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
   - [ ] Encrypted index DB, generations, backfill with durable progress, history polling, expiry rebuild (7.9)
   - [ ] `dove index enable|disable|status|rebuild`, purge + cursor invalidation
   - [ ] Typed query compiler -> parameterized SQL, coverage reporting (5.3, AC17, AC20)
4. Contracts
   - [ ] Projections, keyset cursors (15 min TTL, bounded), count_only, live Gmail route
   - [ ] batch_read with budgets (AC21)
   - [ ] send_draft behind instance gate + send grant + ownership, at-most-once (6.3, AC3)
   - [~] Client onboarding: invitations, `dove login`, remote CLI commands, `mcp install`, `mcp stdio` (5.6, AC22)
     - [x] `dove clients invite` (admin socket): 256-bit `dovei_` secret, hash only, single use, 10 min, `all`
       expanded once, POST `/connect/redeem` rate-limited and atomic (`tests/invite_e2e.rs`)
   - [x] Downstream OAuth AS for ChatGPT/Claude (5.6, AC23 server side): PRM (both paths), RFC 8414 metadata,
     approval page with invitation + narrowing + CSRF, S256 PKCE, exact redirect, resource binding, single-use codes,
     rotating refresh with reuse detection, DCR (bounded, rate-limited, no authority), RFC 7009 revocation,
     pre-registered clients in config (`tests/oauth_e2e.rs`). Unverified: real ChatGPT and Claude hosts (AC23);
     host versions/settings are not recorded because no real host was available.
5. Hardening
   - [~] Fake Google server integration suite covering AC1-AC21 (done: AC1, AC2, AC4, AC6, AC7, AC10, AC12, AC13,
     AC16, AC18 in `tests/mcp_e2e.rs`, `tests/connect_e2e.rs`)
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
- A8. KEK rotation: the KEK file is read-only to the service (systemd credential). The operator appends a new
  `<version> <key>` line (`dove keys generate --version N`), restarts, runs `dove keys rotate` to re-wrap every grant
  under the newest version, then deletes the old line. `keys rotate` reports which versions are still referenced.
- A9. Admin actions are audited in the same transaction as their state change; failed actions get a separate
  `error` record, so every admin request yields exactly one record.
- A10. The OAuth authorization server is hand-written in `src/oauth.rs` on reviewed primitives (sha2 for PKCE,
  HMAC-pepper token hashes, `subtle` constant-time compares, `url` parsing, OS RNG). `oxide-auth` 0.6 (with an
  axum 0.8 frontend) was considered: it has no resource indicators (RFC 8707), dynamic registration (RFC 7591),
  revocation (RFC 7009) or refresh-family reuse detection, and its registrar/authorizer/issuer traits are exactly
  where Dove's security logic lives (invitation consumption, connection-bound families, SQLite transactions), so
  it would add a dependency without removing the code that needs review. Every guard has a mutation-checked test.
- A11. Authority comes only from invitations. One approval creates one `kind = 'oauth'` connection; its code and
  token family point at that connection (`family_id = connection_id`), so no migration was needed. Tokens carry
  no grants, which is why refresh cannot broaden the intersection. Scope is a single informational `mail`;
  unknown requested scopes are ignored, never granted.
- A12. A missing `resource` parameter at authorize binds to `<public_url>/mcp` (the only resource); any other
  value is `invalid_target`. Access tokens are accepted on `/mcp` only for that resource.
- A13. Refresh rotation is strict: reuse of a rotated refresh token, or of a used code, revokes the connection
  and all its tokens (and bumps `auth_epoch`). There is no grace window, so a host that refreshes twice in
  parallel loses the connection and needs a new invitation. Rotation also retires older access tokens.
- A14. Approval-page state (pending requests, CSRF token, browser-binding cookie `__Host-dove_authz`) lives in
  memory, bounded to 10 000 requests (20 per source IP, GET rate-limited per IP) for 10 minutes. A restart only
  makes the user start the sign-in again.
- A15. Dynamic registration accepts public clients only (`token_endpoint_auth_method = none`), 1-5 redirect URIs,
  HTTPS or loopback HTTP; custom schemes and Client ID Metadata Documents are unsupported and fail explicitly.
  Registrations are capped (`oauth.max_dynamic_clients`, unused ones pruned after 24 h) and limited per IP per
  hour. Pre-registered (optionally confidential) clients are configured in `[[oauth.clients]]` with a secret file.
- A16. Removing a mailbox from a project cancels the project's open invitations, so a re-add cannot resurrect
  rights through an old invitation. Accounts deleted before redemption are dropped from the invitation.
- A7. Licence is a placeholder (Apache-2.0) until the owner decides (spec 13.7).
