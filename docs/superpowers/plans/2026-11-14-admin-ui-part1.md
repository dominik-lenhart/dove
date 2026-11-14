# Admin web UI, part 1: foundation, passkeys, Requests page — Implementation Plan

**Goal:** The owner reaches `/admin` over the tailnet, signs in with a passkey, sees the server's state and decides
agent requests on a phone; every approval is confirmed with a fresh passkey assertion bound to exactly that action.

**Spec:** `docs/superpowers/specs/2026-11-14-requests-and-admin-ui-design.md`, section 5 (1-4 context). Stage 1 of
the requests (`src/requests/`, `Requests*` verbs) is in main; stage 2 (access requests) is built in parallel and is
not touched here.

**Tech stack:** Rust, axum 0.8, the crates in the tree. One new *direct* dependency, `aws-lc-rs` (already in the
tree through rustls, same version, no new crate): ECDSA P-256 and Ed25519 verification, and key generation for the
software authenticator in the tests.

## Decisions taken while planning

- **WebAuthn crate:** no `webauthn-rs`. `webauthn-rs-core` 0.6.2 brings x509-parser, der-parser, nom 7,
  serde_cbor_2, a second base64 (0.21), thiserror 1, serde_with and an attestation CA store: a large parsing surface
  for attestation formats Dove never verifies (attestation `none`). Instead `src/admin_ui/webauthn.rs` (registration
  and assertion checks) on `aws-lc-rs`, and `src/admin_ui/cbor.rs`, a minimal definite-length CBOR decoder (no
  indefinite lengths, no tags, no floats, depth and size bounded, duplicate map keys refused). Tested against the
  W3C WebAuthn Level 3 test vectors (section 16; public inputs/outputs in `tests/fixtures/webauthn/w3c-vectors.txt`),
  RFC 8949 Appendix A CBOR examples, and end to end with a software authenticator in `tests/support/authenticator.rs`.
- **Attestation:** Dove requests `attestation: "none"` and never relies on an attestation statement, so any `fmt` is
  accepted and its `attStmt` ignored (some clients still send `packed` self attestation; it proves nothing Dove uses).
- **Algorithms:** ES256 (-7) and EdDSA/Ed25519 (-8). Everything else refused.
- **Discoverable credentials:** login sends no `allowCredentials` (the login page is unauthenticated and must not list
  credential ids); enrolment asks for `residentKey: "required"`. Each passkey has its own random user handle so a
  second enrolment on the same device does not overwrite the first.
- **Step-up uses the session's passkey:** the step-up assertion must come from the passkey the session signed in with
  (fail closed; the audit actor is that passkey's label).
- **Sign counter:** if the stored or the new counter is non-zero, the new one must be greater, else the assertion is
  refused (cloned authenticator). Both zero (synced passkeys) is fine. The backup-eligible flag must not change.
- **CSRF token:** derived, not stored: `b64url(SHA-256("dove-admin-csrf" || session token))`. Only the session token's
  SHA-256 is stored; the CSRF token reveals nothing about it.
- **Enrolment link:** `<origin>/admin/enroll#<token>`. The token sits in the fragment, so it never reaches a proxy or
  server log or a Referer. 32 random bytes, stored as SHA-256, 5 minutes, consumed in the same transaction that
  stores the passkey. Successful enrolment signs the browser in.
- **Doctor on the Overview:** `doctor` probes the public URL and Google (seconds). The Overview shows the last result
  (kept in memory with its time) and a "Run checks" link to `/admin/health`, which runs the `Doctor` verb.
- **DoS by a local process** (filling challenge pools, spending the per-address budget that every loopback caller
  shares behind Tailscale Serve) is out of scope; the pools are bounded so memory stays bounded, and login challenges
  live 2 minutes in a pool of 64 under a per-address rate below 64 per 2 minutes, so one address cannot evict them.
- **Fail closed where the design is silent:** POSTs without `Origin`, or with `Sec-Fetch-Site` other than
  `same-origin`, are refused; `/admin` refuses every method but GET and POST; unknown paths under `/admin` are 404
  only after the session check (no path probing without a session).

## Files

| File | Responsibility |
| --- | --- |
| `src/admin_ui/mod.rs` | `ADMIN_PREFIX`, `ADMIN_PATHS`, `ADMIN_PUBLIC_PATHS`, router, gate middleware (session, CSRF, Origin), security headers, `Runtime` (pools, health cache), the verb coverage table |
| `src/admin_ui/cbor.rs` | minimal CBOR decoder |
| `src/admin_ui/webauthn.rs` | `verify_registration`, `verify_assertion`, COSE key parsing |
| `src/admin_ui/auth.rs` | passkeys, enrolment tokens, sessions in the store; challenge pools; cookie; login, enrolment and step-up handlers |
| `src/admin_ui/html.rs` | escaping template layer (`h!` macro, `Markup`), page shell, shared components |
| `src/admin_ui/pages.rs` | Overview, Health, Requests list and detail, Audit, Settings handlers and renderers |
| `src/admin_ui/static/admin.css`, `admin.js` | the one stylesheet and the one script (WebAuthn calls, step-up forms) |
| `src/admin/mod.rs`, `server.rs`, `src/cli.rs` | verbs `PasskeysAdd/List/Remove`, `SessionsList/Revoke`; `dove admin passkey …`, `dove admin sessions …` |
| `src/config.rs` | `[admin_ui]` |
| `src/store/schema.rs` | `V_ADMIN_UI` (additive) |
| `src/http.rs` | guard: `/admin` host check (404), `Authorization` refused, per-address rate limit, own Origin rule |
| `src/tailscale.rs`, `src/cli.rs` | `dove tailscale setup --admin`, drift test with `ADMIN_PATHS`, doctor understands `/admin` |
| `src/mcp.rs` | `RateLimiter::exhausted` (peek without spending) |
| docs | AGENTS.md invariant, spec, deployment (setup, tailnet nginx block), CHANGELOG, PLAN A73 |

## Config

```toml
[admin_ui]
enabled = false                                  # default
origin = "https://dove-host.tail1234.ts.net"     # required when enabled; https, a DNS name, no path
requests_per_minute = 120                        # per client address, every /admin request
login_failures_per_hour = 10                     # per client address; spent only by failed logins
```

`validate`: enabled in local mode is an error ("not available in local mode"); enabled without a valid origin is an
error. Routes are mounted only when enabled and not local; the guard refuses `/admin` anyway in both cases (404).

## Schema `V_ADMIN_UI`

```sql
CREATE TABLE admin_passkeys (id TEXT PRIMARY KEY, label TEXT NOT NULL UNIQUE, credential_id BLOB NOT NULL UNIQUE,
  user_handle BLOB NOT NULL, alg INTEGER NOT NULL CHECK (alg IN (-7, -8)), public_key BLOB NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0, backup_eligible INTEGER NOT NULL, backup_state INTEGER NOT NULL,
  created_at INTEGER NOT NULL, last_used_at INTEGER);
CREATE TABLE admin_enrolments (token_hash BLOB PRIMARY KEY, label TEXT NOT NULL, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, used_at INTEGER);
CREATE TABLE admin_sessions (id TEXT PRIMARY KEY, token_hash BLOB NOT NULL UNIQUE,
  passkey_id TEXT NOT NULL REFERENCES admin_passkeys(id) ON DELETE CASCADE, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL);
```

## Routes (`ADMIN_PATHS`)

Public (no session; POSTs still need `Origin`): `/admin/login`, `/admin/login/options`, `/admin/login/finish`,
`/admin/enroll`, `/admin/enroll/options`, `/admin/enroll/finish`, `/admin/static/admin.css`, `/admin/static/admin.js`.

Session: `GET /admin` (Overview), `GET /admin/health`, `GET /admin/requests`, `GET /admin/requests/{id}`,
`POST /admin/requests/{id}/approve` (step-up begin), `POST /admin/requests/{id}/deny`,
`POST /admin/requests/{id}/cancel`, `GET /admin/audit`, `GET /admin/audit/verify`, `GET /admin/settings`,
`POST /admin/settings/passkeys/{name}/remove` (step-up begin), `POST /admin/settings/sessions/revoke`,
`POST /admin/stepup` (step-up finish), `POST /admin/logout`.

## Flows

- **Gate (middleware on the admin router):** public path → only the Origin rule for POST. Otherwise: valid session
  cookie `__Host-dove_admin` (SHA-256 lookup, not expired, passkey present) or GET → 303 `/admin/login`, POST → 401.
  POST additionally: `Origin` equals `admin_ui.origin`, `Sec-Fetch-Site` absent or `same-origin`, CSRF token from
  `X-Dove-CSRF` or form field `csrf` equals the session's (constant time). The body is buffered (64 KiB cap) to read
  the form field and handed on unchanged. The `Session` goes into the request extensions.
- **Login:** options → `{id, publicKey}` (challenge in the login pool, 2 min, single use); finish → verify, update
  counter/flags/last use, new session (12 h), `Set-Cookie: __Host-dove_admin=…; Path=/; Secure; HttpOnly;
  SameSite=Strict; Max-Age=43200`, audit `admin_ui.login` (actor `web:<label>`); a failure spends one token of the
  per-address login-failure bucket and is audited (`admin_ui.login`, `denied`, no label).
- **Step-up:** a step-up route builds the `AdminRequest`, stores `{session id, passkey id, action, return path}` under a
  pending id; challenge = SHA-256(32 random bytes || canonical JSON of the action); answers JSON `{id, publicKey}` with
  `allowCredentials` = the session's credential. `POST /admin/stepup {id, credential}` takes the entry out (single use,
  even on failure), checks it belongs to this session, that the clientData challenge is that entry's challenge, and the
  assertion; then runs exactly the stored `AdminRequest` through `admin::server::dispatch` with actor
  `web:<label>`. Pool: 2 min, at most 4 per session (oldest dropped), 64 overall (refused when full).
- **Verbs:** handlers only build `AdminRequest` values and call `dispatch`. `needs_step_up(&AdminRequest)` is an
  exhaustive match; `run_action` (session path) refuses a verb that needs step-up, so a step-up verb cannot be reached
  with session + CSRF alone.

## Pages

Login, Enrol, Overview (pending count, next scheduled sends, index status per mailbox, last health result), Health,
Requests (pending / scheduled / history), Request detail (note, per item the draft as a mail: from, to, cc, bcc,
subject, text body in `<pre>`, attachment names and sizes, planned time, state; approve form with per-item checkboxes
and the late choice; deny; stop), Audit (filters actor, action, mailbox, result, since; verify chain), Settings
(passkeys with remove, sessions with revoke one/all, sign out, how to add a passkey). Navigation: Overview, Requests,
Audit, Settings. Responsive from 360 px, light/dark via `prefers-color-scheme`, buttons at least 44 px high.

## Tests that prove each rule

| Rule | Test |
| --- | --- |
| CBOR decoder: RFC 8949 examples, indefinite/tag/float/duplicate key/trailing bytes/depth refused | `admin_ui::cbor::tests` |
| W3C vectors verify (ES256, EdDSA, long credential id); crossOrigin vector refused; UV is required | `admin_ui::webauthn::tests::w3c_*` |
| wrong RP ID hash, wrong origin, wrong type, wrong challenge, missing UP, missing UV, tampered signature, tampered authData, counter regression, BE change | `webauthn::tests` + `tests/admin_ui_auth.rs` |
| `/admin` with another Host → 404; disabled → 404; local mode → refused by config | `admin_ui_http.rs::host_and_switch` |
| `Authorization` header on any `/admin` path refused, also with a valid session | `admin_ui_http.rs::bearer_refused` |
| every non-public `ADMIN_PATHS` entry answers neither GET nor POST without a session | `admin_ui_http.rs::nothing_answers_without_a_session` |
| POST without CSRF, with a wrong CSRF, without/with a foreign Origin, cross-site `Sec-Fetch-Site` → refused, nothing changed | `admin_ui_http.rs::writes_need_csrf_and_origin` |
| security headers (CSP exactly as designed, frame-ancestors, no-store) on every page | `admin_ui_http.rs::headers` |
| rate limit and login-failure limit per address | `admin_ui_http.rs::limits` |
| enrolment link: one use, 5 minutes, label `valid_name`, unique credential id | `admin_ui_auth.rs::enrolment_*` |
| login with UV; session expiry; revoke ends sessions; passkey removal ends its sessions; only the token hash stored | `admin_ui_auth.rs::login_*`, `sessions_*` |
| step-up: approve runs exactly the stored action; replay refused; assertion for another action refused and nothing runs; other session's pending id refused; expired; a step-up verb is refused on the session-only path | `admin_ui_auth.rs::stepup_*` |
| stored XSS: draft subject/body/headers/attachment name, agent note, client name, audit fields render escaped | `admin_ui_pages.rs::untrusted_values_are_escaped` |
| draft view shows sender, recipients, subject, text body, attachments; HTML never rendered | `admin_ui_pages.rs::draft_view` |
| approve/deny/stop from the UI go through `dispatch` with actor `web:<label>` | `admin_ui_pages.rs::actions_are_audited_as_web` |
| every `AdminRequest` variant is in the UI or excluded with a reason | `admin_ui::tests::every_verb_is_covered` |
| `ADMIN_PATHS` = admin routes; disjoint from `PUBLIC_PATHS`; no deploy template forwards `/admin` | `tailscale::tests::allowlists_do_not_drift` |
| `tailscale setup --admin` mounts `/admin`; refuses with `--funnel` or Funnel on; setup without `--admin` removes it | `tests/tailscale_e2e.rs` |
| no session token, CSRF, challenge, enrolment token, mail content or note in logs/audit | `admin_ui_auth.rs::secrets_stay_out_of_logs_and_audit` |

Every guard above is mutation-checked (remove the guard, see the test fail, restore, `touch`).

## Steps (commit after each)

1. Plan (this file).
2. `cbor.rs`, `webauthn.rs` with unit tests and vectors; `aws-lc-rs` direct dependency; `cargo deny check`.
3. Config `[admin_ui]`, schema `V_ADMIN_UI`, store functions, admin verbs and CLI (`dove admin passkey|sessions`).
4. HTTP guard changes, router, gate, headers, html layer, static assets, login/enrolment/step-up; auth tests.
5. Pages; page tests incl. XSS; coverage test.
6. Tailscale `--admin`, drift test, doctor.
7. Docs; fmt, clippy, deny, full suite under `heavy`, gitleaks; screenshots if possible; PR.
