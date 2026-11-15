# Admin UI part 2 Implementation Plan

> Executed natively in one session (owner's standing go-ahead: build, merge, release).

**Goal:** Every remaining admin verb is reachable in `/admin` (design 2026-11-14 §5.4), plus the request notice to a sink
(§4.6) and an admin-only mode for `dove tailscale setup`.

**Spec:** `docs/superpowers/specs/2026-11-14-requests-and-admin-ui-design.md` §4.6, §5.3, §5.4.

## Global constraints

- Handlers only build `AdminRequest` values (`auth::run_action` / `auth::begin_stepup`); step-up verbs per
  `needs_step_up`. Templates via `h!` with positional `{}`; every value escaped.
- Secrets shown once (token, invitation link, Gmail sign-in link, enrolment link) go through a reveal page: the
  step-up stores the verb's result in a single-use in-memory pool bound to the session; `/admin/reveal/{id}` renders it
  once with `no-store`.
- New verbs (`WatchesList`, `WatchesRemove`) are optional-field safe and classified in `needs_step_up` and `COVERAGE`.
- One store migration, additive only (request notices outbox).

## Tasks

1. Reveal-once results for step-up verbs (`auth::StepUp.return_to` becomes `After::{Redirect, Reveal}`), nav entries,
   coverage test reads all page files.
2. Connections: list (+ unfinished operations), new token / invitation (step-up, reveal), detail with grants
   (step-up), redaction, rotate (step-up, reveal), revoke.
3. Mailboxes: list with index state, connect Gmail (step-up, reveal sign-in link) and IMAP (step-up), detail with
   check, enable/disable, remove, reconnect, indexing, send-as aliases, signatures.
4. Projects: list, create, detail, add/remove mailbox.
5. Watches and sinks: new verbs `WatchesList`/`WatchesRemove` (+ CLI `dove watches list|remove`), sinks add (step-up),
   move, remove.
6. Settings: add a passkey (step-up, reveal enrolment link), export download, re-encrypt keys; audit prune.
7. `[requests] notify_sink`: durable outbox, signed POST `{event, kind, request_id, url}` through the gateway.
8. `dove tailscale setup --admin-only`: mounts only `/admin`, leaves `public_url` alone.
9. Tests per page (HTTP e2e with the soft authenticator), browser walk-through with the demo, docs, release.

## Review focus

- A reveal id used twice, by another session, or after 5 minutes shows nothing.
- An IMAP password or sink secret never lands in an audit row, log line or rendered page.
- Unknown alias / client / project names in a URL give the verb's error page, not a panic or 500.
- Names with `/`, `?`, `#` or spaces in path segments round-trip (percent-encoding).
- Phone layout: eight sections do not overflow the bottom tabs.
