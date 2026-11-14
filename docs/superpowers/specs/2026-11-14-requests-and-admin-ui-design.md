# Dove design: agent requests, scheduled send, admin web UI

Status: approved by the owner on 2026-11-14. Build order in section 6; nothing is built yet.
Where this document and the code disagree, raise it; do not silently diverge. Decisions marked **(owner)** were made
by the owner in conversation; everything marked **(call)** is the author's proposal and may be overruled.

## 1. Intent

Agents should run with as few rights as possible. Whatever goes beyond their grants becomes a *request* that the owner
approves or denies: "send these 20 drafts spread over Tuesday, unless someone replied meanwhile", "give me read on
mailbox X for an hour". The owner decides in a comfortable web page instead of the CLI, and manages the whole server
there: requests, connections and tokens, mailboxes, audit log.

Concrete trigger: an agent without send rights prepared 20 drafts, the owner read them all, and there is no way to
let them go out on a schedule without granting the agent `send`.

## 2. Goals, non-goals, anti-goals

Goals
- An agent can ask for a scheduled send of its own drafts and for more access, and learn the outcome.
- Nothing a request asks for happens before the owner approved exactly that.
- A web UI on the same port as Dove offers every verb the admin socket offers **(owner: "alles wie CLI")**.
- UI login and every approval use a passkey **(owner)**. Network access to the UI is the tailnet only **(owner)**.

Non-goals (this design)
- Conditions other than "no reply arrived" on a scheduled send.
- Editing a draft's text in the UI. The owner edits in their mail client, which makes the draft human-owned and
  therefore drops it from the request (see 4.3).
- Pushing the decision to the agent. The agent polls `list_requests` (a watch-event kind can follow later).
- The admin UI in local mode (the local user is the operator and has the CLI; WebAuthn needs a domain name).
- CLI-side commands that are not admin-socket verbs: `dove upgrade`, `dove tailscale`, `dove local …`, editing the
  config file. The service runs sandboxed as its own user and cannot do these.

Anti-goals (a build that does these has failed even if it works)
- Mail leaving at a time or with content the owner did not approve, or twice.
- An agent token reaching any admin verb, or an agent on the same host approving its own request.
- `/admin` reachable through the public reverse proxy or Funnel.
- Mail content, subjects, addresses or request notes in logs or audit rows.

## 3. Approaches considered

| | Approach | Trade-off |
| --- | --- | --- |
| A | UI inside the service on the same listener; login by a one-time pairing link from the CLI | No new dependency, but a stolen browser session can approve sends |
| B | Same, with passkeys for login and for each approval | Stronger; needs WebAuthn verification and one CLI step to enrol the first passkey |
| C | Separate admin process on its own port, talking to the Unix socket | Keeps HTTP admin out of the service, but needs a second port, which the owner does not want |

**Chosen: B (owner).** C was dropped for the second port. A survives only as the enrolment step of B.

Why a login at all when access is tailnet-only: the agents run on the same host as Dove and reach
`127.0.0.1:<port>/admin` without the tailnet. Tailscale identity headers cannot be trusted over loopback (PLAN A52).
The passkey is the control that separates the owner from local processes. It does not help against an agent with
`sudo` (that agent already has admin rights through the socket); this is documented, not solved here.

## 4. Requests

### 4.1 Model

One table `requests` and one table `request_items` in the state store (new numbered migration; other open PRs add
migration 9, so take the next free number at merge time).

`requests`: `id` (uuid), `client_id`, `project_id`, `kind` (`send` | `access`), `status`, `note_sealed`,
`created_at`, `expires_at`, `decided_at`, `decided_by` (audit actor), `payload` (JSON, ids and times only).

Status: `pending` → `approved` | `denied` | `cancelled` | `expired`; an approved request ends as `done` when no item
or grant is left active.

- The note is free text from the agent (max 500 chars) shown to the owner. It is untrusted and may quote mail, so it is
  sealed with the vault like sink URLs, shown escaped, and never written to logs or audit **(call)**.
- A pending request expires after 7 days **(call)**. Limits per client: 20 open requests, 50 items per send request,
  both in `[limits]` **(call)**.
- Revoking a client cancels its pending requests and its not-yet-sent items. Removing a mailbox does the same for the
  items and grants that name it.
- Every create, decide, cancel and every item outcome writes one audit record (ids, kind, result code; nothing else).

### 4.2 MCP tools

All four are available to every authenticated client, declared `mail_content: false`.

- `request_send { account, items: [{ draft_id, expected_revision, send_at? }], window?: { from, to }, unless_reply?: bool, note? }`
  Needs `draft` on the mailbox and every draft must be one this client's project created and nobody changed
  (the same ownership rule as `send_draft`). It needs neither the `send` grant nor `allow_send` **(owner)**: the
  owner's approval of the exact mail is a stronger gate than a standing grant, and `allow_send` keeps its meaning
  "agents may send on their own". A new switch `[requests] enabled` (default `true`) turns the whole feature off.
  Times: either `send_at` on every item, or one `window` and Dove spreads the items evenly across it in input order.
  The assigned times are stored and shown to the owner before approval. `send_at` must be in the future and at most
  30 days out.
- `request_access { grants: [{ account, actions }], duration_minutes?, note? }`
  `actions` use the grant syntax (`read`, `assistant`, `read,draft`). The account must belong to the client's project.
  An unknown alias and an alias outside the project return the identical `not_found`; there is no tool that lists
  requestable mailboxes, the human tells the agent the alias **(call)**. Without `duration_minutes` the request is for
  a permanent grant; the maximum duration is 30 days. `send` can be requested only when `allow_send` is on.
- `list_requests { status? }` returns the client's own requests with per-item state and reason codes.
- `cancel_request { request_id }` cancels a pending request or the unsent items of an approved one.

Unknown ids and ids of other clients return the identical `not_found`.

### 4.3 Approving a send

The owner sees, per item, the draft as it is now: sender, recipients, subject, text body, attachment names and sizes,
the planned time, and whether `unless_reply` is set. The UI reads the draft through the same code path as `get_draft`.
The body is shown as text; HTML is never rendered.

- Approval is per item: approve all, or untick single items, or deny the request. It records the draft revision the
  owner was shown. Dove refuses the approval if the draft changed between showing and approving (reload).
- At send time the draft must still have that revision and still be owned by Dove. Otherwise the item ends as
  `failed: draft_changed` and nothing is sent. So neither the agent nor anyone else can change approved mail.
- Items whose time has already passed when the owner approves are listed separately with the choice "send now" or
  "skip"; the default is skip. The owner cannot edit times in v1; the agent sends a new request **(call)**.

### 4.4 Sending on schedule

A worker `requests::tick(app, now)` (same pattern as `watch::tick`; tests drive the clock) picks due items.

Per item, in this order: request still approved, client not revoked, mailbox active, draft revision unchanged,
condition holds, then the send claim is recorded **before** the upstream write, then the draft is sent through the
existing send path (same outcome classification as `send_draft`, Sent copy handling and all).

The send core is split out of the `send_draft` tool into a function that takes no part in `policy::authorize`
(it may keep `ToolCx` as the carrier of app, client and write deadline); the tool and the worker both call it. The tool keeps its policy check and its one audit record per call.
The worker authorizes by the checks above and writes its own audit record per item (actor `scheduler`, action
`request.send_item`, request and item ids). The sender identity is checked again at send time as today; if an alias
was removed since approval the item ends as `failed` with that check's code, not as `draft_changed`.
A draft revision that changed for any reason, including a provider-side rewrite, fails closed as `draft_changed`;
a spurious failure is accepted and visible in the request.

- An item found in `sending` after a restart, or whose write ended `outcome_unknown`, ends as `send_unknown` and is
  never retried. A write that was not dispatched (rate limit, mailbox unavailable) is tried again within the
  grace; an upstream refusal is tried 3 times, 5 minutes apart, then ends as `failed` with the code.
- An item that could not be sent within 60 minutes after its time (server down, upstream down) ends as `missed` and
  is not sent **(call)**. The grace is `[requests] late_grace_minutes`.
- `unless_reply`: the item is skipped (`skipped: replied`) when the draft's thread holds a message from someone else
  that arrived after the request was created. This reuses the reply rule of the `no_reply_by` watch (PR #14:
  own addresses, aliases and `SENT` do not count, drafts do not count, `>=` with baseline ids), with one difference:
  a reply in Trash or Spam counts. The owner may have read and binned the answer; the index has one flag for both,
  so a spam message in the thread also skips the send (the fail-closed side). It needs the
  mailbox indexed; `request_send` refuses `unless_reply` otherwise. If the index was not synced within the last
  10 minutes at send time, or the mailbox's index has a message waiting in its retry queue (a fetch that failed;
  it could be the reply, and its thread is unknown until it is fetched), the worker asks for a sync and waits for
  the next pass within the grace; if freshness cannot be established the item ends as `skipped: condition_unknown`.
  Fail closed: never send on a stale check.
  A draft that is not a reply (no thread yet) with `unless_reply` is `invalid_argument` at request time.
  The baseline is request creation, not approval: a reply between request and approval also skips the item. If
  indexing is switched off after approval the item ends as `skipped: condition_unknown`. If the index offers no way
  to ask for a sync of one mailbox yet, add one.
- A server-wide cap `limits.scheduled_sends_per_day` (default 200) bounds what approvals can queue **(call)**.
- The owner can stop any unsent item or the whole request at any time.

### 4.5 Approving access

Approval writes the grants through the existing `write_grants` path (dependency rules of `Actions` apply), so a
request can only add. The owner can shorten the duration or untick single mailboxes before approving.

- Temporary rights live in their own table `client_grant_extras(client_id, account_id, actions, expires_at)`;
  `client_mailboxes` is not touched, so expiry never removes rights the client had before **(call)**. A permanent
  approval goes into `client_mailboxes` as today.
- `policy` builds the client's actions per request as the union of the base grant and the unexpired extras, and applies
  the dependency rules to the union. Expiry therefore takes effect at once, without a cache; the worker deletes
  expired rows and writes an audit record.
- When the owner replaces a client's grants (`clients set-grants`), that client's extras are deleted **(call)**.
- What can be granted is whatever `Actions::parse_grant` accepts for that mailbox today; requests add no new rule.

### 4.6 Telling the owner

Ships with stage 3, when there is an admin URL to link.

Optional `[requests] notify_sink = "<sink name>"`: a new pending request posts `{ kind, request_id, url }` to that
existing sink (ids only, with the admin URL of the request). Without it the owner sees requests in the UI and in
`dove requests list`.

### 4.7 CLI

`dove requests list|show|approve|deny|cancel` as admin-socket verbs, built first. The UI and the tests use the same
verbs. `approve` takes `--items`, `--late send|skip`, and for access `--duration`. `show` prints the draft like the
UI does (to the operator's terminal only).

## 5. Admin web UI

### 5.1 Where it lives

- Routes under `/admin` on Dove's existing listener, enabled by `[admin_ui] enabled = true` (default `false`) and
  `[admin_ui] origin = "https://<host>.<tailnet>.ts.net"`. Requests to `/admin` with another `Host` get 404.
- `/admin` is not in `PUBLIC_PATHS`. A second list `ADMIN_PATHS` joins the drift test, which then also asserts that
  no deploy template forwards it publicly.
- `dove tailscale --admin` mounts `/admin` on the tailnet name and refuses when Funnel is on for that port. For a
  reverse-proxy setup the deployment guide gets a server block bound to the tailnet address. Setting this up on the
  owner's host is a deployment step that needs the owner's go-ahead (the host's Tailscale serves other things).
- `/admin` never accepts an `Authorization` header: a request carrying a bearer token is refused, so an agent token
  cannot become an admin credential by accident.

### 5.2 Login and approvals with passkeys

- Enrolment: `sudo dove admin passkey add --name <label>` prints a one-time link (5 minutes) to the enrolment page.
  `dove admin passkey list|remove`. The trust root stays the admin socket.
- Login: WebAuthn assertion with user verification required. Session cookie `__Host-dove_admin` (HttpOnly, Secure,
  SameSite=Strict), 12 hours, bound server-side; `dove admin sessions revoke` ends all sessions.
- Step-up: approving a request, widening any grant, creating or rotating a token, connecting or reconnecting a
  mailbox, adding a sink and removing a passkey each need a fresh assertion whose challenge is bound to a hash of that
  action's payload. One assertion covers one approval of a whole request (all 20 drafts) **(call)**. Other writes need
  the session, a per-session CSRF token and a matching `Origin`.
- The server generates every challenge and stores the pending action (its canonical payload: for an approval the
  request id, item ids, shown draft revisions, times and the late choice) under it, single-use. The browser only
  signs the challenge; it computes no hash. On success the server executes exactly the stored action.
- Approval through the CLI needs no passkey: the admin socket's peer-uid check is the credential there.
- Passkey labels follow `valid_name` (they appear as the audit actor). Passkeys and sessions live in the state store;
  sessions are not bound to an address. `admin passkey …` and `admin sessions revoke` are admin-socket verbs
  (optional fields per the `deny_unknown_fields` learning in AGENTS.md). The RP ID is the host of `origin`; changing
  that name means enrolling passkeys again, which is accepted.
- WebAuthn verification: attestation `none`, ES256 (and EdDSA if cheap). Builder's choice between `webauthn-rs`
  (only if it builds against what is in the tree and passes `cargo deny`) and a small verifier on the P-256 code
  already in the tree with a CBOR parser, tested against published vectors. Either way: sign-count/backup flags
  stored, challenges single-use and bounded in memory, security review by a second model before merge.

### 5.3 One implementation of every verb

UI handlers build `AdminRequest` values and call the same `admin::server::dispatch` as the socket, with the audit
actor `web:<passkey label>`. A test walks every `AdminRequest` variant and requires it to be reachable in the UI or
named on an explicit exclusion list with a reason. Secrets entered in the UI (IMAP password) travel as
`admin::Password`; a token shown once is sent with `Cache-Control: no-store`.

### 5.4 Pages

| Page | Content |
| --- | --- |
| Overview | doctor result, index status per mailbox, pending requests count, next scheduled sends |
| Requests | pending (approve/deny), scheduled (timeline of a day, stop), history |
| Connections | clients and invitations: grants, expiry, redaction, IP lists, rotate, revoke, invite |
| Mailboxes | connect Gmail (starts the existing OAuth flow) and IMAP, reconnect, enable/disable, aliases, signatures, indexing |
| Projects | projects and their mailboxes |
| Watches and sinks | list, remove, add sink |
| Audit | search by actor, tool, mailbox, result, time; verify the chain |
| Settings | passkeys, sessions |

Server-rendered HTML in the style of the OAuth approval page: no framework, no build step, no external asset.
One small script file for the WebAuthn calls. Headers: `Content-Security-Policy: default-src 'none'; script-src 'self';
style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`, no inline script or
style. Every value is escaped by the template layer; draft text, mail headers and agent notes are untrusted input.
The look gets a real design pass at build time (the owner wants it comfortable, not a bare table dump), including a
phone layout, since approvals will often happen on a phone.

### 5.5 Security invariant that changes

AGENTS.md today: "Admin happens only over the Unix socket after a peer-uid check." New wording: admin happens over the
Unix socket after a peer-uid check, or over `/admin` after passkey authentication; agent tokens never reach admin
verbs. `/admin` has its own rate limit and login-attempt limit per address.

## 6. Build order

Each stage is a release of its own and useful alone.

1. **Requests and scheduled send, CLI approval** (4.1–4.4, 4.7; 4.6 ships with stage 3). Solves the trigger case with
   `dove requests approve`.
2. **Access requests and temporary grants** (4.5).
3. **Admin UI**: passkeys and sessions first (reviewed alone), then pages, Requests page first (5).

## 7. Left to the builder

Table and column details beyond the above, template mechanism (hand-written with an escape helper or a compile-time
template crate that auto-escapes), WebAuthn crate choice within 5.2, exact page layout, how the worker shares code
with `send_draft`, PLAN entry numbers (take the next free ones after the open PRs). One store migration per stage,
additive only (`CREATE TABLE`, `ALTER TABLE ADD COLUMN`); never rebuild `client_mailboxes`.

## 8. Testing

As everywhere in Dove: integration tests against the fake Google and fake IMAP/SMTP servers, each new guard
mutation-checked. Must-have cases: approved mail changed before send; item due during downtime; restart while
`sending`; reply arrives before the time (`unless_reply`), own follow-up does not count; stale index fails closed;
revoked client; temporary grant expires and earlier rights stay; bearer token on `/admin`; `/admin` with a wrong
`Host`; assertion replay and assertion bound to another action; every `AdminRequest` variant covered or excluded.
