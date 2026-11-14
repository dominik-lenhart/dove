# Requests stage 1: scheduled send with CLI approval — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An agent without send rights can ask Dove to send its own drafts at given times; the operator approves with
`dove requests approve`, and Dove sends exactly the approved revision at the approved time.

**Architecture:** A new module `src/requests/` owns two state-store tables, the request lifecycle and a worker
`requests::tick` (same pattern as `watch::tick`). MCP tools create and inspect requests; admin-socket verbs decide
them. Sending reuses the `send_draft` path through one shared core, so ownership, the send claim and outcome
classification exist once.

**Tech Stack:** Rust, the crates already in the tree. No new dependency.

**Spec:** `docs/superpowers/specs/2026-11-14-requests-and-admin-ui-design.md`, sections 4.1–4.4 and 4.7.
Deviations decided while planning: 4.6 (notify sink) moves to stage 3, when there is an admin URL to link; the send
core keeps `ToolCx` as its carrier (it holds the app, the client and the write deadline) but takes no part in
`policy::authorize`.

## Global Constraints

- Read `AGENTS.md` and `AGENTS.local.md` first. Builds and full suites only through
  `CARGO_BUILD_JOBS=3 heavy cargo …`, tests with `--test-threads=2`, a private target dir per worktree.
- Every new guard gets a test that fails when the guard is removed (mutation-check, then restore and `touch`).
- No mail content, subjects, addresses or request notes in logs or audit rows. Events and audit carry ids only.
- Unknown ids and ids of other clients return the identical `not_found`.
- SQLite transactions never span an `.await` on network I/O.
- Write paths call `cx.commit()` right before the first side effect and use `cx.write_deadline()`.
- A send with an unknown outcome is never retried. Mail is never sent later than `send_at + late_grace_minutes`.
- `request_send` needs `draft` on the mailbox, not `send`, and works with `allow_send = false` (owner decision).
- Store migration is additive (`CREATE TABLE` only), appended to `MIGRATIONS` as `V_REQUESTS`.
- Release as a minor version (new tools, CLI verbs, config keys, migration).

## Review Focus

1. `send_at` or `window` without a UTC offset, date-only, in the past, more than 30 days out, or `window.from >= to`:
   `invalid_argument` naming the field (Task 2 test `request_send_validates_times`).
2. The same draft in two open requests, or twice in one request: second use is `invalid_argument`, so no draft can be
   scheduled twice (Task 2 test `a_draft_is_requested_once`).
3. Upstream briefly down at `send_at`: the item stays `scheduled` and is retried on later ticks, then `missed` after
   the grace; it is never sent after the grace (Task 5 test `not_dispatched_is_retried_until_grace`).
4. Many items due at once (long downtime, same `send_at`): at most 10 sends per tick, oldest first, and items past
   the grace are `missed` before anything is sent (Task 5 test `due_items_are_bounded_and_missed_first`).
5. The agent updates or deletes the draft after approval, or sends it itself with a `send` grant: the item ends
   `failed` with `draft_changed` / `not_found`, nothing is sent twice (Task 5 test `approved_revision_is_binding`).

---

## File Structure

| File | Responsibility |
| --- | --- |
| `src/requests/mod.rs` (new) | types, status/state names, create/list/cancel/decide in the store, expiry, cascades |
| `src/requests/worker.rs` (new) | `tick`, `start`, `recover_after_restart`, the `unless_reply` check |
| `src/tools/requests.rs` (new) | MCP tools `request_send`, `list_requests`, `cancel_request` |
| `src/tools/drafts.rs` | split `send_core` out of `send_draft` |
| `src/store/schema.rs` | `V_REQUESTS` |
| `src/config.rs` | `[requests]` section, three `[limits]` keys |
| `src/admin/mod.rs`, `server.rs`, `ops.rs`, `src/cli.rs` | `Requests*` verbs and `dove requests …` |
| `src/serve.rs` | start the worker, run recovery |
| `tests/requests_e2e.rs` (new) | everything below, against fake Google and fake IMAP/SMTP |

### Task 1: Store, config and lifecycle

**Files:** `src/store/schema.rs`, `src/config.rs`, `src/requests/mod.rs`, `src/lib.rs`, unit tests in the module.

**Interfaces — produces:**

```sql
CREATE TABLE requests (
    id            TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    account_id    TEXT REFERENCES accounts(id) ON DELETE CASCADE,   -- NULL for kind 'access' (stage 2)
    kind          TEXT NOT NULL CHECK (kind IN ('send', 'access')),
    status        TEXT NOT NULL CHECK (status IN ('pending','approved','denied','cancelled','expired','done')),
    unless_reply  INTEGER NOT NULL DEFAULT 0,
    note_sealed   BLOB,
    payload       TEXT NOT NULL DEFAULT '{}',
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    decided_at    INTEGER,
    decided_by    TEXT
);
CREATE INDEX requests_client ON requests(client_id, status);
CREATE TABLE request_items (
    request_id        TEXT NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
    idx               INTEGER NOT NULL,
    draft_id          TEXT NOT NULL,
    requested_rev     TEXT NOT NULL,
    approved_rev      TEXT,
    send_at           INTEGER NOT NULL,
    state             TEXT NOT NULL CHECK (state IN ('pending','scheduled','sending','sent','skipped','failed',
                                                     'missed','send_unknown','cancelled','denied')),
    reason            TEXT,
    thread_id         TEXT,
    baseline_ms       INTEGER,
    baseline_ids      TEXT,
    sent_message_id   TEXT,
    attempts          INTEGER NOT NULL DEFAULT 0,
    next_try_at       INTEGER,
    updated_at        INTEGER NOT NULL,
    PRIMARY KEY (request_id, idx)
);
CREATE INDEX request_items_due ON request_items(state, send_at);
```

Config (all with defaults, so existing config files keep working):
`[requests] enabled = true`, `late_grace_minutes = 60`, `pending_days = 7`;
`[limits] client_open_requests = 20`, `request_items = 50`, `scheduled_sends_per_day = 200`.

```rust
pub struct NewItem { pub draft_id: String, pub requested_rev: String, pub send_at: i64,
                     pub thread_id: Option<String>, pub baseline_ms: Option<i64>, pub baseline_ids: Option<Vec<String>> }
pub struct NewSend { pub client_id: String, pub project_id: String, pub account_id: String,
                     pub unless_reply: bool, pub note_sealed: Option<Vec<u8>>, pub items: Vec<NewItem> }
pub fn create_send(tx: &Transaction, cfg: &Config, new: NewSend, now: i64) -> Result<String, CreateError>;
pub enum CreateError { TooManyOpen, DraftAlreadyRequested(usize /* item index */), Store(anyhow::Error) }
pub fn list_for_client(c: &Connection, client_id: &str, status: Option<&str>) -> anyhow::Result<Vec<RequestView>>;
pub fn cancel_by_client(tx: &Transaction, client_id: &str, id: &str, now: i64) -> anyhow::Result<bool>; // false = not_found
pub fn spread(from: i64, to: i64, n: usize) -> Vec<i64>;   // n == 1 → [from]; else from + i*(to-from)/(n-1)
pub fn close_if_finished(tx: &Transaction, request_id: &str) -> anyhow::Result<()>; // approved → done when no item is pending/scheduled/sending
pub fn cancel_for_client(tx: &Transaction, client_id: &str, now: i64) -> anyhow::Result<usize>;   // on revoke
pub fn cancel_for_account(tx: &Transaction, account_id: &str, now: i64) -> anyhow::Result<usize>; // on remove/disable
```

`RequestView` carries ids, kind, status, times, `unless_reply`, and per item `idx, draft_id, send_at, state, reason,
sent_message_id`. It never carries the note for agents (the note is write-only from the agent's side).

- [ ] Unit tests first: `spread` (1, 2 and 20 items, inclusive ends); `create_send` refuses the 21st open request
  and a draft that sits in another `pending`/`approved` request's unfinished item; `cancel_by_client` on someone
  else's id returns `false` and changes nothing; `close_if_finished` turns `approved` into `done` only when no item
  is `pending`, `scheduled` or `sending`.
- [ ] Implement, run `cargo test --lib requests::`, mutation-check the open-request limit and the duplicate guard.
- [ ] Wire `cancel_for_client` into the client-revoke path and `cancel_for_account` into account remove/disable in
  `admin/ops.rs`; integration test in Task 5 covers both.
- [ ] Commit: `requests: store, config and lifecycle`.

### Task 2: MCP tools

**Files:** `src/tools/requests.rs`, `src/tools/mod.rs` (register), `tests/requests_e2e.rs`.

**Interfaces — consumes** Task 1. **Produces** the tools:

- `request_send { account, items: [{draft_id, expected_revision, send_at?}], window?: {from, to}, unless_reply?, note? }`,
  capability `Draft`, `mail_content: false`, not read-only. Returns `{ request_id, status: "pending", items: [{idx,
  draft_id, send_at}] }`.
- `list_requests { status? }` and `cancel_request { request_id }`, capability `Read`.

Rules to pin:
- Every draft must be an `own_drafts` row of this project in state `active` whose `message_id` equals
  `expected_revision`; otherwise the same errors `send_draft` gives (`not_found`, `draft_conflict`). No upstream call
  is needed to create a request; the fresh check happens at approval and at send.
- Times are RFC 3339 with an offset; either every item has `send_at` or there is a `window` (not both, not neither);
  window times are assigned with `spread` in input order. Bounds: later than now, at most 30 days out.
- `note` at most 500 chars, sealed with the vault (new AAD kind `request_note`), never logged.
- `unless_reply: true` needs an indexed mailbox with a serving generation and a thread that holds at least one indexed
  message besides the draft; store `thread_id`, `baseline_ms = now*1000` and the ids of the thread's messages as
  `baseline_ids`. Otherwise `invalid_argument` naming `unless_reply`.
- With `[requests] enabled = false` the three tools are treated exactly as `send_draft` is treated under
  `allow_send = false` (same listing and same error).

Tests (integration, `tests/requests_e2e.rs`):
- [ ] `request_send_needs_draft_not_send`: a `read,draft` token with `allow_send = false` gets a `pending` request;
  a `read` token gets `forbidden`; fake Google saw no send.
- [ ] `request_send_validates_times` (Review Focus 1) and `a_draft_is_requested_once` (Review Focus 2).
- [ ] `window_spreads_items`: 5 drafts, window 09:00–17:00Z → 09:00, 11:00, 13:00, 15:00, 17:00.
- [ ] `requests_are_private_to_the_client`: a second client's `list_requests` is empty and its `cancel_request` of
  the first client's id is the identical `not_found` as for a random id.
- [ ] `note_is_sealed_and_absent_from_audit`: the note's text appears in no `audit` cell and no captured log line,
  and `requests.note_sealed` does not contain it in plaintext.
- [ ] Implement, mutation-check each rule, commit: `tools: request_send, list_requests, cancel_request`.

### Task 3: Shared send core

**Files:** `src/tools/drafts.rs`.

**Produces:**

```rust
pub(crate) enum SendAuth { Grant, Approved }
pub(crate) struct Sent { pub sent_message_id: Option<String>, pub thread_id: Value }
pub(crate) async fn send_core(cx: &ToolCx, mb: &Mailbox, draft_id: &str, expected: &str, auth: SendAuth)
    -> Result<Sent, ToolError>;
```

`send_draft` becomes argument parsing, `send_core(.., SendAuth::Grant)` and the output. Behaviour of the tool does
not change. With `SendAuth::Approved` the pre-dispatch recheck requires a live client epoch and the mailbox still
granted to the client with `draft` and status `active` (no `allow_send`, no `send` action), and the per-client
`client_sends_per_hour` budget is not charged (the approval cap in Task 4 bounds it instead).

- [ ] Run `cargo test --test send_e2e --test imap_send_e2e --test send_identities_e2e` before and after: unchanged.
- [ ] Commit: `drafts: send core shared by the tool and scheduled sends`.

### Task 4: Admin verbs and CLI

**Files:** `src/admin/mod.rs`, `src/admin/server.rs`, `src/requests/mod.rs`, `src/cli.rs`, `tests/requests_e2e.rs`.

**Produces** `AdminRequest` variants (new optional fields follow the `deny_unknown_fields` learning):

```rust
RequestsList { status: Option<String> },
RequestsShow { id: String },
RequestsApprove { id: String, shown: Vec<ShownItem>, items: Option<Vec<u32>>, late: Late },
RequestsDeny { id: String },
RequestsCancel { id: String, items: Option<Vec<u32>> },
pub struct ShownItem { pub idx: u32, pub revision: String }
pub enum Late { Skip, Send }
```

- `RequestsShow` reads each item's draft fresh through the `get_draft` code path (build the client's `ToolCx` the way
  `mcp.rs` does after token lookup) and returns per item: `idx, draft_id, revision, send_at, state, changed_since_request,
  from, to, cc, bcc, subject, body_text, attachments[{name, size}]`, plus the unsealed note. This content goes to the
  admin socket only; the audit row holds the request id.
- `RequestsApprove` re-reads every chosen draft; if any current revision differs from `shown`, nothing is approved and
  the error says to look again. Otherwise each chosen item becomes `scheduled` with `approved_rev`, unchosen items
  `denied`, the request `approved` with `decided_by` = audit actor. Items with `send_at <= now`: `Late::Skip` →
  `skipped` reason `late`; `Late::Send` → `scheduled` with `send_at = now`. The approval is refused when, for any UTC
  day, items in `scheduled|sending|sent|send_unknown` on that day plus the new ones exceed
  `limits.scheduled_sends_per_day`.
- `RequestsDeny`: `pending` → `denied`, items `denied`. `RequestsCancel`: unsent items (`pending|scheduled`) →
  `cancelled`; then `close_if_finished`.
- CLI: `dove requests list [--status s]`, `show <id>`, `approve <id> [--items 0,2] [--late send|skip] [--yes]`,
  `deny <id>`, `cancel <id> [--items …]`. `approve` calls Show, prints the drafts, asks `Approve N mails? [y/N]`
  unless `--yes`, then sends Approve with the revisions it printed.
- Audit actions: `requests.list`, `requests.show`, `requests.approve`, `requests.deny`, `requests.cancel`.

Tests:
- [ ] `approve_binds_what_was_shown`: Show, then the agent updates one draft, then Approve with the old revisions →
  error, every item still `pending`.
- [ ] `approve_selected_items_and_late_choice`: 3 items, one already past: `items=[0,1]`, `late=Skip` → states
  `scheduled`, `skipped(late)`, `denied`.
- [ ] `daily_cap_refuses_the_approval` with `scheduled_sends_per_day = 2`.
- [ ] `show_content_stays_out_of_audit`: subject and body of the shown draft appear in no audit cell.
- [ ] CLI parse tests in `src/cli.rs` for the five subcommands.
- [ ] Mutation-check, commit: `admin: requests list, show, approve, deny, cancel`.

### Task 5: Worker

**Files:** `src/requests/worker.rs`, `src/serve.rs`, `tests/requests_e2e.rs`.

**Produces:**

```rust
pub struct TickReport { pub sent: usize, pub failed: usize, pub skipped: usize, pub missed: usize,
                        pub unknown: usize, pub expired: usize, pub deferred: usize }
pub async fn tick(app: &Arc<App>, now: i64) -> anyhow::Result<TickReport>;
pub fn start(app: Arc<App>) -> tokio::task::JoinHandle<()>;            // every 30 s; not started by the test harness
pub fn recover_after_restart(c: &Connection) -> anyhow::Result<usize>; // items 'sending' → 'send_unknown'
```

`tick` order: (1) `pending` requests past `expires_at` → `expired`, items `cancelled`; (2) `scheduled` items with
`send_at + grace < now` → `missed`; (3) up to 10 `scheduled` items with `send_at <= now` and `next_try_at` unset or
`<= now`, oldest first, one at a time:
re-check request `approved`, client live, mailbox active and granted; claim `scheduled → sending` (one row or skip);
`send_core(cx, mb, draft_id, approved_rev, SendAuth::Approved)`; map the result:

| Result | Item state | reason |
| --- | --- | --- |
| `Ok` | `sent` (+ `sent_message_id`) | |
| `OutcomeUnknown` | `send_unknown` | |
| `DraftConflict` | `failed` | `draft_changed` |
| `NotFound` | `failed` | `not_found` |
| `RateLimited`, `AccountUnavailable` | back to `scheduled`, `next_try_at = now + 300` (counted `deferred`) | |
| `UpstreamError` | the same for the first 3 attempts, then `failed` | `upstream_error` |
| anything else | `failed` | the error code |

Each terminal outcome writes one audit record (actor `scheduler`, action `request.send_item`, object ids = request id,
item index, draft id, sent message id) and calls `close_if_finished`.

Tests (drive the clock through `tick(app, now)`; Gmail and IMAP/SMTP each get the happy path):
- [ ] `approved_items_are_sent_at_their_time` (Gmail) and `…_over_smtp` (IMAP): nothing before `send_at`, exactly one
  send at it, request `done`, a second tick sends nothing.
- [ ] `approved_revision_is_binding` (Review Focus 5).
- [ ] `refused_send_fails_after_three_attempts`: an upstream refusal is tried 3 times, 5 minutes apart, then `failed`.
- [ ] `not_dispatched_is_retried_until_grace` (Review Focus 3) and `due_items_are_bounded_and_missed_first` (4).
- [ ] `unknown_outcome_is_never_retried`: fake Google answers the send with 503 → `send_unknown`, later ticks send
  nothing.
- [ ] `restart_while_sending`: set an item to `sending`, `h.restart()`, item is `send_unknown`.
- [ ] `revoked_client_and_removed_mailbox_cancel_items` (Task 1 cascades), `pending_request_expires`.
- [ ] `scheduled_send_writes_one_audit_row_without_content`.
- [ ] Wire `start` and `recover_after_restart` into `serve.rs` next to the watch worker; mutation-check each row of the
  table and each re-check; commit: `requests: worker sends approved items on schedule`.

### Task 6: `unless_reply`

**Files:** `src/requests/worker.rs`, `tests/requests_e2e.rs`.

Before the claim, for requests with `unless_reply`: no serving generation or indexing off → `skipped`
reason `condition_unknown`. `sync_state.last_success_at < now - 600` → `index::wake(app, account)`, leave the item
`scheduled` (`deferred`); when the grace runs out it becomes `skipped` reason `condition_unknown` instead of `missed`.
Fresh index: `watch::first_reply(c, gen, thread_id, &Baseline { ms: baseline_ms, ids: Some(baseline_ids) }, &owners)`
with the owners set the watch code uses; a reply → `skipped` reason `replied`.

Tests:
- [ ] `reply_before_send_skips_the_item`; `own_follow_up_does_not_skip`; `reply_between_request_and_approval_skips`.
- [ ] `stale_index_fails_closed`: age `sync_state.last_success_at`, tick at `send_at` → nothing sent and a sync was
  asked for; tick after the grace → `skipped(condition_unknown)`, fake server saw no send.
- [ ] `indexing_switched_off_after_approval` → `skipped(condition_unknown)`.
- [ ] Mutation-check (drop the freshness check; drop the baseline ids), commit: `requests: unless_reply condition`.

### Task 7: Docs and release notes

- [ ] `docs/spec.md` (tools table, a requests section, admin verbs), `docs/deployment.md` (config keys, the CLI flow),
  `CHANGELOG.md` `[Unreleased]`, `docs/PLAN.md` (next free A-number), `AGENTS.md` (layout line for `src/requests/`,
  one learning), the design doc's 4.6 note ("ships with stage 3").
- [ ] `cargo fmt`, `heavy cargo clippy --all-targets -- -D warnings`, the full suite under `heavy`, gitleaks docker
  check, Windows type-check not required (no platform code).
- [ ] Commit, push a branch, open a PR against `main`; do not merge.
