# Requests stage 2: access requests and temporary grants — Implementation Plan

**Goal:** An agent can ask for more rights on a mailbox of its project (`request_access`), for a while or for good;
the operator approves with `dove requests approve` (admin socket only), may shorten the duration and untick single
mailboxes; temporary rights end on their own, at once, without touching what the client had before.

**Spec:** `docs/superpowers/specs/2026-11-14-requests-and-admin-ui-design.md` sections 4.1, 4.2 (`request_access`), 4.5,
4.7 (`--duration`). Stage 1 (PLAN A71) built the lifecycle, the admin verbs and the worker this plan extends.

**Tech stack:** the crates in the tree; no new dependency.

## Global constraints

- Read `AGENTS.md` and `AGENTS.local.md`. Single test files directly; full builds, clippy and the suite only through
  `CARGO_BUILD_JOBS=3 heavy cargo …` with `--test-threads=2`.
- Every new guard gets a test that fails without it (mutation-check, restore, `touch`).
- No note, address or content in logs or audit rows; audit rows carry request ids, aliases and result codes.
- Unknown and out-of-project aliases are the identical `not_found`.
- One store migration, additive only (`CREATE TABLE`); `client_mailboxes` is never rebuilt.
- New `AdminRequest` fields are `Option<_>` with `#[serde(default, skip_serializing_if = "Option::is_none")]`.

## Decisions (where the design is silent; all fail closed, recorded as PLAN A73)

1. **One extras row per approved temporary grant**, keyed `(client_id, account_id, request_id)`: two temporary
   approvals on one mailbox never merge, so neither outlives what the operator approved. The union is computed per
   request in `policy`.
2. **Request status for access.** Permanent approval: the grant is written to `client_mailboxes` and the request is
   `done` at once (the right now belongs to the client's grants and is managed with `clients set-grants`). Temporary
   approval: the request stays `approved` while it has extras rows and becomes `done` when the last one is gone
   (expiry, cancel, `set-grants`, revoke, mailbox removal). An approved temporary request therefore counts towards
   `limits.client_open_requests`, which also bounds the extras rows per client.
3. **Permanent approval only adds**: `client_mailboxes` becomes old ∪ approved per mailbox; the approved part is
   validated by `resolve_grants` (grant syntax, project membership, send gate); existing rows are kept as stored.
4. **Duration**: requested 1..=43 200 minutes (30 days) or absent (permanent). The operator may pass a shorter
   duration, or a duration on a permanent request (which makes it temporary); a longer one is refused. The expiry runs
   from the approval, not from the request.
5. **Policy**: `load_mailboxes` = base rows ∪ unexpired extras (`expires_at > now`), both intersected with project
   membership; actions are unioned (`Actions::union`) and the result re-validated by the dependency rules (an invalid
   result yields no access, never partial). Expiry is evaluated per request: no cache, no wait for the worker.
6. **`auth_epoch`** moves on every approval that changes rights and on every extras deletion (expiry sweep,
   `set-grants`, revoke, cancel), so cursors made with a wider scope stop working.
7. **What ends with a temporary right**: watches end at the next watch tick or event (`watch::end_reason` sees the
   loss, reason `access_lost`); scheduled sends fail at their time with `access_lost` (worker re-check and the pre-dispatch
   re-check in `send_core`); pending send requests cannot be approved (`may_draft`). Drafts created during the grant
   stay in the mailbox (they are the owner's mail) but the client can no longer reach them.
8. **Cancel**: `cancel_request` (agent) and `dove requests cancel` (operator) on an approved temporary request delete
   its extras at once (the agent may give rights back; it can never take them). `--items` is refused for access.
9. **Mailbox removal** (`accounts remove`, `projects remove-account`): extras on it go (FK cascade / explicit delete),
   pending access requests naming it are cancelled (`account_removed`), approved ones close when no extras are left.
   Disabling a mailbox leaves access requests alone (the policy's status check already refuses use).
10. **No redundancy check** in `request_access`: the operator's `show` lists what the client holds now on each mailbox.

## Schema (store migration `V_ACCESS_GRANTS`, appended to `MIGRATIONS`)

```sql
CREATE TABLE client_grant_extras (
    client_id  TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    request_id TEXT NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
    actions    TEXT NOT NULL,
    granted_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (client_id, account_id, request_id)
);
CREATE INDEX client_grant_extras_expiry ON client_grant_extras(expires_at);
CREATE INDEX client_grant_extras_request ON client_grant_extras(request_id);
```

`requests` rows of kind `access` have `account_id` NULL and `payload`
`{"grants":[{"account_id":"…","actions":"read,draft"}],"duration_secs":3600|null}`; after approval the payload gains
`"decision":{"granted":[0,2],"expires_at":…|null}` (ids, action names and times only).

## Files

| File | Change |
| --- | --- |
| `src/store/schema.rs` | `V_ACCESS_GRANTS` |
| `src/policy.rs` | `Actions::union`, `TempGrant`, `Mailbox.temporary`, `load_mailboxes_at` (base ∪ extras) |
| `src/requests/mod.rs` | `NewAccess`, `create_access`, access view in `RequestView`, `close_if_finished` and `cancel_one` aware of extras, `drop_extras_*`, `expire_extras`, cascades for account/project removal |
| `src/requests/admin.rs` | `show` / `list` for access, `approve_access` |
| `src/requests/worker.rs` | tick step 0: `expire_extras` |
| `src/tools/requests.rs` | `request_access` |
| `src/tools/read.rs` | `list_accounts` shows `temporary` |
| `src/admin/mod.rs`, `server.rs`, `ops.rs` | `RequestsApprove.duration_minutes`; set-grants/revoke/project-remove drop extras; `clients show` lists them |
| `src/cli.rs` | `approve --duration`, access rendering |
| `src/watch/mod.rs` | `end_reason` uses the tick's clock for extras |
| `tests/requests_access_e2e.rs` | the tests below |

## Tests (`tests/requests_access_e2e.rs`) and the rule each proves

- `access_request_needs_approval`: pending request changes nothing (tool still `not_found`/`forbidden`), audit has no
  note; deny leaves rights unchanged.
- `temporary_grant_works_then_expires_and_earlier_rights_stay`: base `read` on `info`, temporary `read,draft` → can
  draft; after the sweep only `read` remains, request `done`, one `request.grant_expire` audit row.
- `expiry_takes_effect_on_the_next_call_without_the_worker`: `expires_at` moved into the past, no tick → next call
  refused.
- `union_and_dependency_rules`: temporary `organize` on base `read,draft` gives `read,draft,organize`; a mailbox held
  only through an extra resolves, searches and lists like a granted one; an extras row with a broken action list
  grants nothing (unit test on `load_mailboxes`).
- `set_grants_revoke_and_mailbox_removal_drop_extras`: each path deletes the rows and closes the request.
- `unknown_and_out_of_project_alias_are_identical`: whole error objects compared.
- `send_needs_allow_send`; `duration_bounds` (0, 43 201, non-integer refused; 43 200 accepted).
- `operator_shortens_and_unticks`: `duration_minutes` shorter → shorter expiry; longer → refused; `items` → only the
  chosen mailboxes; permanent approval adds to `client_mailboxes` and keeps the rest.
- `watch_and_scheduled_send_end_with_the_right`: a watch on an extra-only mailbox ends `access_lost`; an approved
  scheduled send whose `draft` came from an extra fails `access_lost` after expiry and nothing is sent.
- `cancel_gives_rights_back`: agent cancel of an approved temporary request removes the extras.
- `list_accounts_and_clients_show_show_the_expiry`.
- `admin_request_stays_compatible` (`tests/admin.rs`): an approve request without `duration_minutes` parses, and one
  serialized with `None` carries no such key.

Mutation checks: the `expires_at > now` filter, the project join of extras, the union re-validation, each extras
deletion (set-grants, revoke, project removal, cancel), the duration upper bound and the "shorter only" check, the
`allow_send` check at request and at approval, the project-scoped alias lookup, the `close_if_finished` extras clause.
