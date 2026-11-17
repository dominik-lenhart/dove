# Health alerts over Web Push (design 2026-11-17)

Step 2 of four (owner's order 2026-11-16): after push, health and owner alerts over the same channel. Owner's go:
"klingt gut mach das gerne" (2026-11-17).

## Why

Dove already decides when the owner must act (`notifier`: a mailbox needs reconnecting, a client used a new address,
a burst of denied calls, a failed IMAP draft cleanup), but those notices go only to the log and to an optional
webhook that production does not have. A sync that silently stops, or a full disk, is not noticed at all until an
agent gets stale answers. The owner now has a phone with push; the alerts should arrive there.

## Goals

- Every owner notification also pushes to every device, with lock-screen text that names only the mailbox alias or
  connection name and the kind of problem (owner's lock-screen rule from 2026-11-16: no addresses, IPs, subjects or
  server text). Tapping opens the admin page where it can be fixed.
- A health watcher (every 5 minutes) adds two checks:
  - a mailbox with indexing on that has not synced for 2 hours (`stalled`), with one "syncs again" push when it
    recovers;
  - less than 1 GiB free on the data directory's file system (`low_disk`), cleared above 2 GiB.
- The health page shows the mailboxes (status, last sync, retry queue, last error code), free disk space, and
  whether alerts reach any device. `dove doctor` gains the disk check.

## Non-goals

- No per-alert settings, no quiet hours. One device list, one switch (the device itself).
- No restore drill: production has no Dove-managed backup to probe (docs/deployment.md leaves backups to the owner).
- The webhook path stays as it is.

## Approaches

1. **Chosen: typed alerts in the notifier.** `Notifier::notify_once(key, Alert)` writes the dedupe row and the push
   outbox rows in one state-store transaction; `Alert` constructors hold both the long log/webhook text and the short
   push text. Every existing call site moves to a constructor, so no call site can push free text.
2. Push straight from each call site. Rejected: four call sites would each need their own lock-screen-safe text and
   their own transaction, and a new one could forget the push.
3. A separate alerts table with history. Rejected for now (YAGNI): the outbox already holds what was sent.

## Design

- `notifier::Alert { message, push: push::Text }` with constructors `reauth`, `new_ip`, `denial_burst`,
  `draft_cleanup`, `sync_stalled`, `sync_recovered`, `low_disk`. Push titles start with "Dove:"; URLs point to
  `/admin/mailboxes/<alias>`, `/admin/connections/<name>` or `/admin/health`.
- `notify_once` and `send` queue the push with `push::queue_text(tx, "alert", None, ..)` in the same transaction as
  the dedupe row. `clear(key) -> bool` reports whether an alert was open (for "syncs again").
- `src/health.rs`: `tick(app, now) -> Report`, `start(app)` (5 min), `disk_free(path) -> u64` via `statvfs`.
  Stall: index enabled, account `active`, `now - coalesce(last_success_at, enabled_at) > 7200`. Key
  `stalled:<account_id>`; disk key `disk:low`.
- Health page: new "Mailboxes" and "Alerts" sections next to the doctor checks.

## Tests

Integration tests in `tests/health_alerts_e2e.rs` with the fake push service from `tests/admin_push_e2e.rs`: a stalled
mailbox pushes once, a second tick does not, recovery pushes "syncs again" once; reauth (IMAP 535) pushes with no
address in the decrypted payload; low disk with an injected threshold; no devices means no outbox rows.
