//! Coverage exceptions and account errors (spec 5.3, PLAN A59): the shapes `search_messages`, `digest` and
//! `search_contacts` report when the index cannot answer completely, and what each one tells the agent to do next.
//!
//! Every exception carries `resolves`:
//! - `automatic`: Dove fixes it by itself (a sync pass, a retry). Waiting helps. `retry_after_seconds` /
//!   `next_retry_at` / `next_sync_at` come from the scheduler's own state (`sync_state.next_run_at`,
//!   `pending.next_attempt_at`), never from a guess.
//! - `operator`: it will not resolve on its own; the operator has to act (enable indexing, reconnect, rebuild).
//! - `never`: the gap is a property of the message (for example a body over the size cap); waiting changes nothing.
//!
//! Nothing here carries mail content: only aliases, stage names, counts, stable error codes and timestamps.

use serde_json::{Value, json};

use crate::error::ErrorCode;
use crate::index::sync::SyncState;
use crate::util;

pub(crate) const AUTOMATIC: &str = "automatic";
pub(crate) const OPERATOR: &str = "operator";
pub(crate) const NEVER: &str = "never";

/// Stage of a mailbox whose indexing was never switched on.
pub(crate) const NOT_INDEXED: &str = "not_indexed";

fn base(alias: &str, stage: &str, reason: &str, resolves: &str, hint: &str) -> Value {
    json!({ "account": alias, "stage": stage, "reason": reason, "resolves": resolves, "hint": hint })
}

/// Sets `next_retry_at` and `retry_after_seconds` (0 when the time has passed: a pass is due or running now).
fn set_time(v: &mut Value, key: &str, at: i64, now: i64) {
    v[key] = json!(util::rfc3339(at));
    v["retry_after_seconds"] = json!((at - now).max(0));
}

/// Adds the scheduler's view of the mailbox: when the next sync pass is due and whether the last one failed.
fn sync_info(v: &mut Value, s: &SyncState, now: i64) {
    if s.next_run_at > 0 {
        set_time(v, "next_sync_at", s.next_run_at, now);
    }
    if let Some(e) = &s.last_error {
        v["last_sync_error"] = json!(e);
    }
}

fn with_last_success(mut v: Value, last: Option<i64>) -> Value {
    v["last_success_at"] = json!(last.map(util::rfc3339));
    v
}

pub(crate) fn not_indexed(alias: &str) -> Value {
    with_last_success(
        base(
            alias,
            NOT_INDEXED,
            "indexing is not enabled",
            OPERATOR,
            "Indexing is off for this mailbox and will not start on its own; the operator must enable it \
             (dove index enable). This mailbox is not covered until then.",
        ),
        None,
    )
}

/// The index has no state row yet; the scheduler creates it on its next tick.
pub(crate) fn not_started(alias: &str) -> Value {
    let mut v = base(
        alias,
        "pending",
        "indexing has not started",
        AUTOMATIC,
        "Indexing was just enabled and starts within seconds; retry shortly.",
    );
    v["retry_after_seconds"] = json!(crate::index::sync::TICK_SECS);
    with_last_success(v, None)
}

/// A mailbox that is not complete: first backfill, rebuild, or no generation to read yet.
pub(crate) fn stage(alias: &str, s: &SyncState, reason: &str, queued: i64, now: i64) -> Value {
    let hint = match s.stage.as_str() {
        "backfill" => {
            "The first full indexing of this mailbox is still running, newest mail first. There is no completion \
             estimate; retry later, or proceed and treat the result as incomplete."
        }
        "rebuilding" => {
            "The index is being rebuilt (after a history gap or an operator rebuild); Dove finishes it on its own. \
             Retry later, or proceed and treat the result as incomplete."
        }
        _ => "Dove is still indexing this mailbox; retry later, or proceed and treat the result as incomplete.",
    };
    let mut v = base(alias, &s.stage, reason, AUTOMATIC, hint);
    sync_info(&mut v, s, now);
    if queued > 0 {
        v["queued"] = json!(queued);
    }
    with_last_success(v, s.last_success_at)
}

pub(crate) fn no_sync_yet(alias: &str, s: &SyncState, now: i64) -> Value {
    let mut v = base(
        alias,
        &s.stage,
        "no successful sync yet",
        AUTOMATIC,
        "The mailbox has not completed a sync pass yet; Dove retries on its own (see next_sync_at). Retry later.",
    );
    sync_info(&mut v, s, now);
    with_last_success(v, None)
}

pub(crate) fn stale(alias: &str, s: &SyncState, now: i64) -> Value {
    let mut v = base(
        alias,
        "stale",
        "last sync is older than max_lag_seconds",
        AUTOMATIC,
        "The last successful sync is older than the lag you asked for; Dove syncs again by itself (see \
         next_sync_at). Retry after that, or raise max_lag_seconds.",
    );
    sync_info(&mut v, s, now);
    with_last_success(v, s.last_success_at)
}

/// What `pending` holds for the serving generation of one mailbox.
#[derive(Debug, Clone, Default)]
pub(crate) struct PendingInfo {
    /// Listed but never fetched (`attempts = 0`).
    pub queued: i64,
    /// Failed at least once and waiting for a retry.
    pub retrying: i64,
    /// Earliest `next_attempt_at` among the retrying rows.
    pub first_retry_at: Option<i64>,
    /// Stable error code of the failure due first.
    pub last_error: Option<String>,
}

impl PendingInfo {
    pub(crate) fn load(c: &rusqlite::Connection, gen_id: i64) -> rusqlite::Result<Self> {
        let (queued, retrying, first_retry_at) = c.query_row(
            "SELECT count(*) FILTER (WHERE attempts = 0), count(*) FILTER (WHERE attempts > 0), \
             min(next_attempt_at) FILTER (WHERE attempts > 0) FROM pending WHERE gen = ?1",
            [gen_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let last_error = if retrying > 0 {
            c.query_row(
                "SELECT last_error FROM pending WHERE gen = ?1 AND attempts > 0 ORDER BY next_attempt_at, seq LIMIT 1",
                [gen_id],
                |r| r.get(0),
            )?
        } else {
            None
        };
        Ok(Self { queued, retrying, first_retry_at, last_error })
    }
}

/// Messages that failed a fetch and wait for a retry. The retry cannot happen before the record is due and not
/// before the next sync pass runs (a pass hydrates due records), so `next_retry_at` is the later of the two.
pub(crate) fn pending_retry(alias: &str, s: &SyncState, p: &PendingInfo, now: i64) -> Value {
    let mut v = base(
        alias,
        &s.stage,
        "messages pending retry",
        AUTOMATIC,
        "Some messages could not be fetched yet and Dove retries them by itself with growing delays. They are \
         missing from results until then. Retry after retry_after_seconds, or proceed and treat the result as \
         incomplete.",
    );
    v["count"] = json!(p.retrying);
    if let Some(first) = p.first_retry_at {
        set_time(&mut v, "next_retry_at", first.max(s.next_run_at), now);
    }
    if let Some(e) = &p.last_error {
        v["last_error"] = json!(e);
    }
    with_last_success(v, s.last_success_at)
}

/// Messages listed but not yet fetched while the mailbox is otherwise ready (new mail in flight).
pub(crate) fn queued(alias: &str, s: &SyncState, p: &PendingInfo, now: i64) -> Value {
    let mut v = base(
        alias,
        &s.stage,
        "messages waiting to be indexed",
        AUTOMATIC,
        "New messages were found and are being indexed; they are missing from results until then. Retry shortly.",
    );
    v["count"] = json!(p.queued);
    sync_info(&mut v, s, now);
    with_last_success(v, s.last_success_at)
}

/// A field gap on rows already in the index.
pub(crate) fn field_gap(alias: &str, reason: &str, n: i64, resolves: &str, hint: &str) -> Value {
    let mut v = base(alias, "ready", reason, resolves, hint);
    v["count"] = json!(n);
    v
}

pub(crate) const BODY_HINT: &str = "These messages were too large or unreadable to index their text; their \
    body is not searchable and waiting does not change that. Their subject and headers are indexed.";
pub(crate) const META_HINT: &str = "Attachment and MIME details of these messages could not be read; waiting does \
    not change that.";
pub(crate) const CATEGORY_HINT: &str = "These messages were indexed before categories existed. Waiting does not fill \
    them in; the operator can run an index rebuild (dove index rebuild).";
pub(crate) const ATTACHMENT_HINT: &str = "Attachment text of these messages was not read (too large, unreadable, \
    extraction off or indexed by an older version). Waiting does not change that; an operator index rebuild \
    re-reads what can be read.";
pub(crate) const CONTACTS_HINT: &str = "Names and counts for these messages are incomplete because they were \
    indexed before categories existed. The operator can run an index rebuild (dove index rebuild).";

/// A mailbox the connection may read but that cannot be used. `status` is the account status in the state store.
pub(crate) fn account_error(alias: &str, status: &str) -> Value {
    let (reason, hint) = match status {
        "reauth_required" => (
            "reauth_required",
            "Dove's access to this mailbox was rejected (revoked grant or wrong password). It will not recover on \
             its own; the operator must reconnect it (dove accounts reconnect). Results from other mailboxes are \
             unaffected.",
        ),
        "disabled" => (
            "disabled",
            "The operator disabled this mailbox. It will not come back on its own; the operator must enable it \
             (dove accounts enable).",
        ),
        _ => (
            "access_changed",
            "Access to this mailbox changed while the request ran (disabled, disconnected or the grant changed). \
             Retry once; if it persists the operator has to restore access.",
        ),
    };
    json!({ "account": alias, "code": ErrorCode::AccountUnavailable.as_str(), "reason": reason,
        "resolves": OPERATOR, "hint": hint })
}

/// One sentence for the top level of a partial result, or `None` when everything is complete. The exceptions are
/// built here, so `resolves` is always present; a missing one counts as not automatic.
pub(crate) fn summary(exceptions: &[Value], account_errors: &[Value]) -> Option<String> {
    if exceptions.is_empty() && account_errors.is_empty() {
        return None;
    }
    let all = || exceptions.iter().chain(account_errors.iter());
    let blocked = |v: &Value, kinds: &[&str]| kinds.contains(&v["resolves"].as_str().unwrap_or(OPERATOR));
    let (auto, other): (Vec<&Value>, Vec<&Value>) = all().partition(|v| blocked(v, &[AUTOMATIC]));
    if other.is_empty() {
        return Some(
            "Every gap is temporary and Dove closes it on its own. Retry after the smallest retry_after_seconds \
             (or next_sync_at / next_retry_at) shown, or proceed and treat the result as incomplete."
                .into(),
        );
    }
    let mut aliases: Vec<&str> = other.iter().filter_map(|v| v["account"].as_str()).collect();
    aliases.sort_unstable();
    aliases.dedup();
    let names = aliases.join(", ");
    Some(if auto.is_empty() {
        format!(
            "Waiting will not help: {names} need operator action or have gaps that never fill in (see resolves and \
             hint per entry). Proceed and treat the result as incomplete."
        )
    } else {
        format!(
            "Some gaps are temporary (resolves=automatic: retry later), but {names} need operator action or have \
             gaps that never fill in and will not resolve by waiting. Treat the result as incomplete."
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ex(account: &str, resolves: &str) -> Value {
        json!({ "account": account, "resolves": resolves })
    }

    #[test]
    fn summary_is_none_when_complete_and_transient_only_says_retry() {
        assert_eq!(summary(&[], &[]), None);
        let s = summary(&[ex("a", AUTOMATIC), ex("b", AUTOMATIC)], &[]).unwrap();
        assert!(s.starts_with("Every gap is temporary"), "{s}");
    }

    #[test]
    fn summary_names_the_mailboxes_that_will_not_resolve() {
        let s = summary(&[ex("a", AUTOMATIC)], &[ex("ops", OPERATOR)]).unwrap();
        assert!(s.contains("ops") && !s.contains("a,") && s.contains("temporary"), "{s}");
        let only = summary(&[], &[ex("ops", OPERATOR), ex("ops", OPERATOR)]).unwrap();
        assert!(only.starts_with("Waiting will not help: ops need"), "{only}");
        // A missing `resolves` must never read as transient.
        let s = summary(&[json!({ "account": "x" })], &[]).unwrap();
        assert!(s.starts_with("Waiting will not help"), "{s}");
    }

    #[test]
    fn account_errors_keep_the_stable_code_and_give_a_reason() {
        for (status, reason) in
            [("reauth_required", "reauth_required"), ("disabled", "disabled"), ("x", "access_changed")]
        {
            let v = account_error("ops", status);
            assert_eq!(v["code"], "account_unavailable");
            assert_eq!(v["reason"], reason);
            assert_eq!(v["resolves"], OPERATOR);
        }
    }
}
