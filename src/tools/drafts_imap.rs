//! IMAP drafts and sending (design 2026-11-12 "Drafts", "Send"). `tools::drafts` keeps the shared flow (arguments,
//! idempotency, locks, gates, the send state machine); this module does the IMAP-specific steps.
//!
//! A Dove draft on IMAP is one message in the Drafts folder. Its record holds the agent-visible id (also the
//! revision) and the SHA-256 of the bytes the server returned for it after `APPEND`, so a server that rewrites
//! stored bytes causes no false conflict. A missing UID, a changed hash, a changed UIDVALIDITY or a different Drafts
//! folder all mean the draft is not provably Dove's any more: `draft_conflict`, human-owned from then on.
//!
//! Deleting: [`OwnDraftUid`] is the only way to `UID STORE \Deleted` / `UID EXPUNGE`, and this module is the only
//! place that constructs one, always for the previous revision of an own draft (after its replacement is recorded) or
//! the sent draft (after the send). Nothing else is ever deleted.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use futures::{StreamExt, stream};
use rusqlite::params;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::drafts::{Created, OwnRow};
use super::read::{DEFAULT_BODY_CHARS, Fetched, MAX_BODY_CHARS, ShapeOpts, fmt_addrs, render, shape};
use super::{AuditInfo, ToolCx, ToolOutput, gmail_id_arg, opt_bool, opt_str, opt_u64};
use crate::content;
use crate::error::{ErrorCode, ToolError};
use crate::gmail::gateway::Priority;
use crate::imap::account::{self, Folder, ImapSettings};
use crate::imap::pool::SessionFuture;
use crate::imap::{
    AppendFlag, AppendTarget, AppendUid, Credentials, ImapError, ImapMsgId, ImapSession, OwnDraftUid, Special, smtp,
};
use crate::mail;
use crate::mime;
use crate::policy::Mailbox;
use crate::util;

const DRAFT_FLAGS: &[AppendFlag] = &[AppendFlag::Draft, AppendFlag::Seen];
const SENT_FLAGS: &[AppendFlag] = &[AppendFlag::Seen];

fn hash(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

/// Dove's stable draft id for IMAP: `"d"` + 22 random base64url characters.
fn new_draft_id() -> String {
    format!("d{}", util::b64url(&util::random_bytes::<16>()))
}

fn max_bytes() -> usize {
    mime::Limits::default().max_raw_bytes
}

/// Settings and credentials loaded once per tool call, used for every IMAP and SMTP step of that call.
pub(super) struct Conn {
    account_id: String,
    settings: ImapSettings,
    creds: Credentials,
}

impl Conn {
    async fn load(cx: &ToolCx, mb: &Mailbox) -> Result<Self, ToolError> {
        let (settings, creds) = account::load(&cx.app, &mb.account_id).await?;
        Ok(Self { account_id: mb.account_id.clone(), settings, creds })
    }

    /// Runs `f` on a pooled session with the Drafts/Sent append targets set. An authentication failure marks the
    /// account `reauth_required` (once per credential generation); the raw error goes back for classification.
    async fn run<T, F>(&self, cx: &ToolCx, f: F) -> Result<T, ImapError>
    where
        F: for<'s> FnOnce(&'s mut ImapSession) -> SessionFuture<'s, T>,
    {
        let (drafts, sent) = (self.settings.drafts_folder.clone(), self.settings.sent_folder.clone());
        let r = cx
            .app
            .imap
            .with_session(&self.account_id, &self.settings.imap, &self.creds, move |s| {
                s.set_append_targets(drafts, sent);
                f(s)
            })
            .await;
        if r.as_ref().err() == Some(&ImapError::Auth) {
            account::mark_auth_failure(&cx.app, &self.account_id, self.settings.generation, &self.settings.alias).await;
        }
        r
    }
}

async fn special_folder(cx: &ToolCx, account_id: &str, special: Special) -> Result<Option<Folder>, ToolError> {
    let aid = account_id.to_string();
    let folders = cx.app.store.call(move |c| account::load_folders(c, &aid)).await?;
    Ok(folders.into_iter().find(|f| f.special == Some(special)))
}

async fn drafts_folder(cx: &ToolCx, account_id: &str) -> Result<Folder, ToolError> {
    special_folder(cx, account_id, Special::Drafts)
        .await?
        .ok_or_else(|| ToolError::upstream("the mailbox has no Drafts folder"))
}

/// `APPEND` to Drafts or Sent. The bool in the error says whether the message may have reached the server: false
/// when the connection or login failed (the closure never ran) or nothing was written.
async fn append(
    conn: &Conn,
    cx: &ToolCx,
    target: AppendTarget,
    flags: &'static [AppendFlag],
    bytes: Vec<u8>,
) -> Result<AppendUid, (ToolError, bool)> {
    let started = Arc::new(AtomicBool::new(false));
    let s2 = started.clone();
    let r = conn
        .run(cx, move |s| {
            s2.store(true, Ordering::SeqCst);
            Box::pin(async move { s.append(target, flags, &bytes).await })
        })
        .await;
    r.map_err(|e| {
        if !started.load(Ordering::SeqCst) {
            return (ToolError::from(e), false);
        }
        match e {
            ImapError::NotDispatched => (ToolError::from(e), false),
            ImapError::OutcomeUnknown => (ToolError::from(e), true),
            ImapError::Missing => (ToolError::upstream("the target folder is missing on the mail server"), true),
            _ => (ToolError::upstream("the mail server refused the message"), true),
        }
    })
}

/// The bytes the server stores for a just-appended draft (read-only `EXAMINE`, `BODY.PEEK[]`).
async fn read_back(conn: &Conn, cx: &ToolCx, drafts: &Folder, au: AppendUid) -> Result<Vec<u8>, ImapError> {
    let name = drafts.name.clone();
    let max = max_bytes();
    conn.run(cx, move |s| {
        Box::pin(async move {
            let st = s.select(&name, true).await?;
            if st.uidvalidity != au.uidvalidity {
                return Err(ImapError::Missing);
            }
            s.fetch_raw(au.uid, max).await?.ok_or(ImapError::Protocol("stored draft exceeds the size limit"))
        })
    })
    .await
}

/// Reports a best-effort cleanup failure to the operator once (no content: ids and the alias only).
async fn report(cx: &ToolCx, mb: &Mailbox, key: String, message: String) {
    tracing::warn!(account = %mb.account_id, kind = %key.split(':').next().unwrap_or_default(), "IMAP draft cleanup step failed");
    let _ = cx.app.notifier.notify_once(&key, &message).await;
}

/// Flags and expunges exactly one Dove-owned draft UID. Failures are reported, never retried blindly.
async fn delete_own_draft(cx: &ToolCx, conn: &Conn, mb: &Mailbox, draft_id: &str, id: ImapMsgId) {
    // The caller proved ownership: the own_drafts record names this id, its content hash matched, and its folder is
    // the account's Drafts folder (checked again by `delete_own` through UIDVALIDITY).
    let own = OwnDraftUid::new_for_drafts(id.uidvalidity, id.uid);
    if conn.run(cx, move |s| Box::pin(s.delete_own(own))).await.is_err() {
        report(
            cx,
            mb,
            format!("stale-draft:{}:{}", mb.account_id, id.encode()),
            format!(
                "Mailbox '{}': Dove could not remove an old copy of its draft {draft_id} from Drafts. Delete the \
                 older copy by hand if it is still there.",
                mb.alias
            ),
        )
        .await;
    }
}

// ------------------------------------------------------------------ create

/// Appends a new draft and records the hash of the server's copy. The bool in the error says whether the draft may
/// exist on the server.
pub(super) async fn append_new(cx: &ToolCx, mb: &Mailbox, raw: Vec<u8>) -> Result<Created, (ToolError, bool)> {
    let pre = |e: ToolError| (e, false);
    let conn = Conn::load(cx, mb).await.map_err(pre)?;
    let drafts = drafts_folder(cx, &mb.account_id).await.map_err(pre)?;
    let au = append(&conn, cx, AppendTarget::Drafts, DRAFT_FLAGS, raw).await?;
    let id = ImapMsgId { folder_id: drafts.folder_id, uidvalidity: au.uidvalidity, uid: au.uid }.encode();
    // The draft exists now. Without the server's bytes Dove cannot prove ownership later, so it does not claim it.
    let unknown = || {
        (
            ToolError::new(
                ErrorCode::OutcomeUnknown,
                "the draft was saved but could not be read back; check the mailbox's Drafts",
            ),
            true,
        )
    };
    let stored = read_back(&conn, cx, &drafts, au).await.map_err(|_| unknown())?;
    let parsed = mime::parse(&stored, &mime::Limits::default()).map_err(|_| unknown())?;
    Ok(Created {
        draft_id: new_draft_id(),
        thread_id: mail::imap_thread_id(&parsed, &id),
        message_id: id,
        content_hash: Some(hash(&stored)),
    })
}

// ------------------------------------------------------------------ fresh check

pub(super) struct Checked {
    pub fetched: Fetched,
    pub id: ImapMsgId,
}

fn not_ours(current: Option<&str>) -> ToolError {
    ToolError::new(ErrorCode::DraftConflict, "the draft was changed or removed outside Dove; it is now human-owned")
        .with_details(json!({ "current_revision": current }))
}

/// Fresh read of an own draft and the ownership checks: the record's id is in the current Drafts folder, the UID
/// still exists under the same UIDVALIDITY, and the server's bytes hash to the recorded value. Then the caller's
/// expected revision.
pub(super) async fn fresh_checked(
    cx: &ToolCx,
    mb: &Mailbox,
    own: &OwnRow,
    expected: &str,
) -> Result<Checked, ToolError> {
    let id = ImapMsgId::parse(&own.message_id).ok_or_else(|| not_ours(None))?;
    if drafts_folder(cx, &mb.account_id).await?.folder_id != id.folder_id {
        return Err(not_ours(None));
    }
    let fetched = match mail::fetch_message(cx, mb, &own.message_id, Priority::Interactive).await {
        Ok(f) => f,
        // Gone or renumbered (UIDVALIDITY): a human client re-saved or deleted it.
        Err(e) if e.code == ErrorCode::NotFound => return Err(not_ours(None)),
        Err(e) => return Err(e),
    };
    if own.content_hash.as_deref() != Some(hash(&fetched.raw).as_slice()) {
        return Err(not_ours(Some(&own.message_id)));
    }
    if own.message_id != expected {
        return Err(ToolError::new(ErrorCode::DraftConflict, "expected_revision is stale")
            .with_details(json!({ "current_revision": own.message_id })));
    }
    Ok(Checked { fetched, id })
}

// ------------------------------------------------------------------ update

/// Replaces an own draft: `APPEND` the new bytes, read them back, move the record to the new UID, then delete the
/// previous UID. Returns (new revision, thread id). An unknown `APPEND` outcome is `outcome_unknown` (the caller
/// marks `update_unknown`); the previous revision is then never deleted.
pub(super) async fn replace(
    cx: &ToolCx,
    mb: &Mailbox,
    draft_id: &str,
    old: ImapMsgId,
    raw: Vec<u8>,
) -> Result<(String, String), ToolError> {
    let conn = Conn::load(cx, mb).await?;
    let drafts = drafts_folder(cx, &mb.account_id).await?;
    if drafts.folder_id != old.folder_id {
        return Err(not_ours(None));
    }
    let au = append(&conn, cx, AppendTarget::Drafts, DRAFT_FLAGS, raw).await.map_err(|(e, _)| e)?;
    let new_id = ImapMsgId { folder_id: drafts.folder_id, uidvalidity: au.uidvalidity, uid: au.uid }.encode();
    let unknown = |why: &str| ToolError::new(ErrorCode::OutcomeUnknown, why.to_string());
    let stored = read_back(&conn, cx, &drafts, au)
        .await
        .map_err(|_| unknown("the new revision was saved but could not be read back; check the mailbox's Drafts"))?;
    let parsed = mime::parse(&stored, &mime::Limits::default())
        .map_err(|_| unknown("the new revision was saved but could not be read back; check the mailbox's Drafts"))?;
    let thread_id = mail::imap_thread_id(&parsed, &new_id);
    let (aid, did, nid, oid, h, t) =
        (mb.account_id.clone(), draft_id.to_string(), new_id.clone(), old.encode(), hash(&stored), thread_id.clone());
    let moved = cx
        .app
        .store
        .call(move |c| {
            Ok(c.execute(
                "UPDATE own_drafts SET message_id = ?1, content_hash = ?2, thread_id = ?3, updated_at = ?4 \
                 WHERE account_id = ?5 AND draft_id = ?6 AND message_id = ?7 AND state = 'active'",
                params![nid, h, t, util::now_unix(), aid, did, oid],
            )?)
        })
        .await;
    if !matches!(moved, Ok(1)) {
        return Err(unknown("the draft was updated but the new revision could not be recorded"));
    }
    // Only now, with the replacement recorded, the previous revision goes.
    delete_own_draft(cx, &conn, mb, draft_id, old).await;
    Ok((new_id, thread_id))
}

// ------------------------------------------------------------------ send

pub(super) struct PreparedSend {
    conn: Conn,
    /// The draft's bytes on the server (filed as the Sent copy).
    raw: Vec<u8>,
    /// What goes over SMTP: the same bytes without `Bcc`.
    submit: Vec<u8>,
    rcpts: Vec<String>,
    id: ImapMsgId,
    pub thread_id: String,
}

/// Fresh check, envelope recipients from To/Cc/Bcc, the submission bytes without `Bcc`, and credentials, all before
/// the send is claimed.
pub(super) async fn prepare_send(
    cx: &ToolCx,
    mb: &Mailbox,
    own: &OwnRow,
    expected: &str,
) -> Result<PreparedSend, ToolError> {
    let Checked { fetched, id } = fresh_checked(cx, mb, own, expected).await?;
    let p = &fetched.parsed;
    let mut rcpts: Vec<String> = Vec::new();
    for a in p.to.iter().chain(&p.cc).chain(&p.bcc) {
        if !rcpts.iter().any(|r| r.eq_ignore_ascii_case(&a.email)) {
            rcpts.push(a.email.clone());
        }
    }
    if rcpts.is_empty() {
        return Err(ToolError::invalid("the draft has no recipients"));
    }
    let submit = mime::without_header(&fetched.raw, "Bcc");
    let conn = Conn::load(cx, mb).await?;
    Ok(PreparedSend { conn, submit, rcpts, id, thread_id: fetched.meta.thread_id, raw: fetched.raw })
}

/// SMTP submission. `outcome_unknown` only when the server may have accepted the message (connection lost after the
/// final `.` of `DATA`); every other error is definitive and leaves nothing sent.
pub(super) async fn submit(cx: &ToolCx, mb: &Mailbox, p: &PreparedSend) -> Result<(), ToolError> {
    let s = &p.conn.settings;
    let creds = s.smtp_credentials(&p.conn.creds);
    let r = smtp::submit(cx.app.imap.connector(), &s.smtp, &creds, &s.email, &p.rcpts, &p.submit, cx.write_deadline())
        .await;
    match r {
        Ok(()) => Ok(()),
        Err(e) if e.kind == ImapError::OutcomeUnknown => Err(ToolError::from(ImapError::OutcomeUnknown)),
        Err(e) if e.kind == ImapError::Auth => {
            account::mark_auth_failure(&cx.app, &mb.account_id, s.generation, &s.alias).await;
            Err(ToolError::unavailable())
        }
        Err(e) => {
            match e.code {
                Some(code) => Err(ToolError::upstream("the mail server refused the message")
                    .with_details(json!({ "smtp_code": code }))),
                None => Err(ToolError::from(e.kind)),
            }
        }
    }
}

/// After a confirmed send: file the Sent copy (unless the provider does it itself) and delete the draft. Both are
/// best effort; failures go to the operator and nothing is sent again. Returns the Sent copy's id.
pub(super) async fn after_send(cx: &ToolCx, mb: &Mailbox, draft_id: &str, p: PreparedSend) -> Option<String> {
    let mut sent_id = None;
    if p.conn.settings.save_sent_copy {
        let sent = special_folder(cx, &mb.account_id, Special::Sent).await.ok().flatten();
        let filed = match sent {
            Some(f) => append(&p.conn, cx, AppendTarget::Sent, SENT_FLAGS, p.raw.clone())
                .await
                .ok()
                .map(|au| ImapMsgId { folder_id: f.folder_id, uidvalidity: au.uidvalidity, uid: au.uid }.encode()),
            None => None,
        };
        if filed.is_none() {
            report(
                cx,
                mb,
                format!("sent-copy:{}:{draft_id}", mb.account_id),
                format!("Mailbox '{}': draft {draft_id} was sent, but Dove could not file a copy in Sent.", mb.alias),
            )
            .await;
        }
        sent_id = filed;
    }
    delete_own_draft(cx, &p.conn, mb, draft_id, p.id).await;
    if let Some(sid) = sent_id.clone() {
        let (aid, did) = (mb.account_id.clone(), draft_id.to_string());
        let _ = cx
            .app
            .store
            .call(move |c| {
                Ok(c.execute(
                    "UPDATE own_drafts SET sent_message_id = ?1 WHERE account_id = ?2 AND draft_id = ?3",
                    params![sid, aid, did],
                )?)
            })
            .await;
    }
    sent_id
}

// ------------------------------------------------------------------ list / get

struct OwnedDraft {
    draft_id: String,
    message_id: String,
    content_hash: Option<Vec<u8>>,
}

async fn owned(cx: &ToolCx, account_id: &str) -> Result<Vec<OwnedDraft>, ToolError> {
    let (aid, pid) = (account_id.to_string(), cx.client.project_id.clone());
    Ok(cx
        .app
        .store
        .call(move |c| {
            let mut stmt = c.prepare(
                "SELECT draft_id, message_id, content_hash FROM own_drafts WHERE account_id = ?1 AND project_id = ?2",
            )?;
            let rows = stmt.query_map([aid, pid], |r| {
                Ok(OwnedDraft { draft_id: r.get(0)?, message_id: r.get(1)?, content_hash: r.get(2)? })
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
        .await?)
}

fn changed(own: &OwnedDraft, f: &Fetched) -> bool {
    own.content_hash.as_deref() != Some(hash(&f.raw).as_slice())
}

/// `list_drafts` on IMAP: the Drafts folder, newest first. Dove's own drafts carry their Dove draft id; other drafts
/// use their message id as draft id. `page_token` (all drafts only) is the UID to continue below.
pub(super) async fn list_drafts(cx: &ToolCx, mb: &Mailbox, args: &Value) -> Result<ToolOutput, ToolError> {
    let own_only = opt_bool(args, "own_only", true)?;
    let limit = opt_u64(args, "limit", 20, 1, 50)? as usize;
    let before = match opt_str(args, "page_token")? {
        Some(t) => Some(
            t.parse::<u32>()
                .ok()
                .filter(|u| *u > 0 && u.to_string() == t)
                .ok_or_else(|| ToolError::new(ErrorCode::CursorInvalid, "invalid page token"))?,
        ),
        None => None,
    };
    let owned = owned(cx, &mb.account_id).await?;
    let drafts = drafts_folder(cx, &mb.account_id).await?;
    let name = drafts.name.clone();
    let (uidvalidity, mut uids) = account::with_session(&cx.app, &mb.account_id, move |s| {
        Box::pin(async move {
            let st = s.select(&name, true).await?;
            Ok((st.uidvalidity, s.uid_search_all().await?))
        })
    })
    .await?;
    uids.sort_unstable_by(|a, b| b.cmp(a));
    if let Some(b) = before {
        uids.retain(|u| *u < b);
    }
    let mut cands: Vec<(u32, String, Option<&OwnedDraft>)> = uids
        .iter()
        .map(|u| {
            let id = ImapMsgId { folder_id: drafts.folder_id, uidvalidity, uid: *u }.encode();
            let own = owned.iter().find(|o| o.message_id == id);
            (*u, id, own)
        })
        .collect();
    if own_only {
        cands.retain(|c| c.2.is_some());
    }
    let more = cands.len() > limit;
    cands.truncate(limit);
    let next = if !own_only && more { cands.last().map(|c| c.0.to_string()) } else { None };
    let cands = &cands;
    let details: Vec<Result<Value, ToolError>> = stream::iter((0..cands.len()).map(|i| async move {
        let (_, id, own) = &cands[i];
        let f = mail::fetch_message(cx, mb, id, Priority::Interactive).await?;
        Ok(json!({
            "draft_id": own.map(|o| o.draft_id.as_str()).unwrap_or(id),
            "revision": id,
            "owned": own.is_some(),
            "changed_outside_dove": own.is_some_and(|o| changed(o, &f)),
            "thread_id": f.meta.thread_id,
            "to": fmt_addrs(&f.parsed.to),
            "subject": f.parsed.subject.as_deref().map(content::clean_text),
            "updated_at": util::rfc3339_ms(f.meta.internal_date_ms),
        }))
    }))
    .buffered(2)
    .collect()
    .await;
    let mut out = Vec::new();
    for d in details {
        match d {
            Ok(v) => out.push(v),
            // Expunged between the search and the fetch.
            Err(e) if e.code == ErrorCode::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    let text = out
        .iter()
        .map(|d| {
            format!(
                "{} {} to {}",
                d["draft_id"].as_str().unwrap_or(""),
                d["subject"].as_str().unwrap_or(""),
                d["to"]
                    .as_array()
                    .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
                    .unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let n = out.len() as i64;
    Ok(ToolOutput {
        extra: Vec::new(),
        text: content::envelope(&mb.alias, "drafts", &text),
        structured: json!({ "account": mb.alias, "drafts": out, "next_page_token": next }),
        audit: AuditInfo { account: Some(mb.alias.clone()), result_count: Some(n), ..Default::default() },
    })
}

/// `get_draft` on IMAP: a Dove draft id, or the message id of any message in the Drafts folder.
pub(super) async fn get_draft(cx: &ToolCx, mb: &Mailbox, args: &Value) -> Result<ToolOutput, ToolError> {
    let did = gmail_id_arg(args, "draft_id")?;
    let opts = ShapeOpts {
        max_body_chars: opt_u64(args, "max_body_chars", DEFAULT_BODY_CHARS, 1, MAX_BODY_CHARS)? as usize,
        include_headers: vec!["In-Reply-To".into(), "References".into()],
        select: None,
    };
    let owned = owned(cx, &mb.account_id).await?;
    let drafts = drafts_folder(cx, &mb.account_id).await?;
    let in_drafts = |id: &str| ImapMsgId::parse(id).is_some_and(|m| m.folder_id == drafts.folder_id);
    let (own, message_id) = match owned.iter().find(|o| o.draft_id == did) {
        Some(o) => (Some(o), o.message_id.clone()),
        None if in_drafts(did) => (owned.iter().find(|o| o.message_id == did), did.to_string()),
        None => return Err(ToolError::not_found()),
    };
    let f = mail::fetch_message(cx, mb, &message_id, Priority::Interactive).await?;
    let changed = own.is_some_and(|o| changed(o, &f) || !in_drafts(&o.message_id));
    let draft_id = own.map(|o| o.draft_id.clone()).unwrap_or_else(|| did.to_string());
    let (msg, _) = shape(mb, &f, &opts);
    let text = format!(
        "draft {draft_id} revision {message_id}{}\n{}",
        if changed { " (changed outside Dove: human-owned, Dove will not edit it)" } else { "" },
        render(&msg)
    );
    Ok(ToolOutput {
        extra: Vec::new(),
        structured: json!({ "account": mb.alias, "draft_id": draft_id, "revision": message_id, "owned": own.is_some(),
                            "editable_by_dove": own.is_some() && !changed && f.parsed.is_draft_shape, "message": msg }),
        text,
        audit: AuditInfo {
            account: Some(mb.alias.clone()),
            object_ids: vec![draft_id],
            result_count: Some(1),
            ..Default::default()
        },
    })
}
