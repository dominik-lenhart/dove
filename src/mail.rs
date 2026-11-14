//! Provider-neutral message access for tools: one `fetch_message` / `list_labels` API that dispatches on
//! [`Provider`]. IMAP messages are presented with Gmail-compatible system labels (`UNREAD`, `STARRED`, `DRAFT`,
//! `SENT`, `TRASH`, `SPAM`) plus their folder path, so shaping, filters and the index stay unchanged. Gmail-mode
//! messages (PLAN A57) take their labels from `X-GM-LABELS` instead of the folder they were read from.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::content;
use crate::error::{ErrorCode, ToolError};
use crate::gmail::gateway::{GmailOp, Priority};
use crate::imap::account::{self, Folder};
use crate::imap::{FetchedMeta, ImapError, ImapMsgId, Special, utf7};
use crate::mime::{self, ParsedMessage};
use crate::policy::{Mailbox, Provider};
use crate::tools::ToolCx;
use crate::tools::read::{self, Fetched};
use crate::util;

/// Message metadata every provider returns (the former `index::ingest::GmailMeta`).
#[derive(Debug, Clone, Default)]
pub struct MessageMeta {
    pub id: String,
    pub thread_id: String,
    pub labels: Vec<String>,
    pub internal_date_ms: i64,
    pub size_estimate: i64,
    pub snippet: Option<String>,
}

impl MessageMeta {
    /// From a Gmail message resource (any format).
    pub fn from_json(v: &Value) -> Option<Self> {
        let id = v["id"].as_str()?.to_string();
        if !crate::gmail::gateway::valid_id(&id) {
            return None;
        }
        Some(Self {
            id,
            thread_id: v["threadId"].as_str().unwrap_or_default().to_string(),
            labels: crate::index::ingest::labels_of(v),
            internal_date_ms: v["internalDate"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0),
            size_estimate: v["sizeEstimate"].as_i64().unwrap_or(0),
            snippet: v["snippet"].as_str().map(gmail_snippet),
        })
    }
}

/// Snippet length for IMAP messages (Gmail computes its own).
const SNIPPET_CHARS: usize = 200;

/// One message with raw bytes and parsed MIME, from whichever provider the mailbox uses.
pub async fn fetch_message(cx: &ToolCx, mb: &Mailbox, id: &str, prio: Priority) -> Result<Fetched, ToolError> {
    match mb.provider {
        Provider::Gmail => {
            let v = cx
                .app
                .google
                .call(&mb.account_id, || GmailOp::GetMessage(id), &[("format", "raw".into())], None, prio, cx.deadline)
                .await?;
            read::from_meta(v)
        }
        Provider::Imap => fetch_imap(cx, mb, id).await,
    }
}

async fn fetch_imap(cx: &ToolCx, mb: &Mailbox, id: &str) -> Result<Fetched, ToolError> {
    fetch_imap_many(cx, mb, &[id.to_string()]).await?.pop().unwrap_or_else(|| Err(ToolError::internal()))
}

/// Several messages of one mailbox, in input order, each with its own result. Gmail messages are read with bounded
/// concurrency; IMAP messages share one session: each folder is selected once and its metadata (with sizes) comes in
/// one `UID FETCH`, then one body fetch per message. A message that is gone is `not_found` in its slot; a failure of
/// the connection itself fails the whole call.
pub async fn fetch_many(
    cx: &ToolCx,
    mb: &Mailbox,
    ids: &[String],
    prio: Priority,
) -> Result<Vec<Result<Fetched, ToolError>>, ToolError> {
    use futures::stream::{self, StreamExt};
    match mb.provider {
        Provider::Gmail => Ok(stream::iter((0..ids.len()).map(|i| fetch_message(cx, mb, &ids[i], prio)))
            .buffered(cx.app.cfg.limits.upstream_per_mailbox.max(1))
            .collect()
            .await),
        Provider::Imap => fetch_imap_many(cx, mb, ids).await,
    }
}

struct Group {
    name: String,
    uidvalidity: u32,
    /// (result slot, UID)
    items: Vec<(usize, u32)>,
}

async fn fetch_imap_many(
    cx: &ToolCx,
    mb: &Mailbox,
    ids: &[String],
) -> Result<Vec<Result<Fetched, ToolError>>, ToolError> {
    // Unknown, malformed and stale (UIDVALIDITY changed) ids are all the same `not_found`.
    let parsed_ids: Vec<Option<ImapMsgId>> = ids.iter().map(|id| ImapMsgId::parse(id)).collect();
    let aid = mb.account_id.clone();
    let folders = cx.app.store.call(move |c| account::load_folders(c, &aid)).await.map_err(ToolError::from)?;
    // Wanted (slot, uid) pairs per folder and UIDVALIDITY, in first-appearance order.
    let mut groups: Vec<Group> = Vec::new();
    for (i, mid) in parsed_ids.iter().enumerate() {
        let Some(mid) = mid else { continue };
        let Some(f) = folders.iter().find(|f| f.folder_id == mid.folder_id) else { continue };
        match groups.iter_mut().find(|g| g.name == f.name && g.uidvalidity == mid.uidvalidity) {
            Some(g) => g.items.push((i, mid.uid)),
            None => {
                groups.push(Group { name: f.name.clone(), uidvalidity: mid.uidvalidity, items: vec![(i, mid.uid)] })
            }
        }
    }
    let max = mime::Limits::default().max_raw_bytes;
    type Got = (usize, FetchedMeta, Option<Vec<u8>>);
    let (got, gmail): (Vec<Got>, bool) = if groups.is_empty() {
        (Vec::new(), false)
    } else {
        account::with_session(&cx.app, &mb.account_id, move |s| {
            Box::pin(async move {
                let mut got = Vec::new();
                for Group { name, uidvalidity, items } in groups {
                    let st = match s.select(&name, true).await {
                        Ok(st) => st,
                        Err(ImapError::Missing) => continue,
                        Err(e) => return Err(e),
                    };
                    if st.uidvalidity != uidvalidity {
                        continue;
                    }
                    let mut uids: Vec<u32> = items.iter().map(|(_, u)| *u).collect();
                    uids.sort_unstable();
                    uids.dedup();
                    let metas = s.fetch_meta(&uids).await?;
                    for (slot, uid) in items {
                        let Some(m) = metas.iter().find(|m| m.uid == uid) else { continue };
                        let raw = match s.fetch_raw_sized(uid, m.size, max).await {
                            Ok(r) => r,
                            Err(ImapError::Missing) => continue,
                            Err(e) => return Err(e),
                        };
                        got.push((slot, m.clone(), raw));
                    }
                }
                Ok((got, s.is_gmail()))
            })
        })
        .await?
    };
    let mut out: Vec<Result<Fetched, ToolError>> = (0..ids.len()).map(|_| Err(ToolError::not_found())).collect();
    for (slot, meta, raw) in got {
        let Some(f) = parsed_ids[slot].and_then(|mid| folders.iter().find(|f| f.folder_id == mid.folder_id)) else {
            continue;
        };
        out[slot] = shape_imap(&ids[slot], f, &meta, raw, gmail);
    }
    Ok(out)
}

fn shape_imap(
    id: &str,
    f: &Folder,
    meta: &FetchedMeta,
    raw: Option<Vec<u8>>,
    gmail: bool,
) -> Result<Fetched, ToolError> {
    let raw = raw.ok_or_else(|| {
        ToolError::new(ErrorCode::TooLarge, "the message exceeds the size limit")
            .with_details(json!({ "size_bytes": meta.size }))
    })?;
    let parsed =
        mime::parse(&raw, &mime::Limits::default()).map_err(|_| ToolError::upstream("message could not be parsed"))?;
    let snippet = Some(imap_snippet(&parsed));
    let meta = MessageMeta {
        id: id.to_string(),
        thread_id: imap_thread_id(&parsed, id),
        labels: message_labels(f, meta, gmail),
        internal_date_ms: meta.internal_date_s.saturating_mul(1000),
        size_estimate: meta.size as i64,
        snippet,
    };
    Ok(Fetched { meta, raw, parsed })
}

/// Snippet of an IMAP message: the start of its body text with whitespace collapsed (Gmail computes its own).
/// Gmail's `snippet` is HTML-escaped (`&#39;`, `&amp;`, ...): resolve the references, then clean it like any text.
pub fn gmail_snippet(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    crate::attachment_text::push_unescaped(raw, &mut out);
    content::clean_text(&out).trim().to_string()
}

pub fn imap_snippet(parsed: &ParsedMessage) -> String {
    let text = read::body_text(parsed);
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    content::truncate_chars(&flat, SNIPPET_CHARS).0
}

/// Labels of an IMAP message read from `folder`. In Gmail mode a message outside Trash and Spam is labelled from its
/// `X-GM-LABELS` ([`gmail_labels`]; always in All Mail, whose path is no label); everything else from its folder
/// ([`imap_labels`]).
pub fn message_labels(folder: &Folder, meta: &FetchedMeta, gmail: bool) -> Vec<String> {
    let in_all = folder.special == Some(Special::All);
    let trashy = matches!(folder.special, Some(Special::Trash | Special::Junk));
    match (&meta.gm_labels, gmail && !trashy) {
        (Some(gm), true) => gmail_labels(&meta.flags, gm),
        (None, true) if in_all => gmail_labels(&meta.flags, &[]),
        _ => imap_labels(&folder.name_utf8, &meta.flags, folder.special),
    }
}

/// Labels of a Gmail message from its `X-GM-LABELS` and flags: `\Inbox` → `INBOX`, `\Sent` → `SENT`, `\Draft` →
/// `DRAFT`, `\Important` → `IMPORTANT`, `\Starred` → `STARRED`, other system labels are left out, user labels by
/// their decoded name; flags as in [`imap_labels`] (`UNREAD`, `STARRED`, `DRAFT`, keywords).
pub fn gmail_labels(flags: &[String], gm_labels: &[String]) -> Vec<String> {
    let has = |f: &str| flags.iter().any(|x| x.eq_ignore_ascii_case(f));
    let mut out: Vec<String> = Vec::new();
    let mut add = |l: &str| {
        if !l.is_empty() && !out.iter().any(|x| x == l) {
            out.push(l.to_string());
        }
    };
    for l in gm_labels {
        match l.to_ascii_lowercase().as_str() {
            "\\inbox" => add("INBOX"),
            "\\sent" => add("SENT"),
            "\\draft" => add("DRAFT"),
            "\\important" => add("IMPORTANT"),
            "\\starred" => add("STARRED"),
            s if s.starts_with('\\') => {}
            _ => add(&label_text(&utf7::display_name(l))),
        }
    }
    if !has("\\Seen") {
        add("UNREAD");
    }
    if has("\\Flagged") {
        add("STARRED");
    }
    if has("\\Draft") {
        add("DRAFT");
    }
    for k in flags.iter().filter(|f| !f.starts_with('\\')) {
        add(&label_text(k));
    }
    out
}

/// Labels of an IMAP message: its folder path, Gmail-style system labels from flags and the folder's special use,
/// and keywords.
pub fn imap_labels(folder_path: &str, flags: &[String], special: Option<Special>) -> Vec<String> {
    let has = |f: &str| flags.iter().any(|x| x.eq_ignore_ascii_case(f));
    let mut out = vec![label_text(folder_path)];
    let mut add = |l: &str| {
        if !out.iter().any(|x| x == l) {
            out.push(l.to_string());
        }
    };
    if !has("\\Seen") {
        add("UNREAD");
    }
    if has("\\Flagged") {
        add("STARRED");
    }
    if has("\\Draft") || special == Some(Special::Drafts) {
        add("DRAFT");
    }
    match special {
        Some(Special::Sent) => add("SENT"),
        Some(Special::Trash) => add("TRASH"),
        Some(Special::Junk) => add("SPAM"),
        _ => {}
    }
    for k in flags.iter().filter(|f| !f.starts_with('\\')) {
        add(&label_text(k));
    }
    out
}

/// A folder name or keyword as a label: cleaned like other untrusted text, and always on one line (an agent reads
/// labels inside the untrusted envelope, where a line break could forge a line).
pub fn label_text(s: &str) -> String {
    content::clean_text(s).replace(['\n', '\t'], " ")
}

/// Derived thread id: the root of the `References` chain, else the first `In-Reply-To`, else the message's own
/// `Message-ID`, together with the normalised subject ([`thread_subject`]); without any Message-ID, `message_id`
/// alone. `"t"` + the first 22 characters of base64url(SHA-256).
///
/// The subject is part of the key because anyone can send a message whose `References` name a root Message-ID they
/// have seen (quoted in a forward, a mailing list archive): with the root alone that message would join the thread
/// and be returned by `get_thread` as part of the conversation. Requiring the same normalised subject as well is what
/// common clients do (Gmail threads by references and subject too); a reply that changes its subject starts a new
/// thread, as it does there.
pub fn imap_thread_id(parsed: &ParsedMessage, message_id: &str) -> String {
    let root = parsed
        .references
        .first()
        .or(parsed.in_reply_to.first())
        .or(parsed.message_id_header.as_ref())
        .map(|s| s.trim().trim_start_matches('<').trim_end_matches('>').to_ascii_lowercase())
        .filter(|s| !s.is_empty());
    match root {
        Some(root) => {
            thread_hash(&format!("{root}\n{}", thread_subject(parsed.subject.as_deref().unwrap_or_default())))
        }
        None => imap_own_thread_id(message_id),
    }
}

/// Reply and forward prefixes stripped from a subject before threading (English and the common European ones).
const SUBJECT_PREFIXES: &[&str] =
    &["re", "fw", "fwd", "aw", "wg", "sv", "vs", "antw", "doorst", "tr", "rif", "r", "res", "enc"];

/// A subject as threading compares it: cleaned, leading reply/forward prefixes removed (`Re:`, `AW:`, `Fwd:`,
/// `Re[2]:`, repeated), whitespace collapsed, lower case.
pub fn thread_subject(subject: &str) -> String {
    let cleaned = content::clean_text(subject);
    let mut s = cleaned.trim();
    while let Some((prefix, rest)) = s.split_once(':') {
        let p = prefix.trim_end();
        // `Re[2]` / `Re(2)`: a reply counter some clients add.
        let p = match p.strip_suffix(']').and_then(|q| q.rsplit_once('[')) {
            Some((head, n)) if n.chars().all(|c| c.is_ascii_digit()) => head,
            _ => match p.strip_suffix(')').and_then(|q| q.rsplit_once('(')) {
                Some((head, n)) if n.chars().all(|c| c.is_ascii_digit()) => head,
                _ => p,
            },
        };
        if !SUBJECT_PREFIXES.iter().any(|x| p.trim_end().eq_ignore_ascii_case(x)) {
            break;
        }
        s = rest.trim_start();
    }
    s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

/// Thread id of an IMAP message whose headers are unknown (indexed from metadata only): a thread of its own, the
/// same id [`imap_thread_id`] gives a message without any Message-ID.
pub fn imap_own_thread_id(message_id: &str) -> String {
    thread_hash(&format!("dove:{message_id}"))
}

fn thread_hash(root: &str) -> String {
    let h = util::b64url(&Sha256::digest(root.as_bytes()));
    format!("t{}", &h[..22])
}

/// Labels for building filters: Gmail labels, or the IMAP folders (refreshed from the server) plus system labels.
pub async fn list_labels(cx: &ToolCx, mb: &Mailbox) -> Result<Vec<Value>, ToolError> {
    match mb.provider {
        Provider::Gmail => {
            let v = cx
                .app
                .google
                .call(&mb.account_id, || GmailOp::Labels, &[], None, Priority::Interactive, cx.deadline)
                .await?;
            Ok(v["labels"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|l| json!({ "id": l["id"], "name": l["name"].as_str().map(content::clean_text), "type": l["type"] }))
                        .collect()
                })
                .unwrap_or_default())
        }
        Provider::Imap => {
            let (listed, gmail) = account::with_session(&cx.app, &mb.account_id, |s| {
                Box::pin(async move { Ok((s.list_folders().await?, s.is_gmail())) })
            })
            .await?;
            let aid = mb.account_id.clone();
            let folders = cx
                .app
                .store
                .call(move |c| {
                    let tx = c.transaction()?;
                    account::upsert_folders(&tx, &aid, &listed, None)?;
                    tx.commit()?;
                    account::load_folders(c, &aid)
                })
                .await
                .map_err(ToolError::from)?;
            let mut out: Vec<Value> = folders
                .iter()
                .map(|f| {
                    let name = label_text(&f.name_utf8);
                    json!({ "id": name, "name": name, "type": "folder", "special_use": f.special.map(Special::as_str) })
                })
                .collect();
            for l in ["UNREAD", "STARRED", "DRAFT", "SENT", "TRASH", "SPAM"] {
                out.push(json!({ "id": l, "name": l, "type": "system" }));
            }
            if gmail {
                // Gmail labels map INBOX and user labels to their folder names, `\Important` to IMPORTANT.
                out.push(json!({ "id": "IMPORTANT", "name": "IMPORTANT", "type": "system" }));
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn gmail_snippets_are_unescaped() {
        let m = MessageMeta::from_json(&serde_json::json!({
            "id": "1a1d456be54939a3",
            "snippet": "If you didn&#39;t allow it, check &quot;Security&quot; &amp; act &lt;now&gt;",
        }))
        .unwrap();
        assert_eq!(m.snippet.as_deref(), Some("If you didn't allow it, check \"Security\" & act <now>"));
    }

    use super::*;

    #[test]
    fn subjects_normalise_for_threading() {
        for s in ["Plan", "Re: Plan", "RE:re: plan", "AW: WG:  Plan ", "Fwd: Re[2]: Plan", "Antw:Plan", "re (3): plan"]
        {
            assert_eq!(thread_subject(s), "plan", "{s:?}");
        }
        assert_eq!(thread_subject("Report: Q3"), "report: q3", "only known prefixes are stripped");
        assert_eq!(thread_subject(""), "");
    }

    fn parsed(headers: &str) -> ParsedMessage {
        let raw = format!("From: a@example.org\r\n{headers}\r\n\r\nbody\r\n");
        mime::parse(raw.as_bytes(), &mime::Limits::default()).unwrap()
    }

    /// The thread id needs both the root Message-ID and the normalised subject: a stranger who only knows the root
    /// cannot join the thread.
    #[test]
    fn thread_id_needs_root_and_subject() {
        let root = parsed("Message-ID: <root@x>\r\nSubject: Plan");
        let reply = parsed("Message-ID: <r1@x>\r\nIn-Reply-To: <root@x>\r\nReferences: <root@x>\r\nSubject: Re: Plan");
        let forged = parsed("Message-ID: <f@evil>\r\nReferences: <root@x>\r\nSubject: Urgent: new bank details");
        let t = imap_thread_id(&root, "f1-1-1");
        assert_eq!(imap_thread_id(&reply, "f1-1-2"), t);
        assert_ne!(imap_thread_id(&forged, "f1-1-3"), t);
        // Without any Message-ID a message is a thread of its own, the id metadata-only rows get.
        let bare = parsed("Subject: Plan");
        assert_eq!(imap_thread_id(&bare, "f1-1-4"), imap_own_thread_id("f1-1-4"));
    }

    #[test]
    fn gmail_labels_map_system_and_user_labels() {
        let gm: Vec<String> = [
            "\\Inbox",
            "\\IMPORTANT",
            "\\Sent",
            "\\Draft",
            "\\Starred",
            "\\Chats",
            "Work",
            "K&AOQ-se/Ablage",
            "Bad\r\nLabel",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let labels = gmail_labels(&["\\Seen".into(), "$Kw".into()], &gm);
        assert_eq!(
            labels,
            [
                "INBOX",
                "IMPORTANT",
                "SENT",
                "DRAFT",
                "STARRED",
                "Work",
                "K\u{e4}se/Ablage",
                "Bad\u{fffd}\u{fffd}Label",
                "$Kw"
            ]
            .map(String::from)
        );
        // Unread and flagged come from flags; no labels at all is just that.
        assert_eq!(gmail_labels(&["\\Flagged".into()], &[]), vec!["UNREAD".to_string(), "STARRED".into()]);
        // In Gmail mode All Mail is never a label, Trash and Spam keep the folder mapping.
        let f = |name: &str, special| Folder { folder_id: 1, name: name.into(), name_utf8: name.into(), special };
        let meta =
            FetchedMeta { flags: vec!["\\Seen".into()], gm_labels: Some(vec!["\\Inbox".into()]), ..Default::default() };
        assert_eq!(message_labels(&f("[Gmail]/All Mail", Some(Special::All)), &meta, true), vec!["INBOX".to_string()]);
        assert_eq!(
            message_labels(&f("[Gmail]/Trash", Some(Special::Trash)), &meta, true),
            vec!["[Gmail]/Trash".to_string(), "TRASH".into()]
        );
        let bare = FetchedMeta { flags: vec!["\\Seen".into()], ..Default::default() };
        assert!(message_labels(&f("[Gmail]/All Mail", Some(Special::All)), &bare, true).is_empty());
        // Outside Gmail mode nothing changes.
        assert_eq!(message_labels(&f("INBOX", None), &meta, false), vec!["INBOX".to_string()]);
    }

    /// Labels built from server data (folder path, keywords) are one line without control or invisible characters,
    /// in message labels, index rows and `list_labels` alike.
    #[test]
    fn labels_are_single_clean_lines() {
        let labels = imap_labels("Evil\r\nFolder\u{200B}", &["$kw\n\u{7}x".into(), "\\Seen".into()], None);
        assert_eq!(labels, vec!["Evil Folder".to_string(), "$kw x".to_string()]);
        for l in &labels {
            assert!(!l.chars().any(|c| c.is_control()), "{l:?}");
        }
    }
}
