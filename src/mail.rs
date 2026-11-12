//! Provider-neutral message access for tools: one `fetch_message` / `list_labels` API that dispatches on
//! [`Provider`]. IMAP messages are presented with Gmail-compatible system labels (`UNREAD`, `STARRED`, `DRAFT`,
//! `SENT`, `TRASH`, `SPAM`) plus their folder path, so shaping, filters and the index stay unchanged.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::content;
use crate::error::{ErrorCode, ToolError};
use crate::gmail::gateway::{GmailOp, Priority};
use crate::imap::account::{self, Folder};
use crate::imap::{ImapError, ImapMsgId, Special};
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
            snippet: v["snippet"].as_str().map(|s| content::clean_text(s).trim().to_string()),
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

async fn folder(cx: &ToolCx, account_id: &str, folder_id: i64) -> Result<Folder, ToolError> {
    let aid = account_id.to_string();
    let folders = cx.app.store.call(move |c| account::load_folders(c, &aid)).await.map_err(ToolError::from)?;
    folders.into_iter().find(|f| f.folder_id == folder_id).ok_or_else(ToolError::not_found)
}

async fn fetch_imap(cx: &ToolCx, mb: &Mailbox, id: &str) -> Result<Fetched, ToolError> {
    // Unknown, malformed and stale (UIDVALIDITY changed) ids are all the same `not_found`.
    let mid = ImapMsgId::parse(id).ok_or_else(ToolError::not_found)?;
    let f = folder(cx, &mb.account_id, mid.folder_id).await?;
    let name = f.name.clone();
    let max = mime::Limits::default().max_raw_bytes;
    let (meta, raw) = account::with_session(&cx.app, &mb.account_id, move |s| {
        Box::pin(async move {
            let st = s.select(&name, true).await?;
            if st.uidvalidity != mid.uidvalidity {
                return Err(ImapError::Missing);
            }
            let meta = s.fetch_meta(&[mid.uid]).await?.into_iter().next().ok_or(ImapError::Missing)?;
            let raw = s.fetch_raw(mid.uid, max).await?;
            Ok((meta, raw))
        })
    })
    .await?;
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
        labels: imap_labels(&f.name_utf8, &meta.flags, f.special),
        internal_date_ms: meta.internal_date_s.saturating_mul(1000),
        size_estimate: meta.size as i64,
        snippet,
    };
    Ok(Fetched { meta, raw, parsed })
}

/// Snippet of an IMAP message: the start of its body text with whitespace collapsed (Gmail computes its own).
pub fn imap_snippet(parsed: &ParsedMessage) -> String {
    let text = read::body_text(parsed);
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    content::truncate_chars(&flat, SNIPPET_CHARS).0
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
            let listed = account::with_session(&cx.app, &mb.account_id, |s| Box::pin(s.list_folders())).await?;
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
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
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
