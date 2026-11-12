//! Derived index rows from Gmail messages (spec 7.9 "Data").
//!
//! Stored per message: ids, internalDate, size estimate, normalized address roles/domains, cleaned subject with a
//! case-folded sort key, labels, attachment names/types and the sanitized body as FTS postings only. No raw MIME.
//! Body text beyond the limits or undecodable content records incomplete coverage instead of a silent gap.

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use unicode_normalization::UnicodeNormalization;

use crate::content;
use crate::mime::{self, Addr, ParsedMessage};
use crate::tools::read::{body_text, fmt_addr};

pub const ROLE_FROM: i64 = 1;
pub const ROLE_TO: i64 = 2;
pub const ROLE_CC: i64 = 3;
pub const ROLE_BCC: i64 = 4;

/// Gmail message metadata that every format returns.
#[derive(Debug, Clone, Default)]
pub struct GmailMeta {
    pub id: String,
    pub thread_id: String,
    pub labels: Vec<String>,
    pub internal_date_ms: i64,
    pub size_estimate: i64,
    pub snippet: Option<String>,
}

impl GmailMeta {
    pub fn from_json(v: &Value) -> Option<Self> {
        let id = v["id"].as_str()?.to_string();
        if !crate::gmail::gateway::valid_id(&id) {
            return None;
        }
        Some(Self {
            id,
            thread_id: v["threadId"].as_str().unwrap_or_default().to_string(),
            labels: labels_of(v),
            internal_date_ms: v["internalDate"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0),
            size_estimate: v["sizeEstimate"].as_i64().unwrap_or(0),
            snippet: v["snippet"].as_str().map(|s| content::clean_text(s).trim().to_string()),
        })
    }
}

pub fn labels_of(v: &Value) -> Vec<String> {
    v["labelIds"]
        .as_array()
        .map(|a| a.iter().filter_map(|l| l.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// One message as stored in the index.
#[derive(Debug, Clone, Default)]
pub struct Doc {
    pub meta: GmailMeta,
    pub subject: Option<String>,
    pub from: Vec<Addr>,
    pub to: Vec<Addr>,
    pub cc: Vec<Addr>,
    pub bcc: Vec<Addr>,
    /// None = MIME metadata unknown.
    pub has_attachment: Option<bool>,
    /// (filename, mime type)
    pub attachments: Vec<(Option<String>, String)>,
    pub body: String,
    pub body_complete: bool,
    pub meta_complete: bool,
}

/// Normalized address used at ingest and lookup alike: trimmed, lowercased (spec 5.3 "Normalize addresses
/// consistently"). Local parts are compared case-insensitively, as every major provider does.
pub fn norm_addr(s: &str) -> String {
    s.trim().trim_matches(|c| c == '<' || c == '>').trim().to_lowercase()
}

/// Exact normalized domain (no subdomain folding). Trailing dots are dropped.
pub fn norm_domain(s: &str) -> String {
    s.trim().trim_start_matches('@').trim_end_matches('.').to_lowercase()
}

pub fn domain_of(addr: &str) -> String {
    addr.rsplit_once('@').map(|(_, d)| norm_domain(d)).unwrap_or_default()
}

/// Case-folded sort key for subjects (NFKC + lowercase, whitespace collapsed).
pub fn subject_key(s: &str) -> String {
    let folded: String = s.nfkc().collect::<String>().to_lowercase();
    folded.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl Doc {
    /// Builds a doc from a parsed message. `max_body_chars` caps the FTS body.
    pub fn from_parsed(meta: GmailMeta, p: &ParsedMessage, max_body_chars: usize) -> Self {
        let body = body_text(p);
        let (body, truncated) = content::truncate_chars(&body, max_body_chars);
        Doc {
            meta,
            subject: p.subject.as_deref().map(|s| content::clean_text(s).trim().to_string()),
            from: p.from.clone(),
            to: p.to.clone(),
            cc: p.cc.clone(),
            bcc: p.bcc.clone(),
            has_attachment: Some(p.has_attachment),
            attachments: p.attachments.iter().map(|a| (a.filename.clone(), a.mime_type.clone())).collect(),
            body,
            body_complete: p.body_complete && !truncated,
            meta_complete: true,
        }
    }

    /// A message whose MIME could not be parsed (too large, malformed): Gmail metadata only, coverage unknown.
    pub fn metadata_only(meta: GmailMeta) -> Self {
        Doc { meta, has_attachment: None, body_complete: false, meta_complete: false, ..Default::default() }
    }

    /// Parses raw bytes within limits; failures degrade to a metadata-only doc.
    pub fn from_raw(meta: GmailMeta, raw: &[u8], max_message_bytes: usize, max_body_chars: usize) -> Self {
        let limits = mime::Limits { max_raw_bytes: max_message_bytes, ..Default::default() };
        match mime::parse(raw, &limits) {
            Ok(p) => Self::from_parsed(meta, &p, max_body_chars),
            Err(_) => Self::metadata_only(meta),
        }
    }
}

fn has(labels: &[String], l: &str) -> bool {
    labels.iter().any(|x| x == l)
}

fn spam_trash(labels: &[String]) -> bool {
    has(labels, "SPAM") || has(labels, "TRASH")
}

/// Deletes one derived row of a generation with its FTS postings, addresses, labels and attachments.
pub fn delete_row(tx: &Connection, gen_id: i64, id: i64) -> anyhow::Result<()> {
    let fts = super::schema::fts_table(gen_id);
    tx.prepare_cached(&format!("DELETE FROM {fts} WHERE rowid = ?1"))?.execute([id])?;
    delete_row_meta(tx, id)
}

/// Deletes one derived row without touching FTS: only for dropping a whole generation, whose FTS table goes with it.
pub fn delete_row_meta(tx: &Connection, id: i64) -> anyhow::Result<()> {
    tx.execute("DELETE FROM addrs WHERE msg = ?1", [id])?;
    tx.execute("DELETE FROM labels WHERE msg = ?1", [id])?;
    tx.execute("DELETE FROM atts WHERE msg = ?1", [id])?;
    tx.execute("DELETE FROM messages WHERE id = ?1", [id])?;
    Ok(())
}

pub fn row_id(tx: &Connection, gen_id: i64, gmail_id: &str) -> anyhow::Result<Option<i64>> {
    Ok(tx
        .query_row("SELECT id FROM messages WHERE gen = ?1 AND gmail_id = ?2", params![gen_id, gmail_id], |r| r.get(0))
        .optional()?)
}

/// Removes a message from a generation if present. Returns true if a row was removed.
pub fn remove(tx: &Connection, gen_id: i64, gmail_id: &str) -> anyhow::Result<bool> {
    match row_id(tx, gen_id, gmail_id)? {
        Some(id) => {
            delete_row(tx, gen_id, id)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

fn display_list(v: &[Addr]) -> String {
    json!(v.iter().map(fmt_addr).collect::<Vec<_>>()).to_string()
}

/// Inserts or replaces a message in a generation: metadata and FTS in the caller's transaction (idempotent).
pub fn upsert(tx: &Connection, gen_id: i64, account_id: &str, d: &Doc) -> anyhow::Result<()> {
    remove(tx, gen_id, &d.meta.id)?;
    let labels = &d.meta.labels;
    let subject_missing = d.subject.as_deref().is_none_or(|s| s.trim().is_empty());
    let key = d.subject.as_deref().map(subject_key).unwrap_or_default();
    let names: Vec<String> = d.attachments.iter().filter_map(|(n, _)| n.clone()).collect();
    let mimes: Vec<String> = d.attachments.iter().map(|(_, m)| m.clone()).collect();
    tx.execute(
        "INSERT INTO messages(gen, account_id, gmail_id, thread_id, received_at, size_bytes, subject, subject_missing, \
         subject_key, from_list, to_list, cc_list, bcc_list, labels, snippet, is_unread, is_starred, is_draft, \
         spam_trash, has_attachment, attachment_names, attachment_mimes, body_complete, meta_complete) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, \
         ?23, ?24)",
        params![
            gen_id,
            account_id,
            d.meta.id,
            d.meta.thread_id,
            d.meta.internal_date_ms,
            d.meta.size_estimate,
            d.subject,
            subject_missing,
            key,
            display_list(&d.from),
            display_list(&d.to),
            display_list(&d.cc),
            display_list(&d.bcc),
            json!(labels).to_string(),
            d.meta.snippet,
            has(labels, "UNREAD"),
            has(labels, "STARRED"),
            has(labels, "DRAFT"),
            spam_trash(labels),
            d.has_attachment,
            json!(names).to_string(),
            json!(mimes).to_string(),
            d.body_complete,
            d.meta_complete,
        ],
    )?;
    let id = tx.last_insert_rowid();
    let fts = super::schema::fts_table(gen_id);
    tx.prepare_cached(&format!("INSERT INTO {fts}(rowid, subject, body) VALUES (?1, ?2, ?3)"))?.execute(params![
        id,
        d.subject.as_deref().unwrap_or(""),
        d.body
    ])?;
    {
        let mut st =
            tx.prepare_cached("INSERT INTO addrs(msg, gen, role, addr, domain) VALUES (?1, ?2, ?3, ?4, ?5)")?;
        for (role, list) in [(ROLE_FROM, &d.from), (ROLE_TO, &d.to), (ROLE_CC, &d.cc), (ROLE_BCC, &d.bcc)] {
            let mut seen = std::collections::HashSet::new();
            for a in list.iter() {
                let addr = norm_addr(&a.email);
                if addr.is_empty() || !seen.insert(addr.clone()) {
                    continue;
                }
                st.execute(params![id, gen_id, role, addr, domain_of(&addr)])?;
            }
        }
    }
    write_labels(tx, gen_id, id, labels)?;
    {
        let mut st =
            tx.prepare_cached("INSERT INTO atts(msg, gen, name_lc, name_rev, mime_lc) VALUES (?1, ?2, ?3, ?4, ?5)")?;
        for (name, mime) in &d.attachments {
            let lc = name.as_deref().map(str::to_lowercase);
            let rev = lc.as_deref().map(|s| s.chars().rev().collect::<String>());
            st.execute(params![id, gen_id, lc, rev, mime.to_lowercase()])?;
        }
    }
    Ok(())
}

fn write_labels(tx: &Connection, gen_id: i64, id: i64, labels: &[String]) -> anyhow::Result<()> {
    tx.execute("DELETE FROM labels WHERE msg = ?1", [id])?;
    let mut st = tx.prepare_cached("INSERT OR IGNORE INTO labels(label, gen, msg) VALUES (?1, ?2, ?3)")?;
    for l in labels {
        st.execute(params![l, gen_id, id])?;
    }
    Ok(())
}

/// Updates labels and label-derived flags of an indexed message. Returns false if the message is not indexed.
pub fn update_labels(tx: &Connection, gen_id: i64, gmail_id: &str, labels: &[String]) -> anyhow::Result<bool> {
    let Some(id) = row_id(tx, gen_id, gmail_id)? else {
        return Ok(false);
    };
    tx.execute(
        "UPDATE messages SET labels = ?1, is_unread = ?2, is_starred = ?3, is_draft = ?4, spam_trash = ?5 WHERE id = ?6",
        params![
            json!(labels).to_string(),
            has(labels, "UNREAD"),
            has(labels, "STARRED"),
            has(labels, "DRAFT"),
            spam_trash(labels),
            id
        ],
    )?;
    write_labels(tx, gen_id, id, labels)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization() {
        assert_eq!(norm_addr(" <Anna.B@Example.COM> "), "anna.b@example.com");
        assert_eq!(domain_of("x@Mail.Example.com"), "mail.example.com");
        assert_eq!(norm_domain("@Example.com."), "example.com");
        assert_eq!(subject_key("  Ｒe:   Hallo  WELT "), "re: hallo welt");
    }
}
