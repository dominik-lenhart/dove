//! Draft composition beyond plain text (owner request 2026-11-12): attachments by reference or inline, forwarding,
//! and quoting the original in replies. `tools::drafts` keeps the create/update flow; this module parses and
//! authorizes the extra inputs, fetches referenced attachments and builds the forwarded/quoted body text.
//!
//! Rules:
//! - Every referenced message (attachment source, forwarded message) needs `read` on its mailbox. Anything else,
//!   including a mailbox the caller may only draft in, is the identical `not_found`, decided before any upstream call.
//! - Referenced attachment bytes are fetched server-side and never pass through the agent.
//! - At most [`mime::MAX_DRAFT_ATTACHMENTS`] attachments and `limits.draft_attachment_bytes` decoded bytes per draft.
//!   Exceeding a limit is an error, never a silent drop.
//! - Original text (quote, forward block) is untrusted content: it goes into the body only, never into headers. The
//!   one header value taken from the original, its subject, is reduced to a single clean line.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::attachments::sanitize_filename;
use super::read::{Fetched, body_text, fmt_addrs};
use super::{ToolCx, opt_str, resolve_ref};
use crate::content;
use crate::error::{ErrorCode, ToolError};
use crate::gmail::gateway::Priority;
use crate::mime::{self, Addr, DraftAttachment, MAX_DRAFT_ATTACHMENTS, MimeError};
use crate::policy::{Capability, Mailbox};
use crate::util;

/// Most bytes of original text quoted in a reply or included in a forward.
pub const QUOTE_MAX_BYTES: usize = 100 * 1024;

const MIB: u64 = 1024 * 1024;

/// Audit size class of a draft's attachments (never names or content).
pub fn size_class(n: u64) -> &'static str {
    match n {
        n if n < MIB => "attachments<1MiB",
        n if n <= 10 * MIB => "attachments<=10MiB",
        _ => "attachments>10MiB",
    }
}

/// One requested attachment, validated and authorized but not fetched.
pub enum AttachSpec {
    /// An attachment of a message the caller may read.
    Ref {
        account_id: String,
        message_id: String,
        part: String,
    },
    Inline(DraftAttachment),
}

impl AttachSpec {
    /// Canonical form for the create idempotency hash (no content: a digest of inline bytes).
    pub fn canonical(&self) -> Value {
        match self {
            AttachSpec::Ref { account_id, message_id, part } => json!(["ref", account_id, message_id, part]),
            AttachSpec::Inline(a) => {
                json!(["inline", a.filename, a.mime_type, util::hex(&Sha256::digest(&a.bytes))])
            }
        }
    }
}

fn hide_forbidden(e: ToolError) -> ToolError {
    // A mailbox without `read` looks exactly like one outside the grants.
    if e.code == ErrorCode::Forbidden { ToolError::not_found() } else { e }
}

/// A message the caller may read, by `ref` or `account` + `message_id`. Every failure that could reveal a mailbox or
/// message (unknown, out of scope, no `read`, malformed id) is the same `not_found`. No upstream call.
pub fn readable_message<'a>(
    cx: &'a ToolCx,
    r: Option<&str>,
    account: Option<&str>,
    message_id: Option<&str>,
) -> Result<(&'a Mailbox, String), ToolError> {
    match (r, account, message_id) {
        (Some(r), None, None) => resolve_ref(&cx.client, r, Capability::Read).map_err(hide_forbidden),
        (None, Some(a), Some(m)) => {
            let mb = cx.client.authorize(Capability::Read, a).map_err(hide_forbidden)?;
            if !crate::gmail::gateway::valid_id(m) {
                return Err(ToolError::not_found());
            }
            Ok((mb, m.to_string()))
        }
        (Some(_), _, _) => Err(ToolError::invalid("pass either ref or account + message_id, not both")),
        _ => Err(ToolError::invalid("a message reference needs ref, or account and message_id")),
    }
}

fn too_large(limit: usize, size: Option<u64>, hint: &str) -> ToolError {
    ToolError::new(
        ErrorCode::TooLarge,
        format!("the draft's attachments would exceed the limit of {limit} bytes{hint}"),
    )
    .with_details(json!({ "size_bytes": size, "limit_bytes": limit }))
}

fn too_many(n: usize, hint: &str) -> ToolError {
    ToolError::invalid(format!(
        "the draft would have {n} attachments; at most {MAX_DRAFT_ATTACHMENTS} are allowed{hint}"
    ))
}

/// Parses an `attachments` argument. `None` when absent (update: keep the current attachments); `Some(vec![])`
/// removes them. Inline bytes are decoded and counted against `limit` here; references are authorized here and
/// fetched by [`resolve`].
pub fn parse_attachments(cx: &ToolCx, v: Option<&Value>, limit: usize) -> Result<Option<Vec<AttachSpec>>, ToolError> {
    let items = match v {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Array(a)) => a,
        Some(_) => return Err(ToolError::invalid("'attachments' must be a list")),
    };
    if items.len() > MAX_DRAFT_ATTACHMENTS {
        return Err(too_many(items.len(), ""));
    }
    let mut out = Vec::with_capacity(items.len());
    let mut inline_total = 0usize;
    for it in items {
        if !it.is_object() {
            return Err(ToolError::invalid("each attachment must be an object"));
        }
        if it.get("content_base64").is_some() {
            super::only_keys(it, &["filename", "mime_type", "content_base64"])?;
            let name =
                opt_str(it, "filename")?.ok_or_else(|| ToolError::invalid("inline attachments need a filename"))?;
            let filename = sanitize_filename(Some(name));
            let mime_type = opt_str(it, "mime_type")?
                .and_then(mime::normalize_mime_type)
                .ok_or_else(|| ToolError::invalid("mime_type must be a plain type/subtype such as application/pdf"))?;
            let b64 = opt_str(it, "content_base64")?.unwrap_or_default();
            // Reject before decoding what cannot fit (base64 is 4 characters per 3 bytes).
            if b64.len() / 4 * 3 > limit.saturating_sub(inline_total).saturating_add(3) {
                return Err(too_large(limit, None, ""));
            }
            let bytes = util::b64_decode_any(b64).ok_or_else(|| ToolError::invalid("content_base64 is not base64"))?;
            inline_total += bytes.len();
            if inline_total > limit {
                return Err(too_large(limit, Some(inline_total as u64), ""));
            }
            out.push(AttachSpec::Inline(DraftAttachment { filename, mime_type, bytes }));
        } else {
            super::only_keys(it, &["ref", "account", "message_id", "attachment_id"])?;
            let part = opt_str(it, "attachment_id")?
                .ok_or_else(|| ToolError::invalid("attachment references need attachment_id"))?;
            let (mb, message_id) =
                readable_message(cx, opt_str(it, "ref")?, opt_str(it, "account")?, opt_str(it, "message_id")?)?;
            if !valid_part_id(part) {
                return Err(ToolError::not_found());
            }
            out.push(AttachSpec::Ref { account_id: mb.account_id.clone(), message_id, part: part.to_string() });
        }
    }
    Ok(Some(out))
}

fn valid_part_id(s: &str) -> bool {
    s.strip_prefix("part-").is_some_and(|n| (1..=10).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit()))
}

/// An attachment taken from a message (reference or forward): sanitized filename, validated type (anything Dove may
/// not write becomes `application/octet-stream`), exact decoded bytes.
fn from_message(meta: mime::AttachmentMeta, bytes: Vec<u8>) -> DraftAttachment {
    DraftAttachment {
        filename: sanitize_filename(meta.filename.as_deref()),
        mime_type: mime::normalize_mime_type(&meta.mime_type).unwrap_or_else(|| "application/octet-stream".into()),
        bytes,
    }
}

/// Fetches referenced attachments (each source message once) and returns all attachments in request order.
/// `used` counts attachments and bytes already in the draft (a forward's), so the limits cover the whole draft.
pub async fn resolve(
    cx: &ToolCx,
    specs: Vec<AttachSpec>,
    limit: usize,
    used: (usize, usize),
) -> Result<Vec<DraftAttachment>, ToolError> {
    let (used_count, mut total) = used;
    if used_count + specs.len() > MAX_DRAFT_ATTACHMENTS {
        return Err(too_many(used_count + specs.len(), ""));
    }
    let mut out: Vec<Option<DraftAttachment>> = Vec::with_capacity(specs.len());
    let mut pending: Vec<(usize, String, String, String)> = Vec::new();
    for (i, s) in specs.into_iter().enumerate() {
        match s {
            AttachSpec::Inline(a) => {
                total += a.bytes.len();
                out.push(Some(a));
            }
            AttachSpec::Ref { account_id, message_id, part } => {
                out.push(None);
                pending.push((i, account_id, message_id, part));
            }
        }
    }
    if total > limit {
        return Err(too_large(limit, Some(total as u64), ""));
    }
    // One fetch per source message; the raw message is dropped before the next one is fetched.
    while let Some((_, aid, mid, _)) = pending.first().cloned() {
        let mb = cx.client.resolve_id(&aid)?.clone();
        let f = crate::mail::fetch_message(cx, &mb, &mid, Priority::Interactive).await?;
        let (now, rest): (Vec<_>, Vec<_>) = pending.into_iter().partition(|p| p.1 == aid && p.2 == mid);
        pending = rest;
        for (i, _, _, part) in now {
            let (meta, bytes) = match mime::attachment_bytes(&f.raw, &part, limit - total) {
                Ok(Some(v)) => v,
                Ok(None) => return Err(ToolError::not_found()),
                Err(MimeError::TooLarge) => {
                    let size = f.parsed.attachments.iter().find(|a| a.attachment_id == part).map(|a| a.size_bytes);
                    return Err(too_large(limit, size.map(|s| s + total as u64), ""));
                }
                Err(_) => return Err(ToolError::upstream("message could not be parsed")),
            };
            total += bytes.len();
            out[i] = Some(from_message(meta, bytes));
        }
    }
    Ok(out.into_iter().map(|a| a.expect("every reference resolved")).collect())
}

/// All attachments of a forwarded message, within the per-draft limits. Over a limit is an error that says how to
/// forward without them.
pub fn forward_attachments(f: &Fetched, limit: usize) -> Result<Vec<DraftAttachment>, ToolError> {
    const HINT: &str = "; pass include_attachments: false to forward the text only";
    let list = &f.parsed.attachments;
    if list.len() > MAX_DRAFT_ATTACHMENTS {
        return Err(too_many(list.len(), HINT));
    }
    let announced: u64 = list.iter().map(|a| a.size_bytes).sum();
    if announced > limit as u64 {
        return Err(too_large(limit, Some(announced), HINT));
    }
    let mut out = Vec::with_capacity(list.len());
    let mut total = 0usize;
    for a in list {
        match mime::attachment_bytes(&f.raw, &a.attachment_id, limit - total) {
            Ok(Some((meta, bytes))) => {
                total += bytes.len();
                out.push(from_message(meta, bytes));
            }
            Ok(None) => return Err(ToolError::upstream("message could not be parsed")),
            Err(MimeError::TooLarge) => return Err(too_large(limit, Some(announced), HINT)),
            Err(_) => return Err(ToolError::upstream("message could not be parsed")),
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------ text

/// One line of untrusted text safe for a header or a header-like body line: cleaned, control characters and line
/// breaks replaced by spaces, whitespace collapsed.
pub fn one_line(s: &str) -> String {
    let cleaned = content::clean_text(s);
    let spaced: String = cleaned.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    spaced.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn addr_line(list: &[Addr]) -> String {
    one_line(&fmt_addrs(list).join(", "))
}

fn date_line(unix: Option<i64>) -> Option<String> {
    let d = time::OffsetDateTime::from_unix_timestamp(unix?).ok()?;
    d.format(&time::format_description::well_known::Rfc2822).ok()
}

/// `s` cut to at most `max` bytes at a line end (or a character boundary if a single line is longer).
fn cut(s: &str, max: usize) -> (&str, bool) {
    if s.len() <= max {
        return (s, false);
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    let at_line = s[..end].rfind('\n').unwrap_or(end);
    (&s[..at_line], true)
}

/// The original's text for quoting: plain text (or HTML converted to text), cleaned, trailing whitespace removed.
fn original_text(f: &Fetched) -> String {
    body_text(&f.parsed).trim_end().to_string()
}

/// Joins the agent's text and a generated block with one blank line between them.
fn join(body: &str, block: &str, max_total: usize) -> String {
    let head = body.trim_end();
    let sep = if head.is_empty() { "" } else { "\n\n" };
    let room = max_total.saturating_sub(head.len() + sep.len());
    let (block, _) = cut(block, room);
    format!("{head}{sep}{block}\n")
}

/// The reply body: the agent's text, then `On <date>, <sender> wrote:` and the original text with `> ` prefixes,
/// at most [`QUOTE_MAX_BYTES`] of original and never more than the draft body limit in total.
pub fn with_quote(body: &str, orig: &Fetched) -> String {
    let who = orig.parsed.from.first().map(|a| addr_line(std::slice::from_ref(a))).unwrap_or_default();
    let who = if who.is_empty() { "the sender".to_string() } else { who };
    let attribution = match date_line(orig.parsed.date) {
        Some(d) => format!("On {d}, {who} wrote:"),
        None => format!("{who} wrote:"),
    };
    let text = original_text(orig);
    let (text, truncated) = cut(&text, QUOTE_MAX_BYTES);
    let mut quoted: Vec<String> =
        text.lines().map(|l| if l.is_empty() { ">".to_string() } else { format!("> {l}") }).collect();
    if truncated {
        quoted.push("> [...]".into());
    }
    join(body, &format!("{attribution}\n{}", quoted.join("\n")), mime::MAX_BODY_BYTES)
}

/// The forward body: the agent's text, then a standard forwarded-message header block and the original text.
pub fn with_forward(body: &str, orig: &Fetched) -> String {
    let p = &orig.parsed;
    let mut block = String::from("---------- Forwarded message ---------\n");
    block.push_str(&format!("From: {}\n", addr_line(&p.from)));
    if let Some(d) = date_line(p.date) {
        block.push_str(&format!("Date: {d}\n"));
    }
    block.push_str(&format!("Subject: {}\n", one_line(p.subject.as_deref().unwrap_or_default())));
    if !p.to.is_empty() {
        block.push_str(&format!("To: {}\n", addr_line(&p.to)));
    }
    if !p.cc.is_empty() {
        block.push_str(&format!("Cc: {}\n", addr_line(&p.cc)));
    }
    let text = original_text(orig);
    let (text, truncated) = cut(&text, QUOTE_MAX_BYTES);
    block.push('\n');
    block.push_str(text);
    if truncated {
        block.push_str("\n[...]");
    }
    join(body, &block, mime::MAX_BODY_BYTES)
}

/// `Fwd: <original subject>` (unchanged if it already carries a forward prefix), one clean line.
pub fn forward_subject(orig: Option<&str>) -> String {
    let s = one_line(orig.unwrap_or_default());
    let lower = s.to_lowercase();
    if ["fwd:", "fw:", "wg:"].iter().any(|p| lower.starts_with(p)) { s } else { format!("Fwd: {s}").trim().into() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fetched(raw: &str) -> Fetched {
        let parsed = mime::parse(raw.as_bytes(), &mime::Limits::default()).unwrap();
        Fetched { meta: Default::default(), raw: raw.as_bytes().to_vec(), parsed }
    }

    const ORIG: &str = "From: \"Jane\r\n Doe\" <jane@example.org>\r\nTo: info@example.org\r\nCc: c@example.org\r\n\
Subject: =?utf-8?q?Angebot_=0D=0ABcc=3A_x=40evil=2Eorg?=\r\nDate: Tue, 14 Nov 2023 22:13:20 +0000\r\n\r\n\
Hallo,\r\n\r\nwie besprochen.\r\n> alt\r\n";

    #[test]
    fn quote_prefixes_lines_and_keeps_headers_out() {
        let f = fetched(ORIG);
        let b = with_quote("Danke!\n", &f);
        assert_eq!(
            b,
            "Danke!\n\nOn Tue, 14 Nov 2023 22:13:20 +0000, Jane Doe <jane@example.org> wrote:\n> Hallo,\n>\n\
> wie besprochen.\n> > alt\n"
        );
        // Empty agent text: the quote starts the body.
        assert!(with_quote("", &f).starts_with("On Tue"));
        // An encoded CR/LF in the subject cannot become a header line.
        let s = forward_subject(f.parsed.subject.as_deref());
        assert!(!s.contains('\r') && !s.contains('\n'), "{s:?}");
        assert!(s.starts_with("Fwd: Angebot"), "{s}");
        assert!(mime::validate_header_text(&s).is_ok());
        assert_eq!(forward_subject(Some("FW: x")), "FW: x");
        assert_eq!(forward_subject(None), "Fwd:");
    }

    #[test]
    fn quote_is_bounded() {
        let long = format!("From: a@example.org\r\n\r\n{}", "zeile mit text\r\n".repeat(20_000));
        let f = fetched(&long);
        let b = with_quote("x", &f);
        let quoted: usize = b.lines().filter(|l| l.starts_with('>')).map(|l| l.len() - 1).sum();
        assert!(quoted <= QUOTE_MAX_BYTES + 2 * 20_000, "{quoted}");
        assert!(b.trim_end().ends_with("> [...]"));
        assert!(b.len() < QUOTE_MAX_BYTES * 2);
        // Near the body limit, the quote shrinks so the whole body still fits.
        let big = "y".repeat(mime::MAX_BODY_BYTES - 100);
        let b = with_quote(&big, &f);
        assert!(b.len() <= mime::MAX_BODY_BYTES + 1, "{}", b.len());
        let fw = with_forward(&big, &f);
        assert!(fw.len() <= mime::MAX_BODY_BYTES + 1, "{}", fw.len());
    }

    #[test]
    fn forward_block() {
        let f = fetched(ORIG);
        let b = with_forward("FYI", &f);
        assert_eq!(
            b,
            "FYI\n\n---------- Forwarded message ---------\nFrom: Jane Doe <jane@example.org>\n\
Date: Tue, 14 Nov 2023 22:13:20 +0000\nSubject: Angebot Bcc: x@evil.org\nTo: info@example.org\nCc: c@example.org\n\n\
Hallo,\n\nwie besprochen.\n> alt\n"
        );
    }
}
