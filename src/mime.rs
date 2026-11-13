//! MIME parsing for reads and RFC 5322 construction for drafts (spec 5.3, 6.2, 7.6).
//!
//! Parsing is bounded by [`Limits`]. Building never emits headers beyond the fixed allowlist and validates every
//! header-bound string against CR/LF/NUL injection. HTML-to-text conversion is not done here: raw HTML is returned.

use std::str::FromStr;

use email_address::EmailAddress;
use mail_builder::MessageBuilder;
use mail_builder::headers::address::Address as BAddress;
use mail_builder::headers::content_type::ContentType as BContentType;
use mail_builder::headers::message_id::MessageId as BMessageId;
use mail_builder::mime::{BodyPart, MimePart};
use mail_parser::{HeaderForm, MessageParser, MessagePart, PartFlags, PartKind};

const MAX_RECIPIENTS: usize = 50;
const MAX_SUBJECT_ENCODED: usize = 998;
/// Largest draft body text (spec 7.6).
pub const MAX_BODY_BYTES: usize = 500 * 1024;
/// Most attachments in one draft (spec 7.6).
pub const MAX_DRAFT_ATTACHMENTS: usize = 10;
/// Longest attachment filename Dove writes, in characters.
const MAX_FILENAME_CHARS: usize = 200;

/// What kind of mail a message is, derived from its headers and parts at ingest (v0.2 design section 4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Everything that is none of the others: mail written by a person.
    #[default]
    Personal,
    /// `List-Unsubscribe` or `List-Id` present.
    Newsletter,
    /// `Auto-Submitted` other than `no`, `Precedence: bulk|list|junk`, or a no-reply style sender.
    Notification,
    /// Has a `text/calendar` part.
    Calendar,
}

impl Category {
    pub const ALL: [Category; 4] =
        [Category::Personal, Category::Newsletter, Category::Notification, Category::Calendar];

    pub fn as_str(self) -> &'static str {
        match self {
            Category::Personal => "personal",
            Category::Newsletter => "newsletter",
            Category::Notification => "notification",
            Category::Calendar => "calendar",
        }
    }

    pub fn parse(s: &str) -> Option<Category> {
        Category::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

/// Local-part fragments that mark an address as automated. Compared on the lower-cased local part with `-`, `_` and
/// `.` removed, so `no-reply`, `No_Reply` and `do.not.reply` all match. Shared by the category rule and by
/// `search_contacts` (which leaves such addresses out unless asked).
pub const NOREPLY_MARKERS: [&str; 4] = ["noreply", "donotreply", "mailerdaemon", "postmaster"];

/// Normalized local part (see [`NOREPLY_MARKERS`]).
fn local_key(email: &str) -> String {
    email
        .rsplit_once('@')
        .map_or(email, |(l, _)| l)
        .chars()
        .filter(|c| !matches!(c, '-' | '_' | '.'))
        .flat_map(char::to_lowercase)
        .collect()
}

/// True for no-reply style senders (`noreply@`, `no-reply@`, `do-not-reply@`, `mailer-daemon@`, `postmaster@`,
/// `bounce...@`).
pub fn is_noreply(email: &str) -> bool {
    let k = local_key(email);
    NOREPLY_MARKERS.iter().any(|m| k.contains(m)) || k.starts_with("bounce")
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Addr {
    pub name: Option<String>,
    /// Local part as written, domain lowercased.
    pub email: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AttachmentMeta {
    /// Stable per message: `part-<document order index>`.
    pub attachment_id: String,
    pub filename: Option<String>,
    pub mime_type: String,
    /// Decoded size.
    pub size_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_raw_bytes: usize,
    pub max_parts: usize,
    pub max_depth: usize,
    pub max_text_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_raw_bytes: 25 * 1024 * 1024, max_parts: 500, max_depth: 20, max_text_bytes: 2 * 1024 * 1024 }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ParsedMessage {
    pub from: Vec<Addr>,
    pub to: Vec<Addr>,
    pub cc: Vec<Addr>,
    pub bcc: Vec<Addr>,
    pub reply_to: Vec<Addr>,
    pub subject: Option<String>,
    /// Date header as unix seconds.
    pub date: Option<i64>,
    /// With angle brackets.
    pub message_id_header: Option<String>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    /// First text/plain body part, decoded to UTF-8.
    pub text_plain: Option<String>,
    /// First text/html body part, decoded (raw HTML).
    pub text_html: Option<String>,
    /// False if a limit was hit, text was truncated or decoding had problems.
    pub body_complete: bool,
    pub attachments: Vec<AttachmentMeta>,
    pub has_attachment: bool,
    pub part_count: usize,
    /// Exactly one leaf part, text/plain, no attachments.
    pub is_simple_text: bool,
    /// What Dove builds and can rebuild without loss: a simple text/plain message, or `multipart/mixed` whose first
    /// part is the text/plain body and every other part is a leaf with `Content-Disposition: attachment` (no nested
    /// multiparts, no HTML, no inline parts).
    pub is_draft_shape: bool,
    /// Derived from headers and parts, see [`Category`].
    pub category: Category,
    /// First `VEVENT` of a `text/calendar` part, if it parsed.
    pub calendar: Option<crate::calendar::CalendarEvent>,
}

#[derive(Debug, thiserror::Error)]
pub enum MimeError {
    #[error("message too large")]
    TooLarge,
    #[error("unparseable message")]
    Unparseable,
    #[error("{0}")]
    Invalid(String),
}

fn bracket(id: &str) -> Option<String> {
    let t = id.trim().trim_start_matches('<').trim_end_matches('>').trim();
    if t.is_empty() { None } else { Some(format!("<{t}>")) }
}

fn normalize_addr(email: &str) -> String {
    match email.rsplit_once('@') {
        Some((local, domain)) => format!("{local}@{}", domain.to_ascii_lowercase()),
        None => email.to_string(),
    }
}

fn addr_list(list: Option<mail_parser::AddressList<'_>>) -> Vec<Addr> {
    let Some(list) = list else { return Vec::new() };
    list.mailboxes()
        .filter_map(|m| {
            let email = m.address()?.trim();
            if email.is_empty() {
                return None;
            }
            let name = m.name().map(str::trim).filter(|n| !n.is_empty()).map(str::to_string);
            Some(Addr { name, email: normalize_addr(email) })
        })
        .collect()
}

fn id_list(list: Option<mail_parser::TextList<'_>>) -> Vec<String> {
    list.map(|l| l.iter().filter_map(bracket).collect()).unwrap_or_default()
}

fn mime_type_of(part: &MessagePart<'_>) -> String {
    match part.content_type() {
        Some(ct) => {
            let sub = ct.subtype().unwrap_or("plain");
            format!("{}/{}", ct.ctype(), sub).to_ascii_lowercase()
        }
        None => "text/plain".to_string(),
    }
}

fn is_attachment_part(part: &MessagePart<'_>, filename: &Option<String>) -> bool {
    let explicit = part.content_disposition().is_some_and(|d| d.is_attachment());
    if explicit {
        return true;
    }
    if filename.is_none() {
        return false;
    }
    // Inline resources referenced by Content-ID are not attachments unless explicitly marked.
    part.content_id().map(|c| c.trim().is_empty()).unwrap_or(true)
}

fn floor_boundary(s: &str, max: usize) -> usize {
    let mut end = max.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// Decoded text of a body part, cut at `max` bytes. Returns (text, complete).
fn body_text(part: &MessagePart<'_>, max: usize) -> (String, bool) {
    if part.decoded_len() > max {
        let prefix = part.text_prefix_bytes(max.saturating_add(1)).map(|c| c.into_owned()).unwrap_or_default();
        let end = floor_boundary(&prefix, max);
        return (prefix[..end].to_string(), false);
    }
    match part.text_checked() {
        Some((text, problems)) => {
            let mut complete = problems.is_empty();
            let mut s = text.into_owned();
            if s.len() > max {
                let end = floor_boundary(&s, max);
                s.truncate(end);
                complete = false;
            }
            (s, complete)
        }
        None => (String::new(), false),
    }
}

/// Header value as trimmed, lower-cased text (folding whitespace collapsed); `None` when the header is absent.
fn header_lc(hdr: &mail_parser::Headers<'_>, name: &str) -> Option<String> {
    hdr.iter()
        .find(|h| h.raw_name().trim().eq_ignore_ascii_case(name))
        .map(|h| String::from_utf8_lossy(h.raw_value()).split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase())
}

/// Category of a message (first match wins): calendar part, then newsletter, notification, personal.
fn classify(hdr: &mail_parser::Headers<'_>, from: &[Addr], has_calendar_part: bool) -> Category {
    if has_calendar_part {
        return Category::Calendar;
    }
    if ["list-unsubscribe", "list-id"].iter().any(|n| header_lc(hdr, n).is_some_and(|v| !v.is_empty())) {
        return Category::Newsletter;
    }
    let auto = header_lc(hdr, "auto-submitted").is_some_and(|v| !v.is_empty() && v != "no" && !v.starts_with("no;"));
    let bulk = header_lc(hdr, "precedence").is_some_and(|v| matches!(v.as_str(), "bulk" | "list" | "junk"));
    if auto || bulk || from.first().is_some_and(|a| is_noreply(&a.email)) {
        return Category::Notification;
    }
    Category::Personal
}

pub fn parse(raw: &[u8], limits: &Limits) -> Result<ParsedMessage, MimeError> {
    if raw.len() > limits.max_raw_bytes {
        return Err(MimeError::TooLarge);
    }
    let parser = MessageParser::new().max_parts(limits.max_parts).max_depth(limits.max_depth);
    let msg = parser.parse(raw).ok_or(MimeError::Unparseable)?;
    let root = msg.root();
    let hdr = root.headers();

    let mut out = ParsedMessage {
        from: addr_list(hdr.from()),
        to: Vec::new(),
        cc: addr_list(hdr.cc()),
        bcc: addr_list(hdr.bcc()),
        reply_to: addr_list(hdr.reply_to()),
        subject: hdr.subject().map(str::to_string),
        date: hdr.date().filter(|d| d.is_valid()).map(|d| d.to_timestamp()),
        message_id_header: hdr.message_id().and_then(bracket),
        in_reply_to: id_list(hdr.in_reply_to()),
        references: id_list(hdr.references()),
        body_complete: true,
        ..Default::default()
    };
    // Several To headers are unusual; merge them all rather than keeping only the last.
    out.to = hdr.all_to().flat_map(|l| addr_list(Some(l))).collect();

    let mut leaves = 0usize;
    let mut simple_leaf_is_plain = false;
    let mut part_count = 0usize;
    let mut multiparts = 0usize;
    // Every leaf after the first is an explicit attachment (draft shape).
    let mut rest_are_attachments = true;
    let mut has_calendar_part = false;
    for part in root.parts() {
        part_count += 1;
        if part.flags().contains(PartFlags::LIMIT_REACHED) {
            out.body_complete = false;
        }
        if part.is_multipart() {
            multiparts += 1;
            continue;
        }
        leaves += 1;
        let mime = mime_type_of(&part);
        if matches!(mime.as_str(), "text/calendar" | "application/ics") {
            has_calendar_part = true;
            if out.calendar.is_none() && part.decoded_len() <= crate::calendar::MAX_BYTES * 4 {
                let bytes = part.decoded();
                let text = String::from_utf8_lossy(&bytes);
                let method = part.content_type().and_then(|ct| ct.attribute("method"));
                out.calendar = crate::calendar::parse(&text, method);
            }
        }
        let filename = part.attachment_name().map(str::trim).filter(|n| !n.is_empty()).map(str::to_string);
        if leaves == 1 {
            simple_leaf_is_plain = mime == "text/plain"
                && matches!(part.kind(), PartKind::Text)
                && !part.content_disposition().is_some_and(|d| d.is_attachment());
        } else if !(part.content_disposition().is_some_and(|d| d.is_attachment())
            && matches!(part.kind(), PartKind::Binary | PartKind::InlineBinary | PartKind::Text))
        {
            rest_are_attachments = false;
        }
        if is_attachment_part(&part, &filename) {
            out.attachments.push(AttachmentMeta {
                attachment_id: format!("part-{}", part.id()),
                filename,
                mime_type: mime,
                size_bytes: part.decoded_len() as u64,
            });
        }
    }
    out.part_count = part_count;
    out.category = classify(&hdr, &out.from, has_calendar_part);
    out.has_attachment = !out.attachments.is_empty();
    out.is_simple_text = leaves == 1 && simple_leaf_is_plain && out.attachments.is_empty();
    let root_part = root.root_part();
    let mixed_root = root_part.is_multipart() && mime_type_of(&root_part) == "multipart/mixed";
    out.is_draft_shape = out.is_simple_text
        || (mixed_root
            && multiparts == 1
            && simple_leaf_is_plain
            && rest_are_attachments
            && leaves >= 2
            && out.body_complete
            && out.attachments.len() == leaves - 1);

    let is_att = |p: &MessagePart<'_>| {
        let f = p.attachment_name().map(str::trim).filter(|n| !n.is_empty()).map(str::to_string);
        is_attachment_part(p, &f)
    };
    let plain =
        root.text_body().find(|p| matches!(p.kind(), PartKind::Text) && mime_type_of(p) == "text/plain" && !is_att(p));
    let html = root.html_body().find(|p| matches!(p.kind(), PartKind::Html) && !is_att(p));
    if let Some(p) = plain {
        let (t, ok) = body_text(&p, limits.max_text_bytes);
        out.text_plain = Some(t);
        out.body_complete &= ok;
    }
    if let Some(p) = html {
        let (t, ok) = body_text(&p, limits.max_text_bytes);
        out.text_html = Some(t);
        out.body_complete &= ok;
    }
    Ok(out)
}

/// Decoded bytes of one attachment (`part-<n>` as listed by [`parse`]). `Ok(None)` when the message has no such
/// attachment; [`MimeError::TooLarge`] when its decoded size exceeds `max_bytes` (checked before copying).
pub fn attachment_bytes(
    raw: &[u8],
    part_id: &str,
    max_bytes: usize,
) -> Result<Option<(AttachmentMeta, Vec<u8>)>, MimeError> {
    let limits = Limits::default();
    if raw.len() > limits.max_raw_bytes {
        return Err(MimeError::TooLarge);
    }
    let Some(n) = part_id.strip_prefix("part-").filter(|n| !n.starts_with('0') || *n == "0") else {
        return Ok(None);
    };
    let Ok(n) = n.parse::<u32>() else { return Ok(None) };
    let parser = MessageParser::new().max_parts(limits.max_parts).max_depth(limits.max_depth);
    let msg = parser.parse(raw).ok_or(MimeError::Unparseable)?;
    let Some(part) = msg.root().parts().find(|p| p.id() == n && !p.is_multipart()) else { return Ok(None) };
    let filename = part.attachment_name().map(str::trim).filter(|n| !n.is_empty()).map(str::to_string);
    if !is_attachment_part(&part, &filename) {
        return Ok(None);
    }
    if part.decoded_len() > max_bytes {
        return Err(MimeError::TooLarge);
    }
    let bytes = part.decoded().into_owned();
    let meta = AttachmentMeta {
        attachment_id: part_id.to_string(),
        filename,
        mime_type: mime_type_of(&part),
        size_bytes: bytes.len() as u64,
    };
    Ok(Some((meta, bytes)))
}

/// Callback of [`visit_attachments`]: attachment metadata and a lazy decoder of its bytes.
pub type AttachmentVisitor<'a> = dyn FnMut(&AttachmentMeta, &dyn Fn() -> Vec<u8>) -> std::ops::ControlFlow<()> + 'a;

/// Calls `f` for every attachment of `raw` (same part numbering and attachment rule as [`parse`]) with its metadata
/// and a function that decodes its bytes on demand, so attachments the caller does not want are never copied.
/// `f` returns `Break` to stop. Used by ingest-time attachment text extraction.
pub fn visit_attachments(raw: &[u8], f: &mut AttachmentVisitor<'_>) -> Result<(), MimeError> {
    let limits = Limits::default();
    if raw.len() > limits.max_raw_bytes {
        return Err(MimeError::TooLarge);
    }
    let parser = MessageParser::new().max_parts(limits.max_parts).max_depth(limits.max_depth);
    let msg = parser.parse(raw).ok_or(MimeError::Unparseable)?;
    for part in msg.root().parts() {
        if part.is_multipart() {
            continue;
        }
        let filename = part.attachment_name().map(str::trim).filter(|n| !n.is_empty()).map(str::to_string);
        if !is_attachment_part(&part, &filename) {
            continue;
        }
        let meta = AttachmentMeta {
            attachment_id: format!("part-{}", part.id()),
            filename,
            mime_type: mime_type_of(&part),
            size_bytes: part.decoded_len() as u64,
        };
        if f(&meta, &|| part.decoded().into_owned()).is_break() {
            break;
        }
    }
    Ok(())
}

/// Decoded values of one header (case-insensitive name), unfolded, RFC 2047 decoded.
pub fn header_values(raw: &[u8], name: &str) -> Vec<String> {
    let Some(msg) = MessageParser::new().parse_headers(raw) else { return Vec::new() };
    msg.headers()
        .iter()
        .filter(|h| h.raw_name().trim().eq_ignore_ascii_case(name))
        .filter_map(|h| h.parse_as(HeaderForm::Text).value().as_text().map(str::to_string))
        .collect()
}

/// `raw` without every field named `name` (case-insensitive, folded continuation lines included) in the header
/// section. The body is copied unchanged, so a `Bcc:` line in the body stays.
pub fn without_header(raw: &[u8], name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut skipping = false;
    let mut i = 0;
    while i < raw.len() {
        let end = raw[i..].iter().position(|b| *b == b'\n').map_or(raw.len(), |p| i + p + 1);
        let line = &raw[i..end];
        if matches!(line, b"\r\n" | b"\n") {
            out.extend_from_slice(&raw[i..]);
            return out;
        }
        if !matches!(line[0], b' ' | b'\t') {
            skipping = line
                .iter()
                .position(|b| *b == b':')
                .is_some_and(|c| line[..c].trim_ascii_end().eq_ignore_ascii_case(name.as_bytes()));
        }
        if !skipping {
            out.extend_from_slice(line);
        }
        i = end;
    }
    out
}

/// Rejects CR, LF and NUL in any header-bound text.
pub fn validate_header_text(s: &str) -> Result<(), MimeError> {
    if s.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
        return Err(MimeError::Invalid("header text contains a forbidden control character".into()));
    }
    Ok(())
}

fn invalid(msg: &str) -> MimeError {
    MimeError::Invalid(msg.to_string())
}

fn unquote_name(raw: &str) -> Result<String, MimeError> {
    let name = raw.trim();
    if let Some(inner) = name.strip_prefix('"') {
        let inner = inner.strip_suffix('"').ok_or_else(|| invalid("invalid display name"))?;
        let mut out = String::new();
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => out.push(chars.next().ok_or_else(|| invalid("invalid display name"))?),
                '"' => return Err(invalid("invalid display name")),
                c => out.push(c),
            }
        }
        Ok(out)
    } else {
        if name.chars().any(|c| matches!(c, '"' | '<' | '>' | ',' | ';' | ':' | '@' | '\\' | '(' | ')' | '[' | ']')) {
            return Err(invalid("invalid display name"));
        }
        Ok(name.to_string())
    }
}

/// Strict address parsing: `a@b.example` or `Display Name <a@b.example>` (quoted names allowed).
pub fn parse_address(s: &str) -> Result<Addr, MimeError> {
    validate_header_text(s)?;
    let s = s.trim();
    if s.is_empty() {
        return Err(invalid("empty address"));
    }
    let (name, spec) = if let Some(lt) = s.find('<') {
        // The angle-addr must be last: `name <spec>`; a '<' inside a quoted name is handled by locating the final one.
        let lt =
            if s.trim_start().starts_with('"') { s.rfind('<').ok_or_else(|| invalid("invalid address"))? } else { lt };
        let inner = s[lt + 1..].strip_suffix('>').ok_or_else(|| invalid("invalid address"))?;
        if inner.contains(['<', '>']) {
            return Err(invalid("invalid address"));
        }
        let name = unquote_name(&s[..lt])?;
        (Some(name).filter(|n| !n.is_empty()), inner.trim())
    } else {
        (None, s)
    };
    if spec.contains(char::is_whitespace) || spec.contains(['<', '>', ',', ';']) {
        return Err(invalid("invalid address"));
    }
    EmailAddress::from_str(spec).map_err(|_| invalid("invalid address"))?;
    Ok(Addr { name, email: normalize_addr(spec) })
}

#[derive(Debug, Clone)]
pub struct DraftFields {
    pub from: Addr,
    pub to: Vec<Addr>,
    pub cc: Vec<Addr>,
    pub bcc: Vec<Addr>,
    pub subject: String,
    pub body_text: String,
    /// With angle brackets.
    pub message_id: String,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    /// Unix seconds.
    pub date: i64,
    /// Files attached after the text body (at most [`MAX_DRAFT_ATTACHMENTS`]). Empty: a plain text/plain message.
    pub attachments: Vec<DraftAttachment>,
}

/// One attachment of a Dove-built draft: decoded bytes plus the filename and MIME type Dove writes for it.
#[derive(Clone, PartialEq, Eq)]
pub struct DraftAttachment {
    pub filename: String,
    pub mime_type: String,
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for DraftAttachment {
    // Never print a filename or content (logs, panics).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DraftAttachment").field("mime_type", &self.mime_type).field("len", &self.bytes.len()).finish()
    }
}

/// A MIME type Dove writes into a header: `type/subtype`, lowercase, RFC 6838 restricted-name characters only, no
/// parameters. `multipart/*` and `message/*` are refused: as attachments they would change the message structure.
pub fn normalize_mime_type(s: &str) -> Option<String> {
    if s.chars().any(char::is_control) {
        return None;
    }
    let s = s.trim().to_ascii_lowercase();
    let (t, sub) = s.split_once('/')?;
    let name_ok = |n: &str| {
        (1..=127).contains(&n.len())
            && n.as_bytes()[0].is_ascii_alphanumeric()
            && n.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&b))
    };
    if !name_ok(t) || !name_ok(sub) || matches!(t, "multipart" | "message") {
        return None;
    }
    Some(s)
}

/// An attachment filename Dove may write: non-empty, at most 200 characters, no control characters or path
/// separators. Header encoding (RFC 2231) is the builder's job; this only keeps the name meaningful and safe.
fn check_filename(name: &str) -> Result<(), MimeError> {
    let n = name.chars().count();
    if n == 0
        || n > MAX_FILENAME_CHARS
        || name.trim() != name
        || name.starts_with('.')
        || name.chars().any(|c| c.is_control() || matches!(c, '/' | '\\'))
    {
        return Err(invalid("invalid attachment filename"));
    }
    Ok(())
}

/// Standard base64 in 76-character lines (RFC 2045), CRLF separated.
fn base64_lines(bytes: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let enc = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut out = Vec::with_capacity(enc.len() + enc.len() / 76 * 2 + 2);
    for (i, chunk) in enc.as_bytes().chunks(76).enumerate() {
        if i > 0 {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(chunk);
    }
    out
}

fn check_addr(a: &Addr) -> Result<(), MimeError> {
    if let Some(n) = &a.name {
        validate_header_text(n)?;
    }
    validate_header_text(&a.email)?;
    let re = parse_address(&a.email)?;
    if re.name.is_some() || re.email != a.email {
        return Err(invalid("invalid address"));
    }
    Ok(())
}

/// Validates `<local@domain>` style ids and returns the inner id.
fn check_msg_id(id: &str) -> Result<&str, MimeError> {
    validate_header_text(id)?;
    let inner = id
        .strip_prefix('<')
        .and_then(|i| i.strip_suffix('>'))
        .ok_or_else(|| invalid("message id must be in angle brackets"))?;
    if inner.is_empty() || inner.contains(['<', '>']) || inner.contains(char::is_whitespace) || !inner.is_ascii() {
        return Err(invalid("invalid message id"));
    }
    Ok(inner)
}

fn baddr(list: &[Addr]) -> BAddress<'static> {
    BAddress::new_list(list.iter().map(|a| BAddress::new_address(a.name.clone(), a.email.clone())).collect::<Vec<_>>())
}

/// RFC 5322 `text/plain; charset=utf-8` draft. Only the allowlisted headers are written (plus the two MIME body
/// headers required to describe the body).
pub fn build_draft(f: &DraftFields) -> Result<Vec<u8>, MimeError> {
    check_addr(&f.from)?;
    for a in f.to.iter().chain(&f.cc).chain(&f.bcc) {
        check_addr(a)?;
    }
    if f.to.len() + f.cc.len() + f.bcc.len() > MAX_RECIPIENTS {
        return Err(invalid("too many recipients"));
    }
    validate_header_text(&f.subject)?;
    if f.body_text.len() > MAX_BODY_BYTES {
        return Err(invalid("body too large"));
    }
    let message_id = check_msg_id(&f.message_id)?;
    let in_reply_to = f.in_reply_to.as_deref().map(check_msg_id).transpose()?;
    let refs = f.references.iter().map(|r| check_msg_id(r)).collect::<Result<Vec<_>, _>>()?;
    if f.attachments.len() > MAX_DRAFT_ATTACHMENTS {
        return Err(invalid("too many attachments"));
    }
    for a in &f.attachments {
        check_filename(&a.filename)?;
        // The type is written verbatim into Content-Type: only the normalized form passes.
        if normalize_mime_type(&a.mime_type).as_deref() != Some(a.mime_type.as_str()) {
            return Err(invalid("invalid attachment MIME type"));
        }
    }

    let mut b = MessageBuilder::new()
        .from(BAddress::new_address(f.from.name.clone(), f.from.email.clone()))
        .message_id(BMessageId::new(message_id.to_string()))
        .date(f.date)
        .subject(f.subject.clone());
    if !f.to.is_empty() {
        b = b.to(baddr(&f.to));
    }
    if !f.cc.is_empty() {
        b = b.cc(baddr(&f.cc));
    }
    if !f.bcc.is_empty() {
        b = b.bcc(baddr(&f.bcc));
    }
    if let Some(i) = in_reply_to {
        b = b.in_reply_to(BMessageId::new(i.to_string()));
    }
    if !refs.is_empty() {
        b = b.references(BMessageId::new_list(refs.into_iter().map(str::to_string)));
    }
    // Normalize to LF first so the builder's CRLF conversion cannot produce CR CR LF.
    let body = f.body_text.replace("\r\n", "\n").replace('\r', "\n");
    if f.attachments.is_empty() {
        b = b.text_body(body);
    } else {
        // multipart/mixed: the text body, then each attachment base64 encoded (also text/*, so the decoded bytes are
        // exactly the input: no line-ending or charset conversion).
        let mut parts = vec![MimePart::new("text/plain", BodyPart::Text(body.into()))];
        for a in &f.attachments {
            parts.push(
                MimePart::new(BContentType::new(a.mime_type.clone()), BodyPart::Binary(base64_lines(&a.bytes).into()))
                    .attachment(a.filename.clone())
                    .transfer_encoding("base64"),
            );
        }
        b = b.body(MimePart::new("multipart/mixed", parts));
    }
    let out = b.write_to_vec().map_err(|_| invalid("failed to build message"))?;
    if out.len() > Limits::default().max_raw_bytes {
        return Err(MimeError::TooLarge);
    }

    // Subject length after encoding (unfolded).
    if let Some(msg) = MessageParser::new().parse_headers(&out)
        && let Some(h) = msg.headers().iter().find(|h| h.raw_name().eq_ignore_ascii_case("subject"))
    {
        let unfolded = h.raw_value().iter().filter(|c| !matches!(**c, b'\r' | b'\n')).count();
        if unfolded > MAX_SUBJECT_ENCODED {
            return Err(invalid("subject too long"));
        }
    }
    Ok(out)
}

/// Reads back the fields of a Dove-built draft (text/plain, optionally with attachments: see
/// [`ParsedMessage::is_draft_shape`]). Body line endings are normalized to LF. Attachment filenames and types are
/// returned as found; callers sanitize them before rebuilding.
pub fn read_draft_fields(raw: &[u8]) -> Result<DraftFields, MimeError> {
    let p = parse(raw, &Limits::default())?;
    if !p.is_draft_shape {
        return Err(invalid("unsupported structure"));
    }
    let mut attachments = Vec::new();
    if !p.is_simple_text {
        let limits = Limits::default();
        let msg = MessageParser::new()
            .max_parts(limits.max_parts)
            .max_depth(limits.max_depth)
            .parse(raw)
            .ok_or(MimeError::Unparseable)?;
        for part in msg.root().parts().filter(|p| !p.is_multipart()).skip(1) {
            attachments.push(DraftAttachment {
                filename: part.attachment_name().map(str::to_string).unwrap_or_default(),
                mime_type: mime_type_of(&part),
                bytes: part.decoded().into_owned(),
            });
        }
    }
    Ok(DraftFields {
        from: p.from.into_iter().next().ok_or_else(|| invalid("draft has no From"))?,
        to: p.to,
        cc: p.cc,
        bcc: p.bcc,
        subject: p.subject.unwrap_or_default(),
        body_text: p.text_plain.unwrap_or_default().replace("\r\n", "\n"),
        message_id: p.message_id_header.ok_or_else(|| invalid("draft has no Message-ID"))?,
        in_reply_to: p.in_reply_to.into_iter().next(),
        references: p.references,
        date: p.date.ok_or_else(|| invalid("draft has no Date"))?,
        attachments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(name: Option<&str>, email: &str) -> Addr {
        Addr { name: name.map(str::to_string), email: email.to_string() }
    }

    fn fields() -> DraftFields {
        DraftFields {
            from: a(Some("Me"), "me@example.com"),
            to: vec![a(Some("Zoë Müller"), "zoe@example.org")],
            cc: vec![a(None, "cc@example.org")],
            bcc: vec![a(None, "bcc@example.org")],
            subject: "Grüße – Überblick".into(),
            body_text: "Hallo Zoë,\n\nschöne Grüße\n".into(),
            message_id: "<new123@example.com>".into(),
            in_reply_to: Some("<orig@example.org>".into()),
            references: vec!["<root@example.org>".into(), "<orig@example.org>".into()],
            date: 1_700_000_000,
            attachments: vec![],
        }
    }

    #[test]
    fn without_header_strips_folded_fields_only_in_the_header() {
        let raw = b"From: a@x.org\r\nBcc: one@x.org,\r\n two@x.org\r\nTo: b@x.org\r\nBCC : three@x.org\r\n\
Subject: Bcc: kept\r\n\r\nBcc: body line stays\r\n";
        let out = without_header(raw, "Bcc");
        assert_eq!(out, b"From: a@x.org\r\nTo: b@x.org\r\nSubject: Bcc: kept\r\n\r\nBcc: body line stays\r\n".to_vec());
        assert_eq!(without_header(b"Bcc: x\nTo: y\n\nbody", "bcc"), b"To: y\n\nbody".to_vec());
        // A Dove-built draft loses its Bcc and keeps everything else.
        let built = build_draft(&fields()).unwrap();
        let p = parse(&without_header(&built, "Bcc"), &Limits::default()).unwrap();
        assert!(p.bcc.is_empty());
        assert_eq!(p.to.len() + p.cc.len(), 2);
        assert_eq!(p.message_id_header.as_deref(), Some("<new123@example.com>"));
    }

    #[test]
    fn multipart_alternative() {
        let raw = b"From: A <a@x.org>\r\nTo: b@x.org\r\nSubject: Hi\r\nContent-Type: multipart/alternative; boundary=BB\r\n\r\n--BB\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nplain body\r\n--BB\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>html body</p>\r\n--BB--\r\n";
        let p = parse(raw, &Limits::default()).unwrap();
        assert_eq!(p.text_plain.as_deref().map(str::trim), Some("plain body"));
        assert_eq!(p.text_html.as_deref().map(str::trim), Some("<p>html body</p>"));
        assert!(p.body_complete);
        assert!(!p.is_simple_text);
        assert!(!p.has_attachment);
    }

    #[test]
    fn html_only() {
        let raw = b"From: a@x.org\r\nContent-Type: text/html\r\n\r\n<b>x</b>\r\n";
        let p = parse(raw, &Limits::default()).unwrap();
        assert!(p.text_plain.is_none());
        assert_eq!(p.text_html.as_deref().map(str::trim), Some("<b>x</b>"));
        assert!(!p.is_simple_text);
    }

    #[test]
    fn attachments_and_inline() {
        let raw = b"From: a@x.org\r\nContent-Type: multipart/mixed; boundary=M\r\n\r\n\
--M\r\nContent-Type: text/plain\r\n\r\nhello\r\n\
--M\r\nContent-Type: image/png\r\nContent-Disposition: inline; filename=\"logo.png\"\r\nContent-ID: <logo@x>\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n\
--M\r\nContent-Type: image/png\r\nContent-Disposition: attachment; filename=\"pic.png\"\r\nContent-ID: <pic@x>\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8gd29ybGQ=\r\n\
--M\r\nContent-Type: application/pdf; name=\"doc.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\naGk=\r\n\
--M--\r\n";
        let p = parse(raw, &Limits::default()).unwrap();
        let names: Vec<_> = p.attachments.iter().map(|x| x.filename.clone().unwrap()).collect();
        assert_eq!(names, ["pic.png", "doc.pdf"]);
        assert_eq!(p.attachments[0].size_bytes, 11);
        assert_eq!(p.attachments[0].mime_type, "image/png");
        assert_eq!(p.attachments[1].size_bytes, 2);
        assert_ne!(p.attachments[0].attachment_id, p.attachments[1].attachment_id);
        assert!(p.has_attachment);
        assert!(!p.is_simple_text);
        assert_eq!(p.text_plain.as_deref().map(str::trim), Some("hello"));
    }

    #[test]
    fn rfc2047_roundtrip_through_build() {
        let f = fields();
        let raw = build_draft(&f).unwrap();
        let p = parse(&raw, &Limits::default()).unwrap();
        assert_eq!(p.subject.as_deref(), Some("Grüße – Überblick"));
        assert_eq!(p.to[0].name.as_deref(), Some("Zoë Müller"));
        assert_eq!(p.to[0].email, "zoe@example.org");
        assert!(p.is_simple_text);
        assert_eq!(header_values(&raw, "subject"), vec!["Grüße – Überblick".to_string()]);
        assert_eq!(header_values(&raw, "SUBJECT").len(), 1);
    }

    #[test]
    fn header_injection_rejected() {
        let mut f = fields();
        f.subject = "hi\r\nBcc: evil@x.org".into();
        assert!(build_draft(&f).is_err());
        let mut f = fields();
        f.subject = "hi\nX: y".into();
        assert!(build_draft(&f).is_err());
        let mut f = fields();
        f.to[0].name = Some("Bob\r\nBcc: evil@x.org".into());
        assert!(build_draft(&f).is_err());
        let mut f = fields();
        f.to[0].email = "a@b.example\r\nBcc: evil@x.org".into();
        assert!(build_draft(&f).is_err());
        let mut f = fields();
        f.message_id = "<a@b>\r\nX: y".into();
        assert!(build_draft(&f).is_err());
        assert!(parse_address("Bob\r\nBcc: x@y.org <a@b.example>").is_err());
        assert!(parse_address("a@b.example\r\n").is_err());
        assert!(parse_address("a@b.example\0").is_err());
        assert!(validate_header_text("x\0y").is_err());
        assert!(validate_header_text("fine").is_ok());
    }

    #[test]
    fn parse_address_strict() {
        let x = parse_address("Jane Doe <Jane@Example.ORG>").unwrap();
        assert_eq!(x, a(Some("Jane Doe"), "Jane@example.org"));
        let x = parse_address("\"Doe, Jane\" <j@example.org>").unwrap();
        assert_eq!(x.name.as_deref(), Some("Doe, Jane"));
        assert_eq!(parse_address("j@example.org").unwrap().name, None);
        assert!(parse_address("a@b.example, c@d.example").is_err());
        assert!(parse_address("Team: a@b.example, c@d.example;").is_err());
        assert!(parse_address("not an address").is_err());
        assert!(parse_address("Bob <a@b.example> trailing").is_err());
        assert!(parse_address("").is_err());
    }

    #[test]
    fn too_many_recipients() {
        let mut f = fields();
        f.to = (0..51).map(|i| a(None, &format!("u{i}@example.org"))).collect();
        f.cc.clear();
        f.bcc.clear();
        assert!(build_draft(&f).is_err());
        f.to.truncate(50);
        assert!(build_draft(&f).is_ok());
    }

    #[test]
    fn size_limits() {
        let mut f = fields();
        f.body_text = "x".repeat(500 * 1024 + 1);
        assert!(build_draft(&f).is_err());
        let mut f = fields();
        f.subject = "s".repeat(1000);
        assert!(build_draft(&f).is_err());
        let l = Limits { max_raw_bytes: 10, ..Limits::default() };
        assert!(matches!(parse(b"Subject: way too long for limit\r\n\r\nx", &l), Err(MimeError::TooLarge)));
    }

    #[test]
    fn draft_fields_roundtrip() {
        let f = fields();
        let raw = build_draft(&f).unwrap();
        let g = read_draft_fields(&raw).unwrap();
        assert_eq!(g.from, f.from);
        assert_eq!(g.to, f.to);
        assert_eq!(g.cc, f.cc);
        assert_eq!(g.bcc, f.bcc);
        assert_eq!(g.subject, f.subject);
        assert_eq!(g.body_text, f.body_text);
        assert_eq!(g.message_id, f.message_id);
        assert_eq!(g.in_reply_to, f.in_reply_to);
        assert_eq!(g.references, f.references);
        assert_eq!(g.date, f.date);
        // Rebuild is stable.
        assert_eq!(build_draft(&g).unwrap(), raw);
    }

    #[test]
    fn read_draft_rejects_multipart_html() {
        let raw = b"From: a@x.org\r\nMessage-ID: <m@x>\r\nDate: Tue, 14 Nov 2023 22:13:20 +0000\r\nContent-Type: multipart/alternative; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\np\r\n--B\r\nContent-Type: text/html\r\n\r\n<p>h</p>\r\n--B--\r\n";
        match read_draft_fields(raw) {
            Err(MimeError::Invalid(m)) => assert_eq!(m, "unsupported structure"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn reply_headers_multiple_ids() {
        let raw = b"From: a@x.org\r\nMessage-ID: <m1@x.org>\r\nIn-Reply-To: <p1@x.org> <p2@x.org>\r\nReferences: <r1@x.org>\r\n <r2@x.org> <r3@x.org>\r\nDate: Tue, 14 Nov 2023 22:13:20 +0000\r\n\r\nbody\r\n";
        let p = parse(raw, &Limits::default()).unwrap();
        assert_eq!(p.message_id_header.as_deref(), Some("<m1@x.org>"));
        assert_eq!(p.in_reply_to, ["<p1@x.org>", "<p2@x.org>"]);
        assert_eq!(p.references, ["<r1@x.org>", "<r2@x.org>", "<r3@x.org>"]);
        assert_eq!(p.date, Some(1_700_000_000));
    }

    #[test]
    fn text_truncated_sets_incomplete() {
        let raw = format!("From: a@x.org\r\n\r\n{}\r\n", "é".repeat(100));
        let l = Limits { max_text_bytes: 51, ..Limits::default() };
        let p = parse(raw.as_bytes(), &l).unwrap();
        assert!(!p.body_complete);
        let t = p.text_plain.unwrap();
        assert!(t.len() <= 51);
        assert!(t.chars().all(|c| c == 'é'));
        let p = parse(raw.as_bytes(), &Limits::default()).unwrap();
        assert!(p.body_complete);
    }

    #[test]
    fn part_limit_marks_incomplete() {
        let mut raw = String::from("From: a@x.org\r\nContent-Type: multipart/mixed; boundary=M\r\n\r\n");
        for i in 0..10 {
            raw.push_str(&format!("--M\r\nContent-Type: text/plain\r\n\r\nbody {i}\r\n"));
        }
        raw.push_str("--M--\r\n");
        let l = Limits { max_parts: 3, ..Limits::default() };
        let p = parse(raw.as_bytes(), &l).unwrap();
        assert!(!p.body_complete);
        assert!(p.part_count <= 4);
    }

    #[test]
    fn build_emits_only_allowed_headers() {
        let raw = build_draft(&fields()).unwrap();
        let text = String::from_utf8(raw).unwrap();
        assert!(text.contains("\r\n\r\n"));
        let head = text.split("\r\n\r\n").next().unwrap();
        assert!(!head.contains('\n') || head.replace("\r\n", "").find('\n').is_none(), "bare LF in headers");
        let allowed = [
            "from",
            "to",
            "cc",
            "bcc",
            "subject",
            "date",
            "message-id",
            "mime-version",
            "in-reply-to",
            "references",
            "content-type",
            "content-transfer-encoding",
        ];
        let mut seen = Vec::new();
        for line in head.split("\r\n") {
            if line.starts_with(' ') || line.starts_with('\t') {
                continue;
            }
            let name = line.split(':').next().unwrap().to_ascii_lowercase();
            assert!(allowed.contains(&name.as_str()), "unexpected header {name}");
            seen.push(name);
        }
        for need in
            ["from", "to", "cc", "bcc", "subject", "date", "message-id", "mime-version", "in-reply-to", "references"]
        {
            assert!(seen.iter().any(|s| s == need), "missing {need}");
        }
        assert!(!text.replace("\r\n", "").contains('\r'));
        assert!(text.matches('\n').count() == text.matches("\r\n").count(), "bare LF in output");
    }

    #[test]
    fn attachment_bytes_by_part_id() {
        let raw = b"From: a@example.org\r\nSubject: x\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nbody\r\n\
--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"x.bin\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\nAAECAwQFBgcICQ==\r\n--b--\r\n";
        let p = parse(raw, &Limits::default()).unwrap();
        let id = p.attachments[0].attachment_id.clone();
        let (meta, bytes) = attachment_bytes(raw, &id, 10).unwrap().unwrap();
        assert_eq!(bytes, (0u8..10).collect::<Vec<_>>());
        assert_eq!((meta.filename.as_deref(), meta.size_bytes), (Some("x.bin"), 10));
        // One byte over the limit is refused before copying; the text body and unknown parts are not attachments.
        assert!(matches!(attachment_bytes(raw, &id, 9), Err(MimeError::TooLarge)));
        assert!(attachment_bytes(raw, "part-1", 100).unwrap().is_none());
        assert!(attachment_bytes(raw, "part-9", 100).unwrap().is_none());
        assert!(attachment_bytes(raw, "part-02", 100).unwrap().is_none());
    }

    fn att(name: &str, mime: &str, bytes: &[u8]) -> DraftAttachment {
        DraftAttachment { filename: name.into(), mime_type: mime.into(), bytes: bytes.to_vec() }
    }

    #[test]
    fn draft_with_attachments_roundtrips_exact_bytes() {
        let mut f = fields();
        let binary: Vec<u8> = (0..=255u8).cycle().take(5000).collect();
        // Text attachments keep bare LF, lone CR and a trailing space: no canonicalisation of attachment bytes.
        let text = b"line1\nline2\r\nline3\rend \n".to_vec();
        f.attachments = vec![
            att("Rechnung \"März\" 2026.pdf", "application/pdf", &binary),
            att("notes.txt", "text/plain", &text),
            att("empty.bin", "application/octet-stream", b""),
            // Plain ASCII with bare LF: a text encoder would send this as 7bit and turn LF into CRLF.
            att("plain.txt", "text/plain", b"hello\nworld\n"),
        ];
        let raw = build_draft(&f).unwrap();
        let p = parse(&raw, &Limits::default()).unwrap();
        assert!(p.is_draft_shape && !p.is_simple_text, "{}", String::from_utf8_lossy(&raw));
        assert_eq!(p.text_plain.as_deref().map(|t| t.replace("\r\n", "\n")), Some(f.body_text.clone()));
        let names: Vec<_> = p.attachments.iter().map(|a| a.filename.clone().unwrap_or_default()).collect();
        assert_eq!(names, ["Rechnung \"März\" 2026.pdf", "notes.txt", "empty.bin", "plain.txt"]);
        let g = read_draft_fields(&raw).unwrap();
        assert_eq!(g.attachments, f.attachments);
        assert_eq!((g.subject.as_str(), g.body_text.as_str()), (f.subject.as_str(), f.body_text.as_str()));
        assert_eq!((g.to, g.bcc, g.in_reply_to), (f.to.clone(), f.bcc.clone(), f.in_reply_to.clone()));
        // get_attachment's extractor sees the same bytes under the listed ids.
        let (_, bytes) = attachment_bytes(&raw, &p.attachments[1].attachment_id, 1 << 20).unwrap().unwrap();
        assert_eq!(bytes, text);
        // A rebuild from the read-back fields is again the draft shape with the same attachments.
        let again = read_draft_fields(&build_draft(&read_draft_fields(&raw).unwrap()).unwrap()).unwrap();
        assert_eq!(again.attachments, f.attachments);
        // Only the allowlisted top-level headers; every attachment is base64.
        let text = String::from_utf8(raw).unwrap();
        assert_eq!(text.matches("Content-Disposition: attachment").count(), 4, "{text}");
        for part in text.split("Content-Disposition: attachment").skip(1) {
            let head = part.split("\r\n\r\n").next().unwrap();
            assert!(head.contains("Content-Transfer-Encoding: base64"), "{head}");
        }
        assert!(text.matches('\n').count() == text.matches("\r\n").count(), "bare LF in output");
    }

    #[test]
    fn draft_shape_rejects_other_structures() {
        let shape = |raw: &[u8]| parse(raw, &Limits::default()).unwrap().is_draft_shape;
        let mixed = |inner: &str| {
            format!(
                "From: a@x.org\r\nMessage-ID: <m@x>\r\nDate: Tue, 14 Nov 2023 22:13:20 +0000\r\n\
                 Content-Type: multipart/mixed; boundary=M\r\n\r\n--M\r\nContent-Type: text/plain\r\n\r\nhi\r\n{inner}--M--\r\n"
            )
        };
        let ok =
            mixed("--M\r\nContent-Type: image/png\r\nContent-Disposition: attachment; filename=a.png\r\n\r\nx\r\n");
        assert!(shape(ok.as_bytes()));
        assert_eq!(read_draft_fields(ok.as_bytes()).unwrap().attachments.len(), 1);
        for bad in [
            // Inline image, an extra text part without disposition, a nested message, nested multipart.
            mixed("--M\r\nContent-Type: image/png\r\nContent-Disposition: inline; filename=a.png\r\n\r\nx\r\n"),
            mixed("--M\r\nContent-Type: text/plain\r\n\r\nsecond\r\n"),
            mixed(
                "--M\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment\r\n\r\nSubject: x\r\n\r\ny\r\n",
            ),
            mixed(
                "--M\r\nContent-Type: multipart/alternative; boundary=A\r\n\r\n--A\r\nContent-Type: text/plain\r\n\r\np\r\n\
                 --A\r\nContent-Type: text/html\r\n\r\n<p>h</p>\r\n--A--\r\n",
            ),
        ] {
            assert!(!shape(bad.as_bytes()), "{bad}");
            assert!(read_draft_fields(bad.as_bytes()).is_err());
        }
        // An HTML body with an attachment is not a Dove draft either.
        let html = "From: a@x.org\r\nContent-Type: multipart/mixed; boundary=M\r\n\r\n--M\r\nContent-Type: text/html\r\n\r\n<b>x</b>\r\n\
                    --M\r\nContent-Type: image/png\r\nContent-Disposition: attachment; filename=a.png\r\n\r\nx\r\n--M--\r\n";
        assert!(!shape(html.as_bytes()));
    }

    #[test]
    fn attachment_header_injection_impossible() {
        for name in [
            "a\r\nBcc: evil@x.org",
            "a\nb",
            "a\u{0}b",
            "../etc/passwd",
            "a\\b",
            ".hidden",
            " pad",
            "",
            &"x".repeat(201),
        ] {
            let mut f = fields();
            f.attachments = vec![att(name, "application/pdf", b"x")];
            assert!(build_draft(&f).is_err(), "{name:?}");
        }
        for t in [
            "application/pdf\r\nBcc: evil@x.org",
            "application/pdf; name=x",
            "text/plain;charset=utf-8",
            "multipart/mixed",
            "message/rfc822",
            "Application/PDF",
            "pdf",
            "/pdf",
            "a/b/c",
            "application/\"x\"",
        ] {
            let mut f = fields();
            f.attachments = vec![att("a.pdf", t, b"x")];
            assert!(build_draft(&f).is_err(), "{t:?}");
        }
        assert_eq!(normalize_mime_type(" Application/PDF ").as_deref(), Some("application/pdf"));
        assert_eq!(normalize_mime_type("application/vnd.ms-excel").as_deref(), Some("application/vnd.ms-excel"));
        assert_eq!(normalize_mime_type("image/svg+xml").as_deref(), Some("image/svg+xml"));
        for t in ["multipart/mixed", "message/rfc822", "text/plain; charset=x", "a b/c", "x/", "text/plain\r\n"] {
            assert_eq!(normalize_mime_type(t), None, "{t:?}");
        }
        let mut f = fields();
        f.attachments = (0..11).map(|i| att(&format!("{i}.txt"), "text/plain", b"x")).collect();
        assert!(build_draft(&f).is_err());
        f.attachments.truncate(10);
        let raw = build_draft(&f).unwrap();
        assert_eq!(parse(&raw, &Limits::default()).unwrap().attachments.len(), 10);
    }
}
