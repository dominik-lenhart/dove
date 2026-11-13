//! Text extraction from attachments at ingest (v0.2 design section 4): PDF, DOCX, ODT, plain text and CSV.
//!
//! Extraction never executes anything: no macros, scripts, forms, embedded files, external references or XML
//! entities are processed, and nothing is fetched. Every input is bounded:
//!
//! * the attachment size (`max_attachment_bytes`, checked before the bytes are decoded or copied),
//! * the decompressed size of every ZIP entry and PDF stream (a "zip bomb" stops at the cap, never allocates past it),
//! * the produced text (characters per attachment and per message), and
//! * the wall-clock time of one message (checked between pages, ZIP entries and XML elements).
//!
//! Extraction runs on blocking threads (`spawn_blocking` in the index sync) with the message that is being indexed.
//! A format parser that panics on hostile input is contained, and its panic message (which could quote attachment
//! content) is not printed.

use std::cell::Cell;
use std::io::Read;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Once;
use std::time::{Duration, Instant};

use crate::content;

/// Configuration of ingest-time extraction (`[index]` keys `attachment_text*`).
#[derive(Debug, Clone)]
pub struct Cfg {
    pub enabled: bool,
    /// Largest decoded attachment that is opened.
    pub max_attachment_bytes: usize,
    /// Characters of attachment text indexed per message.
    pub max_chars: usize,
    /// Wall-clock budget of all extraction for one message.
    pub budget: Duration,
}

impl Default for Cfg {
    fn default() -> Self {
        Cfg {
            enabled: true,
            max_attachment_bytes: 8 * 1024 * 1024,
            max_chars: 100_000,
            budget: Duration::from_secs(10),
        }
    }
}

impl Cfg {
    pub fn disabled() -> Self {
        Cfg { enabled: false, ..Default::default() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Pdf,
    Docx,
    Odt,
    /// Plain text and CSV.
    Text,
}

/// Which extractor handles an attachment, from its MIME type and, for generic types, its file extension.
pub fn kind_of(mime: &str, filename: Option<&str>) -> Option<Kind> {
    let mime = mime.trim().to_ascii_lowercase();
    let by_mime = match mime.as_str() {
        "application/pdf" | "application/x-pdf" => Some(Kind::Pdf),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => Some(Kind::Docx),
        "application/vnd.oasis.opendocument.text" => Some(Kind::Odt),
        "text/plain" | "text/csv" | "application/csv" | "text/comma-separated-values" => Some(Kind::Text),
        _ => None,
    };
    if by_mime.is_some() {
        return by_mime;
    }
    // Generic or wrong types (mail clients send PDFs as application/octet-stream): trust the extension.
    if !(mime.is_empty() || mime == "application/octet-stream" || mime == "binary/octet-stream") {
        return None;
    }
    let ext = filename?.rsplit_once('.')?.1.to_ascii_lowercase();
    match ext.as_str() {
        "pdf" => Some(Kind::Pdf),
        "docx" => Some(Kind::Docx),
        "odt" => Some(Kind::Odt),
        "txt" | "csv" => Some(Kind::Text),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExtractError {
    #[error("not a supported or valid document")]
    Invalid,
    #[error("encrypted document")]
    Encrypted,
    #[error("decompressed size limit exceeded")]
    TooLarge,
    #[error("time budget exhausted")]
    Timeout,
}

/// Limits of one extraction.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Characters of text returned.
    pub max_chars: usize,
    /// Most bytes any single decompressed ZIP entry or PDF stream may have.
    pub max_decompressed: usize,
    pub deadline: Instant,
}

/// Result of one extraction: the text (at most `max_chars`) and whether it was cut at that limit.
#[derive(Debug)]
pub struct Text {
    pub text: String,
    pub truncated: bool,
}

/// Extracts the text of one attachment. `bytes` are the decoded attachment.
pub fn extract(bytes: &[u8], kind: Kind, lim: &Limits) -> Result<Text, ExtractError> {
    if Instant::now() >= lim.deadline {
        return Err(ExtractError::Timeout);
    }
    let raw = match kind {
        Kind::Text => text_file(bytes, lim.max_chars)?,
        Kind::Docx => ooxml_text(bytes, lim, Flavor::Docx)?,
        Kind::Odt => ooxml_text(bytes, lim, Flavor::Odt)?,
        Kind::Pdf => guarded(|| pdf_text(bytes, lim)).ok_or(ExtractError::Invalid)??,
    };
    let (text, cut) = content::truncate_chars(&raw, lim.max_chars.saturating_mul(2));
    let cleaned = content::clean_text(&text);
    let (text, cut2) = content::truncate_chars(cleaned.trim(), lim.max_chars);
    Ok(Text { text, truncated: cut || cut2 })
}

// ------------------------------------------------------------------ message level

/// Result of extracting all supported attachments of one message.
#[derive(Debug, Default)]
pub struct Extracted {
    pub text: String,
    /// False when a supported attachment was skipped (too large, unreadable, over budget) or the text was cut.
    pub complete: bool,
}

/// Extracts the text of every supported attachment of the message `raw`, within `cfg`. The caller has already
/// seen that the message has at least one supported attachment (see [`kind_of`]).
pub fn extract_message(raw: &[u8], cfg: &Cfg) -> Extracted {
    let deadline = Instant::now() + cfg.budget;
    let mut out = Extracted { text: String::new(), complete: true };
    let mut chars = 0usize;
    let visited = crate::mime::visit_attachments(raw, &mut |meta, decode| {
        let Some(kind) = kind_of(&meta.mime_type, meta.filename.as_deref()) else {
            return std::ops::ControlFlow::Continue(());
        };
        let left = cfg.max_chars.saturating_sub(chars);
        if left == 0 || Instant::now() >= deadline {
            out.complete = false;
            return std::ops::ControlFlow::Break(());
        }
        if meta.size_bytes > cfg.max_attachment_bytes as u64 {
            out.complete = false;
            return std::ops::ControlFlow::Continue(());
        }
        let bytes = decode();
        let lim = Limits { max_chars: left, max_decompressed: decompressed_cap(cfg), deadline };
        match extract(&bytes, kind, &lim) {
            Ok(t) => {
                if t.truncated {
                    out.complete = false;
                }
                if !t.text.is_empty() {
                    if !out.text.is_empty() {
                        out.text.push('\n');
                        chars += 1;
                    }
                    chars += t.text.chars().count();
                    out.text.push_str(&t.text);
                }
            }
            Err(_) => out.complete = false,
        }
        std::ops::ControlFlow::Continue(())
    });
    if visited.is_err() {
        out.complete = false;
    }
    out
}

/// Decompressed-size cap per ZIP entry or PDF stream: generous for real documents (text compresses well), small
/// enough that a bomb never holds more than this plus the attachment itself.
fn decompressed_cap(cfg: &Cfg) -> usize {
    cfg.max_attachment_bytes.saturating_mul(4).clamp(1024 * 1024, 32 * 1024 * 1024)
}

// ------------------------------------------------------------------ panic containment

thread_local! {
    static CONTAINED: Cell<bool> = const { Cell::new(false) };
}

/// Runs `f`, returning `None` if it panicked. While it runs, a panic prints nothing on this thread (the message of
/// a parser panic can quote the document it choked on); panics elsewhere keep the previous hook.
fn guarded<T>(f: impl FnOnce() -> T) -> Option<T> {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if CONTAINED.with(Cell::get) {
                return;
            }
            previous(info);
        }));
    });
    CONTAINED.with(|c| c.set(true));
    let r = catch_unwind(AssertUnwindSafe(f));
    CONTAINED.with(|c| c.set(false));
    r.ok()
}

// ------------------------------------------------------------------ plain text and CSV

fn text_file(bytes: &[u8], max_chars: usize) -> Result<String, ExtractError> {
    // Only what can be used is decoded; the cut may land inside a character, which `from_utf8_lossy` repairs.
    let head = &bytes[..bytes.len().min(max_chars.saturating_mul(8).max(4096))];
    let s = match head {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, u16::from_be_bytes),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(head).into_owned(),
    };
    // Binary data posing as text: many NUL or replacement characters.
    let n = s.chars().take(4096).count().max(1);
    let bad = s.chars().take(4096).filter(|c| *c == '\u{0}' || *c == '\u{FFFD}').count();
    if bad * 10 > n {
        return Err(ExtractError::Invalid);
    }
    Ok(s)
}

fn utf16(bytes: &[u8], word: fn([u8; 2]) -> u16) -> String {
    let units = bytes.as_chunks::<2>().0.iter().map(|c| word(*c));
    char::decode_utf16(units).map(|r| r.unwrap_or('\u{FFFD}')).collect()
}

// ------------------------------------------------------------------ ZIP (DOCX, ODT)

/// A ZIP archive's central directory. Only what OOXML and ODF documents need: stored and deflated entries, no
/// ZIP64, no encryption.
struct Zip<'a> {
    data: &'a [u8],
    entries: Vec<ZipEntry>,
}

struct ZipEntry {
    name: String,
    method: u16,
    flags: u16,
    compressed: u32,
    uncompressed: u32,
    local_offset: u32,
}

const MAX_ZIP_ENTRIES: usize = 20_000;

fn le16(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(at..at + 2)?.try_into().ok()?))
}

fn le32(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(at..at + 4)?.try_into().ok()?))
}

impl<'a> Zip<'a> {
    fn open(data: &'a [u8]) -> Result<Self, ExtractError> {
        let bad = || ExtractError::Invalid;
        // End of central directory record: within the last 64 KiB + 22 bytes.
        let tail_start = data.len().saturating_sub(65_557);
        let eocd = data[tail_start..]
            .windows(4)
            .rposition(|w| w == [0x50, 0x4B, 0x05, 0x06])
            .map(|p| tail_start + p)
            .ok_or_else(bad)?;
        let entries = le16(data, eocd + 10).ok_or_else(bad)? as usize;
        let cd_size = le32(data, eocd + 12).ok_or_else(bad)? as usize;
        let cd_offset = le32(data, eocd + 16).ok_or_else(bad)? as usize;
        if entries == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF || entries > MAX_ZIP_ENTRIES {
            return Err(bad());
        }
        let cd = data.get(cd_offset..cd_offset.checked_add(cd_size).ok_or_else(bad)?).ok_or_else(bad)?;
        let mut out = Vec::with_capacity(entries.min(1024));
        let mut p = 0usize;
        for _ in 0..entries {
            if le32(cd, p).ok_or_else(bad)? != 0x0201_4B50 {
                return Err(bad());
            }
            let name_len = le16(cd, p + 28).ok_or_else(bad)? as usize;
            let extra_len = le16(cd, p + 30).ok_or_else(bad)? as usize;
            let comment_len = le16(cd, p + 32).ok_or_else(bad)? as usize;
            let name = cd.get(p + 46..p + 46 + name_len).ok_or_else(bad)?;
            out.push(ZipEntry {
                name: String::from_utf8_lossy(name).into_owned(),
                flags: le16(cd, p + 8).ok_or_else(bad)?,
                method: le16(cd, p + 10).ok_or_else(bad)?,
                compressed: le32(cd, p + 20).ok_or_else(bad)?,
                uncompressed: le32(cd, p + 24).ok_or_else(bad)?,
                local_offset: le32(cd, p + 42).ok_or_else(bad)?,
            });
            p += 46 + name_len + extra_len + comment_len;
        }
        Ok(Zip { data, entries: out })
    }

    fn find(&self, name: &str) -> Option<&ZipEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Decompressed bytes of an entry, at most `max` (more is `TooLarge`, checked while inflating, not trusted from
    /// the header: a bomb's declared size can lie).
    fn read(&self, e: &ZipEntry, max: usize) -> Result<Vec<u8>, ExtractError> {
        let bad = ExtractError::Invalid;
        if e.flags & 1 != 0 {
            return Err(ExtractError::Encrypted);
        }
        if e.uncompressed as usize > max {
            return Err(ExtractError::TooLarge);
        }
        let off = e.local_offset as usize;
        if le32(self.data, off) != Some(0x0403_4B50) {
            return Err(bad);
        }
        let name_len = le16(self.data, off + 26).ok_or(bad)? as usize;
        let extra_len = le16(self.data, off + 28).ok_or(bad)? as usize;
        let start = off + 30 + name_len + extra_len;
        let comp = self.data.get(start..start.checked_add(e.compressed as usize).ok_or(bad)?).ok_or(bad)?;
        match e.method {
            0 => {
                if comp.len() > max {
                    return Err(ExtractError::TooLarge);
                }
                Ok(comp.to_vec())
            }
            8 => {
                let out = read_bounded(flate2::read::DeflateDecoder::new(comp), max).map_err(|_| bad)?;
                if out.len() > max {
                    return Err(ExtractError::TooLarge);
                }
                Ok(out)
            }
            _ => Err(bad),
        }
    }
}

/// Reads at most `max + 1` bytes: one more than allowed, so the caller can tell "exactly max" from "too much"
/// without ever holding more. The bound on memory for an inflate bomb.
fn read_bounded(r: impl Read, max: usize) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    r.take(max as u64 + 1).read_to_end(&mut out)?;
    Ok(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flavor {
    Docx,
    Odt,
}

fn ooxml_text(bytes: &[u8], lim: &Limits, flavor: Flavor) -> Result<String, ExtractError> {
    let zip = Zip::open(bytes)?;
    let entry_name = if flavor == Flavor::Docx { "word/document.xml" } else { "content.xml" };
    let e = zip.find(entry_name).ok_or(ExtractError::Invalid)?;
    let xml = zip.read(e, lim.max_decompressed)?;
    xml_text(&xml, flavor, lim)
}

// ------------------------------------------------------------------ XML text

/// Character data of a word-processing document, paragraphs separated by line breaks. This is a tag scanner, not an
/// XML parser: entities are limited to the five predefined ones and numeric references (nothing a document declares
/// is ever expanded), and DOCTYPEs, comments and processing instructions are skipped.
fn xml_text(xml: &[u8], flavor: Flavor, lim: &Limits) -> Result<String, ExtractError> {
    let src = String::from_utf8_lossy(xml);
    let s = src.as_ref();
    let b = s.as_bytes();
    let budget = lim.max_chars.saturating_mul(2);
    let mut out = String::new();
    let mut i = 0usize;
    let mut in_wt = false;
    let mut steps = 0u32;
    while i < b.len() && out.len() < budget {
        steps += 1;
        if steps.is_multiple_of(1024) && Instant::now() >= lim.deadline {
            return Err(ExtractError::Timeout);
        }
        if b[i] != b'<' {
            let end = memchr(b'<', b, i).unwrap_or(b.len());
            // DOCX: text only inside <w:t>. ODT: every text node of content.xml. A node is cut to what the output
            // budget still allows before it is unescaped.
            if flavor == Flavor::Odt || in_wt {
                let mut stop = end.min(i + budget.saturating_sub(out.len()));
                while !s.is_char_boundary(stop) {
                    stop -= 1;
                }
                push_unescaped(&s[i..stop], &mut out);
            }
            i = end;
            continue;
        }
        let rest = &s[i..];
        if let Some(r) = rest.strip_prefix("<!--") {
            i += 4 + r.find("-->").map_or(r.len(), |p| p + 3);
            continue;
        }
        if let Some(r) = rest.strip_prefix("<![CDATA[") {
            let end = r.find("]]>").unwrap_or(r.len());
            if flavor == Flavor::Odt || in_wt {
                out.push_str(&r[..end]);
            }
            i += 9 + (end + 3).min(r.len());
            continue;
        }
        if rest.starts_with("<?") || rest.starts_with("<!") {
            i += rest.find('>').map_or(rest.len(), |p| p + 1);
            continue;
        }
        // An ordinary tag: scan to its closing '>' outside quoted attribute values.
        let mut j = 1usize;
        let rb = rest.as_bytes();
        let mut quote = 0u8;
        while j < rb.len() {
            match (quote, rb[j]) {
                (0, b'"' | b'\'') => quote = rb[j],
                (q, c) if q != 0 && c == q => quote = 0,
                (0, b'>') => break,
                _ => {}
            }
            j += 1;
        }
        let tag = &rest[1..j.min(rest.len())];
        i += j + 1;
        let closing = tag.starts_with('/');
        let self_closing = tag.ends_with('/');
        let name = tag.trim_start_matches('/').split(|c: char| c.is_whitespace() || c == '/').next().unwrap_or("");
        match (flavor, name) {
            (Flavor::Docx, "w:t") => in_wt = !closing && !self_closing,
            (Flavor::Docx, "w:tab") => out.push('\t'),
            (Flavor::Docx, "w:br" | "w:cr") => out.push('\n'),
            (Flavor::Docx, "w:p") if closing => out.push('\n'),
            (Flavor::Odt, "text:tab") => out.push('\t'),
            (Flavor::Odt, "text:line-break") => out.push('\n'),
            (Flavor::Odt, "text:s") => out.push(' '),
            (Flavor::Odt, "text:p" | "text:h") if closing => out.push('\n'),
            _ => {}
        }
    }
    Ok(out)
}

fn memchr(needle: u8, hay: &[u8], from: usize) -> Option<usize> {
    hay[from..].iter().position(|b| *b == needle).map(|p| from + p)
}

/// Appends `s` with XML character references resolved (five predefined entities and numeric references).
pub(crate) fn push_unescaped(s: &str, out: &mut String) {
    let mut rest = s;
    while let Some(p) = rest.find('&') {
        out.push_str(&rest[..p]);
        rest = &rest[p..];
        // The terminator must be within the next 12 bytes: a long run of `&` without `;` stays linear.
        let Some(semi) = rest.as_bytes().iter().take(13).position(|b| *b == b';') else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let ent = &rest[1..semi];
        let ch = match ent {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => ent
                .strip_prefix("#x")
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| ent.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        if let Some(c) = ch {
            out.push(c);
        }
        rest = &rest[semi + 1..];
    }
    out.push_str(rest);
}

// ------------------------------------------------------------------ PDF

/// Pages read from one PDF, at most.
const MAX_PDF_PAGES: usize = 300;
/// Object and cross-reference streams a PDF may declare together. Real documents within the attachment size cap have
/// a few dozen; every one is inflated and parsed eagerly while the document loads, so a crafted file with thousands
/// is refused before that.
const MAX_PDF_LOAD_STREAMS: usize = 128;
/// Most bytes one PDF stream may inflate to (object, cross-reference and page content streams alike).
const MAX_PDF_STREAM_BYTES: usize = 8 * 1024 * 1024;

/// Number of name tokens in `pdf` equal to one of `wanted` after resolving `#XX` escapes (`/Obj#53tm` is
/// `/ObjStm`). Names are plain text even in encrypted or compressed documents; a count that is too high only makes
/// the check stricter, so strings and stream data containing a slash do no harm.
fn count_pdf_names(pdf: &[u8], wanted: &[&[u8]]) -> usize {
    // The PDF whitespace set (including NUL, which `is_ascii_whitespace` lacks) and delimiters, as lopdf's tokenizer.
    let is_delim = |b: u8| b" \t\n\r\0\x0C()<>[]{}/%".contains(&b);
    let mut count = 0usize;
    let mut i = 0usize;
    let mut name: Vec<u8> = Vec::with_capacity(16);
    while i < pdf.len() {
        if pdf[i] != b'/' {
            i += 1;
            continue;
        }
        i += 1;
        name.clear();
        while i < pdf.len() && !is_delim(pdf[i]) {
            let b = pdf[i];
            let hex = |c: u8| (c as char).to_digit(16);
            if b == b'#' && i + 2 < pdf.len() && hex(pdf[i + 1]).is_some() && hex(pdf[i + 2]).is_some() {
                name.push((hex(pdf[i + 1]).unwrap_or(0) * 16 + hex(pdf[i + 2]).unwrap_or(0)) as u8);
                i += 3;
            } else {
                name.push(b);
                i += 1;
            }
            if name.len() > 32 {
                // Longer than any name we look for: skip the rest of this token.
                while i < pdf.len() && !is_delim(pdf[i]) {
                    i += 1;
                }
                break;
            }
        }
        if wanted.contains(&name.as_slice()) {
            count += 1;
        }
    }
    count
}

fn pdf_text(bytes: &[u8], lim: &Limits) -> Result<String, ExtractError> {
    if !bytes.get(..1024.min(bytes.len())).is_some_and(|h| h.windows(5).any(|w| w == b"%PDF-")) {
        return Err(ExtractError::Invalid);
    }
    // lopdf loads the whole document eagerly and cannot be interrupted, so the work is bounded by what goes in: the
    // attachment size cap, the number of object and cross-reference streams, and the inflated size of every stream and page.
    if count_pdf_names(bytes, &[b"ObjStm", b"XRef"]) > MAX_PDF_LOAD_STREAMS {
        return Err(ExtractError::TooLarge);
    }
    let stream_cap = lim.max_decompressed.min(MAX_PDF_STREAM_BYTES);
    let opts = lopdf::LoadOptions { max_decompressed_size: Some(stream_cap), strict: false, ..Default::default() };
    let doc = lopdf::Document::load_mem_with_options(bytes, opts).map_err(|_| ExtractError::Invalid)?;
    if doc.is_encrypted() {
        return Err(ExtractError::Encrypted);
    }
    let pages: Vec<u32> = doc.get_pages().keys().copied().take(MAX_PDF_PAGES).collect();
    if pages.is_empty() {
        return Err(ExtractError::Invalid);
    }
    let mut out = String::new();
    let budget = lim.max_chars.saturating_mul(2);
    let mut failed = 0usize;
    for n in &pages {
        if Instant::now() >= lim.deadline {
            return if out.is_empty() { Err(ExtractError::Timeout) } else { Ok(out) };
        }
        if out.len() >= budget {
            break;
        }
        match doc.extract_text_with_limit(&[*n], stream_cap) {
            Ok(t) => {
                out.push_str(&t);
                out.push('\n');
            }
            Err(_) => failed += 1,
        }
    }
    if out.trim().is_empty() && failed > 0 {
        // Nothing readable (scanned pages are images, which are not read): not a complete extraction either.
        return Err(ExtractError::Invalid);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim(max_chars: usize) -> Limits {
        Limits { max_chars, max_decompressed: 4 * 1024 * 1024, deadline: Instant::now() + Duration::from_secs(10) }
    }

    /// A ZIP with stored or deflated entries, built by hand (names, contents, deflate?).
    pub(crate) fn zip_of(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        use std::io::Write;
        let mut out = Vec::new();
        let mut cd = Vec::new();
        for (name, data, deflate) in entries {
            let (method, body): (u16, Vec<u8>) = if *deflate {
                let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(data).unwrap();
                (8, e.finish().unwrap())
            } else {
                (0, data.to_vec())
            };
            let off = out.len() as u32;
            out.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
            out.extend_from_slice(&[20, 0, 0, 0]);
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0, 0, 0, 0]);
            out.extend_from_slice(&0u32.to_le_bytes()); // crc (not checked)
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&body);
            cd.extend_from_slice(&0x0201_4B50u32.to_le_bytes());
            cd.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            cd.extend_from_slice(&method.to_le_bytes());
            cd.extend_from_slice(&[0, 0, 0, 0]);
            cd.extend_from_slice(&0u32.to_le_bytes());
            cd.extend_from_slice(&(body.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&[0; 12]);
            cd.extend_from_slice(&off.to_le_bytes());
            cd.extend_from_slice(name.as_bytes());
        }
        let cd_off = out.len() as u32;
        let n = entries.len() as u16;
        out.extend_from_slice(&cd);
        out.extend_from_slice(&0x0605_4B50u32.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    pub(crate) fn docx(body_xml: &str, deflate: bool) -> Vec<u8> {
        let xml = format!("<?xml version=\"1.0\"?><w:document xmlns:w=\"x\"><w:body>{body_xml}</w:body></w:document>");
        zip_of(&[("[Content_Types].xml", b"<Types/>", false), ("word/document.xml", xml.as_bytes(), deflate)])
    }

    #[test]
    fn kinds_by_mime_and_extension() {
        assert_eq!(kind_of("application/pdf", None), Some(Kind::Pdf));
        assert_eq!(kind_of("APPLICATION/PDF; x", Some("a.pdf")), None, "parameters are not part of the type");
        assert_eq!(kind_of("application/octet-stream", Some("Report.PDF")), Some(Kind::Pdf));
        assert_eq!(kind_of("application/octet-stream", Some("a.DOCX")), Some(Kind::Docx));
        assert_eq!(kind_of("text/csv", Some("x.bin")), Some(Kind::Text));
        assert_eq!(kind_of("image/png", Some("a.pdf")), None, "a specific other type is not overridden");
        assert_eq!(kind_of("application/octet-stream", Some("a.exe")), None);
        assert_eq!(kind_of("application/octet-stream", None), None);
    }

    #[test]
    fn docx_text_paragraphs_tabs_and_entities() {
        let d = docx(
            "<w:p><w:r><w:t>Hello &amp; welcome</w:t></w:r><w:r><w:tab/><w:t xml:space=\"preserve\"> to &#68;ove &#x21;</w:t></w:r></w:p>\
             <w:p><w:r><w:instrText>HYPERLINK \"x\"</w:instrText><w:t>Second</w:t><w:br/><w:t>line</w:t></w:r></w:p><w:p/>",
            true,
        );
        let t = extract(&d, Kind::Docx, &lim(1000)).unwrap();
        assert_eq!(t.text, "Hello & welcome\t to Dove !\nSecondline".replace("Secondline", "Second\nline"));
        assert!(!t.truncated);
        // Stored (method 0) entries work too.
        let d = docx("<w:p><w:r><w:t>plain</w:t></w:r></w:p>", false);
        assert_eq!(extract(&d, Kind::Docx, &lim(1000)).unwrap().text, "plain");
    }

    #[test]
    fn odt_text() {
        let xml = "<office:document-content><office:body><office:text><text:h>Title</text:h><text:p>One<text:s/>two<text:tab/>three</text:p>\
                   <text:p>A &lt;b&gt;<text:line-break/>c</text:p></office:text></office:body></office:document-content>";
        let z = zip_of(&[
            ("mimetype", b"application/vnd.oasis.opendocument.text", false),
            ("content.xml", xml.as_bytes(), true),
        ]);
        assert_eq!(extract(&z, Kind::Odt, &lim(1000)).unwrap().text, "Title\nOne two\tthree\nA <b>\nc");
    }

    #[test]
    fn xml_declarations_are_never_expanded() {
        let xml = "<!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;\">]>\
                   <w:document><w:p><w:t>a &lol2; b</w:t></w:p><!-- <w:t>hidden</w:t> --></w:document>";
        let z = zip_of(&[("word/document.xml", xml.as_bytes(), true)]);
        let t = extract(&z, Kind::Docx, &lim(1000)).unwrap().text;
        assert_eq!(t, "a  b", "unknown entities are dropped, comments skipped");
        assert!(!t.contains("lol") && !t.contains("hidden"));
    }

    #[test]
    fn zip_bomb_stops_at_the_cap() {
        // 64 MiB of 'a' deflates to about 64 KiB; the declared size lies (header says 10 bytes).
        let big = vec![b'a'; 64 * 1024 * 1024];
        let mut z = zip_of(&[("word/document.xml", &big, true)]);
        assert!(z.len() < 200_000, "the bomb is small: {}", z.len());
        let l = Limits {
            max_chars: 1000,
            max_decompressed: 1024 * 1024,
            deadline: Instant::now() + Duration::from_secs(10),
        };
        assert_eq!(extract(&z, Kind::Docx, &l).unwrap_err(), ExtractError::TooLarge, "declared size over the cap");
        // Patch the declared sizes in the central directory to claim 10 bytes: inflating must still stop.
        let cd = z.windows(4).position(|w| w == [0x50, 0x4B, 0x01, 0x02]).unwrap();
        z[cd + 24..cd + 28].copy_from_slice(&10u32.to_le_bytes());
        assert_eq!(
            extract(&z, Kind::Docx, &l).unwrap_err(),
            ExtractError::TooLarge,
            "inflation is bounded, not trusted"
        );
    }

    #[test]
    fn broken_and_hostile_archives_are_errors() {
        let l = lim(1000);
        for bad in [&b""[..], b"PK\x03\x04junk", b"not a zip at all", &[0x50, 0x4B, 0x05, 0x06][..]] {
            assert_eq!(extract(bad, Kind::Docx, &l).unwrap_err(), ExtractError::Invalid);
        }
        let mut z = docx("<w:p><w:t>x</w:t></w:p>", true);
        // Central directory offset beyond the file.
        let n = z.len();
        z[n - 6..n - 2].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
        assert_eq!(extract(&z, Kind::Docx, &l).unwrap_err(), ExtractError::Invalid);
        // Local header offset beyond the file.
        let mut z = docx("<w:p><w:t>x</w:t></w:p>", true);
        let cd = z.windows(4).rposition(|w| w == [0x50, 0x4B, 0x01, 0x02]).unwrap();
        z[cd + 42..cd + 46].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
        assert_eq!(extract(&z, Kind::Docx, &l).unwrap_err(), ExtractError::Invalid);
        // Encrypted entry.
        let mut z = docx("<w:p><w:t>x</w:t></w:p>", true);
        let cd = z.windows(4).rposition(|w| w == [0x50, 0x4B, 0x01, 0x02]).unwrap();
        z[cd + 8] |= 1;
        assert_eq!(extract(&z, Kind::Docx, &l).unwrap_err(), ExtractError::Encrypted);
        // Missing document part and unsupported compression method.
        let z = zip_of(&[("other.xml", b"<a/>", false)]);
        assert_eq!(extract(&z, Kind::Docx, &l).unwrap_err(), ExtractError::Invalid);
        let mut z = docx("<w:p><w:t>x</w:t></w:p>", false);
        let cd = z.windows(4).rposition(|w| w == [0x50, 0x4B, 0x01, 0x02]).unwrap();
        z[cd + 10] = 14;
        assert_eq!(extract(&z, Kind::Docx, &l).unwrap_err(), ExtractError::Invalid);
    }

    #[test]
    fn text_and_csv() {
        let l = lim(1000);
        assert_eq!(extract(b"hello\r\nworld", Kind::Text, &l).unwrap().text, "hello\nworld");
        assert_eq!(extract("\u{FEFF}Größe;Wert\n1;2".as_bytes(), Kind::Text, &l).unwrap().text, "Größe;Wert\n1;2");
        let mut u16le = vec![0xFF, 0xFE];
        u16le.extend("Name,Wert\nÄ,1".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(extract(&u16le, Kind::Text, &l).unwrap().text, "Name,Wert\nÄ,1");
        // Binary content posing as text is refused, not indexed as noise.
        assert_eq!(extract(&[0u8; 400], Kind::Text, &l).unwrap_err(), ExtractError::Invalid);
        assert_eq!(
            extract(&(0..=255u8).cycle().take(3000).collect::<Vec<_>>(), Kind::Text, &l).unwrap_err(),
            ExtractError::Invalid
        );
    }

    #[test]
    fn output_is_cut_at_the_limit_and_cleaned() {
        let t = extract("a\u{202e}b\u{200b}c ".repeat(500).as_bytes(), Kind::Text, &lim(100)).unwrap();
        assert!(t.truncated && t.text.chars().count() <= 100, "{}", t.text.len());
        assert!(!t.text.contains('\u{202e}') && !t.text.contains('\u{200b}'));
        let t = extract(b"short", Kind::Text, &lim(100)).unwrap();
        assert!(!t.truncated);
    }

    #[test]
    fn deadline_is_honoured() {
        let past =
            Limits { max_chars: 100, max_decompressed: 1 << 20, deadline: Instant::now() - Duration::from_secs(1) };
        assert_eq!(extract(b"x", Kind::Text, &past).unwrap_err(), ExtractError::Timeout);
        // An XML with many tags notices an expired deadline mid-way.
        let xml = format!("<w:document>{}</w:document>", "<w:p><w:t>a</w:t></w:p>".repeat(5000));
        let z = zip_of(&[("word/document.xml", xml.as_bytes(), true)]);
        let soon = Limits {
            max_chars: 1_000_000,
            max_decompressed: 1 << 24,
            deadline: Instant::now() + Duration::from_millis(0),
        };
        assert!(matches!(extract(&z, Kind::Docx, &soon), Err(ExtractError::Timeout)));
    }

    #[test]
    fn long_runs_of_ampersands_stay_linear() {
        // 8 MiB of '&' without a terminator used to rescan to the end of the text for every '&'.
        let xml = format!("<w:document><w:p><w:t>{}</w:t></w:p></w:document>", "&".repeat(8 * 1024 * 1024));
        let z = zip_of(&[("word/document.xml", xml.as_bytes(), true)]);
        let started = Instant::now();
        let t = extract(&z, Kind::Docx, &Limits { max_decompressed: 16 << 20, ..lim(1000) }).unwrap();
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        assert!(t.text.chars().count() <= 1000);
    }

    #[test]
    fn unescape_is_linear_without_terminators() {
        let started = Instant::now();
        let mut out = String::new();
        push_unescaped(&"&".repeat(1024 * 1024), &mut out);
        assert_eq!(out.len(), 1024 * 1024);
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
        let mut out = String::new();
        push_unescaped("a &amp; b &#x41;&#66; &unknown; &lt", &mut out);
        assert_eq!(out, "a & b AB  &lt");
    }

    #[test]
    fn inflating_never_reads_more_than_one_byte_past_the_limit() {
        // An endless source that panics once more than a few bytes past the limit were requested.
        struct Endless(usize);
        impl Read for Endless {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.0 += buf.len();
                assert!(self.0 < 1_000_000, "read far past the limit");
                buf.fill(b'a');
                Ok(buf.len())
            }
        }
        let out = read_bounded(Endless(0), 1000).unwrap();
        assert_eq!(out.len(), 1001);
    }

    #[test]
    fn pdf_with_many_object_streams_is_refused() {
        // The type name can be written with #XX escapes: /Obj#53tm is /ObjStm.
        for ty in ["ObjStm", "Obj#53tm", "#4fbj#53t#6d", "XRef"] {
            let mut pdf = b"%PDF-1.5\n".to_vec();
            for i in 0..300 {
                pdf.extend(
                    format!("{i} 0 obj\n<< /Type /{ty} /N 0 /First 0 /Length 0 >>\nstream\n\nendstream\nendobj\n")
                        .bytes(),
                );
            }
            assert_eq!(extract(&pdf, Kind::Pdf, &lim(1000)).unwrap_err(), ExtractError::TooLarge, "{ty}");
        }
        // Ordinary escapes in other names, and a few object streams, are fine to count.
        assert_eq!(count_pdf_names(b"/BaseFont /Arial#20Bold /Type/ObjStm /Type /ObjStm>>/ObjStmX", &[b"ObjStm"]), 2);
        assert_eq!(count_pdf_names(b"/Obj#5", &[b"ObjStm"]), 0, "a truncated escape is not an escape");
        // NUL ends a name like any other PDF whitespace: `/ObjStm\0` must still count.
        assert_eq!(count_pdf_names(b"/Type /ObjStm\0/N 1 /Type/XRef\0", &[b"ObjStm", b"XRef"]), 2);
        let mut pdf = b"%PDF-1.5\n".to_vec();
        for i in 0..300 {
            pdf.extend(
                format!("{i} 0 obj\n<< /Type /ObjStm\0/N 0 /Length 0 >>\nstream\n\nendstream\nendobj\n").bytes(),
            );
        }
        assert_eq!(extract(&pdf, Kind::Pdf, &lim(1000)).unwrap_err(), ExtractError::TooLarge);
    }

    #[test]
    fn pdf_garbage_is_an_error_not_a_panic() {
        let l = lim(1000);
        for bad in
            [&b""[..], b"%PDF-1.4\n", b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<</Root 1 0 R>>\n%%EOF", b"not a pdf"]
        {
            assert!(extract(bad, Kind::Pdf, &l).is_err());
        }
        let mut junk = b"%PDF-1.7\n".to_vec();
        junk.extend((0..5000u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8));
        assert!(extract(&junk, Kind::Pdf, &l).is_err());
    }

    /// A one-page PDF whose content stream shows `text` (Helvetica, Tj).
    pub(crate) fn pdf_with(pages: &[&str], compress: bool) -> Vec<u8> {
        use lopdf::content::{Content, Operation};
        use lopdf::{Document, Object, Stream, dictionary};
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {"Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica"});
        let resources_id = doc.add_object(dictionary! {"Font" => dictionary! {"F1" => font_id}});
        let mut kids = vec![];
        for text in pages {
            let content = Content {
                operations: vec![
                    Operation::new("BT", vec![]),
                    Operation::new("Tf", vec!["F1".into(), 12.into()]),
                    Operation::new("Td", vec![50.into(), 700.into()]),
                    Operation::new("Tj", vec![Object::string_literal(*text)]),
                    Operation::new("ET", vec![]),
                ],
            };
            let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
            let page_id =
                doc.add_object(dictionary! {"Type" => "Page", "Parent" => pages_id, "Contents" => content_id});
            kids.push(Object::from(page_id));
        }
        let count = kids.len() as i64;
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => kids, "Count" => count, "Resources" => resources_id,
                "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
            }),
        );
        let catalog_id = doc.add_object(dictionary! {"Type" => "Catalog", "Pages" => pages_id});
        doc.trailer.set("Root", catalog_id);
        if compress {
            doc.compress();
        }
        let mut out = Vec::new();
        doc.save_to(&mut out).unwrap();
        out
    }

    #[test]
    fn pdf_text_plain_and_compressed() {
        for compress in [false, true] {
            let pdf = pdf_with(&["Invoice 4711 for Dove", "Second page Ünïcode"], compress);
            let t = extract(&pdf, Kind::Pdf, &lim(1000)).unwrap();
            assert!(t.text.contains("Invoice 4711 for Dove"), "{:?}", t.text);
            assert!(t.text.contains("Second page"), "{:?}", t.text);
            assert!(!t.truncated);
        }
        let t = extract(&pdf_with(&[&"word ".repeat(400)], true), Kind::Pdf, &lim(50)).unwrap();
        assert!(t.truncated && t.text.chars().count() <= 50);
    }

    #[test]
    fn pdf_stream_bomb_is_bounded() {
        use lopdf::{Document, Object, Stream, dictionary};
        use std::io::Write;
        // A content stream that inflates to 64 MiB; the cap is 1 MiB.
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&vec![b' '; 64 * 1024 * 1024]).unwrap();
        let bomb = enc.finish().unwrap();
        assert!(bomb.len() < 200_000);
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let content_id = doc.add_object(Stream::new(dictionary! {"Filter" => "FlateDecode"}, bomb));
        let page_id = doc.add_object(dictionary! {"Type" => "Page", "Parent" => pages_id, "Contents" => content_id});
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {"Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1}),
        );
        let catalog_id = doc.add_object(dictionary! {"Type" => "Catalog", "Pages" => pages_id});
        doc.trailer.set("Root", catalog_id);
        let mut pdf = Vec::new();
        doc.save_to(&mut pdf).unwrap();
        let l = Limits {
            max_chars: 1000,
            max_decompressed: 1024 * 1024,
            deadline: Instant::now() + Duration::from_secs(20),
        };
        assert!(extract(&pdf, Kind::Pdf, &l).is_err(), "the bomb page yields no text");
    }

    #[test]
    fn panics_are_contained() {
        assert_eq!(guarded(|| 7), Some(7));
        let r: Option<()> = guarded(|| panic!("secret attachment text"));
        assert!(r.is_none());
        // The flag is reset: a later panic on this thread is not silenced.
        assert!(!CONTAINED.with(Cell::get));
    }
}
