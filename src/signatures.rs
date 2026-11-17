//! Named signatures with HTML and inline images (design 2026-11-17 "html signatures", PLAN A79).
//!
//! A mailbox has any number of named signatures; one is the mailbox default and a send-as alias may have its own
//! default. A signature always has a plain-text form (given, or derived from the HTML) and optionally HTML whose images
//! travel inside the mail as `multipart/related` parts referenced by `cid:`.
//!
//! Rules:
//! - Names are `[a-z0-9][a-z0-9-]{0,39}`, cids `[A-Za-z0-9._-]{1,64}`.
//! - HTML is parsed and re-serialized from an allowlist ([`clean_html`]): no scripts, styles blocks, forms, frames,
//!   event attributes or `url(...)` in styles; links only https, http, mailto and tel; images only `cid:` of this
//!   signature or https. A `cid:` without its image, or an image no `cid:` uses, is an error.
//! - Images are PNG, JPEG or GIF, recognized by their bytes; at most [`MAX_IMAGES`] and [`MAX_IMAGE_BYTES`] in total.
//! - Who may change them is decided by the callers: the operator over the admin socket, an agent with the
//!   `signatures` action on the mailbox.

use std::collections::BTreeSet;

use anyhow::{anyhow, bail};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use scraper::{ElementRef, Html, Node};
use serde_json::{Value, json};

use crate::http::html_escape;
use crate::identity::{self, MAX_SIGNATURE_BYTES};
use crate::util;

/// Largest cleaned HTML, in bytes.
pub const MAX_HTML_BYTES: usize = 32 * 1024;
/// Largest HTML accepted before cleaning.
pub const MAX_RAW_HTML_BYTES: usize = 64 * 1024;
pub const MAX_IMAGES: usize = 6;
/// All images of one signature together.
pub const MAX_IMAGE_BYTES: usize = 512 * 1024;
/// Signatures per mailbox.
pub const MAX_SIGNATURES: i64 = 20;

/// The `signature_defaults.address` of the mailbox's own default.
pub const MAILBOX_DEFAULT: &str = "";

pub fn valid_name(s: &str) -> bool {
    (1..=40).contains(&s.len())
        && s.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn valid_cid(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// One inline image of a signature.
#[derive(Clone, PartialEq, Eq)]
pub struct Image {
    pub cid: String,
    pub mime_type: String,
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for Image {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Image")
            .field("cid", &self.cid)
            .field("mime_type", &self.mime_type)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// A stored signature with its images.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub name: String,
    pub text: String,
    pub html: Option<String>,
    pub images: Vec<Image>,
}

impl Signature {
    /// The block appended to a plain-text body: the usual `-- ` separator line and the text.
    pub fn text_block(&self) -> String {
        format!("-- \n{}\n", self.text)
    }
}

/// The image type of `bytes` by their magic number.
pub fn sniff_image(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else {
        None
    }
}

/// Builds an [`Image`] from its declared parts: the bytes decide the type; a declared type must agree.
pub fn image(cid: &str, declared: Option<&str>, bytes: Vec<u8>) -> anyhow::Result<Image> {
    if !valid_cid(cid) {
        bail!("image cid '{}' must be 1 to 64 letters, digits, '.', '_' or '-'", clip(cid));
    }
    let Some(mime) = sniff_image(&bytes) else {
        bail!("image '{cid}' is not a PNG, JPEG or GIF file");
    };
    if let Some(d) = declared.map(str::trim).filter(|d| !d.is_empty())
        && !d.eq_ignore_ascii_case(mime)
    {
        bail!("image '{cid}' is {mime}, not {}", clip(d));
    }
    Ok(Image { cid: cid.to_string(), mime_type: mime.to_string(), bytes })
}

fn clip(s: &str) -> String {
    s.chars().take(64).collect()
}

// ------------------------------------------------------------------ HTML

/// Elements kept (with their allowed attributes).
const KEEP: &[&str] = &[
    // No `small`, `sub`, `sup` or `big`: nested, they change the text size without a style rule to check.
    "a", "b", "br", "div", "em", "font", "hr", "i", "img", "p", "span", "strong", "table", "tbody", "td", "th", "thead",
    "tr", "u", "center",
];
/// Elements dropped together with their content.
const DROP: &[&str] = &[
    "script", "style", "iframe", "frame", "frameset", "object", "embed", "applet", "template", "noscript", "title",
    "head", "svg", "math", "form", "input", "select", "textarea", "button", "link", "meta", "base", "audio", "video",
    "canvas", "picture", "source",
];
const VOID: &[&str] = &["br", "hr", "img"];
/// Attributes kept on any kept element (besides `href` and `src`, which have their own rules).
const ATTRS: &[&str] = &[
    "style",
    "width",
    "height",
    "align",
    "valign",
    "border",
    "cellpadding",
    "cellspacing",
    "role",
    "alt",
    "title",
    // `color` (on `font`) passes the same check as the CSS colour; `bgcolor` and `size` are dropped.
    "color",
    "dir",
    "face",
    "colspan",
    "rowspan",
];

/// CSS properties a signature may set, each with its own value rule ([`css_value_ok`]). Nothing that hides or moves
/// content (`display`, `visibility`, `opacity`, `position`, `overflow`, `text-indent`, backgrounds, ...): the plain-text
/// version must show everything the HTML shows.
const CSS: &[&str] = &[
    "color",
    "font-family",
    "font-size",
    "font-weight",
    "font-style",
    "text-decoration",
    "text-align",
    "vertical-align",
    "line-height",
    "letter-spacing",
    "margin",
    "margin-top",
    "margin-right",
    "margin-bottom",
    "margin-left",
    "padding",
    "padding-top",
    "padding-right",
    "padding-bottom",
    "padding-left",
    "border",
    "border-top",
    "border-right",
    "border-bottom",
    "border-left",
    "border-collapse",
    "border-spacing",
    "border-radius",
    "width",
    "max-width",
    "min-width",
    "height",
];

/// A number with a unit, e.g. `13px` -> (13.0, "px").
fn number_unit(v: &str) -> Option<(f64, &str)> {
    let split = v.find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-')).unwrap_or(v.len());
    let (num, unit) = v.split_at(split);
    num.parse::<f64>().ok().filter(|n| n.is_finite()).map(|n| (n, unit))
}

/// Named colours a signature may use (all dark enough to read on white).
const NAMED_COLORS: &[(&str, (u8, u8, u8))] = &[
    ("black", (0, 0, 0)),
    ("gray", (128, 128, 128)),
    ("grey", (128, 128, 128)),
    ("dimgray", (105, 105, 105)),
    ("darkgray", (169, 169, 169)),
    ("navy", (0, 0, 128)),
    ("blue", (0, 0, 255)),
    ("red", (255, 0, 0)),
    ("maroon", (128, 0, 0)),
    ("green", (0, 128, 0)),
    ("darkgreen", (0, 100, 0)),
    ("purple", (128, 0, 128)),
    ("teal", (0, 128, 128)),
    ("olive", (128, 128, 0)),
];

/// An opaque colour: `#rgb`, `#rrggbb`, `rgb(r, g, b)` or a name from [`NAMED_COLORS`]. Anything with an alpha part
/// (`#rgba`, `rgba()`, `/`), `hsl()`, `transparent` or `currentcolor` is None.
fn opaque_color(v: &str) -> Option<(u8, u8, u8)> {
    let v = v.trim();
    if let Some(hex) = v.strip_prefix('#') {
        let d = |s: &str| u8::from_str_radix(s, 16).ok();
        return match hex.len() {
            3 if hex.is_ascii() => {
                let c = |i: usize| d(&hex[i..i + 1]).map(|x| x * 17);
                Some((c(0)?, c(1)?, c(2)?))
            }
            6 if hex.is_ascii() => Some((d(&hex[0..2])?, d(&hex[2..4])?, d(&hex[4..6])?)),
            _ => None,
        };
    }
    if let Some(inner) = v.strip_prefix("rgb(").and_then(|r| r.strip_suffix(')')) {
        let parts: Vec<u8> = inner.split(',').map(|p| p.trim().parse::<u8>()).collect::<Result<_, _>>().ok()?;
        return match parts[..] {
            [r, g, b] => Some((r, g, b)),
            _ => None,
        };
    }
    NAMED_COLORS.iter().find(|(n, _)| *n == v).map(|(_, c)| *c)
}

/// A text colour readable on white: opaque, with a WCAG contrast ratio of at least 1.8 (light grey passes, white,
/// near-white and anything see-through do not). Signatures set no background, so white is what mail clients show.
fn readable_color(v: &str) -> bool {
    let Some((r, g, b)) = opaque_color(v) else { return false };
    let lin = |c: u8| {
        let c = f64::from(c) / 255.0;
        if c <= 0.04045 { c / 12.92 } else { ((c + 0.055) / 1.055).powf(2.4) }
    };
    let l = 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
    1.05 / (l + 0.05) >= 1.8
}

/// Whether `value` is allowed for `prop` (both lowercased and trimmed).
fn css_value_ok(prop: &str, value: &str) -> bool {
    let tokens = || value.split_whitespace();
    // Non-negative lengths up to `max` px (or 0, or `auto`).
    let length = |t: &str, max: f64| {
        t == "0"
            || t == "auto"
            || number_unit(t).is_some_and(|(n, u)| {
                (0.0..=max).contains(&n)
                    && matches!(u, "px" | "pt" | "%" | "em" | "")
                    && (!u.is_empty() || n == 0.0)
                    && (u != "%" || n <= 100.0)
                    && (u != "em" || n <= max / 16.0)
            })
    };
    match prop {
        "color" => readable_color(value),
        // Absolute sizes only, so nesting cannot shrink text.
        "font-size" => number_unit(value).is_some_and(|(n, u)| match u {
            "px" => (9.0..=72.0).contains(&n),
            "pt" => (7.0..=54.0).contains(&n),
            _ => false,
        }),
        "vertical-align" => {
            ["baseline", "top", "middle", "bottom", "text-top", "text-bottom"].contains(&value)
                || number_unit(value).is_some_and(|(n, u)| u == "px" && (-10.0..=10.0).contains(&n))
        }
        "line-height" => {
            value == "normal"
                || number_unit(value).is_some_and(|(n, u)| match u {
                    "" => (0.8..=3.0).contains(&n),
                    "px" => (9.0..=80.0).contains(&n),
                    "%" => (80.0..=300.0).contains(&n),
                    _ => false,
                })
        }
        "letter-spacing" => {
            value == "normal" || number_unit(value).is_some_and(|(n, u)| u == "px" && (0.0..=5.0).contains(&n))
        }
        p if p.starts_with("margin") || p.starts_with("padding") => {
            let n = tokens().count();
            (1..=4).contains(&n) && tokens().all(|t| length(t, 60.0))
        }
        "width" | "max-width" | "min-width" | "height" => length(value, 1200.0),
        // Borders cannot hide text; their colour may be anything opaque, so only references and tricks are refused.
        _ => !value
            .char_indices()
            .any(|(i, c)| c == '-' && value[i + 1..].starts_with(|n: char| n.is_ascii_digit() || n == '.')),
    }
}

/// Keeps the allowed declarations of a `style` value (None when nothing is left). Values never reference anything
/// (`url(`, `expression`, `@import`, escapes, `var(`, `calc(`) and pass the rule of their property.
fn clean_style(v: &str) -> Option<String> {
    let mut kept = Vec::new();
    for decl in v.split(';') {
        let Some((prop, value)) = decl.split_once(':') else { continue };
        let prop = prop.trim().to_ascii_lowercase();
        let value = value.trim().to_ascii_lowercase();
        if !CSS.contains(&prop.as_str()) || value.is_empty() || value.len() > 200 {
            continue;
        }
        let bad = [
            "url(",
            "expression",
            "@import",
            "javascript:",
            "\\",
            "behavior",
            "-moz-binding",
            "<",
            ">",
            "var(",
            "calc(",
            "!",
        ]
        .iter()
        .any(|b| value.contains(b));
        if !bad && css_value_ok(&prop, &value) {
            kept.push(format!("{prop}:{value}"));
        }
    }
    (!kept.is_empty()).then(|| kept.join(";"))
}

fn safe_href(v: &str) -> bool {
    let l = v.trim().to_ascii_lowercase();
    ["https://", "http://", "mailto:", "tel:"].iter().any(|p| l.starts_with(p)) && !v.chars().any(char::is_control)
}

/// Re-serializes `raw` from the allowlist. `cids` are the images this signature has; every `cid:` must name one.
/// Returns the clean HTML and the cids it uses.
pub fn clean_html(raw: &str, cids: &BTreeSet<String>) -> anyhow::Result<(String, BTreeSet<String>)> {
    if raw.len() > MAX_RAW_HTML_BYTES {
        bail!("the HTML is {} bytes; at most {MAX_RAW_HTML_BYTES} are accepted", raw.len());
    }
    let frag = Html::parse_fragment(raw);
    let mut out = String::new();
    let mut used = BTreeSet::new();
    // Iterative walk (deep nesting must not overflow the stack).
    enum Ev<'a> {
        El(ElementRef<'a>),
        Text(&'a str),
        Close(&'static str),
    }
    fn children<'a>(el: ElementRef<'a>, stack: &mut Vec<Ev<'a>>) {
        for c in el.children().collect::<Vec<_>>().into_iter().rev() {
            match c.value() {
                Node::Text(t) => stack.push(Ev::Text(t)),
                Node::Element(_) => stack.push(Ev::El(ElementRef::wrap(c).expect("element node"))),
                _ => {}
            }
        }
    }
    let mut stack: Vec<Ev<'_>> = Vec::new();
    children(frag.root_element(), &mut stack);
    while let Some(ev) = stack.pop() {
        let el = match ev {
            Ev::Close(tag) => {
                out.push_str("</");
                out.push_str(tag);
                out.push('>');
                continue;
            }
            Ev::Text(t) => {
                out.push_str(&html_escape(t));
                continue;
            }
            Ev::El(el) => el,
        };
        let name = el.value().name().to_ascii_lowercase();
        if DROP.contains(&name.as_str()) {
            continue;
        }
        let Some(tag) = KEEP.iter().find(|k| **k == name) else {
            // Unknown element: keep its content only.
            children(el, &mut stack);
            continue;
        };
        out.push('<');
        out.push_str(tag);
        for (k, v) in el.value().attrs() {
            let k = k.to_ascii_lowercase();
            if v.len() > 1024 {
                continue;
            }
            let keep = match k.as_str() {
                "href" => *tag == "a" && safe_href(v),
                "src" if *tag == "img" => {
                    let t = v.trim();
                    if let Some(cid) = t.strip_prefix("cid:") {
                        if !cids.contains(cid) {
                            bail!("the HTML uses cid:{} but the signature has no image with that cid", clip(cid));
                        }
                        used.insert(cid.to_string());
                        true
                    } else if t.to_ascii_lowercase().starts_with("https://") {
                        true
                    } else {
                        bail!("an image source must be cid:<name> or an https address");
                    }
                }
                "style" => {
                    if let Some(style) = clean_style(v) {
                        out.push_str(" style=\"");
                        out.push_str(&html_escape(&style));
                        out.push('"');
                    }
                    false
                }
                "color" => readable_color(&v.trim().to_ascii_lowercase()),
                a => ATTRS.contains(&a),
            };
            if keep {
                out.push(' ');
                out.push_str(&k);
                out.push_str("=\"");
                out.push_str(&html_escape(v.trim()));
                out.push('"');
            }
        }
        out.push('>');
        if !VOID.contains(tag) {
            stack.push(Ev::Close(tag));
            children(el, &mut stack);
        }
    }
    let out = out.trim().to_string();
    if out.is_empty() {
        bail!("the HTML has no content Dove keeps");
    }
    if out.len() > MAX_HTML_BYTES {
        bail!("the cleaned HTML is {} bytes; at most {MAX_HTML_BYTES} are allowed", out.len());
    }
    Ok((out, used))
}

/// Elements that end a line in the plain-text form.
const BREAKS: &[&str] = &[
    "br", "p", "div", "tr", "td", "th", "table", "li", "ul", "ol", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "center",
];

/// The plain-text form of a signature's (cleaned) HTML: one line per line break, paragraph or table cell, blank lines
/// dropped, images left out (logos say nothing in text), a link's address added only when its text does not show it.
pub fn text_from_html(html: &str) -> anyhow::Result<String> {
    let frag = Html::parse_fragment(html);
    enum Ev<'a> {
        El(ElementRef<'a>),
        Text(&'a str),
        Push(String),
    }
    let mut out = String::new();
    let mut stack: Vec<Ev<'_>> = vec![Ev::El(frag.root_element())];
    while let Some(ev) = stack.pop() {
        let el = match ev {
            Ev::Text(t) => {
                // Whitespace in HTML text collapses to single spaces.
                let mut last_space = out.ends_with([' ', '\n']) || out.is_empty();
                for ch in t.chars() {
                    if ch.is_whitespace() {
                        if !last_space {
                            out.push(' ');
                            last_space = true;
                        }
                    } else {
                        out.push(ch);
                        last_space = false;
                    }
                }
                continue;
            }
            Ev::Push(s) => {
                out.push_str(&s);
                continue;
            }
            Ev::El(el) => el,
        };
        let name = el.value().name();
        if name == "img" || DROP.contains(&name) {
            continue;
        }
        if BREAKS.contains(&name) {
            out.push('\n');
            stack.push(Ev::Push("\n".into()));
        }
        if name == "a"
            && let Some(href) = el.value().attr("href")
        {
            // Compared without spaces and separators, so "+49 176 1234" shows tel:+491761234.
            let squash = |t: &str| {
                t.chars().filter(|c| !c.is_whitespace() && !"-()/.".contains(*c)).collect::<String>().to_lowercase()
            };
            let shown = el.text().collect::<String>();
            let bare = href.trim().trim_start_matches("mailto:").trim_start_matches("tel:");
            let core = bare.trim_start_matches("https://").trim_start_matches("http://").trim_end_matches('/');
            if !shown.trim().is_empty() && !squash(&shown).contains(&squash(core)) {
                stack.push(Ev::Push(format!(" <{bare}>")));
            }
        }
        for c in el.children().collect::<Vec<_>>().into_iter().rev() {
            match c.value() {
                Node::Text(t) => stack.push(Ev::Text(t)),
                Node::Element(_) => stack.push(Ev::El(ElementRef::wrap(c).expect("element node"))),
                _ => {}
            }
        }
    }
    let lines: Vec<&str> = out.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    identity::clean_signature(&lines.join("\n"))
}

// ------------------------------------------------------------------ storage

/// What a create or change sets. `None` keeps the stored value (a new signature needs `html` or `text`).
#[derive(Debug, Default, Clone)]
pub struct Change {
    pub name: String,
    /// `Some("")` removes the HTML (the signature becomes text only).
    pub html: Option<String>,
    pub text: Option<String>,
    /// Replaces all images.
    pub images: Option<Vec<Image>>,
    /// Agent changes: a signature with HTML always gets the text derived from that HTML, so the text the owner reads
    /// (for example when approving a send) cannot say something else than the HTML the recipient sees.
    pub derive_text: bool,
}

fn account_id_of(conn: &Connection, mailbox: &str) -> anyhow::Result<String> {
    crate::admin::ops::account_id(conn, mailbox)
}

fn sig_id(conn: &Connection, aid: &str, name: &str) -> anyhow::Result<Option<i64>> {
    Ok(conn
        .query_row("SELECT id FROM signatures WHERE account_id = ?1 AND name = ?2", params![aid, name], |r| r.get(0))
        .optional()?)
}

/// Creates or changes signature `c.name` of `mailbox` (alias). The first signature of a mailbox becomes its default.
pub fn set(tx: &Transaction, mailbox: &str, c: Change, actor: &str) -> anyhow::Result<Value> {
    if !valid_name(&c.name) {
        bail!("a signature name is 1 to 40 lowercase letters, digits or '-', starting with a letter or digit");
    }
    let aid = account_id_of(tx, mailbox)?;
    let existing = load_by_id(tx, sig_id(tx, &aid, &c.name)?)?;
    if existing.is_none() {
        if c.html.as_deref().is_none_or(str::is_empty) && c.text.is_none() {
            bail!("a new signature needs html or text");
        }
        let n: i64 = tx.query_row("SELECT count(*) FROM signatures WHERE account_id = ?1", [&aid], |r| r.get(0))?;
        if n >= MAX_SIGNATURES {
            bail!("'{mailbox}' already has {MAX_SIGNATURES} signatures; delete one first");
        }
    }
    let images = match (c.images, &existing) {
        (Some(v), _) => v,
        (None, Some(e)) => e.images.clone(),
        (None, None) => vec![],
    };
    if images.len() > MAX_IMAGES {
        bail!("a signature has at most {MAX_IMAGES} images");
    }
    let total: usize = images.iter().map(|i| i.bytes.len()).sum();
    if total > MAX_IMAGE_BYTES {
        bail!("the images are {total} bytes together; at most {MAX_IMAGE_BYTES} are allowed");
    }
    let cids: BTreeSet<String> = images.iter().map(|i| i.cid.clone()).collect();
    if cids.len() != images.len() {
        bail!("two images have the same cid");
    }
    let raw_html = match (&c.html, &existing) {
        (Some(h), _) if h.trim().is_empty() => None,
        (Some(h), _) => Some(h.clone()),
        (None, Some(e)) => e.html.clone(),
        (None, None) => None,
    };
    let html = match &raw_html {
        Some(h) => {
            let (clean, used) = clean_html(h, &cids)?;
            if let Some(unused) = cids.difference(&used).next() {
                bail!("image '{unused}' is not used by the HTML (reference it as cid:{unused})");
            }
            Some(clean)
        }
        None => {
            if !images.is_empty() {
                bail!("images need HTML that shows them");
            }
            None
        }
    };
    if c.derive_text && html.is_some() && c.text.is_some() {
        bail!("a signature with HTML gets its text derived from the HTML; leave text out");
    }
    // Text: given, else derived from new HTML, else kept (for `derive_text`, derived again whenever there is HTML).
    let text = match (&c.text, &html, &existing) {
        (None, Some(h), _) if c.derive_text => text_from_html(h)?,
        (Some(t), _, _) => identity::clean_signature(t)?,
        (None, Some(h), _) if c.html.is_some() || existing.is_none() => text_from_html(h)?,
        (None, _, Some(e)) => e.text.clone(),
        (None, Some(h), None) => text_from_html(h)?,
        (None, None, None) => bail!("a new signature needs html or text"),
    };
    debug_assert!(text.len() <= MAX_SIGNATURE_BYTES);
    let now = util::now_unix();
    let id = match sig_id(tx, &aid, &c.name)? {
        Some(id) => {
            tx.execute(
                "UPDATE signatures SET text = ?1, html = ?2, updated_at = ?3, updated_by = ?4 WHERE id = ?5",
                params![text, html, now, actor, id],
            )?;
            tx.execute("DELETE FROM signature_images WHERE signature_id = ?1", [id])?;
            id
        }
        None => {
            tx.execute(
                "INSERT INTO signatures(account_id, name, text, html, created_at, updated_at, updated_by) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
                params![aid, c.name, text, html, now, actor],
            )?;
            tx.last_insert_rowid()
        }
    };
    for i in &images {
        tx.execute(
            "INSERT INTO signature_images(signature_id, cid, mime_type, bytes) VALUES (?1, ?2, ?3, ?4)",
            params![id, i.cid, i.mime_type, i.bytes],
        )?;
    }
    let became_default = tx.execute(
        "INSERT OR IGNORE INTO signature_defaults(account_id, address, signature_id) VALUES (?1, '', ?2)",
        params![aid, id],
    )? == 1;
    // Whether what recipients get changed (an identical call changes nothing).
    let changed = existing.as_ref().is_none_or(|e| {
        let mut new: Vec<&Image> = images.iter().collect();
        new.sort_by(|a, b| a.cid.cmp(&b.cid));
        e.text != text || e.html != html || e.images.iter().collect::<Vec<_>>() != new
    }) || became_default;
    Ok(json!({
        "account": mailbox, "name": c.name, "created": existing.is_none(), "changed": changed, "has_html": html.is_some(),
        "text_bytes": text.len(), "images": images.iter().map(|i| &i.cid).collect::<Vec<_>>(),
        "became_default": became_default,
    }))
}

/// Makes `name` the default of the mailbox (`for_address` None) or of one of its send-as addresses; `name` None
/// removes that default (no signature unless the agent names one).
pub fn set_default(
    tx: &Transaction,
    mailbox: &str,
    for_address: Option<&str>,
    name: Option<&str>,
) -> anyhow::Result<Value> {
    let aid = account_id_of(tx, mailbox)?;
    let key = identity::signature_key(tx, &aid, mailbox, for_address)?;
    let before: Option<i64> = tx
        .query_row(
            "SELECT signature_id FROM signature_defaults WHERE account_id = ?1 AND address = ?2",
            params![aid, key],
            |r| r.get(0),
        )
        .optional()?;
    let after = match name {
        Some(n) => sig_id(tx, &aid, n)?,
        None => None,
    };
    match name {
        Some(n) => {
            let id = sig_id(tx, &aid, n)?.ok_or_else(|| anyhow!("'{mailbox}' has no signature '{}'", clip(n)))?;
            tx.execute(
                "INSERT INTO signature_defaults(account_id, address, signature_id) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(account_id, address) DO UPDATE SET signature_id = excluded.signature_id",
                params![aid, key, id],
            )?;
        }
        None => {
            tx.execute("DELETE FROM signature_defaults WHERE account_id = ?1 AND address = ?2", params![aid, key])?;
        }
    }
    Ok(
        json!({ "account": mailbox, "for_address": for_address.map(|_| &key), "default": name, "changed": before != after }),
    )
}

/// Deletes a signature (and any default that pointed to it). Returns whether it existed.
pub fn delete(tx: &Transaction, mailbox: &str, name: &str) -> anyhow::Result<bool> {
    let aid = account_id_of(tx, mailbox)?;
    Ok(tx.execute("DELETE FROM signatures WHERE account_id = ?1 AND name = ?2", params![aid, name])? == 1)
}

fn load_by_id(conn: &Connection, id: Option<i64>) -> anyhow::Result<Option<Signature>> {
    let Some(id) = id else { return Ok(None) };
    let (name, text, html): (String, String, Option<String>) =
        conn.query_row("SELECT name, text, html FROM signatures WHERE id = ?1", [id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
    let mut st =
        conn.prepare_cached("SELECT cid, mime_type, bytes FROM signature_images WHERE signature_id = ?1 ORDER BY cid")?;
    let images = st
        .query_map([id], |r| Ok(Image { cid: r.get(0)?, mime_type: r.get(1)?, bytes: r.get(2)? }))?
        .collect::<Result<_, _>>()?;
    Ok(Some(Signature { name, text, html, images }))
}

/// Signature `name` of the account, if it exists.
pub fn load(conn: &Connection, account_id: &str, name: &str) -> anyhow::Result<Option<Signature>> {
    load_by_id(conn, sig_id(conn, account_id, name)?)
}

/// The default signature for mail sent as `from_email`: the address's own default, else the mailbox's, else none.
pub fn default_for(conn: &Connection, account_id: &str, from_email: &str) -> anyhow::Result<Option<Signature>> {
    let from = from_email.to_lowercase();
    let mut st =
        conn.prepare_cached("SELECT signature_id FROM signature_defaults WHERE account_id = ?1 AND address = ?2")?;
    for key in [from.as_str(), MAILBOX_DEFAULT] {
        if let Some(id) = st.query_row(params![account_id, key], |r| r.get::<_, i64>(0)).optional()? {
            return load_by_id(conn, Some(id));
        }
    }
    Ok(None)
}

/// One `signatures` row as `list` reads it: id, name, text, html, updated_at, updated_by, defaults (JSON array).
type ListRow = (i64, String, String, Option<String>, i64, String, String);

/// The mailbox's signatures for `list_signatures` and the admin socket. No image bytes.
pub fn list(conn: &Connection, account_id: &str, include_html: bool) -> anyhow::Result<Vec<Value>> {
    let mut st = conn.prepare(
        "SELECT s.id, s.name, s.text, s.html, s.updated_at, s.updated_by, \
                (SELECT json_group_array(CASE d.address WHEN '' THEN 'mailbox' ELSE d.address END) \
                 FROM signature_defaults d WHERE d.signature_id = s.id) \
         FROM signatures s WHERE s.account_id = ?1 ORDER BY s.name",
    )?;
    let rows: Vec<ListRow> = st
        .query_map([account_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)))?
        .collect::<Result<_, _>>()?;
    let mut img = conn
        .prepare("SELECT cid, mime_type, length(bytes) FROM signature_images WHERE signature_id = ?1 ORDER BY cid")?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, name, text, html, updated_at, updated_by, defaults) in rows {
        let images: Vec<Value> = img
            .query_map([id], |r| {
                Ok(json!({ "cid": r.get::<_, String>(0)?, "mime_type": r.get::<_, String>(1)?, "bytes": r.get::<_, i64>(2)? }))
            })?
            .collect::<Result<_, _>>()?;
        let default_for: Value = serde_json::from_str(&defaults).unwrap_or(json!([]));
        let mut v = json!({
            "name": name, "default_for": default_for, "text": text, "has_html": html.is_some(), "images": images,
            "updated_at": util::rfc3339(updated_at), "updated_by": updated_by,
        });
        if include_html {
            v["html"] = json!(html);
        }
        out.push(v);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cids(v: &[&str]) -> BTreeSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn clean_html_keeps_layout_and_drops_active_content() {
        let raw = r#"<table cellpadding="0" style="color:#17171A;font-size:14px" onclick="x()"><tr><td>
            <img src="cid:keyset-logo" width="18" alt="" style="border:0"><span>&nbsp;Keyset</span>
            <a href="https://keyset.cloud/" target="_blank">keyset.cloud</a> <a href="javascript:alert(1)">x</a>
            <script>alert(1)</script><style>td{}</style><iframe src="https://e.vil"></iframe>
            <div style="background:url(https://track.er/p.gif)">bg</div><custom-tag>kept text</custom-tag>
            <!-- comment --></td></tr></table>"#;
        let (out, used) = clean_html(raw, &cids(&["keyset-logo"])).unwrap();
        assert_eq!(used, cids(&["keyset-logo"]));
        for gone in [
            "onclick",
            "script",
            "alert",
            "<style",
            "iframe",
            "e.vil",
            "url(",
            "track.er",
            "comment",
            "target",
            "custom-tag",
        ] {
            assert!(!out.contains(gone), "{gone} in {out}");
        }
        for kept in [
            "<table cellpadding=\"0\" style=\"color:#17171a;font-size:14px\">",
            // Attributes come out in the parser's (sorted) order.
            "<img alt=\"\" src=\"cid:keyset-logo\" style=\"border:0\" width=\"18\">",
            "<a href=\"https://keyset.cloud/\">keyset.cloud</a>",
            "<a>x</a>",
            "<div>bg</div>",
            "kept text",
            "\u{a0}Keyset",
        ] {
            assert!(out.contains(kept), "{kept} missing in {out}");
        }
    }

    #[test]
    fn clean_html_checks_image_sources() {
        assert!(clean_html(r#"<img src="cid:nope">"#, &cids(&["logo"])).unwrap_err().to_string().contains("cid:nope"));
        assert!(clean_html(r#"<img src="http://x.org/a.png">"#, &cids(&[])).is_err());
        assert!(clean_html(r#"<img src="data:image/png;base64,AAAA">"#, &cids(&[])).is_err());
        assert!(clean_html(r#"<img src="https://x.org/a.png">"#, &cids(&[])).is_ok());
        assert!(clean_html("<script>x</script>", &cids(&[])).is_err(), "nothing left");
        // Escaping survives the round trip: text and attribute values cannot break out.
        let (out, _) = clean_html(r#"<span title="a&quot;b">1 &lt; 2 &amp; <b>3</b></span>"#, &cids(&[])).unwrap();
        assert_eq!(out, "<span title=\"a&quot;b\">1 &lt; 2 &amp; <b>3</b></span>");
    }

    #[test]
    fn styles_cannot_hide_or_move_text() {
        let style = |s: &str| clean_style(s);
        assert_eq!(
            style("color:#333; font-size:13px; FONT-WEIGHT: bold; padding:0 8px; border-left:2px solid #c00")
                .as_deref(),
            Some("color:#333;font-size:13px;font-weight:bold;padding:0 8px;border-left:2px solid #c00")
        );
        for hidden in [
            "display:none",
            "visibility:hidden",
            "opacity:0",
            "font-size:0",
            "font-size:1px",
            "font-size:0.1em",
            "font-size:xx-small",
            "position:absolute;left:-9999px",
            "margin-left:-9999px",
            "text-indent:-9999px",
            "max-height:0;overflow:hidden",
            "color:transparent",
            "color:rgba(0,0,0,0)",
            "color:#0000",
            "color:#ffffff00",
            "width:calc(0px)",
            "background-color:var(--x)",
            "font-family:x;background:url(https://e.vil/p)",
            "color:#fff",
            "color:#fefefe",
            "color:white",
            "color:rgb(255,255,255)",
            "color:rgb(0 0 0 / 0)",
            "color:hsl(0,0%,0%)",
            "color:currentcolor",
            "background-color:#000",
            "font-size:1em",
            "font-size:100%",
            "font-size:8px",
            "letter-spacing:-3px",
            "line-height:0",
            "vertical-align:-500px",
            "padding:9999px",
            "margin:0 0 0 -50px",
            "color:#000 !important",
        ] {
            let kept = style(hidden).unwrap_or_default();
            let expected = if hidden.starts_with("font-family") { "font-family:x" } else { "" };
            assert_eq!(kept, expected, "{hidden}");
        }
        // An element whose whole style is dropped loses the attribute.
        let (out, _) = clean_html("<span style=\"display:none\">geheim</span>", &BTreeSet::new()).unwrap();
        assert_eq!(out, "<span>geheim</span>");
        // The legacy attributes and tags follow the same rules; the template's styles all pass.
        let (out, _) = clean_html(
            "<font color=\"#ffffff\" size=\"1\" bgcolor=\"#fff\">a</font><font color=\"#17171A\">b</font>\
             <small><small>c</small></small><sup>d</sup>",
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(out, "<font>a</font><font color=\"#17171A\">b</font>cd");
        let kept = "color:#b0b0b8;font-size:11px;vertical-align:-4px;padding-top:14px;line-height:1.5";
        assert_eq!(style(kept).as_deref(), Some(kept));
    }

    #[test]
    fn deep_nesting_does_not_overflow() {
        // 2500 levels stay under the cleaned-size cap; a recursive walk would need a frame per level.
        let raw = "<div>".repeat(2500) + "x" + &"</div>".repeat(2500);
        let (out, _) = clean_html(&raw, &cids(&[])).unwrap();
        assert_eq!(out.matches("<div>").count(), 2500);
    }

    #[test]
    fn images_are_recognized_by_their_bytes() {
        let png = b"\x89PNG\r\n\x1a\nrest".to_vec();
        assert_eq!(image("logo", None, png.clone()).unwrap().mime_type, "image/png");
        assert_eq!(image("logo", Some("image/PNG"), png.clone()).unwrap().mime_type, "image/png");
        assert!(image("logo", Some("image/gif"), png.clone()).is_err());
        assert!(image("logo", None, b"<svg/>".to_vec()).is_err());
        assert!(image("bad cid", None, png).is_err());
        assert_eq!(sniff_image(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("image/jpeg"));
        assert_eq!(sniff_image(b"GIF89a.."), Some("image/gif"));
    }

    #[test]
    fn text_is_derived_from_html_line_by_line() {
        let t = text_from_html(
            "<table><tr><td><b>Dominik Lenhart</b></td></tr><tr><td>Keyset &middot; Direktbuchung</td></tr>\
             <tr><td><a href=\"https://keyset.cloud/\">keyset.cloud</a></td></tr></table>",
        )
        .unwrap();
        assert_eq!(t, "Dominik Lenhart\nKeyset · Direktbuchung\nkeyset.cloud");
        // Images are left out; a link shows its address only when its text does not; whitespace collapses.
        let t = text_from_html(
            "<img src=\"cid:logo\" alt=\"Logo\"><p>Dominik   <i>Lenhart</i><br>\n  <a href=\"https://keyset.cloud/kontakt\">Kontakt</a> \
             | <a href=\"mailto:dominik@keyset.cloud\">dominik@keyset.cloud</a> | <a href=\"tel:+4930123\">Tel.</a></p>",
        )
        .unwrap();
        assert_eq!(
            t,
            "Dominik Lenhart\nKontakt <https://keyset.cloud/kontakt> | dominik@keyset.cloud | Tel. <+4930123>"
        );
        let t = text_from_html("<a href=\"tel:+4917663236211\">+49 176 63236211</a>").unwrap();
        assert_eq!(t, "+49 176 63236211");
    }

    #[test]
    fn names_and_cids() {
        assert!(valid_name("behoerden") && valid_name("a") && valid_name("alias-1"));
        assert!(!valid_name("-x") && !valid_name("Groß") && !valid_name("") && !valid_name(&"a".repeat(41)));
        assert!(valid_cid("keyset-logo") && valid_cid("a.b_c") && !valid_cid("a b") && !valid_cid("a@b"));
    }
}
