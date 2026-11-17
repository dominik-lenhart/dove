//! How Dove composes a draft body from the agent's text, a signature and a quote or forward block (design 2026-11-17
//! "html signatures"), and how it takes its own draft apart again for `get_draft` and `update_draft`.
//!
//! Text: `body`, then `-- ` and the signature's text, then the quote or forward block, separated by blank lines. HTML
//! (only when the signature has HTML): the body escaped with line breaks, the signature's cleaned HTML, and the block
//! with `>` quote runs as `<blockquote>`. The signature is always above the quote.
//!
//! [`Composition`] (stored in `own_drafts.composition`) records the signature's name and the byte lengths of the body
//! and the signature block in the text part. It holds no content: the parts are cut out of Dove's own, unchanged draft.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ToolError;
use crate::http::html_escape;
use crate::mime::{self, DraftHtml, InlineImage};
use crate::signatures::{self, Signature};

/// Which signature a create or update asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigChoice {
    /// The default for the sender (none when there is no default).
    Default,
    None,
    Named(String),
}

impl SigChoice {
    /// `signature`: absent, null or true = default, false = none, a name = that signature.
    pub fn parse(v: Option<&Value>) -> Result<Self, ToolError> {
        match v {
            None | Some(Value::Null) | Some(Value::Bool(true)) => Ok(SigChoice::Default),
            Some(Value::Bool(false)) => Ok(SigChoice::None),
            Some(Value::String(s)) if signatures::valid_name(s) => Ok(SigChoice::Named(s.clone())),
            Some(Value::String(_)) => Err(ToolError::invalid_at("signature", "not a valid signature name")),
            Some(_) => Err(ToolError::invalid_at("signature", "must be true, false or a signature name")),
        }
    }

    /// Canonical form for the create idempotency hash.
    pub fn canonical(&self) -> Value {
        match self {
            SigChoice::Default => Value::Bool(true),
            SigChoice::None => Value::Bool(false),
            SigChoice::Named(n) => Value::String(n.clone()),
        }
    }
}

/// How Dove composed its own draft's text part (byte lengths; the tail is what follows).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Composition {
    pub signature: Option<String>,
    pub body: usize,
    pub sig: usize,
}

/// A composed body: the text part, the HTML alternative (when the signature has HTML) and how it was composed.
#[derive(Debug, Clone)]
pub struct Composed {
    pub text: String,
    pub html: Option<DraftHtml>,
    pub composition: Composition,
}

/// Composes `body`, the signature and `tail` (a quote or forward block without surrounding blank lines). The block
/// is cut at a line end to keep the text within [`mime::MAX_BODY_BYTES`].
pub fn compose(body: &str, sig: Option<&Signature>, tail: &str) -> Composed {
    let mut text;
    let body_len;
    if sig.is_none() && tail.is_empty() {
        // Nothing appended: the agent's text exactly as given (as before signatures).
        text = body.to_string();
        body_len = text.len();
    } else {
        text = body.trim_end().to_string();
        body_len = text.len();
        if let Some(s) = sig {
            if !text.is_empty() {
                text.push_str("\n\n");
            }
            text.push_str("-- \n");
            text.push_str(&s.text);
        }
    }
    let sig_len = text.len() - body_len;
    let mut kept_tail = "";
    if !tail.is_empty() {
        let sep = if text.is_empty() { 0 } else { 2 };
        let room = mime::MAX_BODY_BYTES.saturating_sub(text.len() + sep + 1);
        kept_tail = cut(tail, room);
        if !kept_tail.is_empty() {
            if sep > 0 {
                text.push_str("\n\n");
            }
            text.push_str(kept_tail);
        }
    }
    if sig.is_some() || !kept_tail.is_empty() {
        text.push('\n');
    }
    let html = sig.and_then(|s| {
        s.html.as_ref().map(|h| DraftHtml {
            html: render_html(&text[..body_len], h, kept_tail),
            images: s
                .images
                .iter()
                .map(|i| InlineImage { cid: i.cid.clone(), mime_type: i.mime_type.clone(), bytes: i.bytes.clone() })
                .collect(),
        })
    });
    Composed {
        text,
        html,
        composition: Composition { signature: sig.map(|s| s.name.clone()), body: body_len, sig: sig_len },
    }
}

/// `s` cut to at most `max` bytes at a line end.
fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..s[..end].rfind('\n').unwrap_or(end)]
}

/// The parts of Dove's own draft text by its composition: (body, signature block, tail block). `None` when the
/// lengths do not fit the text (the draft is not what Dove recorded).
pub fn split<'t>(text: &'t str, c: &Composition) -> Option<(&'t str, &'t str, &'t str)> {
    let end = c.body.checked_add(c.sig)?;
    if end > text.len() || !text.is_char_boundary(c.body) || !text.is_char_boundary(end) {
        return None;
    }
    let sig = &text[c.body..end];
    let marker = if c.body == 0 { "-- \n" } else { "\n\n-- \n" };
    if c.signature.is_some() != !sig.is_empty() || (!sig.is_empty() && !sig.starts_with(marker)) {
        return None;
    }
    Some((&text[..c.body], sig, text[end..].trim_matches('\n')))
}

fn text_html(s: &str) -> String {
    html_escape(s).replace('\n', "<br>\n")
}

/// The HTML alternative: body, signature, then the tail with `>` runs as blockquotes.
fn render_html(body: &str, sig_html: &str, tail: &str) -> String {
    let mut h = String::from("<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head><body>\n<div dir=\"auto\">");
    h.push_str(&text_html(body));
    h.push_str("</div>\n");
    h.push_str("<br>\n<div class=\"dove-signature\">");
    h.push_str(sig_html);
    h.push_str("</div>\n");
    if !tail.is_empty() {
        h.push_str("<br>\n<div class=\"dove-quote\">");
        let mut in_quote = false;
        let mut lines = Vec::new();
        let flush = |h: &mut String, lines: &mut Vec<String>, quote: bool| {
            if lines.is_empty() {
                return;
            }
            if quote {
                h.push_str(
                    "<blockquote type=\"cite\" style=\"margin:0 0 0 .8ex;border-left:2px solid #ccc;padding-left:1ex\">",
                );
            }
            h.push_str(&lines.iter().map(|l| html_escape(l)).collect::<Vec<_>>().join("<br>\n"));
            h.push_str(if quote { "</blockquote>\n" } else { "<br>\n" });
            lines.clear();
        };
        for line in tail.lines() {
            let q = line.starts_with('>');
            if q != in_quote {
                flush(&mut h, &mut lines, in_quote);
                in_quote = q;
            }
            let l = if q { line.strip_prefix("> ").or_else(|| line.strip_prefix('>')).unwrap_or(line) } else { line };
            lines.push(l.to_string());
        }
        flush(&mut h, &mut lines, in_quote);
        h.push_str("</div>\n");
    }
    h.push_str("</body></html>\n");
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::Image;

    fn sig(html: Option<&str>) -> Signature {
        Signature {
            name: "behoerden".into(),
            text: "Dominik Lenhart\nKeyset".into(),
            html: html.map(str::to_string),
            images: vec![Image { cid: "keyset-logo".into(), mime_type: "image/png".into(), bytes: vec![1, 2] }],
        }
    }

    #[test]
    fn plain_body_stays_exactly_as_given() {
        let c = compose("Hallo  \n", None, "");
        assert_eq!(c.text, "Hallo  \n");
        assert!(c.html.is_none());
        assert_eq!(split(&c.text, &c.composition), Some(("Hallo  \n", "", "")));
    }

    #[test]
    fn signature_sits_between_body_and_quote_in_text_and_html() {
        let tail = "On Mon, 1 Jan 2024, A <a@x.org> wrote:\n> Frage?\n>\n> <b>Gruß</b>";
        let c = compose("Hallo,\nja gern.\n\n", Some(&sig(Some("<b>Dominik</b> <img src=\"cid:keyset-logo\">"))), tail);
        assert_eq!(c.text, format!("Hallo,\nja gern.\n\n-- \nDominik Lenhart\nKeyset\n\n{tail}\n"));
        let (b, s, t) = split(&c.text, &c.composition).unwrap();
        assert_eq!((b, s, t), ("Hallo,\nja gern.", "\n\n-- \nDominik Lenhart\nKeyset", tail));
        let h = c.html.unwrap();
        let (body_at, sig_at, quote_at) =
            (h.html.find("ja gern.").unwrap(), h.html.find("<b>Dominik</b>").unwrap(), h.html.find("Frage?").unwrap());
        assert!(body_at < sig_at && sig_at < quote_at, "{}", h.html);
        assert!(h.html.contains("Hallo,<br>\nja gern."));
        assert!(h.html.contains("<blockquote type=\"cite\""));
        assert!(h.html.contains("&lt;b&gt;Gruß&lt;/b&gt;"), "quoted text is escaped: {}", h.html);
        assert!(!h.html.contains("&gt; Frage"), "the > markers become the blockquote");
        assert_eq!(h.images.len(), 1);
        assert_eq!(c.composition.signature.as_deref(), Some("behoerden"));
    }

    #[test]
    fn text_only_signature_builds_no_html() {
        let c = compose("Hi", Some(&sig(None)), "");
        assert_eq!(c.text, "Hi\n\n-- \nDominik Lenhart\nKeyset\n");
        assert!(c.html.is_none());
    }

    #[test]
    fn split_refuses_lengths_that_do_not_fit() {
        let c = compose("Hi", Some(&sig(None)), "");
        let mut bad = c.composition.clone();
        bad.body += 1;
        assert_eq!(split(&c.text, &bad), None);
        bad = c.composition.clone();
        bad.sig = 10_000;
        assert_eq!(split(&c.text, &bad), None);
        bad = c.composition.clone();
        bad.signature = None;
        assert_eq!(split(&c.text, &bad), None);
        assert_eq!(split("Ünï", &Composition { signature: None, body: 1, sig: 0 }), None, "not a char boundary");
    }

    #[test]
    fn choice_parsing() {
        assert_eq!(SigChoice::parse(None).unwrap(), SigChoice::Default);
        assert_eq!(SigChoice::parse(Some(&Value::Bool(false))).unwrap(), SigChoice::None);
        assert_eq!(
            SigChoice::parse(Some(&serde_json::json!("gastgeber"))).unwrap(),
            SigChoice::Named("gastgeber".into())
        );
        assert!(SigChoice::parse(Some(&serde_json::json!("Bad Name"))).is_err());
        assert!(SigChoice::parse(Some(&serde_json::json!(1))).is_err());
    }
}
