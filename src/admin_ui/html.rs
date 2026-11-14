//! The admin UI's template layer. Every dynamic value is escaped: [`h!`] takes a literal format string and wraps each
//! argument in [`Esc`], which escapes text and passes only [`Markup`] through unchanged. `Markup` is built only by
//! [`h!`], from `&'static str` literals ([`Markup::lit`]) or by joining other `Markup`. Format strings must use
//! positional `{}` only (a captured `{name}` would bypass the escaping; `tests::templates_use_positional_args` scans
//! the sources).
//!
//! Untrusted text (draft content, mail headers, agent notes, client names, audit fields) additionally loses control
//! characters and bidirectional overrides, which are shown as U+FFFD, so a subject cannot reorder what the owner reads
//! (the same rule as `cli::terminal_safe`).

use std::fmt::{self, Write as _};

use axum::http::{HeaderValue, header};
use axum::response::{Html, IntoResponse, Response};

/// HTML that is safe to emit as is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Markup(String);

impl Markup {
    pub fn lit(s: &'static str) -> Self {
        Markup(s.to_string())
    }

    pub fn concat(parts: impl IntoIterator<Item = Markup>) -> Self {
        let mut s = String::new();
        for p in parts {
            s.push_str(&p.0);
        }
        Markup(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Only for [`h!`]: the caller must have escaped every argument.
    pub(crate) fn from_format(args: fmt::Arguments<'_>) -> Self {
        Markup(fmt::format(args))
    }
}

/// How a value goes into HTML.
pub trait Render {
    fn render(&self, out: &mut String);
}

impl Render for str {
    fn render(&self, out: &mut String) {
        escape_into(self, out);
    }
}

impl Render for String {
    fn render(&self, out: &mut String) {
        escape_into(self, out);
    }
}

impl Render for Markup {
    fn render(&self, out: &mut String) {
        out.push_str(&self.0);
    }
}

impl<T: Render + ?Sized> Render for &T {
    fn render(&self, out: &mut String) {
        (**self).render(out);
    }
}

impl<T: Render> Render for Option<T> {
    fn render(&self, out: &mut String) {
        if let Some(v) = self {
            v.render(out);
        }
    }
}

macro_rules! render_number {
    ($($t:ty),*) => {$(
        impl Render for $t {
            fn render(&self, out: &mut String) {
                let _ = write!(out, "{}", self);
            }
        }
    )*};
}
render_number!(i64, u64, u32, i32, usize);

/// Display adapter used by [`h!`]: escapes everything except [`Markup`].
pub struct Esc<'a, T: Render + ?Sized>(pub &'a T);

impl<T: Render + ?Sized> fmt::Display for Esc<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        self.0.render(&mut s);
        f.write_str(&s)
    }
}

/// Builds [`Markup`] from a literal template with positional `{}` arguments, each escaped.
macro_rules! h {
    ($fmt:literal $(, $arg:expr)* $(,)?) => {
        $crate::admin_ui::html::Markup::from_format(format_args!($fmt $(, $crate::admin_ui::html::Esc(&$arg))*))
    };
}
pub(crate) use h;

fn unsafe_char(c: char) -> bool {
    (c.is_control() && c != '\n' && c != '\t')
        || matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{061c}')
}

/// Escapes `s` for HTML text and quoted attribute values.
pub fn escape_into(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if unsafe_char(c) => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
}

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    escape_into(s, &mut out);
    out
}

/// An HTML answer.
pub fn respond(m: Markup) -> Response {
    let mut r = Html(m.0).into_response();
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// Navigation entries (part 2 adds Connections, Mailboxes, Projects, Watches).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Nav {
    Overview,
    Requests,
    Audit,
    Settings,
    None,
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn head(title: &str, csrf: Option<&str>) -> Markup {
    let csrf_meta = match csrf {
        Some(t) => h!("<meta name=\"dove-csrf\" content=\"{}\">", t),
        None => Markup::default(),
    };
    h!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"color-scheme\" content=\"light dark\"><meta name=\"robots\" content=\"noindex\">{}\
         <title>{} – Dove</title>\
         <link rel=\"stylesheet\" href=\"/admin/static/admin.css?v={}\">\
         <script src=\"/admin/static/admin.js?v={}\" defer></script></head>",
        csrf_meta,
        title,
        VERSION,
        VERSION
    )
}

fn brand() -> Markup {
    Markup::lit(
        "<a class=\"brand\" href=\"/admin\" aria-label=\"Dove admin, overview\">\
         <svg viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M3 13c4 0 6-2 8-6 1 3 3 5 6 5l4-2-2 4c-1 3-4 5-8 \
         5H6l-3 3z\"/></svg><span>Dove</span></a>",
    )
}

/// A full page for a signed-in session.
pub fn page(title: &str, nav: Nav, csrf: &str, label: &str, body: Markup) -> Markup {
    let item = |n: Nav, href: &'static str, text: &'static str| {
        if n == nav {
            h!("<a href=\"{}\" aria-current=\"page\">{}</a>", href, text)
        } else {
            h!("<a href=\"{}\">{}</a>", href, text)
        }
    };
    let navs = Markup::concat([
        item(Nav::Overview, "/admin", "Overview"),
        item(Nav::Requests, "/admin/requests", "Requests"),
        item(Nav::Audit, "/admin/audit", "Audit"),
        item(Nav::Settings, "/admin/settings", "Settings"),
    ]);
    h!(
        "{}<body><header class=\"top\"><div class=\"top-inner\">{}<nav aria-label=\"Main\">{}</nav>\
         <form class=\"signout\" method=\"post\" action=\"/admin/logout\"><input type=\"hidden\" name=\"csrf\" \
         value=\"{}\"><button type=\"submit\" title=\"Signed in with the passkey {}\">Sign out</button></form>\
         </div></header><main id=\"main\">{}</main></body></html>",
        head(title, Some(csrf)),
        brand(),
        navs,
        csrf,
        label,
        body
    )
}

/// A page without a session (sign-in, enrolment).
fn bare(title: &str, body: Markup) -> Markup {
    h!(
        "{}<body class=\"bare\"><main id=\"main\" class=\"narrow\">{}{}</main></body></html>",
        head(title, None),
        brand(),
        body
    )
}

pub fn login_page() -> Markup {
    bare(
        "Sign in",
        Markup::lit(
            "<section class=\"card signin\"><h1>Sign in</h1>\
             <p>Use the passkey you enrolled for this Dove. Your device asks for your PIN, fingerprint or face.</p>\
             <button type=\"button\" class=\"btn primary wide\" data-action=\"login\">Sign in with passkey</button>\
             <p class=\"status\" role=\"status\" aria-live=\"polite\"></p>\
             <p class=\"hint\">No passkey yet? On the server, run <code>sudo dove admin passkey add --name \
             &lt;device&gt;</code> and open the link it prints.</p></section>",
        ),
    )
}

pub fn enrol_page() -> Markup {
    bare(
        "Add a passkey",
        Markup::lit(
            "<section class=\"card signin\"><h1>Add a passkey</h1>\
             <p>This link adds a passkey for signing in to Dove's admin pages. It works once and for five \
             minutes.</p><button type=\"button\" class=\"btn primary wide\" data-action=\"enrol\">Create \
             passkey</button><p class=\"status\" role=\"status\" aria-live=\"polite\"></p>\
             <p class=\"hint\">Use a device you keep with you. Dove asks for this passkey again before it \
             approves anything.</p></section>",
        ),
    )
}

/// A short page for a failed action.
pub fn problem(title: &str, csrf: &str, label: &str, message: &str, back: &str) -> Markup {
    page(
        title,
        Nav::None,
        csrf,
        label,
        h!(
            "<section class=\"card\"><h1>{}</h1><p class=\"notice error\">{}</p><p><a class=\"btn\" href=\"{}\">\
             Back</a></p></section>",
            title,
            message,
            back
        ),
    )
}

/// `2026-11-14T09:30:00Z` as `14 Nov 2026, 09:30 UTC`; anything else is returned as given.
pub fn when(rfc3339: &str) -> String {
    let fmt = time::format_description::well_known::Rfc3339;
    match time::OffsetDateTime::parse(rfc3339, &fmt) {
        Ok(t) => {
            let t = t.to_offset(time::UtcOffset::UTC);
            let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
            format!(
                "{} {} {}, {:02}:{:02} UTC",
                t.day(),
                months[usize::from(u8::from(t.month())) - 1],
                t.year(),
                t.hour(),
                t.minute()
            )
        }
        Err(_) => rfc3339.to_string(),
    }
}

/// A `<time>` element for an RFC 3339 instant.
pub fn time_el(rfc3339: &str) -> Markup {
    h!("<time datetime=\"{}\">{}</time>", rfc3339, when(rfc3339))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping() {
        let evil = "<script>alert(1)</script>\"'&";
        assert_eq!(
            h!("<p title=\"{}\">{}</p>", evil, evil).as_str(),
            "<p title=\"&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#39;&amp;\">&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#39;&amp;</p>"
        );
        let inner = h!("<b>{}</b>", "<i>");
        assert_eq!(h!("<p>{}</p>", inner).as_str(), "<p><b>&lt;i&gt;</b></p>", "Markup nests unescaped once");
        assert_eq!(h!("{}", "a\u{202e}b\u{1b}[31mc\nd").as_str(), "a\u{fffd}b\u{fffd}[31mc\nd");
        assert_eq!(h!("{}{}", 5i64, Some("x".to_string())).as_str(), "5x");
    }

    /// Every `h!` template in the admin UI uses positional `{}` only, so no value can skip [`Esc`].
    #[test]
    fn templates_use_positional_args() {
        for (name, src) in [("html.rs", include_str!("html.rs")), ("pages.rs", include_str!("pages.rs"))] {
            let src = src.split("#[cfg(test)]").next().unwrap();
            for part in src.split("h!(").skip(1) {
                let lit = part.trim_start();
                if !lit.starts_with('"') {
                    continue;
                }
                let end = lit[1..].find("\",").or_else(|| lit[1..].find("\")")).unwrap_or(lit.len() - 1);
                let body = lit[1..=end].replace("{{", "").replace("}}", "");
                let mut rest = body.as_str();
                while let Some(i) = rest.find('{') {
                    assert!(
                        rest[i..].starts_with("{}"),
                        "{name}: template with a named or formatted argument: {lit:.80}"
                    );
                    rest = &rest[i + 2..];
                }
            }
        }
    }

    #[test]
    fn times() {
        assert_eq!(when("2026-11-14T09:05:00Z"), "14 Nov 2026, 09:05 UTC");
        assert_eq!(when("nonsense"), "nonsense");
    }
}
