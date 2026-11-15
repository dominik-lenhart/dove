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

/// Navigation entries.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Nav {
    Overview,
    Requests,
    Connections,
    Mailboxes,
    Projects,
    Watches,
    Audit,
    Settings,
    None,
}

fn head(title: &str, csrf: Option<&str>) -> Markup {
    let csrf_meta = match csrf {
        Some(t) => h!("<meta name=\"dove-csrf\" content=\"{}\">", t),
        None => Markup::default(),
    };
    h!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">\
         <meta name=\"color-scheme\" content=\"light\"><meta name=\"robots\" content=\"noindex\">{}\
         <title>{} – Dove</title>\
         <link rel=\"preload\" href=\"/admin/static/inter.woff2\" as=\"font\" type=\"font/woff2\" \
         crossorigin><link rel=\"stylesheet\" href=\"/admin/static/admin.css?v={}\">\
         <script src=\"/admin/static/admin.js?v={}\" defer></script></head>",
        csrf_meta,
        title,
        super::asset_version(),
        super::asset_version()
    )
}

/// The Dove mark: a bird in flight, filled.
const MARK: &str = "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\"><path d=\"M2.5 13.2c3.6.3 6.1-1.4 8-5.2.9 2.6 \
                    2.8 4.3 5.6 4.3l5.4-2.6-2.4 4.3c-1.3 3.4-4.4 5.5-8.4 5.5H6.3l-3.8 2.7 1.6-4.3z\"/></svg>";

fn workspace(href_label: &'static str) -> Markup {
    h!(
        "<a class=\"workspace\" href=\"/admin\" aria-label=\"{}\"><span class=\"workspace__mark\">{}</span>\
         <span class=\"workspace__text\"><span class=\"workspace__name\">Dove</span>\
         <span class=\"workspace__sub\">Admin</span></span></a>",
        href_label,
        Markup::lit(MARK)
    )
}

/// Line icons (24px grid, stroked with `currentColor`).
fn icon(paths: &'static str) -> Markup {
    h!("<svg class=\"icon\" viewBox=\"0 0 24 24\" aria-hidden=\"true\">{}</svg>", Markup::lit(paths))
}
const ICON_OVERVIEW: &str = "<rect x=\"3\" y=\"3\" width=\"7\" height=\"9\" rx=\"1.5\"/><rect x=\"14\" y=\"3\" \
                             width=\"7\" height=\"5\" rx=\"1.5\"/><rect x=\"14\" y=\"12\" width=\"7\" height=\"9\" \
                             rx=\"1.5\"/><rect x=\"3\" y=\"16\" width=\"7\" height=\"5\" rx=\"1.5\"/>";
const ICON_REQUESTS: &str = "<path d=\"M22 12h-6l-2 3h-4l-2-3H2\"/><path d=\"M5.5 5.1 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 \
                             0 2-2v-6l-3.5-6.9A2 2 0 0 0 16.8 4H7.2a2 2 0 0 0-1.7 1.1z\"/>";
const ICON_AUDIT: &str = "<path d=\"M14 3v4a1 1 0 0 0 1 1h4\"/><path d=\"M17 21H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h7l5 5v11a2 \
                          2 0 0 1-2 2z\"/><path d=\"M9 13h6M9 17h4\"/>";
const ICON_SETTINGS: &str = "<path d=\"M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1\"/><circle cx=\"15\" cy=\"6\" \
                             r=\"2\"/><circle cx=\"9\" cy=\"12\" r=\"2\"/><circle cx=\"17\" cy=\"18\" r=\"2\"/>";
const ICON_CONNECTIONS: &str = "<path d=\"M9 15 15 9\"/><path d=\"m11 6 1.5-1.5a4.2 4.2 0 0 1 6 6L17 12\"/><path d=\"m13 \
                                18-1.5 1.5a4.2 4.2 0 0 1-6-6L7 12\"/>";
const ICON_MAILBOXES: &str = "<rect x=\"3\" y=\"5\" width=\"18\" height=\"14\" rx=\"2\"/><path d=\"m3.5 6.5 8.5 6 \
                              8.5-6\"/>";
const ICON_PROJECTS: &str = "<path d=\"M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z\"/>";
const ICON_WATCHES: &str = "<path d=\"M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9\"/><path d=\"M10.3 21a1.9 1.9 0 0 0 \
                            3.4 0\"/>";
const ICON_MORE: &str = "<circle cx=\"5\" cy=\"12\" r=\"1.5\"/><circle cx=\"12\" cy=\"12\" r=\"1.5\"/><circle \
                         cx=\"19\" cy=\"12\" r=\"1.5\"/>";
const ICON_KEY: &str = "<circle cx=\"7.5\" cy=\"15.5\" r=\"4.5\"/><path d=\"m10.7 12.3 9.3-9.3M17 6l2.5 2.5M14.5 \
                        8.5 16.5 10.5\"/>";
const ICON_SIGNOUT: &str = "<path d=\"M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4\"/><path d=\"m16 17 5-5-5-5M21 12H9\"/>";

/// A full page for a signed-in session: the Keyset shell (rail on the left; on phones a bar and bottom tabs).
pub fn page(title: &str, nav: Nav, csrf: &str, label: &str, body: Markup) -> Markup {
    let item = |n: Nav, href: &'static str, text: &'static str, glyph: &'static str| {
        if n == nav {
            h!("<a href=\"{}\" aria-current=\"page\">{}<span>{}</span></a>", href, icon(glyph), text)
        } else {
            h!("<a href=\"{}\">{}<span>{}</span></a>", href, icon(glyph), text)
        }
    };
    let navs = Markup::concat([
        item(Nav::Overview, "/admin", "Overview", ICON_OVERVIEW),
        item(Nav::Requests, "/admin/requests", "Requests", ICON_REQUESTS),
        item(Nav::Connections, "/admin/connections", "Connections", ICON_CONNECTIONS),
        item(Nav::Mailboxes, "/admin/mailboxes", "Mailboxes", ICON_MAILBOXES),
        item(Nav::Projects, "/admin/projects", "Projects", ICON_PROJECTS),
        item(Nav::Watches, "/admin/watches", "Watches", ICON_WATCHES),
        item(Nav::Audit, "/admin/audit", "Audit", ICON_AUDIT),
        item(Nav::Settings, "/admin/settings", "Settings", ICON_SETTINGS),
    ]);
    // Phones get five tabs; the last one leads to a list of the other sections.
    let more = matches!(nav, Nav::Projects | Nav::Watches | Nav::Audit | Nav::Settings);
    let more_tab = if more {
        h!("<a href=\"/admin/more\" aria-current=\"page\">{}<span>More</span></a>", icon(ICON_MORE))
    } else {
        h!("<a href=\"/admin/more\">{}<span>More</span></a>", icon(ICON_MORE))
    };
    let tabs = Markup::concat([
        item(Nav::Overview, "/admin", "Overview", ICON_OVERVIEW),
        item(Nav::Requests, "/admin/requests", "Requests", ICON_REQUESTS),
        item(Nav::Connections, "/admin/connections", "Connections", ICON_CONNECTIONS),
        item(Nav::Mailboxes, "/admin/mailboxes", "Mailboxes", ICON_MAILBOXES),
        more_tab,
    ]);
    let signout = h!(
        "<form class=\"signout\" method=\"post\" action=\"/admin/logout\"><input type=\"hidden\" name=\"csrf\" \
         value=\"{}\"><button type=\"submit\">{}<span>Sign out</span></button></form>",
        csrf,
        icon(ICON_SIGNOUT)
    );
    h!(
        "{}<body><a class=\"skip\" href=\"#main\">Skip to content</a><div class=\"shell\">\
         <nav class=\"shell__nav\" aria-label=\"Main\">{}<div class=\"shell__links\">{}</div>\
         <div class=\"shell__foot\"><div class=\"account\" title=\"Signed in with this passkey\">\
         <span class=\"account__mark\">{}</span><span class=\"account__text\"><span class=\"account__name\">{}</span>\
         <span class=\"account__sub\">Passkey</span></span></div>{}</div></nav>\
         <header class=\"shell__bar\">{}{}</header>\
         <main id=\"main\" class=\"shell__main\"><div class=\"page\">{}</div></main>\
         <nav class=\"shell__tabs\" aria-label=\"Main\">{}</nav></div></body></html>",
        head(title, Some(csrf)),
        workspace("Dove admin, overview"),
        navs,
        icon(ICON_KEY),
        label,
        signout.clone(),
        workspace("Dove admin, overview"),
        signout,
        body,
        tabs
    )
}

/// The sections behind the phone's "More" tab.
pub fn more_links() -> Markup {
    let link = |href: &'static str, text: &'static str, sub: &'static str, glyph: &'static str| {
        h!(
            "<a class=\"row\" href=\"{}\"><span class=\"row-main\">{}<strong>{}</strong>\
             <span class=\"detail\">{}</span></span></a>",
            href,
            icon(glyph),
            text,
            sub
        )
    };
    Markup::concat([
        link("/admin/projects", "Projects", "Which mailboxes belong together", ICON_PROJECTS),
        link("/admin/watches", "Watches and sinks", "What agents wait for, where Dove pushes", ICON_WATCHES),
        link("/admin/audit", "Audit", "Every call and every admin action", ICON_AUDIT),
        link("/admin/settings", "Settings", "Passkeys, sessions, keys, export", ICON_SETTINGS),
    ])
}

/// A page without a session (sign-in, enrolment).
fn bare(title: &str, body: Markup) -> Markup {
    h!(
        "{}<body class=\"bare\"><main id=\"main\" class=\"bare-main\">{}{}</main></body></html>",
        head(title, None),
        workspace("Dove admin"),
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
