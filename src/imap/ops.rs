//! The IMAP and SMTP command allowlist (design "Command allowlist"), the counterpart of `gmail::gateway`.
//!
//! Every byte Dove sends to a mail server is built here from a typed operation. Reads use `BODY.PEEK` only, so
//! `\Seen` is never set; `UID STORE`/`UID EXPUNGE` exist only for an [`OwnDraftUid`]; `APPEND` takes a mailbox the
//! session resolved from its Drafts or Sent target. Nothing else can be produced.

use std::borrow::Cow;

use zeroize::Zeroizing;

use super::ImapError;
use super::session::OwnDraftUid;
use crate::util;

/// Command verbs Dove's IMAP client may send.
pub const IMAP_VERBS: &[&str] = &[
    "CAPABILITY",
    "LOGIN",
    "AUTHENTICATE",
    "STARTTLS",
    "ID",
    "LIST",
    "LSUB",
    "STATUS",
    "SELECT",
    "EXAMINE",
    "UID SEARCH",
    "UID FETCH",
    "APPEND",
    "UID STORE",
    "UID EXPUNGE",
    "NOOP",
    "LOGOUT",
    "ENABLE",
    "IDLE",
    "DONE",
];

/// Command verbs Dove's SMTP client may send.
pub const SMTP_VERBS: &[&str] = &["EHLO", "STARTTLS", "AUTH", "MAIL", "RCPT", "DATA", "QUIT", "RSET"];

/// One piece of an IMAP command line.
pub(crate) enum Part<'a> {
    Text(String),
    /// Sent as `{n}`, then the bytes after the server's continuation request.
    Literal(Cow<'a, [u8]>),
    /// A SASL response line sent after the server's continuation request (`AUTHENTICATE`).
    Sasl(Zeroizing<String>),
}

pub(crate) struct Command<'a> {
    pub verb: &'static str,
    pub parts: Vec<Part<'a>>,
}

impl Command<'_> {
    /// The text parts only (commands without literals, such as `STARTTLS`).
    pub(crate) fn text(&self) -> String {
        self.parts.iter().filter_map(|p| if let Part::Text(t) = p { Some(t.as_str()) } else { None }).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendFlag {
    Seen,
    Draft,
}

pub(crate) enum ImapOp<'a> {
    Capability,
    Login {
        username: &'a str,
        password: &'a str,
    },
    AuthenticatePlain {
        username: &'a str,
        password: &'a str,
    },
    StartTls,
    List {
        special_use: bool,
    },
    Status {
        mailbox: &'a str,
    },
    Select {
        mailbox: &'a str,
        readonly: bool,
        condstore: bool,
    },
    UidSearchAll,
    /// `UID SEARCH UID <n>:*`
    UidSearchFrom(u32),
    UidFetchMeta {
        uids: &'a [u32],
        modseq: bool,
    },
    UidFetchSize(u32),
    UidFetchRaw(u32),
    UidFetchChangedSince {
        modseq: u64,
        vanished: bool,
    },
    Append {
        mailbox: &'a str,
        flags: &'a [AppendFlag],
        message: &'a [u8],
    },
    UidStoreDeleted(&'a OwnDraftUid),
    UidExpunge(&'a OwnDraftUid),
    Noop,
    Logout,
    EnableQresync,
    /// `IDLE` (RFC 2177) on the selected folder; only the dedicated push connection sends it.
    Idle,
    /// Ends `IDLE`. Sent untagged, as a bare continuation line.
    Done,
}

/// A mailbox name as an IMAP astring: quoted when printable ASCII, else a literal.
fn mailbox(name: &str) -> Part<'_> {
    if !name.is_empty() && name.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        Part::Text(format!("\"{}\"", name.replace('\\', "\\\\").replace('"', "\\\"")))
    } else {
        Part::Literal(Cow::Borrowed(name.as_bytes()))
    }
}

/// Compact UID set: `1:3,7,9:10`. Callers pass non-empty lists.
pub(crate) fn uid_set(uids: &[u32]) -> String {
    let mut v: Vec<u32> = uids.iter().copied().filter(|u| *u > 0).collect();
    v.sort_unstable();
    v.dedup();
    let mut out = String::new();
    let mut i = 0;
    while i < v.len() {
        let start = v[i];
        let mut end = start;
        while i + 1 < v.len() && v[i + 1] == end + 1 {
            i += 1;
            end = v[i];
        }
        if !out.is_empty() {
            out.push(',');
        }
        if start == end {
            out.push_str(&start.to_string());
        } else {
            out.push_str(&format!("{start}:{end}"));
        }
        i += 1;
    }
    out
}

fn text(s: impl Into<String>) -> Part<'static> {
    Part::Text(s.into())
}

impl<'a> ImapOp<'a> {
    pub(crate) fn render(&self) -> Command<'a> {
        let (verb, parts): (&'static str, Vec<Part<'a>>) = match *self {
            ImapOp::Capability => ("CAPABILITY", vec![text("CAPABILITY")]),
            ImapOp::Login { username, password } => (
                "LOGIN",
                // Both as literals: any byte (quotes, backslash, non-ASCII) survives unchanged.
                vec![
                    text("LOGIN "),
                    Part::Literal(Cow::Borrowed(username.as_bytes())),
                    text(" "),
                    Part::Literal(Cow::Borrowed(password.as_bytes())),
                ],
            ),
            ImapOp::AuthenticatePlain { username, password } => {
                let mut raw = Zeroizing::new(Vec::with_capacity(username.len() + password.len() + 2));
                raw.push(0);
                raw.extend_from_slice(username.as_bytes());
                raw.push(0);
                raw.extend_from_slice(password.as_bytes());
                ("AUTHENTICATE", vec![text("AUTHENTICATE PLAIN"), Part::Sasl(Zeroizing::new(util::b64std(&raw)))])
            }
            ImapOp::StartTls => ("STARTTLS", vec![text("STARTTLS")]),
            ImapOp::List { special_use } => (
                "LIST",
                vec![text(if special_use { "LIST \"\" \"*\" RETURN (SPECIAL-USE)" } else { "LIST \"\" \"*\"" })],
            ),
            ImapOp::Status { mailbox: m } => {
                ("STATUS", vec![text("STATUS "), mailbox(m), text(" (MESSAGES UIDNEXT UIDVALIDITY)")])
            }
            ImapOp::Select { mailbox: m, readonly, condstore } => {
                let verb = if readonly { "EXAMINE" } else { "SELECT" };
                let mut p = vec![text(format!("{verb} ")), mailbox(m)];
                if condstore {
                    p.push(text(" (CONDSTORE)"));
                }
                (verb, p)
            }
            ImapOp::UidSearchAll => ("UID SEARCH", vec![text("UID SEARCH ALL")]),
            ImapOp::UidSearchFrom(uid) => ("UID SEARCH", vec![text(format!("UID SEARCH UID {}:*", uid.max(1)))]),
            ImapOp::UidFetchMeta { uids, modseq } => (
                "UID FETCH",
                vec![text(format!(
                    "UID FETCH {} (UID FLAGS INTERNALDATE RFC822.SIZE{})",
                    uid_set(uids),
                    if modseq { " MODSEQ" } else { "" }
                ))],
            ),
            ImapOp::UidFetchSize(uid) => ("UID FETCH", vec![text(format!("UID FETCH {uid} (UID RFC822.SIZE)"))]),
            ImapOp::UidFetchRaw(uid) => ("UID FETCH", vec![text(format!("UID FETCH {uid} (UID BODY.PEEK[])"))]),
            ImapOp::UidFetchChangedSince { modseq, vanished } => (
                "UID FETCH",
                vec![text(format!(
                    "UID FETCH 1:* (UID FLAGS INTERNALDATE RFC822.SIZE MODSEQ) (CHANGEDSINCE {modseq}{})",
                    if vanished { " VANISHED" } else { "" }
                ))],
            ),
            ImapOp::Append { mailbox: m, flags, message } => {
                let f: Vec<&str> = flags
                    .iter()
                    .map(|f| match f {
                        AppendFlag::Seen => "\\Seen",
                        AppendFlag::Draft => "\\Draft",
                    })
                    .collect();
                (
                    "APPEND",
                    vec![
                        text("APPEND "),
                        mailbox(m),
                        text(format!(" ({}) ", f.join(" "))),
                        Part::Literal(Cow::Borrowed(message)),
                    ],
                )
            }
            ImapOp::UidStoreDeleted(own) => {
                ("UID STORE", vec![text(format!("UID STORE {} +FLAGS.SILENT (\\Deleted)", own.uid()))])
            }
            ImapOp::UidExpunge(own) => ("UID EXPUNGE", vec![text(format!("UID EXPUNGE {}", own.uid()))]),
            ImapOp::Noop => ("NOOP", vec![text("NOOP")]),
            ImapOp::Logout => ("LOGOUT", vec![text("LOGOUT")]),
            ImapOp::EnableQresync => ("ENABLE", vec![text("ENABLE QRESYNC")]),
            ImapOp::Idle => ("IDLE", vec![text("IDLE")]),
            ImapOp::Done => ("DONE", vec![text("DONE")]),
        };
        Command { verb, parts }
    }
}

// ------------------------------------------------------------------ SMTP

pub(crate) enum SmtpOp<'a> {
    Ehlo,
    StartTls,
    /// `AUTH PLAIN <initial response>`
    AuthPlain {
        username: &'a str,
        password: &'a str,
    },
    /// `AUTH LOGIN`, then the two continuation lines below.
    AuthLogin,
    LoginLine(&'a str),
    MailFrom(&'a str),
    RcptTo(&'a str),
    Data,
    Quit,
    Rset,
}

/// Envelope addresses: ASCII, no whitespace, brackets or control characters (no SMTP command injection).
pub(crate) fn valid_envelope_addr(a: &str) -> bool {
    (3..=254).contains(&a.len())
        && a.contains('@')
        && a.bytes().all(|b| b.is_ascii_graphic() && !matches!(b, b'<' | b'>' | b'(' | b')' | b',' | b';' | b'"'))
}

impl SmtpOp<'_> {
    pub(crate) fn verb(&self) -> &'static str {
        match self {
            SmtpOp::Ehlo => "EHLO",
            SmtpOp::StartTls => "STARTTLS",
            SmtpOp::AuthPlain { .. } | SmtpOp::AuthLogin | SmtpOp::LoginLine(_) => "AUTH",
            SmtpOp::MailFrom(_) => "MAIL",
            SmtpOp::RcptTo(_) => "RCPT",
            SmtpOp::Data => "DATA",
            SmtpOp::Quit => "QUIT",
            SmtpOp::Rset => "RSET",
        }
    }

    /// The command line including CRLF.
    pub(crate) fn render(&self) -> Result<Zeroizing<String>, ImapError> {
        let line = match *self {
            SmtpOp::Ehlo => "EHLO localhost".to_string(),
            SmtpOp::StartTls => "STARTTLS".to_string(),
            SmtpOp::AuthPlain { username, password } => {
                let mut raw = Zeroizing::new(Vec::new());
                raw.push(0);
                raw.extend_from_slice(username.as_bytes());
                raw.push(0);
                raw.extend_from_slice(password.as_bytes());
                format!("AUTH PLAIN {}", util::b64std(&raw))
            }
            SmtpOp::AuthLogin => "AUTH LOGIN".to_string(),
            SmtpOp::LoginLine(s) => util::b64std(s.as_bytes()),
            SmtpOp::MailFrom(a) | SmtpOp::RcptTo(a) => {
                if !valid_envelope_addr(a) {
                    return Err(ImapError::Protocol("invalid envelope address"));
                }
                if matches!(self, SmtpOp::MailFrom(_)) { format!("MAIL FROM:<{a}>") } else { format!("RCPT TO:<{a}>") }
            }
            SmtpOp::Data => "DATA".to_string(),
            SmtpOp::Quit => "QUIT".to_string(),
            SmtpOp::Rset => "RSET".to_string(),
        };
        let mut z = Zeroizing::new(line);
        z.push_str("\r\n");
        Ok(z)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Index of every variant; a new variant does not compile until it is listed here and in `samples`.
    fn index(op: &ImapOp<'_>) -> usize {
        match op {
            ImapOp::Capability => 0,
            ImapOp::Login { .. } => 1,
            ImapOp::AuthenticatePlain { .. } => 2,
            ImapOp::StartTls => 3,
            ImapOp::List { .. } => 4,
            ImapOp::Status { .. } => 5,
            ImapOp::Select { .. } => 6,
            ImapOp::UidSearchAll => 7,
            ImapOp::UidSearchFrom(_) => 8,
            ImapOp::UidFetchMeta { .. } => 9,
            ImapOp::UidFetchSize(_) => 10,
            ImapOp::UidFetchRaw(_) => 11,
            ImapOp::UidFetchChangedSince { .. } => 12,
            ImapOp::Append { .. } => 13,
            ImapOp::UidStoreDeleted(_) => 14,
            ImapOp::UidExpunge(_) => 15,
            ImapOp::Noop => 16,
            ImapOp::Logout => 17,
            ImapOp::EnableQresync => 18,
            ImapOp::Idle => 19,
            ImapOp::Done => 20,
        }
    }
    const VARIANTS: usize = 21;

    fn wire(c: &Command<'_>) -> String {
        c.parts
            .iter()
            .map(|p| match p {
                Part::Text(t) => t.clone(),
                Part::Literal(b) => format!("{{{}}}", b.len()),
                Part::Sasl(_) => String::new(),
            })
            .collect()
    }

    #[test]
    fn every_imap_op_is_allowlisted() {
        let own = OwnDraftUid::new_for_drafts(7, 42);
        let uids = [3, 1, 2, 9];
        let samples = vec![
            ImapOp::Capability,
            ImapOp::Login { username: "u", password: "p\"a\\\u{df} w" },
            ImapOp::AuthenticatePlain { username: "u", password: "p" },
            ImapOp::StartTls,
            ImapOp::List { special_use: true },
            ImapOp::List { special_use: false },
            ImapOp::Status { mailbox: "INBOX" },
            ImapOp::Select { mailbox: "Entw&APw-rfe", readonly: true, condstore: true },
            ImapOp::Select { mailbox: "INBOX", readonly: false, condstore: false },
            ImapOp::UidSearchAll,
            ImapOp::UidSearchFrom(5),
            ImapOp::UidFetchMeta { uids: &uids, modseq: true },
            ImapOp::UidFetchSize(4),
            ImapOp::UidFetchRaw(4),
            ImapOp::UidFetchChangedSince { modseq: 9, vanished: true },
            ImapOp::Append { mailbox: "Drafts", flags: &[AppendFlag::Draft, AppendFlag::Seen], message: b"x" },
            ImapOp::UidStoreDeleted(&own),
            ImapOp::UidExpunge(&own),
            ImapOp::Noop,
            ImapOp::Logout,
            ImapOp::EnableQresync,
            ImapOp::Idle,
            ImapOp::Done,
        ];
        let mut seen = vec![false; VARIANTS];
        for op in &samples {
            seen[index(op)] = true;
            let c = op.render();
            let line = wire(&c);
            assert!(IMAP_VERBS.contains(&c.verb), "{} not allowlisted", c.verb);
            assert!(line.starts_with(c.verb), "{line} does not start with {}", c.verb);
            let upper = line.to_ascii_uppercase();
            if c.verb == "UID FETCH" {
                // Only BODY.PEEK reads content; BODY[...] and RFC822 / RFC822.TEXT would set \Seen.
                assert!(!upper.contains("BODY["), "{line}");
                assert!(!upper.replace("RFC822.SIZE", "").contains("RFC822"), "{line}");
            }
            if c.verb == "UID STORE" {
                assert!(line.ends_with("+FLAGS.SILENT (\\Deleted)"), "{line}");
            }
            if matches!(c.verb, "IDLE" | "DONE") {
                // Exactly the bare verb: nothing else can ride on the push connection.
                assert_eq!(line, c.verb);
            }
            // Passwords are never part of the command text.
            assert!(!line.contains("p\"a"), "{line}");
        }
        assert!(seen.iter().all(|s| *s), "a variant has no sample: {seen:?}");
        assert_eq!(uid_set(&uids), "1:3,9");
    }

    #[test]
    fn every_smtp_op_is_allowlisted() {
        let samples = [
            SmtpOp::Ehlo,
            SmtpOp::StartTls,
            SmtpOp::AuthPlain { username: "u", password: "p" },
            SmtpOp::AuthLogin,
            SmtpOp::LoginLine("u"),
            SmtpOp::MailFrom("a@example.com"),
            SmtpOp::RcptTo("b@example.com"),
            SmtpOp::Data,
            SmtpOp::Quit,
            SmtpOp::Rset,
        ];
        for op in &samples {
            assert!(SMTP_VERBS.contains(&op.verb()));
            let line = op.render().unwrap();
            assert!(line.ends_with("\r\n") && line.matches("\r\n").count() == 1);
            if !matches!(op, SmtpOp::LoginLine(_)) {
                assert!(line.starts_with(op.verb()), "{}", line.as_str());
            }
        }
        for bad in ["a@b.c>\r\nRCPT TO:<x@y.z", "a b@c.d", "<a@b.c>", "nobody"] {
            assert!(SmtpOp::RcptTo(bad).render().is_err(), "{bad}");
            assert!(SmtpOp::MailFrom(bad).render().is_err(), "{bad}");
        }
    }
}
