//! The IMAP and SMTP command allowlist (design "Command allowlist"), the counterpart of `gmail::gateway`.
//!
//! Every byte Dove sends to a mail server is built here from a typed operation. Reads use `BODY.PEEK` only, so
//! `\Seen` is never set by reading; `UID STORE` sets `\Deleted` and `UID EXPUNGE` runs only for an [`OwnDraftUid`]
//! or a [`CopiedUid`] (the source of a confirmed copy); other flag changes take typed [`StoreFlag`]s, which cannot
//! name `\Deleted`; Gmail label changes take typed [`GmLabel`]s (the inbox or an existing user label, PLAN A52);
//! `APPEND` takes a mailbox the session resolved from its Drafts or Sent target. Nothing else can be produced.

use std::borrow::Cow;

use zeroize::Zeroizing;

use super::ImapError;
use super::session::{CopiedUid, OwnDraftUid};
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
    "UID MOVE",
    "UID COPY",
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

/// A flag the organize tools may set or clear. `\Deleted`, `\Draft` and `\Recent` cannot be expressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreFlag {
    Seen,
    Flagged,
    Keyword(Keyword),
}

/// A user keyword (RFC 3501 flag-keyword): an atom of at most 64 characters that is not a system flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keyword(String);

impl Keyword {
    pub fn new(s: &str) -> Option<Self> {
        let ok = (1..=64).contains(&s.len())
            && !s.starts_with('\\')
            && s.bytes()
                .all(|b| b.is_ascii_graphic() && !matches!(b, b'(' | b')' | b'{' | b'%' | b'*' | b'"' | b'\\' | b']'));
        ok.then(|| Self(s.to_string()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A Gmail label for `UID STORE +/-X-GM-LABELS` (Gmail mode, PLAN A52): the inbox, or a user label named by the wire
/// name of a folder the server listed (Dove creates no labels). Other system labels (`\Trash`, `\Spam`, `\Draft`,
/// ...) cannot be expressed: Trash and Spam are reached only through `UID MOVE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GmLabel {
    Inbox,
    User(UserLabel),
}

/// The wire name of a user label: not empty, no control characters, and not starting with `\` (Gmail reads a
/// backslash label as a system label, quoted or not).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserLabel(String);

impl UserLabel {
    pub fn new(wire: &str) -> Option<Self> {
        let ok = (1..=1000).contains(&wire.len())
            && !wire.starts_with('\\')
            && !wire.chars().any(char::is_control)
            && !wire.eq_ignore_ascii_case("INBOX");
        ok.then(|| Self(wire.to_string()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl StoreFlag {
    fn wire(&self) -> &str {
        match self {
            StoreFlag::Seen => "\\Seen",
            StoreFlag::Flagged => "\\Flagged",
            StoreFlag::Keyword(k) => k.as_str(),
        }
    }
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
        /// Also fetch `X-GM-LABELS` (Gmail mode).
        gm_labels: bool,
    },
    UidFetchSize(u32),
    UidFetchRaw(u32),
    UidFetchChangedSince {
        modseq: u64,
        vanished: bool,
        gm_labels: bool,
    },
    Append {
        mailbox: &'a str,
        flags: &'a [AppendFlag],
        message: &'a [u8],
    },
    UidStoreDeleted(&'a OwnDraftUid),
    UidExpunge(&'a OwnDraftUid),
    /// `UID STORE <uids> +FLAGS.SILENT (...)` / `-FLAGS.SILENT (...)` with organize flags only.
    UidStoreFlags {
        uids: &'a [u32],
        add: bool,
        flags: &'a [StoreFlag],
    },
    /// `UID STORE <uids> +X-GM-LABELS (...)` / `-X-GM-LABELS (...)` (Gmail mode).
    UidStoreGmLabels {
        uids: &'a [u32],
        add: bool,
        labels: &'a [GmLabel],
    },
    /// `UID MOVE <uids> <mailbox>` (RFC 6851).
    UidMove {
        uids: &'a [u32],
        mailbox: &'a str,
    },
    /// `UID COPY <uids> <mailbox>`: the first step of a move on servers without MOVE.
    UidCopy {
        uids: &'a [u32],
        mailbox: &'a str,
    },
    /// `\Deleted` on the sources of a confirmed copy (move without MOVE).
    UidStoreDeletedCopied(&'a [CopiedUid]),
    /// `UID EXPUNGE` of exactly the sources of a confirmed copy.
    UidExpungeCopied(&'a [CopiedUid]),
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
            ImapOp::UidFetchMeta { uids, modseq, gm_labels } => (
                "UID FETCH",
                vec![text(format!(
                    "UID FETCH {} (UID FLAGS INTERNALDATE RFC822.SIZE{}{})",
                    uid_set(uids),
                    if modseq { " MODSEQ" } else { "" },
                    if gm_labels { " X-GM-LABELS" } else { "" }
                ))],
            ),
            ImapOp::UidFetchSize(uid) => ("UID FETCH", vec![text(format!("UID FETCH {uid} (UID RFC822.SIZE)"))]),
            ImapOp::UidFetchRaw(uid) => ("UID FETCH", vec![text(format!("UID FETCH {uid} (UID BODY.PEEK[])"))]),
            ImapOp::UidFetchChangedSince { modseq, vanished, gm_labels } => (
                "UID FETCH",
                vec![text(format!(
                    "UID FETCH 1:* (UID FLAGS INTERNALDATE RFC822.SIZE MODSEQ{}) (CHANGEDSINCE {modseq}{})",
                    if gm_labels { " X-GM-LABELS" } else { "" },
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
            ImapOp::UidStoreFlags { uids, add, flags } => {
                let f: Vec<&str> = flags.iter().map(StoreFlag::wire).collect();
                (
                    "UID STORE",
                    vec![text(format!(
                        "UID STORE {} {}FLAGS.SILENT ({})",
                        uid_set(uids),
                        if add { '+' } else { '-' },
                        f.join(" ")
                    ))],
                )
            }
            ImapOp::UidStoreGmLabels { uids, add, labels } => {
                let mut p =
                    vec![text(format!("UID STORE {} {}X-GM-LABELS (", uid_set(uids), if add { '+' } else { '-' }))];
                for (i, l) in labels.iter().enumerate() {
                    if i > 0 {
                        p.push(text(" "));
                    }
                    p.push(match l {
                        GmLabel::Inbox => text("\\Inbox"),
                        GmLabel::User(u) => mailbox(u.as_str()),
                    });
                }
                p.push(text(")"));
                ("UID STORE", p)
            }
            ImapOp::UidMove { uids, mailbox: m } => {
                ("UID MOVE", vec![text(format!("UID MOVE {} ", uid_set(uids))), mailbox(m)])
            }
            ImapOp::UidCopy { uids, mailbox: m } => {
                ("UID COPY", vec![text(format!("UID COPY {} ", uid_set(uids))), mailbox(m)])
            }
            ImapOp::UidStoreDeletedCopied(c) => {
                let uids: Vec<u32> = c.iter().map(CopiedUid::uid).collect();
                ("UID STORE", vec![text(format!("UID STORE {} +FLAGS.SILENT (\\Deleted)", uid_set(&uids)))])
            }
            ImapOp::UidExpungeCopied(c) => {
                let uids: Vec<u32> = c.iter().map(CopiedUid::uid).collect();
                ("UID EXPUNGE", vec![text(format!("UID EXPUNGE {}", uid_set(&uids)))])
            }
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
            ImapOp::UidStoreFlags { .. } => 21,
            ImapOp::UidMove { .. } => 22,
            ImapOp::UidCopy { .. } => 23,
            ImapOp::UidStoreDeletedCopied(_) => 24,
            ImapOp::UidExpungeCopied(_) => 25,
            ImapOp::UidStoreGmLabels { .. } => 26,
        }
    }
    const VARIANTS: usize = 27;

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
        let copied = CopiedUid::for_ops_tests(&[5, 6, 8]);
        let uids = [3, 1, 2, 9];
        let kw = Keyword::new("$Follow-up").unwrap();
        let flags = [StoreFlag::Seen, StoreFlag::Flagged, StoreFlag::Keyword(kw)];
        let gm = [
            GmLabel::Inbox,
            GmLabel::User(UserLabel::new("Work").unwrap()),
            GmLabel::User(UserLabel::new("K\u{e4}se \"x\"").unwrap()),
        ];
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
            ImapOp::UidFetchMeta { uids: &uids, modseq: true, gm_labels: false },
            ImapOp::UidFetchMeta { uids: &uids, modseq: false, gm_labels: true },
            ImapOp::UidFetchSize(4),
            ImapOp::UidFetchRaw(4),
            ImapOp::UidFetchChangedSince { modseq: 9, vanished: true, gm_labels: false },
            ImapOp::UidFetchChangedSince { modseq: 9, vanished: false, gm_labels: true },
            ImapOp::Append { mailbox: "Drafts", flags: &[AppendFlag::Draft, AppendFlag::Seen], message: b"x" },
            ImapOp::UidStoreDeleted(&own),
            ImapOp::UidExpunge(&own),
            ImapOp::UidStoreFlags { uids: &uids, add: true, flags: &flags },
            ImapOp::UidStoreFlags { uids: &uids, add: false, flags: &flags[..1] },
            ImapOp::UidStoreGmLabels { uids: &uids, add: true, labels: &gm },
            ImapOp::UidStoreGmLabels { uids: &uids, add: false, labels: &gm[..1] },
            ImapOp::UidMove { uids: &uids, mailbox: "Trash" },
            ImapOp::UidCopy { uids: &uids, mailbox: "Gel&APY-scht" },
            ImapOp::UidStoreDeletedCopied(&copied),
            ImapOp::UidExpungeCopied(&copied),
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
                // \Deleted only in the two guarded forms (an own draft or the sources of a confirmed copy).
                if line.contains("\\Deleted") {
                    assert!(line.ends_with("+FLAGS.SILENT (\\Deleted)"), "{line}");
                    assert!(
                        line == "UID STORE 42 +FLAGS.SILENT (\\Deleted)"
                            || line == "UID STORE 5:6,8 +FLAGS.SILENT (\\Deleted)",
                        "{line}"
                    );
                } else if line.contains("X-GM-LABELS") {
                    // Label changes carry typed labels only: never a flag, never a system label but the inbox.
                    assert!(line.contains(" +X-GM-LABELS (") || line.contains(" -X-GM-LABELS ("), "{line}");
                    assert!(!line.contains("FLAGS"), "{line}");
                    let rest = line.split_once("X-GM-LABELS (").unwrap().1;
                    assert!(!rest.replace("\\Inbox", "").contains('\\'), "{line}");
                } else {
                    assert!(line.contains("FLAGS.SILENT ("), "{line}");
                }
            }
            if c.verb == "UID EXPUNGE" {
                assert!(line == "UID EXPUNGE 42" || line == "UID EXPUNGE 5:6,8", "{line}");
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
        assert_eq!(
            wire(&ImapOp::UidStoreFlags { uids: &uids, add: true, flags: &flags }.render()),
            "UID STORE 1:3,9 +FLAGS.SILENT (\\Seen \\Flagged $Follow-up)"
        );
        assert_eq!(wire(&ImapOp::UidMove { uids: &[4], mailbox: "Trash" }.render()), "UID MOVE 4 \"Trash\"");
        assert_eq!(
            wire(&ImapOp::UidStoreGmLabels { uids: &[4, 5], add: true, labels: &gm }.render()),
            "UID STORE 4:5 +X-GM-LABELS (\\Inbox \"Work\" {9})"
        );
        assert_eq!(
            wire(&ImapOp::UidStoreGmLabels { uids: &[4], add: false, labels: &gm[..1] }.render()),
            "UID STORE 4 -X-GM-LABELS (\\Inbox)"
        );
        assert_eq!(
            wire(&ImapOp::UidFetchMeta { uids: &[4], modseq: true, gm_labels: true }.render()),
            "UID FETCH 4 (UID FLAGS INTERNALDATE RFC822.SIZE MODSEQ X-GM-LABELS)"
        );
    }

    #[test]
    fn user_labels_cannot_name_system_labels() {
        for bad in ["\\Trash", "\\Inbox", "INBOX", "inbox", "", "a\nb", "a\rb", &"x".repeat(1001)] {
            assert!(UserLabel::new(bad).is_none(), "{bad:?}");
        }
        for good in ["Work", "Projekte/Kunden", "K&AOQ-se", "[Gmail]x", "a \"b\""] {
            assert!(UserLabel::new(good).is_some(), "{good}");
        }
        // Quotes and backslashes inside a label are escaped, never closing the list.
        let l = [GmLabel::User(UserLabel::new("a\") b").unwrap())];
        let c = ImapOp::UidStoreGmLabels { uids: &[1], add: true, labels: &l }.render();
        assert_eq!(wire(&c), "UID STORE 1 +X-GM-LABELS (\"a\\\") b\")");
    }

    #[test]
    fn keywords_cannot_smuggle_flags_or_syntax() {
        for bad in ["\\Deleted", "\\Seen", "a b", "a)", "(a", "x\"y", "a]", "a*", "a%", "{3}", "", &"k".repeat(65), "ä"]
        {
            assert!(Keyword::new(bad).is_none(), "{bad}");
        }
        for good in ["$Forwarded", "Work", "follow-up", "$label1"] {
            assert!(Keyword::new(good).is_some(), "{good}");
        }
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
