//! Fake IMAP and SMTP servers (plaintext, loopback) with fault injection and a command log.
//!
//! Implements the subset Dove uses: CAPABILITY, LOGIN/AUTHENTICATE PLAIN, LIST (SPECIAL-USE), STATUS,
//! SELECT/EXAMINE (CONDSTORE), UID SEARCH, UID FETCH (incl. CHANGEDSINCE/VANISHED), APPEND (APPENDUID), UID STORE,
//! UID EXPUNGE, UID COPY / UID MOVE (COPYUID; MOVE optional), ENABLE QRESYNC, NOOP, LOGOUT, IDLE/DONE (pushes EXISTS, EXPUNGE/VANISHED and FETCH for the selected
//! folder; optional server-side IDLE timeout with BYE; `kick_idle` drops idling connections); SMTP EHLO, AUTH PLAIN/LOGIN, MAIL, RCPT, DATA, RSET, QUIT.
//! Non-PEEK body fetches set `\Seen` like a real server, so tests can prove Dove never sets it.
//!
//! Gmail mode ([`Opts::gmail`], [`FakeImap::gmail_user`]): `X-GM-EXT-1`, labels as folders (one message has a copy with
//! its own UID in All Mail and in every label folder, flags shared), `X-GM-LABELS` in FETCH and STORE (MODSEQ bumps on
//! label changes), MOVE into Trash/Spam drops every label, MOVE out of them restores into All Mail (and the target
//! label), EXPUNGE in a label folder removes that label, in Drafts the draft and in All Mail the message everywhere
//! (the "delete for good" setting Dove must never trigger). SMTP submissions are filed in Sent like Gmail does.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

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
pub const SMTP_VERBS: &[&str] = &["EHLO", "STARTTLS", "AUTH", "MAIL", "RCPT", "DATA", "QUIT", "RSET"];

/// IMAP fault for the next command with a matching verb (`"UID FETCH"`, `"APPEND"`, `"LOGIN"`, ...).
#[derive(Debug, Clone)]
pub enum Fault {
    /// Tagged `NO` without applying.
    No,
    /// Tagged `BAD` without applying.
    Bad,
    /// Close the connection without applying or answering.
    Drop,
    /// Apply, then close without answering.
    DropAfterApply,
    /// Apply, send half of the response, close.
    DropMidResponse,
    /// Apply, send half of the response, wait, send the rest.
    StallMidResponse(Duration),
    /// Wait, then handle normally.
    Delay(Duration),
}

#[derive(Debug, Clone)]
pub enum SmtpFault {
    /// Answer the command with this code without applying it.
    Reply(u16),
    /// Close without answering.
    Drop,
    /// For DATA: read the message and terminator, record it, close without the final reply.
    DropAfterTerminator,
    /// Wait, then handle normally. For DATA the wait is after the terminator, before the final reply (the message
    /// is recorded as sent before the wait).
    Delay(Duration),
}

#[derive(Debug, Clone)]
pub struct Opts {
    pub uidplus: bool,
    pub special_use: bool,
    pub condstore: bool,
    pub qresync: bool,
    pub auth_plain: bool,
    pub smtp_auth: &'static str,
    /// Offer IDLE (RFC 2177).
    pub idle: bool,
    /// End IDLE with `* BYE` and close the connection after this long.
    pub idle_timeout: Option<Duration>,
    /// Report `VANISHED (EARLIER)` as wide ranges: every UID from 1 to `UIDNEXT + WIDE_VANISHED` that is not in
    /// the folder (RFC 7162 lets a server include UIDs that never existed).
    pub wide_vanished: bool,
    /// Offer MOVE (RFC 6851). Without it Dove moves with COPY, STORE \Deleted and UID EXPUNGE.
    pub move_cap: bool,
    /// Report COPYUID for COPY and MOVE (UIDPLUS servers do; off simulates a server that omits it).
    pub copyuid: bool,
    /// Gmail semantics and `X-GM-EXT-1` (module docs). Users are created with [`FakeImap::gmail_user`].
    pub gmail: bool,
}

/// How far past `UIDNEXT` the ranges of [`Opts::wide_vanished`] reach.
pub const WIDE_VANISHED: u32 = 2_000_000;

impl Default for Opts {
    fn default() -> Self {
        Self {
            uidplus: true,
            special_use: true,
            condstore: true,
            qresync: true,
            auth_plain: false,
            smtp_auth: "PLAIN LOGIN",
            idle: true,
            idle_timeout: None,
            wide_vanished: false,
            move_cap: true,
            copyuid: true,
            gmail: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SentMail {
    pub from: String,
    pub rcpts: Vec<String>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Msg {
    uid: u32,
    flags: BTreeSet<String>,
    raw: Vec<u8>,
    internal_date: i64,
    modseq: u64,
    /// Gmail mode: the message all copies share (`X-GM-MSGID`); 0 otherwise.
    gm_id: u64,
}

#[derive(Debug, Clone)]
struct Folder {
    raw_name: String,
    special: Option<String>,
    uidvalidity: u32,
    uidnext: u32,
    highestmodseq: u64,
    msgs: Vec<Msg>,
    vanished: Vec<(u32, u64)>,
}

impl Folder {
    fn new(raw_name: String, special: Option<String>, uidvalidity: u32) -> Self {
        Self { raw_name, special, uidvalidity, uidnext: 1, highestmodseq: 1, msgs: Vec::new(), vanished: Vec::new() }
    }
    fn bump(&mut self) -> u64 {
        self.highestmodseq += 1;
        self.highestmodseq
    }
}

#[derive(Debug, Clone)]
struct User {
    password: String,
    folders: Vec<Folder>,
}

#[derive(Default)]
struct State {
    opts: Opts,
    users: HashMap<String, User>,
    faults: Vec<(String, Option<String>, Fault)>,
    smtp_faults: Vec<(String, SmtpFault)>,
    commands: Vec<String>,
    smtp_commands: Vec<String>,
    sent: Vec<SentMail>,
    rewrite_on_append: bool,
    connections: usize,
    smtp_connections: usize,
    next_uidvalidity: u32,
    /// IMAP connections open right now, and the most ever open at once.
    open: usize,
    max_open: usize,
    /// Connections inside IDLE right now.
    idling: usize,
    /// Bumped by `kick_idle`: idling connections close without a word.
    kick: u64,
    next_gm_id: u64,
}

#[derive(Clone)]
pub struct FakeImap {
    pub imap_addr: SocketAddr,
    pub smtp_addr: SocketAddr,
    state: Arc<Mutex<State>>,
    tasks: Arc<Vec<tokio::task::JoinHandle<()>>>,
}

impl Drop for FakeImap {
    fn drop(&mut self) {
        if Arc::strong_count(&self.tasks) == 1 {
            for t in self.tasks.iter() {
                t.abort();
            }
        }
    }
}

pub fn encode_utf7(s: &str) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";
    let mut out = String::new();
    let mut pending: Vec<u16> = Vec::new();
    fn flush(p: &mut Vec<u16>, out: &mut String) {
        const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";
        if p.is_empty() {
            return;
        }
        out.push('&');
        let bytes: Vec<u8> = p.iter().flat_map(|u| u.to_be_bytes()).collect();
        let (mut acc, mut bits) = (0u32, 0u32);
        for b in bytes {
            acc = (acc << 8) | b as u32;
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                out.push(B64[((acc >> bits) & 0x3f) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(B64[((acc << (6 - bits)) & 0x3f) as usize] as char);
        }
        out.push('-');
        p.clear();
    }
    let _ = B64;
    for c in s.chars() {
        if (' '..='~').contains(&c) {
            flush(&mut pending, &mut out);
            if c == '&' { out.push_str("&-") } else { out.push(c) }
        } else {
            let mut b = [0u16; 2];
            pending.extend_from_slice(c.encode_utf16(&mut b));
        }
    }
    flush(&mut pending, &mut out);
    out
}

fn internal_date(ts: i64) -> String {
    let dt = time::OffsetDateTime::from_unix_timestamp(ts).unwrap();
    const M: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    format!(
        "{:02}-{}-{} {:02}:{:02}:{:02} +0000",
        dt.day(),
        M[dt.month() as usize - 1],
        dt.year(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

// ------------------------------------------------------------------ tokens

#[derive(Debug, Clone)]
enum Tok {
    Atom(String),
    Str(Vec<u8>),
    List(Vec<Tok>),
}

impl Tok {
    fn s(&self) -> String {
        match self {
            Tok::Atom(a) => a.clone(),
            Tok::Str(s) => String::from_utf8_lossy(s).into_owned(),
            Tok::List(_) => String::new(),
        }
    }
    fn render(&self) -> String {
        match self {
            Tok::Atom(a) => a.clone(),
            Tok::Str(s) if s.iter().all(|b| (0x20..0x7f).contains(b)) => {
                format!("\"{}\"", String::from_utf8_lossy(s))
            }
            Tok::Str(s) => format!("{{{}}}", s.len()),
            Tok::List(l) => format!("({})", l.iter().map(Tok::render).collect::<Vec<_>>().join(" ")),
        }
    }
}

enum Seg {
    Text(Vec<u8>),
    Lit(Vec<u8>),
}

fn tokenize(segs: Vec<Seg>) -> Vec<Tok> {
    let mut stack: Vec<Vec<Tok>> = vec![Vec::new()];
    for seg in segs {
        match seg {
            Seg::Lit(l) => stack.last_mut().unwrap().push(Tok::Str(l)),
            Seg::Text(t) => {
                let mut i = 0;
                while i < t.len() {
                    match t[i] {
                        b' ' => i += 1,
                        b'(' => {
                            stack.push(Vec::new());
                            i += 1;
                        }
                        b')' => {
                            let l = stack.pop().unwrap();
                            if stack.is_empty() {
                                stack.push(Vec::new());
                            }
                            stack.last_mut().unwrap().push(Tok::List(l));
                            i += 1;
                        }
                        b'"' => {
                            i += 1;
                            let mut s = Vec::new();
                            while i < t.len() && t[i] != b'"' {
                                if t[i] == b'\\' && i + 1 < t.len() {
                                    i += 1;
                                }
                                s.push(t[i]);
                                i += 1;
                            }
                            i += 1;
                            stack.last_mut().unwrap().push(Tok::Str(s));
                        }
                        _ => {
                            let mut a = Vec::new();
                            let mut depth = 0;
                            while i < t.len() && (depth > 0 || !matches!(t[i], b' ' | b'(' | b')')) {
                                if t[i] == b'[' {
                                    depth += 1;
                                }
                                if t[i] == b']' {
                                    depth -= 1;
                                }
                                a.push(t[i]);
                                i += 1;
                            }
                            stack.last_mut().unwrap().push(Tok::Atom(String::from_utf8_lossy(&a).into_owned()));
                        }
                    }
                }
            }
        }
    }
    while stack.len() > 1 {
        let l = stack.pop().unwrap();
        stack.last_mut().unwrap().push(Tok::List(l));
    }
    stack.pop().unwrap()
}

fn literal_len(line: &[u8]) -> Option<(usize, bool, usize)> {
    if !line.ends_with(b"}") {
        return None;
    }
    let open = line.iter().rposition(|b| *b == b'{')?;
    let inner = &line[open + 1..line.len() - 1];
    let (inner, plus) = match inner.strip_suffix(b"+") {
        Some(i) => (i, true),
        None => (inner, false),
    };
    let n = std::str::from_utf8(inner).ok()?.parse().ok()?;
    Some((n, plus, open))
}

async fn read_line(r: &mut BufReader<OwnedReadHalf>) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    let n = r.read_until(b'\n', &mut line).await.ok()?;
    if n == 0 {
        return None;
    }
    while line.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        line.pop();
    }
    Some(line)
}

fn parse_set(s: &str, max: u32) -> Vec<(u32, u32)> {
    s.split(',')
        .filter_map(|p| {
            let v = |x: &str| if x == "*" { Some(max) } else { x.parse().ok() };
            match p.split_once(':') {
                Some((a, b)) => {
                    let (a, b) = (v(a)?, v(b)?);
                    Some((a.min(b), a.max(b)))
                }
                None => v(p).map(|x| (x, x)),
            }
        })
        .collect()
}

fn in_set(set: &[(u32, u32)], uid: u32) -> bool {
    set.iter().any(|(a, b)| (*a..=*b).contains(&uid))
}

/// Verb of a logged command line (`UID FETCH`, `APPEND`, ...).
pub fn verb_of(cmd: &str) -> String {
    let mut w = cmd.split(' ');
    let first = w.next().unwrap_or_default().to_ascii_uppercase();
    if first == "UID" { format!("UID {}", w.next().unwrap_or_default().to_ascii_uppercase()) } else { first }
}

// ------------------------------------------------------------------ public API

impl FakeImap {
    pub async fn start() -> Self {
        Self::start_with(Opts::default()).await
    }

    pub async fn start_with(opts: Opts) -> Self {
        let state = Arc::new(Mutex::new(State { opts, next_uidvalidity: 1_700_000_000, ..Default::default() }));
        let il = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sl = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (imap_addr, smtp_addr) = (il.local_addr().unwrap(), sl.local_addr().unwrap());
        let st = state.clone();
        let t1 = tokio::spawn(async move {
            while let Ok((s, _)) = il.accept().await {
                {
                    let mut g = st.lock().unwrap();
                    g.connections += 1;
                    g.open += 1;
                    g.max_open = g.max_open.max(g.open);
                }
                let st = st.clone();
                tokio::spawn(async move {
                    let (r, w) = s.into_split();
                    imap_conn(st.clone(), BufReader::new(r), w).await;
                    st.lock().unwrap().open -= 1;
                });
            }
        });
        let st = state.clone();
        let t2 = tokio::spawn(async move {
            while let Ok((s, _)) = sl.accept().await {
                st.lock().unwrap().smtp_connections += 1;
                let st = st.clone();
                tokio::spawn(async move {
                    let (r, w) = s.into_split();
                    smtp_conn(st, BufReader::new(r), w).await;
                });
            }
        });
        Self { imap_addr, smtp_addr, state, tasks: Arc::new(vec![t1, t2]) }
    }

    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        f(&mut self.state.lock().unwrap())
    }

    fn folder_mut<'a>(st: &'a mut State, user: &str, folder: &str) -> &'a mut Folder {
        let raw = encode_utf7(folder);
        st.users
            .get_mut(user)
            .expect("unknown fake user")
            .folders
            .iter_mut()
            .find(|f| f.raw_name == raw)
            .expect("unknown fake folder")
    }

    /// A user with an INBOX.
    pub fn add_user(&self, user: &str, password: &str) {
        self.with(|st| {
            st.next_uidvalidity += 1;
            let v = st.next_uidvalidity;
            st.users.insert(
                user.into(),
                User { password: password.into(), folders: vec![Folder::new("INBOX".into(), None, v)] },
            );
        })
    }

    pub fn set_password(&self, user: &str, password: &str) {
        self.with(|st| st.users.get_mut(user).unwrap().password = password.into())
    }

    /// Adds a folder by its UTF-8 name; `special` is a special-use attribute such as `\Drafts`.
    pub fn add_folder(&self, user: &str, name: &str, special: Option<&str>) {
        self.with(|st| {
            st.next_uidvalidity += 1;
            let v = st.next_uidvalidity;
            st.users.get_mut(user).unwrap().folders.push(Folder::new(
                encode_utf7(name),
                special.map(str::to_string),
                v,
            ));
        })
    }

    pub fn add_message(&self, user: &str, folder: &str, raw: &[u8], flags: &[&str]) -> u32 {
        self.add_message_at(user, folder, raw, flags, 1_767_225_600)
    }

    pub fn add_message_at(&self, user: &str, folder: &str, raw: &[u8], flags: &[&str], internal_date: i64) -> u32 {
        self.with(|st| {
            let f = Self::folder_mut(st, user, folder);
            let uid = f.uidnext;
            f.uidnext += 1;
            let modseq = f.bump();
            f.msgs.push(Msg {
                uid,
                flags: flags.iter().map(|s| s.to_string()).collect(),
                raw: raw.to_vec(),
                internal_date,
                modseq,
                gm_id: 0,
            });
            uid
        })
    }

    /// Changes UIDVALIDITY and renumbers the folder's messages (as a server rebuild would).
    pub fn set_uidvalidity(&self, user: &str, folder: &str, uidvalidity: u32) {
        self.with(|st| {
            let f = Self::folder_mut(st, user, folder);
            f.uidvalidity = uidvalidity;
            let mut next = 1;
            for m in f.msgs.iter_mut() {
                m.uid = next;
                next += 1;
            }
            f.uidnext = next;
            f.vanished.clear();
        })
    }

    pub fn set_flags(&self, user: &str, folder: &str, uid: u32, add: &[&str], remove: &[&str]) {
        self.with(|st| {
            let f = Self::folder_mut(st, user, folder);
            let modseq = f.bump();
            let m = f.msgs.iter_mut().find(|m| m.uid == uid).expect("unknown uid");
            for a in add {
                m.flags.insert(a.to_string());
            }
            for r in remove {
                m.flags.remove(*r);
            }
            m.modseq = modseq;
        })
    }

    /// Expunges a message as another client would.
    pub fn expunge_external(&self, user: &str, folder: &str, uid: u32) {
        self.with(|st| {
            let f = Self::folder_mut(st, user, folder);
            let modseq = f.bump();
            f.msgs.retain(|m| m.uid != uid);
            f.vanished.push((uid, modseq));
        })
    }

    pub fn flags(&self, user: &str, folder: &str, uid: u32) -> Option<Vec<String>> {
        self.with(|st| {
            Self::folder_mut(st, user, folder)
                .msgs
                .iter()
                .find(|m| m.uid == uid)
                .map(|m| m.flags.iter().cloned().collect())
        })
    }

    pub fn uids(&self, user: &str, folder: &str) -> Vec<u32> {
        self.with(|st| Self::folder_mut(st, user, folder).msgs.iter().map(|m| m.uid).collect())
    }

    pub fn message_raw(&self, user: &str, folder: &str, uid: u32) -> Option<Vec<u8>> {
        self.with(|st| Self::folder_mut(st, user, folder).msgs.iter().find(|m| m.uid == uid).map(|m| m.raw.clone()))
    }

    pub fn uidvalidity(&self, user: &str, folder: &str) -> u32 {
        self.with(|st| Self::folder_mut(st, user, folder).uidvalidity)
    }

    /// A Gmail-mode user (start the server with `Opts { gmail: true, .. }`): INBOX, `[Gmail]` (`\Noselect`), All Mail
    /// (`\All`), Drafts, Sent Mail, Spam (`\Junk`), Trash, Important (`\Important`) and the user labels `Work` and
    /// `Privat/Kunden`.
    pub fn gmail_user(&self, user: &str, password: &str) {
        self.add_user(user, password);
        for (name, special) in [
            ("[Gmail]", Some("\\Noselect")),
            ("[Gmail]/All Mail", Some("\\All")),
            ("[Gmail]/Drafts", Some("\\Drafts")),
            ("[Gmail]/Sent Mail", Some("\\Sent")),
            ("[Gmail]/Spam", Some("\\Junk")),
            ("[Gmail]/Trash", Some("\\Trash")),
            ("[Gmail]/Important", Some("\\Important")),
            ("Work", None),
            ("Privat/Kunden", None),
        ] {
            self.add_folder(user, name, special);
        }
    }

    /// A Gmail message with `labels` (folder names: `INBOX`, user labels, `[Gmail]/Important`, `[Gmail]/Sent Mail`;
    /// or `[Gmail]/Spam` / `[Gmail]/Trash` alone). It gets a copy in All Mail (unless in Spam/Trash) and in every label
    /// folder. Returns its Gmail id.
    pub fn gm_add(&self, user: &str, labels: &[&str], raw: &[u8], flags: &[&str], internal_date: i64) -> u64 {
        self.with(|st| {
            st.next_gm_id += 1;
            let gm_id = st.next_gm_id;
            let u = st.users.get_mut(user).expect("unknown fake user");
            let mut targets: BTreeSet<usize> = labels
                .iter()
                .map(|l| u.folders.iter().position(|f| f.raw_name == encode_utf7(l)).expect("unknown fake folder"))
                .collect();
            if !targets.iter().any(|i| matches!(gm_kind(&u.folders[*i]), GmKind::Trash | GmKind::Spam)) {
                targets.insert(gm_index(u, GmKind::All).expect("All Mail"));
            }
            let m = Msg {
                uid: 0,
                flags: flags.iter().map(|f| f.to_string()).collect(),
                raw: raw.to_vec(),
                internal_date,
                modseq: 0,
                gm_id,
            };
            for i in targets {
                push_copy(&mut u.folders[i], &m);
            }
            gm_id
        })
    }

    /// The UID of Gmail message `gm_id` in `folder`, if it has a copy there.
    pub fn gm_uid(&self, user: &str, folder: &str, gm_id: u64) -> Option<u32> {
        self.with(|st| Self::folder_mut(st, user, folder).msgs.iter().find(|m| m.gm_id == gm_id).map(|m| m.uid))
    }

    /// Wire names of the folders holding a copy of `gm_id`.
    pub fn gm_folders(&self, user: &str, gm_id: u64) -> Vec<String> {
        self.with(|st| {
            let u = &st.users[user];
            gm_where(u, gm_id).into_iter().map(|i| u.folders[i].raw_name.clone()).collect()
        })
    }

    /// Changes labels (folder names) as another client (Gmail on the web) would; MODSEQ bumps like Gmail's.
    pub fn gm_relabel(&self, user: &str, gm_id: u64, add: &[&str], remove: &[&str]) {
        self.with(|st| {
            let u = st.users.get_mut(user).expect("unknown fake user");
            let idx = |u: &User, n: &str| u.folders.iter().position(|f| f.raw_name == encode_utf7(n)).expect("folder");
            let mut want = gm_where(u, gm_id);
            for a in add {
                want.insert(idx(u, a));
            }
            for r in remove {
                want.remove(&idx(u, r));
            }
            gm_place(u, gm_id, &want);
        })
    }

    /// Flags of Gmail message `gm_id` (from its first copy).
    pub fn gm_flags(&self, user: &str, gm_id: u64) -> Vec<String> {
        self.with(|st| {
            st.users[user]
                .folders
                .iter()
                .flat_map(|f| f.msgs.iter())
                .find(|m| m.gm_id == gm_id)
                .map(|m| m.flags.iter().cloned().collect())
                .unwrap_or_default()
        })
    }

    /// Gmail mode: walks the command log and fails on any `\Deleted` STORE, `EXPUNGE` or `UID EXPUNGE` while a folder
    /// other than Drafts is selected, and on any `UID COPY` (Dove never copies on Gmail: copying adds a label, and the
    /// COPY + EXPUNGE move fallback can delete for good). Returns how many deletes it checked (all in Drafts).
    pub fn assert_gmail_deletes_only_in_drafts(&self) -> usize {
        let (cmds, drafts) = self.with(|st| {
            let drafts: Vec<String> = st
                .users
                .values()
                .flat_map(|u| u.folders.iter())
                .filter(|f| f.special.as_deref() == Some("\\Drafts"))
                .map(|f| f.raw_name.clone())
                .collect();
            (st.commands.clone(), drafts)
        });
        let mut selected: Option<String> = None;
        let mut checked = 0;
        for c in &cmds {
            let verb = verb_of(c);
            let up = c.to_ascii_uppercase();
            match verb.as_str() {
                "SELECT" | "EXAMINE" => {
                    let rest = c.split_once(' ').map(|x| x.1).unwrap_or_default();
                    let name = match rest.strip_prefix('"') {
                        Some(r) => r.split('"').next().unwrap_or_default().to_string(),
                        None => rest.split(' ').next().unwrap_or_default().to_string(),
                    };
                    selected = Some(name);
                }
                "UID COPY" => panic!("UID COPY in Gmail mode: {c}"),
                "EXPUNGE" | "UID EXPUNGE" => {
                    assert!(selected.as_ref().is_some_and(|s| drafts.contains(s)), "{c} outside Drafts ({selected:?})");
                    checked += 1;
                }
                "UID STORE" if up.contains("\\DELETED") => {
                    assert!(selected.as_ref().is_some_and(|s| drafts.contains(s)), "{c} outside Drafts ({selected:?})");
                    checked += 1;
                }
                _ => {}
            }
        }
        checked
    }

    pub fn fail_next(&self, cmd: &str, fault: Fault) {
        self.with(|st| st.faults.push((cmd.to_ascii_uppercase(), None, fault)))
    }

    /// Like [`Self::fail_next`], only for a command whose logged text contains `needle`.
    pub fn fail_next_containing(&self, cmd: &str, needle: &str, fault: Fault) {
        self.with(|st| st.faults.push((cmd.to_ascii_uppercase(), Some(needle.to_string()), fault)))
    }

    pub fn smtp_fail_next(&self, cmd: &str, fault: SmtpFault) {
        self.with(|st| st.smtp_faults.push((cmd.to_ascii_uppercase(), fault)))
    }

    /// When on, APPEND stores normalised bytes (bare LF to CRLF, an added header), as some servers do.
    pub fn rewrite_on_append(&self, on: bool) {
        self.with(|st| st.rewrite_on_append = on)
    }

    /// IMAP commands received, without tags; passwords and SASL responses redacted, literals as `{n}`.
    pub fn commands(&self) -> Vec<String> {
        self.with(|st| st.commands.clone())
    }

    pub fn clear_commands(&self) {
        self.with(|st| {
            st.commands.clear();
            st.smtp_commands.clear();
        })
    }

    pub fn smtp_commands(&self) -> Vec<String> {
        self.with(|st| st.smtp_commands.clone())
    }

    pub fn sent_mails(&self) -> Vec<SentMail> {
        self.with(|st| st.sent.clone())
    }

    /// IMAP connections accepted so far.
    pub fn connections(&self) -> usize {
        self.with(|st| st.connections)
    }

    /// IMAP connections open right now.
    pub fn open_connections(&self) -> usize {
        self.with(|st| st.open)
    }

    /// Most IMAP connections open at the same time since the start or the last `reset_max_open`.
    pub fn max_open_connections(&self) -> usize {
        self.with(|st| st.max_open)
    }

    pub fn reset_max_open(&self) {
        self.with(|st| st.max_open = st.open)
    }

    /// Connections inside IDLE right now.
    pub fn idling(&self) -> usize {
        self.with(|st| st.idling)
    }

    /// Closes every idling connection without `BYE` (a dropped network path).
    pub fn kick_idle(&self) {
        self.with(|st| st.kick += 1)
    }

    pub fn smtp_connections(&self) -> usize {
        self.with(|st| st.smtp_connections)
    }

    /// Fails unless every IMAP and SMTP command was on the allowlist: FETCH only with BODY.PEEK (no RFC822 content
    /// items), STORE `\Deleted` only alone and other STOREs with organize flags only, APPEND only to the Drafts or
    /// Sent folder.
    pub fn assert_only_allowlisted(&self) {
        let (cmds, smtp, specials) = self.with(|st| {
            let specials: Vec<(String, Option<String>)> = st
                .users
                .values()
                .flat_map(|u| u.folders.iter().map(|f| (f.raw_name.clone(), f.special.clone())))
                .collect();
            (st.commands.clone(), st.smtp_commands.clone(), specials)
        });
        for c in &cmds {
            let verb = verb_of(c);
            assert!(IMAP_VERBS.contains(&verb.as_str()), "IMAP command not allowlisted: {c}");
            let up = c.to_ascii_uppercase();
            if verb == "UID FETCH" {
                assert!(!up.contains("BODY["), "FETCH without PEEK: {c}");
                assert!(!up.replace("RFC822.SIZE", "").contains("RFC822"), "RFC822 content fetch: {c}");
            }
            if verb == "UID STORE" {
                // \Deleted only alone (own draft or confirmed copy source); other stores carry organize flags only.
                if up.contains("\\DELETED") {
                    assert!(up.ends_with("+FLAGS.SILENT (\\DELETED)"), "STORE with \\Deleted and more: {c}");
                } else if up.contains("X-GM-LABELS") {
                    // Gmail labels: the inbox or a user label only, never a flag or another system label.
                    assert!(up.contains(" +X-GM-LABELS (") || up.contains(" -X-GM-LABELS ("), "STORE form: {c}");
                    let rest = up.split_once("X-GM-LABELS (").unwrap().1.replace("\\INBOX", "");
                    assert!(!rest.contains('\\') && !up.contains("FLAGS"), "STORE of a system label: {c}");
                } else {
                    assert!(up.contains(" +FLAGS.SILENT (") || up.contains(" -FLAGS.SILENT ("), "STORE form: {c}");
                    assert!(!up.contains("\\DRAFT") && !up.contains("\\RECENT"), "STORE of a system flag: {c}");
                }
            }
            if verb == "APPEND" {
                let ok = specials.iter().any(|(raw, sp)| {
                    matches!(sp.as_deref(), Some("\\Drafts") | Some("\\Sent")) && c.contains(&format!("\"{raw}\""))
                }) || c.contains("\"Drafts\"")
                    || c.contains("\"Entw&APw-rfe\"");
                assert!(ok, "APPEND outside Drafts/Sent: {c}");
            }
        }
        for c in &smtp {
            let verb = c.split([' ', ':']).next().unwrap_or_default().to_ascii_uppercase();
            assert!(SMTP_VERBS.contains(&verb.as_str()) || c == "<auth line>", "SMTP command not allowlisted: {c}");
        }
    }
}

// ------------------------------------------------------------------ IMAP connection

struct Conn {
    user: Option<String>,
    selected: Option<(String, bool)>,
    qresync: bool,
}

fn caps(o: &Opts) -> String {
    let mut c = vec!["IMAP4rev1", "ENABLE", "LITERAL+"];
    if o.uidplus {
        c.push("UIDPLUS");
    }
    if o.special_use {
        c.push("SPECIAL-USE");
    }
    if o.condstore {
        c.push("CONDSTORE");
    }
    if o.qresync {
        c.push("QRESYNC");
    }
    if o.auth_plain {
        c.push("AUTH=PLAIN");
    }
    if o.idle {
        c.push("IDLE");
    }
    if o.move_cap {
        c.push("MOVE");
    }
    if o.gmail {
        c.push("X-GM-EXT-1");
    }
    c.join(" ")
}

async fn imap_conn(st: Arc<Mutex<State>>, mut r: BufReader<OwnedReadHalf>, mut w: OwnedWriteHalf) {
    if w.write_all(b"* OK [CAPABILITY IMAP4rev1] fake ready\r\n").await.is_err() {
        return;
    }
    let mut conn = Conn { user: None, selected: None, qresync: false };
    loop {
        // Read one command with its literals.
        let mut segs = Vec::new();
        loop {
            let Some(line) = read_line(&mut r).await else { return };
            match literal_len(&line) {
                Some((n, plus, open)) => {
                    segs.push(Seg::Text(line[..open].to_vec()));
                    if !plus && w.write_all(b"+ go ahead\r\n").await.is_err() {
                        return;
                    }
                    let mut buf = vec![0; n];
                    if r.read_exact(&mut buf).await.is_err() {
                        return;
                    }
                    segs.push(Seg::Lit(buf));
                }
                None => {
                    segs.push(Seg::Text(line));
                    break;
                }
            }
        }
        let toks = tokenize(segs);
        let tag = toks.first().map(Tok::s).unwrap_or_default();
        let mut verb = toks.get(1).map(Tok::s).unwrap_or_default().to_ascii_uppercase();
        let mut args: Vec<Tok> = toks.iter().skip(2).cloned().collect();
        if verb == "UID" && !args.is_empty() {
            verb = format!("UID {}", args.remove(0).s().to_ascii_uppercase());
        }
        // SASL continuation for AUTHENTICATE PLAIN.
        let mut sasl = None;
        if verb == "AUTHENTICATE" {
            if args.len() >= 2 {
                sasl = Some(args[1].s());
            } else {
                if w.write_all(b"+ \r\n").await.is_err() {
                    return;
                }
                let Some(l) = read_line(&mut r).await else { return };
                sasl = Some(String::from_utf8_lossy(&l).into_owned());
            }
        }
        let logged = match verb.as_str() {
            "LOGIN" => format!("LOGIN {} ***", args.first().map(Tok::s).unwrap_or_default()),
            "AUTHENTICATE" => "AUTHENTICATE PLAIN ***".to_string(),
            "APPEND" => {
                let mut parts: Vec<String> = args.iter().map(Tok::render).collect();
                if let Some(Tok::Str(b)) = args.last() {
                    *parts.last_mut().unwrap() = format!("{{{} bytes}}", b.len());
                }
                format!("APPEND {}", parts.join(" "))
            }
            _ => {
                let rest: Vec<String> = args.iter().map(Tok::render).collect();
                if rest.is_empty() { verb.clone() } else { format!("{verb} {}", rest.join(" ")) }
            }
        };
        let fault = {
            let mut s = st.lock().unwrap();
            s.commands.push(logged);
            let last = s.commands.last().cloned().unwrap_or_default();
            let pos = s
                .faults
                .iter()
                .position(|(c, needle, _)| *c == verb && needle.as_ref().is_none_or(|n| last.contains(n.as_str())));
            pos.map(|p| s.faults.remove(p).2)
        };
        if let Some(Fault::Delay(d)) = &fault {
            tokio::time::sleep(*d).await;
        }
        match &fault {
            Some(Fault::No) => {
                if w.write_all(format!("{tag} NO [UNAVAILABLE] injected\r\n").as_bytes()).await.is_err() {
                    return;
                }
                continue;
            }
            Some(Fault::Bad) => {
                if w.write_all(format!("{tag} BAD injected\r\n").as_bytes()).await.is_err() {
                    return;
                }
                continue;
            }
            Some(Fault::Drop) => return,
            _ => {}
        }
        if verb == "IDLE" && conn.user.is_some() {
            let idle = st.lock().unwrap().opts.idle;
            if !idle {
                if w.write_all(format!("{tag} BAD unknown command\r\n").as_bytes()).await.is_err() {
                    return;
                }
                continue;
            }
            if !idle_conn(&st, &conn, &tag, &mut r, &mut w).await {
                return;
            }
            continue;
        }
        let (out, close) = handle(&st, &mut conn, &tag, &verb, &args, sasl);
        match fault {
            Some(Fault::DropAfterApply) => return,
            Some(Fault::DropMidResponse) => {
                let _ = w.write_all(&out[..out.len() / 2]).await;
                return;
            }
            Some(Fault::StallMidResponse(d)) => {
                if w.write_all(&out[..out.len() / 2]).await.is_err() {
                    return;
                }
                tokio::time::sleep(d).await;
                if w.write_all(&out[out.len() / 2..]).await.is_err() {
                    return;
                }
            }
            _ => {
                if w.write_all(&out).await.is_err() {
                    return;
                }
            }
        }
        if close {
            return;
        }
    }
}

/// Decrements the idling count however IDLE ends.
struct Idling(Arc<Mutex<State>>);

impl Drop for Idling {
    fn drop(&mut self) {
        self.0.lock().unwrap().idling -= 1;
    }
}

/// What an idling client is told about: (uid, modseq) of every message in the selected folder.
fn idle_view(st: &Arc<Mutex<State>>, conn: &Conn) -> Option<Vec<(u32, u64, Vec<String>)>> {
    let s = st.lock().unwrap();
    let (name, _) = conn.selected.as_ref()?;
    let f = s.users.get(conn.user.as_ref()?)?.folders.iter().find(|f| &f.raw_name == name)?;
    Some(f.msgs.iter().map(|m| (m.uid, m.modseq, m.flags.iter().cloned().collect())).collect())
}

/// One IDLE command: `+`, then untagged changes of the selected folder until `DONE` (tagged OK). Returns false
/// when the connection is to be closed (kicked, server timeout, client gone).
async fn idle_conn(
    st: &Arc<Mutex<State>>,
    conn: &Conn,
    tag: &str,
    r: &mut BufReader<OwnedReadHalf>,
    w: &mut OwnedWriteHalf,
) -> bool {
    let Some(mut view) = idle_view(st, conn) else {
        return w.write_all(format!("{tag} BAD no mailbox selected\r\n").as_bytes()).await.is_ok();
    };
    let (kick0, timeout) = {
        let mut s = st.lock().unwrap();
        s.idling += 1;
        (s.kick, s.opts.idle_timeout)
    };
    let _idling = Idling(st.clone());
    if w.write_all(b"+ idling\r\n").await.is_err() {
        return false;
    }
    let started = tokio::time::Instant::now();
    let mut line = Box::pin(read_line(r));
    loop {
        tokio::select! {
            l = &mut line => {
                let Some(l) = l else { return false };
                let text = String::from_utf8_lossy(&l).into_owned();
                st.lock().unwrap().commands.push(text.clone());
                let reply = if text.eq_ignore_ascii_case("DONE") {
                    format!("{tag} OK IDLE terminated\r\n")
                } else {
                    format!("{tag} BAD expected DONE\r\n")
                };
                return w.write_all(reply.as_bytes()).await.is_ok();
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                if st.lock().unwrap().kick != kick0 {
                    return false;
                }
                if timeout.is_some_and(|t| started.elapsed() >= t) {
                    let _ = w.write_all(b"* BYE idle timeout\r\n").await;
                    return false;
                }
                let Some(now) = idle_view(st, conn) else { return false };
                let mut out = Out::default();
                // Expunges first (sequence numbers of the old view), then new mail, then flag changes.
                let mut seq_view: Vec<u32> = view.iter().map(|m| m.0).collect();
                for (uid, _, _) in &view {
                    if !now.iter().any(|m| m.0 == *uid) {
                        let pos = seq_view.iter().position(|u| u == uid).unwrap();
                        if conn.qresync {
                            out.line(format!("* VANISHED {uid}"));
                        } else {
                            out.line(format!("* {} EXPUNGE", pos + 1));
                        }
                        seq_view.remove(pos);
                    }
                }
                if now.len() != seq_view.len() || now.iter().any(|m| !view.iter().any(|v| v.0 == m.0)) {
                    out.line(format!("* {} EXISTS", now.len()));
                }
                for (i, (uid, modseq, flags)) in now.iter().enumerate() {
                    if view.iter().any(|v| v.0 == *uid && v.1 != *modseq) {
                        out.line(format!("* {} FETCH (UID {uid} FLAGS ({}))", i + 1, flags.join(" ")));
                    }
                }
                view = now;
                if !out.0.is_empty() && w.write_all(&out.0).await.is_err() {
                    return false;
                }
            }
        }
    }
}

fn handle(
    st: &Arc<Mutex<State>>,
    conn: &mut Conn,
    tag: &str,
    verb: &str,
    args: &[Tok],
    sasl: Option<String>,
) -> (Vec<u8>, bool) {
    let mut s = st.lock().unwrap();
    let mut out = Out::default();
    let ok = |t: &str| format!("{tag} OK {t}");
    let caps_s = caps(&s.opts);
    let authed = conn.user.clone();
    match verb {
        "CAPABILITY" => {
            out.line(format!("* CAPABILITY {caps_s}"));
            out.line(ok("done"));
        }
        "NOOP" => out.line(ok("noop")),
        "ID" => {
            out.line("* ID NIL");
            out.line(ok("id"));
        }
        "LOGOUT" => {
            out.line("* BYE logging out");
            out.line(ok("bye"));
            return (out.0, true);
        }
        "STARTTLS" => out.line(format!("{tag} BAD plaintext test server")),
        "LOGIN" | "AUTHENTICATE" => {
            let (u, p) = if verb == "LOGIN" {
                let u = match args.first() {
                    Some(Tok::Str(b)) => String::from_utf8_lossy(b).into_owned(),
                    Some(t) => t.s(),
                    None => String::new(),
                };
                let p = match args.get(1) {
                    Some(Tok::Str(b)) => String::from_utf8_lossy(b).into_owned(),
                    Some(t) => t.s(),
                    None => String::new(),
                };
                (u, p)
            } else {
                let raw = STANDARD.decode(sasl.unwrap_or_default().trim()).unwrap_or_default();
                let parts: Vec<&[u8]> = raw.split(|b| *b == 0).collect();
                if parts.len() == 3 {
                    (String::from_utf8_lossy(parts[1]).into_owned(), String::from_utf8_lossy(parts[2]).into_owned())
                } else {
                    (String::new(), String::new())
                }
            };
            if s.users.get(&u).is_some_and(|x| x.password == p) {
                conn.user = Some(u);
                out.line(format!("{tag} OK [CAPABILITY {caps_s}] logged in"));
            } else {
                out.line(format!("{tag} NO [AUTHENTICATIONFAILED] invalid credentials"));
            }
        }
        _ if authed.is_none() => out.line(format!("{tag} BAD not authenticated")),
        "ENABLE" => {
            if s.opts.qresync && args.iter().any(|a| a.s().eq_ignore_ascii_case("QRESYNC")) {
                conn.qresync = true;
                out.line("* ENABLED QRESYNC");
            }
            out.line(ok("enabled"));
        }
        "LIST" | "LSUB" => {
            let su = s.opts.special_use;
            for f in &s.users[authed.as_ref().unwrap()].folders {
                let mut attrs = vec!["\\HasNoChildren".to_string()];
                match &f.special {
                    Some(sp) if sp == "\\Noselect" => attrs.push(sp.clone()),
                    Some(sp) if su => attrs.push(sp.clone()),
                    _ => {}
                }
                out.line(format!("* {verb} ({}) \"/\" \"{}\"", attrs.join(" "), f.raw_name));
            }
            out.line(ok("listed"));
        }
        "STATUS" | "SELECT" | "EXAMINE" => {
            let name = args.first().map(Tok::s).unwrap_or_default();
            let condstore = s.opts.condstore;
            let user = s.users.get_mut(authed.as_ref().unwrap()).unwrap();
            let Some(f) = user.folders.iter().find(|f| f.raw_name == name) else {
                out.line(format!("{tag} NO [NONEXISTENT] no such mailbox"));
                return (out.0, false);
            };
            if verb == "STATUS" {
                out.line(format!(
                    "* STATUS \"{}\" (MESSAGES {} UIDNEXT {} UIDVALIDITY {})",
                    f.raw_name,
                    f.msgs.len(),
                    f.uidnext,
                    f.uidvalidity
                ));
                out.line(ok("status"));
            } else {
                out.line(format!("* {} EXISTS", f.msgs.len()));
                out.line("* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)");
                out.line(format!("* OK [UIDVALIDITY {}] ok", f.uidvalidity));
                out.line(format!("* OK [UIDNEXT {}] ok", f.uidnext));
                if condstore {
                    out.line(format!("* OK [HIGHESTMODSEQ {}] ok", f.highestmodseq));
                }
                let ro = verb == "EXAMINE";
                conn.selected = Some((name, ro));
                out.line(format!("{tag} OK [{}] selected", if ro { "READ-ONLY" } else { "READ-WRITE" }));
            }
        }
        "APPEND" => {
            let name = args.first().map(Tok::s).unwrap_or_default();
            let flags: Vec<String> = match args.get(1) {
                Some(Tok::List(l)) => l.iter().map(Tok::s).collect(),
                _ => vec![],
            };
            let Some(Tok::Str(bytes)) = args.last() else {
                out.line(format!("{tag} BAD no message"));
                return (out.0, false);
            };
            let mut bytes = bytes.clone();
            if s.rewrite_on_append {
                let mut norm = b"X-Fake-Stored: yes\r\n".to_vec();
                let mut prev = 0u8;
                for &b in &bytes {
                    if b == b'\n' && prev != b'\r' {
                        norm.push(b'\r');
                    }
                    norm.push(b);
                    prev = b;
                }
                bytes = norm;
            }
            let uidplus = s.opts.uidplus;
            let gm_id = if s.opts.gmail {
                s.next_gm_id += 1;
                s.next_gm_id
            } else {
                0
            };
            let user = s.users.get_mut(authed.as_ref().unwrap()).unwrap();
            let Some(fi) = user.folders.iter().position(|f| f.raw_name == name) else {
                out.line(format!("{tag} NO [TRYCREATE] no such mailbox"));
                return (out.0, false);
            };
            let msg = Msg {
                uid: 0,
                flags: flags.into_iter().collect(),
                raw: bytes,
                internal_date: 1_767_225_600,
                modseq: 0,
                gm_id,
            };
            if gm_id != 0 && gm_kind(&user.folders[fi]) == GmKind::Label {
                // Gmail: a message appended to a label folder is in All Mail with that label.
                if let Some(all) = user.folders.iter().position(|f| gm_kind(f) == GmKind::All) {
                    let all_flags: BTreeSet<String> = msg.flags.clone();
                    push_copy(&mut user.folders[all], &Msg { flags: all_flags, ..msg.clone() });
                }
            }
            let uid = push_copy(&mut user.folders[fi], &msg);
            let f = &user.folders[fi];
            if uidplus {
                out.line(format!("{tag} OK [APPENDUID {} {uid}] appended", f.uidvalidity));
            } else {
                out.line(ok("appended"));
            }
        }
        "UID COPY" | "UID MOVE" if s.opts.gmail => return (gm_copy_move(&mut s, conn, tag, verb, args).0, false),
        "UID STORE"
            if s.opts.gmail && args.get(1).is_some_and(|a| a.s().to_ascii_uppercase().contains("X-GM-LABELS")) =>
        {
            return (gm_store_labels(&mut s, conn, tag, args).0, false);
        }
        "UID EXPUNGE" if s.opts.gmail && s.opts.uidplus => return (gm_expunge(&mut s, conn, tag, args).0, false),
        "UID COPY" | "UID MOVE" => {
            let Some((sel, ro)) = conn.selected.clone() else {
                out.line(format!("{tag} BAD no mailbox selected"));
                return (out.0, false);
            };
            if verb == "UID MOVE" && (!s.opts.move_cap || ro) {
                out.line(format!("{tag} {} move not possible", if ro { "NO" } else { "BAD" }));
                return (out.0, false);
            }
            let (copyuid, qresync) = (s.opts.copyuid, conn.qresync);
            let dest = args.get(1).map(Tok::s).unwrap_or_default();
            let user = s.users.get_mut(authed.as_ref().unwrap()).unwrap();
            let (Some(si), Some(di)) = (
                user.folders.iter().position(|f| f.raw_name == sel),
                user.folders.iter().position(|f| f.raw_name == dest),
            ) else {
                out.line(format!("{tag} NO [TRYCREATE] no such mailbox"));
                return (out.0, false);
            };
            let max = user.folders[si].msgs.iter().map(|m| m.uid).max().unwrap_or(0);
            let set = parse_set(&args.first().map(Tok::s).unwrap_or_default(), max);
            let picked: Vec<Msg> = user.folders[si].msgs.iter().filter(|m| in_set(&set, m.uid)).cloned().collect();
            let (mut src_uids, mut dst_uids) = (Vec::new(), Vec::new());
            for m in &picked {
                let d = &mut user.folders[di];
                let uid = d.uidnext;
                d.uidnext += 1;
                let modseq = d.bump();
                d.msgs.push(Msg { uid, modseq, gm_id: 0, ..m.clone() });
                src_uids.push(m.uid.to_string());
                dst_uids.push(uid.to_string());
            }
            let code = (copyuid && !picked.is_empty()).then(|| {
                format!("COPYUID {} {} {}", user.folders[di].uidvalidity, src_uids.join(","), dst_uids.join(","))
            });
            if verb == "UID COPY" {
                match code {
                    Some(c) => out.line(format!("{tag} OK [{c}] copied")),
                    None => out.line(ok("copied")),
                }
                return (out.0, false);
            }
            if let Some(c) = code {
                out.line(format!("* OK [{c}] moved"));
            }
            let f = &mut user.folders[si];
            let ms = f.bump();
            let mut seq = 0;
            let mut gone = Vec::new();
            f.msgs.retain(|m| {
                seq += 1;
                let del = in_set(&set, m.uid);
                if del {
                    gone.push((seq, m.uid));
                    seq -= 1;
                }
                !del
            });
            for (sq, uid) in gone {
                f.vanished.push((uid, ms));
                out.line(if qresync { format!("* VANISHED {uid}") } else { format!("* {sq} EXPUNGE") });
            }
            out.line(ok("moved"));
        }
        _ => {
            let Some((sel, ro)) = conn.selected.clone() else {
                out.line(format!("{tag} BAD no mailbox selected"));
                return (out.0, false);
            };
            let uidplus = s.opts.uidplus;
            let qresync = conn.qresync;
            let wide_vanished = s.opts.wide_vanished;
            let gmail = s.opts.gmail;
            let gm_map: HashMap<u64, Vec<String>> = if gmail {
                let u = &s.users[authed.as_ref().unwrap()];
                u.folders.iter().flat_map(|f| f.msgs.iter()).map(|m| (m.gm_id, gm_labels(u, m.gm_id))).collect()
            } else {
                HashMap::new()
            };
            let user = s.users.get_mut(authed.as_ref().unwrap()).unwrap();
            let Some(f) = user.folders.iter_mut().find(|f| f.raw_name == sel) else {
                out.line(format!("{tag} NO mailbox gone"));
                return (out.0, false);
            };
            let max = f.msgs.iter().map(|m| m.uid).max().unwrap_or(0);
            match verb {
                "UID SEARCH" => {
                    let crit: Vec<String> = args.iter().map(Tok::s).collect();
                    let uids: Vec<String> = match crit.first().map(|c| c.to_ascii_uppercase()).as_deref() {
                        Some("ALL") => f.msgs.iter().map(|m| m.uid.to_string()).collect(),
                        Some("UID") => {
                            let set = parse_set(crit.get(1).map(String::as_str).unwrap_or(""), max);
                            f.msgs.iter().filter(|m| in_set(&set, m.uid)).map(|m| m.uid.to_string()).collect()
                        }
                        _ => {
                            out.line(format!("{tag} BAD unsupported search"));
                            return (out.0, false);
                        }
                    };
                    out.line(if uids.is_empty() { "* SEARCH".into() } else { format!("* SEARCH {}", uids.join(" ")) });
                    out.line(ok("searched"));
                }
                "UID FETCH" => {
                    let set = parse_set(&args.first().map(Tok::s).unwrap_or_default(), max);
                    let items: Vec<String> = match args.get(1) {
                        Some(Tok::List(l)) => l.iter().map(|t| t.s().to_ascii_uppercase()).collect(),
                        Some(t) => vec![t.s().to_ascii_uppercase()],
                        None => vec![],
                    };
                    let mut changedsince = None;
                    let mut want_vanished = false;
                    if let Some(Tok::List(m)) = args.get(2) {
                        let m: Vec<String> = m.iter().map(|t| t.s().to_ascii_uppercase()).collect();
                        if let Some(p) = m.iter().position(|x| x == "CHANGEDSINCE") {
                            changedsince = m.get(p + 1).and_then(|v| v.parse::<u64>().ok());
                        }
                        want_vanished = m.iter().any(|x| x == "VANISHED");
                    }
                    if let (Some(cs), true, true) = (changedsince, want_vanished, qresync) {
                        // `*` in a UID range covers expunged UIDs above the current highest one.
                        let vset = parse_set(&args.first().map(Tok::s).unwrap_or_default(), u32::MAX);
                        let mut v: Vec<String> = f
                            .vanished
                            .iter()
                            .filter(|(u, ms)| *ms > cs && in_set(&vset, *u))
                            .map(|(u, _)| u.to_string())
                            .collect();
                        if wide_vanished && !v.is_empty() {
                            // The complement of the folder's UIDs up to far past UIDNEXT, as ranges.
                            let mut present: Vec<u32> = f.msgs.iter().map(|m| m.uid).collect();
                            present.sort_unstable();
                            let (mut lo, end) = (1u32, f.uidnext + WIDE_VANISHED);
                            v.clear();
                            for p in present.into_iter().chain([end + 1]) {
                                if p > lo {
                                    v.push(if p - 1 == lo { lo.to_string() } else { format!("{lo}:{}", p - 1) });
                                }
                                lo = p + 1;
                            }
                        }
                        if !v.is_empty() {
                            out.line(format!("* VANISHED (EARLIER) {}", v.join(",")));
                        }
                    }
                    let mut bump = Vec::new();
                    for (seq, m) in f.msgs.iter().enumerate() {
                        if !in_set(&set, m.uid) || changedsince.is_some_and(|cs| m.modseq <= cs) {
                            continue;
                        }
                        let mut parts = vec![format!("UID {}", m.uid)];
                        let mut body: Option<(String, Vec<u8>)> = None;
                        let mut sets_seen = false;
                        for it in &items {
                            match it.as_str() {
                                "UID" => {}
                                "FLAGS" => {}
                                "INTERNALDATE" => {
                                    parts.push(format!("INTERNALDATE \"{}\"", internal_date(m.internal_date)))
                                }
                                "RFC822.SIZE" => parts.push(format!("RFC822.SIZE {}", m.raw.len())),
                                "MODSEQ" => {}
                                "X-GM-LABELS" if gmail => {
                                    parts.push(gm_render(gm_map.get(&m.gm_id).map(Vec::as_slice).unwrap_or_default()))
                                }
                                "BODY.PEEK[]" => body = Some(("BODY[]".into(), m.raw.clone())),
                                "BODY[]" | "RFC822" => {
                                    body = Some((
                                        if it == "RFC822" { "RFC822".into() } else { "BODY[]".into() },
                                        m.raw.clone(),
                                    ));
                                    sets_seen = true;
                                }
                                _ => {}
                            }
                        }
                        if sets_seen && !m.flags.contains("\\Seen") {
                            bump.push(m.uid);
                        }
                        let mut flags: Vec<String> = m.flags.iter().cloned().collect();
                        if sets_seen && !flags.contains(&"\\Seen".to_string()) {
                            flags.push("\\Seen".into());
                        }
                        if items.iter().any(|i| i == "FLAGS") || sets_seen {
                            parts.push(format!("FLAGS ({})", flags.join(" ")));
                        }
                        if items.iter().any(|i| i == "MODSEQ") || changedsince.is_some() {
                            parts.push(format!("MODSEQ ({})", m.modseq));
                        }
                        match body {
                            Some((name, b)) => {
                                out_push_body(&mut out, seq + 1, &parts, &name, &b);
                            }
                            None => out.line(format!("* {} FETCH ({})", seq + 1, parts.join(" "))),
                        }
                    }
                    for uid in bump {
                        let ms = f.bump();
                        if let Some(m) = f.msgs.iter_mut().find(|m| m.uid == uid) {
                            m.flags.insert("\\Seen".into());
                            m.modseq = ms;
                        }
                    }
                    out.line(ok("fetched"));
                }
                "UID STORE" => {
                    if ro {
                        out.line(format!("{tag} NO read-only"));
                    } else {
                        let set = parse_set(&args.first().map(Tok::s).unwrap_or_default(), max);
                        let op = args.get(1).map(Tok::s).unwrap_or_default().to_ascii_uppercase();
                        let flags: Vec<String> = match args.get(2) {
                            Some(Tok::List(l)) => l.iter().map(Tok::s).collect(),
                            Some(t) => vec![t.s()],
                            None => vec![],
                        };
                        let ms = f.bump();
                        for m in f.msgs.iter_mut().filter(|m| in_set(&set, m.uid)) {
                            for fl in &flags {
                                if op.starts_with('+') {
                                    m.flags.insert(fl.clone());
                                } else if op.starts_with('-') {
                                    m.flags.remove(fl);
                                }
                            }
                            m.modseq = ms;
                        }
                        out.line(ok("stored"));
                    }
                }
                "UID EXPUNGE" if uidplus => {
                    let set = parse_set(&args.first().map(Tok::s).unwrap_or_default(), max);
                    let ms = f.bump();
                    let mut gone = Vec::new();
                    let mut seq = 0;
                    f.msgs.retain(|m| {
                        seq += 1;
                        let del = in_set(&set, m.uid) && m.flags.contains("\\Deleted");
                        if del {
                            gone.push((seq, m.uid));
                            seq -= 1;
                        }
                        !del
                    });
                    for (sq, uid) in gone {
                        f.vanished.push((uid, ms));
                        if qresync {
                            out.line(format!("* VANISHED {uid}"));
                        } else {
                            out.line(format!("* {sq} EXPUNGE"));
                        }
                    }
                    out.line(ok("expunged"));
                }
                _ => out.line(format!("{tag} BAD unknown command")),
            }
            if gmail && let Some(si) = user.folders.iter().position(|f| f.raw_name == sel) {
                gm_sync_flags(user, si);
            }
        }
    }
    (out.0, false)
}

// ------------------------------------------------------------------ Gmail mode

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GmKind {
    All,
    Trash,
    Spam,
    Label,
    NoSelect,
}

fn gm_kind(f: &Folder) -> GmKind {
    match f.special.as_deref() {
        Some("\\All") => GmKind::All,
        Some("\\Trash") => GmKind::Trash,
        Some("\\Junk") => GmKind::Spam,
        Some("\\Noselect") => GmKind::NoSelect,
        _ => GmKind::Label,
    }
}

/// Appends a copy of `m` with the next UID and MODSEQ of `f`; returns the UID.
fn push_copy(f: &mut Folder, m: &Msg) -> u32 {
    let uid = f.uidnext;
    f.uidnext += 1;
    let modseq = f.bump();
    f.msgs.push(Msg { uid, modseq, ..m.clone() });
    uid
}

/// Folders (indices) holding a copy of Gmail message `gm_id`.
fn gm_where(u: &User, gm_id: u64) -> BTreeSet<usize> {
    if gm_id == 0 {
        return BTreeSet::new();
    }
    u.folders.iter().enumerate().filter(|(_, f)| f.msgs.iter().any(|m| m.gm_id == gm_id)).map(|(i, _)| i).collect()
}

fn gm_index(u: &User, kind: GmKind) -> Option<usize> {
    u.folders.iter().position(|f| gm_kind(f) == kind)
}

/// `X-GM-LABELS` of a message: one per label folder holding a copy.
fn gm_labels(u: &User, gm_id: u64) -> Vec<String> {
    u.folders
        .iter()
        .filter(|f| gm_kind(f) == GmKind::Label && gm_id != 0 && f.msgs.iter().any(|m| m.gm_id == gm_id))
        .map(|f| match (f.raw_name.as_str(), f.special.as_deref()) {
            ("INBOX", _) => "\\Inbox".to_string(),
            (_, Some("\\Sent")) => "\\Sent".into(),
            (_, Some("\\Drafts")) => "\\Draft".into(),
            (_, Some("\\Important")) => "\\Important".into(),
            _ => f.raw_name.clone(),
        })
        .collect()
}

/// Renders labels like Gmail does: `\Inbox` as an atom, other system labels quoted with an escaped backslash, user
/// labels quoted.
fn gm_render(labels: &[String]) -> String {
    let items: Vec<String> =
        labels
            .iter()
            .map(|l| {
                if l == "\\Inbox" { l.clone() } else { format!("\"{}\"", l.replace('\\', "\\\\").replace('"', "\\\"")) }
            })
            .collect();
    format!("X-GM-LABELS ({})", items.join(" "))
}

/// The label folder a label names (`\Inbox`, `\Important`, `\Sent`, `\Draft` or a user label's folder name). Other
/// system labels (`\Trash`, `\Spam`, ...) name none.
fn gm_label_folder(u: &User, label: &str) -> Option<usize> {
    let by_special = |sp: &str| u.folders.iter().position(|f| f.special.as_deref() == Some(sp));
    match label.to_ascii_lowercase().as_str() {
        "\\inbox" => u.folders.iter().position(|f| f.raw_name == "INBOX"),
        "\\important" => by_special("\\Important"),
        "\\sent" => by_special("\\Sent"),
        "\\draft" => by_special("\\Drafts"),
        l if l.starts_with('\\') => None,
        _ => u.folders.iter().position(|f| f.raw_name == label && gm_kind(f) == GmKind::Label),
    }
}

/// Copies removed and added by [`gm_place`]: (folder index, UID).
#[derive(Default)]
struct Placed {
    removed: Vec<(usize, u32)>,
    added: Vec<(usize, u32)>,
}

/// Puts Gmail message `gm_id` into exactly the folders `targets`. Removed copies are recorded as vanished; remaining
/// copies get a new MODSEQ (their labels changed), as Gmail does.
fn gm_place(u: &mut User, gm_id: u64, targets: &BTreeSet<usize>) -> Placed {
    let mut p = Placed::default();
    let template = u.folders.iter().flat_map(|f| f.msgs.iter()).find(|m| gm_id != 0 && m.gm_id == gm_id).cloned();
    let Some(mut template) = template else { return p };
    template.flags.remove("\\Deleted");
    for (i, f) in u.folders.iter_mut().enumerate() {
        let has = f.msgs.iter().position(|m| m.gm_id == gm_id);
        match (has, targets.contains(&i)) {
            (Some(pos), false) => {
                let ms = f.bump();
                let uid = f.msgs.remove(pos).uid;
                f.vanished.push((uid, ms));
                p.removed.push((i, uid));
            }
            (None, true) => p.added.push((i, push_copy(f, &template))),
            (Some(pos), true) => {
                let ms = f.bump();
                f.msgs[pos].modseq = ms;
            }
            (None, false) => {}
        }
    }
    p
}

/// Gmail flags belong to the message: copies the flags of every Gmail message in folder `from` to its other copies
/// (all but `\Deleted`, which stays per folder), bumping MODSEQ where they change.
fn gm_sync_flags(u: &mut User, from: usize) {
    let src: Vec<(u64, BTreeSet<String>)> = u.folders[from]
        .msgs
        .iter()
        .filter(|m| m.gm_id != 0)
        .map(|m| (m.gm_id, m.flags.iter().filter(|f| *f != "\\Deleted").cloned().collect()))
        .collect();
    for (gm_id, flags) in src {
        for (i, f) in u.folders.iter_mut().enumerate() {
            if i == from {
                continue;
            }
            let Some(pos) = f.msgs.iter().position(|m| m.gm_id == gm_id) else { continue };
            let mut want = flags.clone();
            if f.msgs[pos].flags.contains("\\Deleted") {
                want.insert("\\Deleted".into());
            }
            if f.msgs[pos].flags != want {
                let ms = f.bump();
                f.msgs[pos].flags = want;
                f.msgs[pos].modseq = ms;
            }
        }
    }
}

/// Reports UIDs removed from the selected folder (`old` is its UID list before the change, in sequence order).
fn expunge_lines(out: &mut Out, old: &[u32], removed: &[u32], qresync: bool) {
    let mut seq_view = old.to_vec();
    for uid in removed {
        let Some(pos) = seq_view.iter().position(|u| u == uid) else { continue };
        out.line(if qresync { format!("* VANISHED {uid}") } else { format!("* {} EXPUNGE", pos + 1) });
        seq_view.remove(pos);
    }
}

/// Gmail-mode COPY/MOVE: into Trash/Spam drops every label; out of Trash/Spam restores into All Mail (plus the
/// target label); MOVE between labels swaps the label, COPY adds one.
fn gm_copy_move(s: &mut State, conn: &Conn, tag: &str, verb: &str, args: &[Tok]) -> Out {
    let mut out = Out::default();
    let Some((sel, ro)) = conn.selected.clone() else {
        out.line(format!("{tag} BAD no mailbox selected"));
        return out;
    };
    if verb == "UID MOVE" && (!s.opts.move_cap || ro) {
        out.line(format!("{tag} {} move not possible", if ro { "NO" } else { "BAD" }));
        return out;
    }
    let (copyuid, qresync) = (s.opts.copyuid, conn.qresync);
    let dest = args.get(1).map(Tok::s).unwrap_or_default();
    let user = s.users.get_mut(conn.user.as_ref().unwrap()).unwrap();
    let (Some(si), Some(di)) = (
        user.folders.iter().position(|f| f.raw_name == sel),
        user.folders.iter().position(|f| f.raw_name == dest && gm_kind(f) != GmKind::NoSelect),
    ) else {
        out.line(format!("{tag} NO [TRYCREATE] no such mailbox"));
        return out;
    };
    let all = gm_index(user, GmKind::All).expect("All Mail");
    let old: Vec<u32> = user.folders[si].msgs.iter().map(|m| m.uid).collect();
    let max = old.iter().copied().max().unwrap_or(0);
    let set = parse_set(&args.first().map(Tok::s).unwrap_or_default(), max);
    let picked: Vec<(u32, u64)> =
        user.folders[si].msgs.iter().filter(|m| in_set(&set, m.uid)).map(|m| (m.uid, m.gm_id)).collect();
    let (sk, dk) = (gm_kind(&user.folders[si]), gm_kind(&user.folders[di]));
    let trashy = |k: GmKind| matches!(k, GmKind::Trash | GmKind::Spam);
    let (mut pairs, mut removed) = (Vec::new(), Vec::new());
    for (uid, gm) in picked {
        let mut want = gm_where(user, gm);
        if trashy(dk) || trashy(sk) {
            want.clear();
        }
        if trashy(sk) && !trashy(dk) {
            want.insert(all);
        }
        want.insert(di);
        if verb == "UID MOVE" && sk == GmKind::Label {
            want.remove(&si);
        }
        let placed = gm_place(user, gm, &want);
        let dst = placed
            .added
            .iter()
            .find(|(i, _)| *i == di)
            .map(|(_, u)| *u)
            .or_else(|| user.folders[di].msgs.iter().find(|m| m.gm_id == gm).map(|m| m.uid));
        if let Some(d) = dst {
            pairs.push((uid, d));
        }
        if placed.removed.iter().any(|(i, u)| *i == si && *u == uid) {
            removed.push(uid);
        }
    }
    let code = (copyuid && !pairs.is_empty()).then(|| {
        let (a, b): (Vec<String>, Vec<String>) = pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).unzip();
        format!("COPYUID {} {} {}", user.folders[di].uidvalidity, a.join(","), b.join(","))
    });
    if verb == "UID COPY" {
        match code {
            Some(c) => out.line(format!("{tag} OK [{c}] copied")),
            None => out.line(format!("{tag} OK copied")),
        }
        return out;
    }
    if let Some(c) = code {
        out.line(format!("* OK [{c}] moved"));
    }
    expunge_lines(&mut out, &old, &removed, qresync);
    out.line(format!("{tag} OK moved"));
    out
}

/// Gmail-mode `UID STORE +/-X-GM-LABELS[.SILENT] (...)` on the selected folder.
fn gm_store_labels(s: &mut State, conn: &Conn, tag: &str, args: &[Tok]) -> Out {
    let mut out = Out::default();
    let Some((sel, ro)) = conn.selected.clone() else {
        out.line(format!("{tag} BAD no mailbox selected"));
        return out;
    };
    if ro {
        out.line(format!("{tag} NO read-only"));
        return out;
    }
    let op = args.get(1).map(Tok::s).unwrap_or_default().to_ascii_uppercase();
    let silent = op.ends_with(".SILENT");
    let labels: Vec<String> = match args.get(2) {
        Some(Tok::List(l)) => l.iter().map(Tok::s).collect(),
        Some(t) => vec![t.s()],
        None => vec![],
    };
    let user = s.users.get_mut(conn.user.as_ref().unwrap()).unwrap();
    let Some(si) = user.folders.iter().position(|f| f.raw_name == sel) else {
        out.line(format!("{tag} NO mailbox gone"));
        return out;
    };
    if matches!(gm_kind(&user.folders[si]), GmKind::Trash | GmKind::Spam) {
        out.line(format!("{tag} NO [CANNOT] no labels in Trash or Spam"));
        return out;
    }
    let mut idx = Vec::new();
    for l in &labels {
        match gm_label_folder(user, l) {
            Some(i) => idx.push(i),
            // Real Gmail would create the label; the fake refuses so a test notices.
            None => {
                out.line(format!("{tag} NO [NONEXISTENT] unknown label"));
                return out;
            }
        }
    }
    let all = gm_index(user, GmKind::All).expect("All Mail");
    let max = user.folders[si].msgs.iter().map(|m| m.uid).max().unwrap_or(0);
    let set = parse_set(&args.first().map(Tok::s).unwrap_or_default(), max);
    let picked: Vec<u64> = user.folders[si].msgs.iter().filter(|m| in_set(&set, m.uid)).map(|m| m.gm_id).collect();
    for gm in picked {
        let mut want = gm_where(user, gm);
        if op.starts_with('+') {
            want.extend(idx.iter().copied());
        } else if op.starts_with('-') {
            idx.iter().for_each(|i| {
                want.remove(i);
            });
        } else {
            want = idx.iter().copied().chain([all]).collect();
        }
        gm_place(user, gm, &want);
    }
    if !silent {
        let f = &user.folders[si];
        let lines: Vec<String> = f
            .msgs
            .iter()
            .enumerate()
            .filter(|(_, m)| in_set(&set, m.uid))
            .map(|(seq, m)| {
                format!(
                    "* {} FETCH (UID {} {} MODSEQ ({}))",
                    seq + 1,
                    m.uid,
                    gm_render(&gm_labels(user, m.gm_id)),
                    m.modseq
                )
            })
            .collect();
        lines.into_iter().for_each(|l| out.line(l));
    }
    out.line(format!("{tag} OK stored"));
    out
}

/// Gmail-mode `UID EXPUNGE`: in a label folder it removes that label, in Drafts the draft, in All Mail (or Trash and
/// Spam) the message everywhere: the "delete for good" outcome Dove must never cause.
fn gm_expunge(s: &mut State, conn: &Conn, tag: &str, args: &[Tok]) -> Out {
    let mut out = Out::default();
    let Some((sel, _)) = conn.selected.clone() else {
        out.line(format!("{tag} BAD no mailbox selected"));
        return out;
    };
    let qresync = conn.qresync;
    let user = s.users.get_mut(conn.user.as_ref().unwrap()).unwrap();
    let Some(si) = user.folders.iter().position(|f| f.raw_name == sel) else {
        out.line(format!("{tag} NO mailbox gone"));
        return out;
    };
    let old: Vec<u32> = user.folders[si].msgs.iter().map(|m| m.uid).collect();
    let max = old.iter().copied().max().unwrap_or(0);
    let set = parse_set(&args.first().map(Tok::s).unwrap_or_default(), max);
    let gone: Vec<(u32, u64)> = user.folders[si]
        .msgs
        .iter()
        .filter(|m| in_set(&set, m.uid) && m.flags.contains("\\Deleted"))
        .map(|m| (m.uid, m.gm_id))
        .collect();
    let drafts = user.folders[si].special.as_deref() == Some("\\Drafts");
    let kind = gm_kind(&user.folders[si]);
    let mut removed = Vec::new();
    for (uid, gm) in gone {
        if gm == 0 {
            let f = &mut user.folders[si];
            let ms = f.bump();
            f.msgs.retain(|m| m.uid != uid);
            f.vanished.push((uid, ms));
        } else {
            let mut want = gm_where(user, gm);
            if kind == GmKind::Label && !drafts {
                want.remove(&si);
            } else {
                want.clear();
            }
            gm_place(user, gm, &want);
        }
        removed.push(uid);
    }
    expunge_lines(&mut out, &old, &removed, qresync);
    out.line(format!("{tag} OK expunged"));
    out
}

fn out_push_body(out: &mut Out, seq: usize, parts: &[String], name: &str, body: &[u8]) {
    out.0.extend_from_slice(format!("* {seq} FETCH ({} {name} {{{}}}\r\n", parts.join(" "), body.len()).as_bytes());
    out.0.extend_from_slice(body);
    out.line(")");
}

#[derive(Default)]
struct Out(Vec<u8>);

impl Out {
    fn line(&mut self, l: impl AsRef<[u8]>) {
        self.0.extend_from_slice(l.as_ref());
        self.0.extend_from_slice(b"\r\n");
    }
}

// ------------------------------------------------------------------ SMTP connection

async fn smtp_conn(st: Arc<Mutex<State>>, mut r: BufReader<OwnedReadHalf>, mut w: OwnedWriteHalf) {
    if w.write_all(b"220 fake ESMTP\r\n").await.is_err() {
        return;
    }
    let mut authed = false;
    let mut from: Option<String> = None;
    let mut rcpts: Vec<String> = Vec::new();
    loop {
        let Some(line) = read_line(&mut r).await else { return };
        let text = String::from_utf8_lossy(&line).into_owned();
        let up = text.to_ascii_uppercase();
        let verb = up.split([' ', ':']).next().unwrap_or_default().to_string();
        let logged = if verb == "AUTH" { "AUTH ***".to_string() } else { text.clone() };
        let fault = {
            let mut s = st.lock().unwrap();
            s.smtp_commands.push(logged);
            let pos = s.smtp_faults.iter().position(|(c, _)| *c == verb);
            pos.map(|p| s.smtp_faults.remove(p).1)
        };
        match &fault {
            Some(SmtpFault::Reply(code)) if verb != "DATA" => {
                if w.write_all(format!("{code} injected\r\n").as_bytes()).await.is_err() {
                    return;
                }
                continue;
            }
            Some(SmtpFault::Drop) => return,
            Some(SmtpFault::Delay(d)) if verb != "DATA" => tokio::time::sleep(*d).await,
            _ => {}
        }
        let check = |u: &str, p: &str| st.lock().unwrap().users.get(u).is_some_and(|x| x.password == p);
        let reply: String = match verb.as_str() {
            "EHLO" => {
                let auth = st.lock().unwrap().opts.smtp_auth;
                format!("250-fake\r\n250-AUTH {auth}\r\n250 8BITMIME")
            }
            "AUTH" => {
                let words: Vec<&str> = text.split_whitespace().collect();
                let mech = words.get(1).map(|m| m.to_ascii_uppercase()).unwrap_or_default();
                let ok = if mech == "PLAIN" {
                    let ir = match words.get(2) {
                        Some(ir) => ir.to_string(),
                        None => {
                            if w.write_all(b"334 \r\n").await.is_err() {
                                return;
                            }
                            let Some(l) = read_line(&mut r).await else { return };
                            st.lock().unwrap().smtp_commands.push("<auth line>".into());
                            String::from_utf8_lossy(&l).into_owned()
                        }
                    };
                    let raw = STANDARD.decode(ir.trim()).unwrap_or_default();
                    let p: Vec<&[u8]> = raw.split(|b| *b == 0).collect();
                    p.len() == 3 && check(&String::from_utf8_lossy(p[1]), &String::from_utf8_lossy(p[2]))
                } else if mech == "LOGIN" {
                    let mut vals = Vec::new();
                    for prompt in ["334 VXNlcm5hbWU6\r\n", "334 UGFzc3dvcmQ6\r\n"] {
                        if w.write_all(prompt.as_bytes()).await.is_err() {
                            return;
                        }
                        let Some(l) = read_line(&mut r).await else { return };
                        st.lock().unwrap().smtp_commands.push("<auth line>".into());
                        vals.push(String::from_utf8_lossy(&STANDARD.decode(l).unwrap_or_default()).into_owned());
                    }
                    check(&vals[0], &vals[1])
                } else {
                    false
                };
                authed = ok;
                if ok { "235 authenticated".into() } else { "535 5.7.8 authentication failed".into() }
            }
            "MAIL" if !authed => "530 authentication required".into(),
            "MAIL" => {
                from = text.split_once('<').and_then(|(_, r)| r.split_once('>')).map(|(a, _)| a.to_string());
                rcpts.clear();
                "250 ok".into()
            }
            "RCPT" => {
                rcpts.push(
                    text.split_once('<')
                        .and_then(|(_, r)| r.split_once('>'))
                        .map(|(a, _)| a.to_string())
                        .unwrap_or_default(),
                );
                "250 ok".into()
            }
            "DATA" => {
                if let Some(SmtpFault::Reply(code)) = &fault {
                    if w.write_all(format!("{code} injected\r\n").as_bytes()).await.is_err() {
                        return;
                    }
                    continue;
                }
                if w.write_all(b"354 go ahead\r\n").await.is_err() {
                    return;
                }
                let mut data = Vec::new();
                loop {
                    let mut l = Vec::new();
                    if r.read_until(b'\n', &mut l).await.unwrap_or(0) == 0 {
                        return;
                    }
                    if l == b".\r\n" {
                        break;
                    }
                    if l.starts_with(b"..") {
                        l.remove(0);
                    }
                    data.extend_from_slice(&l);
                }
                {
                    let mut g = st.lock().unwrap();
                    if g.opts.gmail {
                        // Gmail files every submission in Sent Mail itself.
                        g.next_gm_id += 1;
                        let gm_id = g.next_gm_id;
                        if let Some(u) = g.users.get_mut(from.as_deref().unwrap_or_default())
                            && let (Some(sent), Some(all)) = (
                                u.folders.iter().position(|f| f.special.as_deref() == Some("\\Sent")),
                                gm_index(u, GmKind::All),
                            )
                        {
                            let m = Msg {
                                uid: 0,
                                flags: ["\\Seen".to_string()].into(),
                                raw: data.clone(),
                                internal_date: 1_767_225_600,
                                modseq: 0,
                                gm_id,
                            };
                            push_copy(&mut u.folders[sent], &m);
                            push_copy(&mut u.folders[all], &m);
                        }
                    }
                    g.sent.push(SentMail { from: from.clone().unwrap_or_default(), rcpts: rcpts.clone(), data });
                }
                if matches!(fault, Some(SmtpFault::DropAfterTerminator)) {
                    return;
                }
                if let Some(SmtpFault::Delay(d)) = &fault {
                    tokio::time::sleep(*d).await;
                }
                "250 queued".into()
            }
            "RSET" => {
                from = None;
                rcpts.clear();
                "250 ok".into()
            }
            "QUIT" => {
                let _ = w.write_all(b"221 bye\r\n").await;
                return;
            }
            _ => "500 unknown command".into(),
        };
        if w.write_all(format!("{reply}\r\n").as_bytes()).await.is_err() {
            return;
        }
    }
}
