//! One logged-in IMAP connection with typed calls. Commands come only from [`super::ops`].
//!
//! Any error leaves the stream in an unknown state; the owner must drop the session (the pool does). Responses are
//! bounded: lines at [`MAX_LINE`], literals at the per-call cap.

use std::borrow::Cow;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use zeroize::Zeroizing;

use super::ops::{AppendFlag, IMAP_VERBS, ImapOp, Part};
use super::{Credentials, ImapConnector, ImapError, Io, ServerEndpoint, TlsMode, utf7};

const MAX_LINE: usize = 64 * 1024;
/// Line cap for responses that list UIDs on one line (`SEARCH`, `VANISHED`).
const BIG_LINE: usize = 32 * 1024 * 1024;
/// Literal cap for responses that carry no message content (LIST names, flags).
const SMALL_LITERAL: usize = 64 * 1024;
/// Upper bound for the number of untagged responses collected for one command.
const MAX_UNTAGGED: usize = 200_000;
/// Bytes read for one command beyond its largest literal (all lines and small literals together).
const COMMAND_OVERHEAD: usize = 16 * 1024 * 1024;
/// Nesting depth of parenthesized lists in one response.
const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Special {
    Drafts,
    Sent,
    Junk,
    Trash,
}

impl Special {
    pub fn as_str(self) -> &'static str {
        match self {
            Special::Drafts => "drafts",
            Special::Sent => "sent",
            Special::Junk => "junk",
            Special::Trash => "trash",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "drafts" => Some(Special::Drafts),
            "sent" => Some(Special::Sent),
            "junk" => Some(Special::Junk),
            "trash" => Some(Special::Trash),
            _ => None,
        }
    }
}

/// The only folders Dove may `APPEND` to. The session maps them to names set by [`ImapSession::set_append_targets`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendTarget {
    Drafts,
    Sent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderInfo {
    /// Decoded (UTF-8) name, the agent-visible label.
    pub name_utf8: String,
    /// Name as the server spells it (modified UTF-7), used on the wire.
    pub raw_name: String,
    pub delimiter: Option<char>,
    pub special: Option<Special>,
    pub selectable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FolderStatus {
    pub uidvalidity: u32,
    pub uidnext: u32,
    pub highestmodseq: Option<u64>,
    pub exists: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FetchedMeta {
    pub uid: u32,
    pub flags: Vec<String>,
    pub internal_date_s: i64,
    pub size: u64,
    pub modseq: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Changes {
    /// Messages whose flags (or existence) changed since the given mod-sequence.
    pub changed: Vec<FetchedMeta>,
    /// UIDs expunged since then; `None` when QRESYNC is not enabled (the caller diffs `UID SEARCH ALL` instead).
    pub vanished: Option<Vec<u32>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendUid {
    pub uidvalidity: u32,
    pub uid: u32,
}

/// The UID of a Dove-owned draft in the Drafts folder: the only message Dove may flag `\Deleted` and expunge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnDraftUid {
    uidvalidity: u32,
    uid: u32,
}

impl OwnDraftUid {
    /// Only `tools::drafts` may call this, after checking the `own_drafts` record and a fresh content hash.
    #[allow(dead_code)] // the IMAP drafts tools are the only caller
    pub(crate) fn new_for_drafts(uidvalidity: u32, uid: u32) -> Self {
        Self { uidvalidity, uid }
    }
    pub fn uid(&self) -> u32 {
        self.uid
    }
    pub fn uidvalidity(&self) -> u32 {
        self.uidvalidity
    }
}

// ------------------------------------------------------------------ response model

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Tok {
    Atom(String),
    Str(Vec<u8>),
    List(Vec<Tok>),
    Code(Vec<Tok>),
}

impl Tok {
    fn atom(&self) -> Option<&str> {
        match self {
            Tok::Atom(a) => Some(a),
            _ => None,
        }
    }
    fn text(&self) -> Option<Cow<'_, str>> {
        match self {
            Tok::Atom(a) => Some(Cow::Borrowed(a)),
            Tok::Str(s) => Some(String::from_utf8_lossy(s)),
            _ => None,
        }
    }
    fn num<T: std::str::FromStr>(&self) -> Option<T> {
        self.atom().and_then(|a| a.parse().ok())
    }
    fn is_nil(&self) -> bool {
        matches!(self, Tok::Atom(a) if a.eq_ignore_ascii_case("NIL"))
    }
}

enum Seg {
    Text(Vec<u8>),
    Lit(Vec<u8>),
}

/// Tokenizes one response (text segments and literals). Lenient: unbalanced input ends the current list.
/// `None` when lists nest deeper than [`MAX_DEPTH`] (a hostile server must not exhaust the stack).
fn tokenize(segs: Vec<Seg>) -> Option<Vec<Tok>> {
    struct Cur {
        segs: std::vec::IntoIter<Seg>,
        text: Vec<u8>,
        pos: usize,
        pending_lit: Option<Vec<u8>>,
        too_deep: bool,
    }
    impl Cur {
        fn peek(&mut self) -> Option<u8> {
            loop {
                if self.pending_lit.is_some() {
                    return Some(0);
                }
                if self.pos < self.text.len() {
                    return Some(self.text[self.pos]);
                }
                match self.segs.next()? {
                    Seg::Text(t) => {
                        self.text = t;
                        self.pos = 0;
                    }
                    Seg::Lit(l) => self.pending_lit = Some(l),
                }
            }
        }
    }
    fn list(c: &mut Cur, close: u8, depth: usize) -> Vec<Tok> {
        let mut out = Vec::new();
        if depth > MAX_DEPTH {
            c.too_deep = true;
            return out;
        }
        while let Some(b) = c.peek() {
            if let Some(l) = c.pending_lit.take() {
                out.push(Tok::Str(l));
                continue;
            }
            match b {
                b' ' => c.pos += 1,
                b'(' => {
                    c.pos += 1;
                    out.push(Tok::List(list(c, b')', depth + 1)));
                }
                b'[' => {
                    c.pos += 1;
                    out.push(Tok::Code(list(c, b']', depth + 1)));
                }
                b')' | b']' => {
                    c.pos += 1;
                    if b == close {
                        return out;
                    }
                }
                b'"' => {
                    c.pos += 1;
                    let mut s = Vec::new();
                    while c.pos < c.text.len() {
                        let ch = c.text[c.pos];
                        c.pos += 1;
                        match ch {
                            b'\\' if c.pos < c.text.len() => {
                                s.push(c.text[c.pos]);
                                c.pos += 1;
                            }
                            b'"' => break,
                            _ => s.push(ch),
                        }
                    }
                    out.push(Tok::Str(s));
                }
                _ => {
                    let mut a = Vec::new();
                    let mut depth = 0;
                    while c.pos < c.text.len() {
                        let ch = c.text[c.pos];
                        if depth == 0 && matches!(ch, b' ' | b'(' | b')' | b']' | b'"') {
                            break;
                        }
                        if ch == b'[' {
                            depth += 1;
                        } else if ch == b']' {
                            depth -= 1;
                        }
                        a.push(ch);
                        c.pos += 1;
                    }
                    out.push(Tok::Atom(String::from_utf8_lossy(&a).into_owned()));
                }
            }
        }
        out
    }
    let mut c = Cur { segs: segs.into_iter(), text: Vec::new(), pos: 0, pending_lit: None, too_deep: false };
    let toks = list(&mut c, 0, 0);
    (!c.too_deep).then_some(toks)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Ok,
    No,
    Bad,
}

/// One untagged response, tokenized after the `*`.
#[derive(Debug)]
struct Untagged(Vec<Tok>);

#[derive(Debug)]
struct Done {
    status: Status,
    code: Vec<Tok>,
    untagged: Vec<Untagged>,
}

impl Done {
    fn code_name(&self) -> Option<String> {
        self.code.first().and_then(Tok::atom).map(str::to_ascii_uppercase)
    }
}

/// Where a failed command stopped: needed to classify writes.
struct ExecError {
    err: ImapError,
    /// True when every byte of the command (including literals) was written.
    sent_all: bool,
}

impl From<ExecError> for ImapError {
    fn from(e: ExecError) -> Self {
        e.err
    }
}

/// Parses an IMAP INTERNALDATE (`17-Jul-1996 02:44:25 -0700`) into unix seconds.
pub(crate) fn parse_internal_date(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, rest) = s.split_once(' ')?;
    let (time, zone) = rest.trim().split_once(' ')?;
    let mut d = date.trim().split('-');
    let day: u8 = d.next()?.trim().parse().ok()?;
    let mon = match d.next()?.to_ascii_lowercase().as_str() {
        "jan" => time::Month::January,
        "feb" => time::Month::February,
        "mar" => time::Month::March,
        "apr" => time::Month::April,
        "may" => time::Month::May,
        "jun" => time::Month::June,
        "jul" => time::Month::July,
        "aug" => time::Month::August,
        "sep" => time::Month::September,
        "oct" => time::Month::October,
        "nov" => time::Month::November,
        "dec" => time::Month::December,
        _ => return None,
    };
    let year: i32 = d.next()?.parse().ok()?;
    let mut t = time.split(':');
    let (h, m, sec): (u8, u8, u8) = (t.next()?.parse().ok()?, t.next()?.parse().ok()?, t.next()?.parse().ok()?);
    let z = zone.trim();
    if z.len() != 5 || !z.is_ascii() {
        return None;
    }
    let sign = match &z[..1] {
        "+" => 1,
        "-" => -1,
        _ => return None,
    };
    let zh: i64 = z[1..3].parse().ok()?;
    let zm: i64 = z[3..5].parse().ok()?;
    let dt = time::PrimitiveDateTime::new(
        time::Date::from_calendar_date(year, mon, day).ok()?,
        time::Time::from_hms(h, m, sec).ok()?,
    );
    Some(dt.assume_utc().unix_timestamp() - sign * (zh * 3600 + zm * 60))
}

fn parse_uid_set(s: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for part in s.split(',') {
        match part.split_once(':') {
            Some((a, b)) => {
                if let (Ok(a), Ok(b)) = (a.parse::<u32>(), b.parse::<u32>()) {
                    let (lo, hi) = (a.min(b), a.max(b));
                    // Bounded: a hostile server cannot make us allocate billions of entries.
                    if hi - lo <= 1_000_000 {
                        out.extend(lo..=hi);
                    }
                }
            }
            None => {
                if let Ok(u) = part.parse() {
                    out.push(u);
                }
            }
        }
    }
    out
}

// ------------------------------------------------------------------ session

pub struct ImapSession {
    io: BufReader<Box<dyn Io>>,
    tag: u32,
    caps: Vec<String>,
    timeout: Duration,
    drafts: Option<String>,
    sent: Option<String>,
    selected: Option<(String, bool, FolderStatus)>,
    qresync: bool,
}

impl std::fmt::Debug for ImapSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImapSession").field("caps", &self.caps).finish_non_exhaustive()
    }
}

async fn read_raw_line<R: tokio::io::AsyncBufRead + Unpin>(
    r: &mut R,
    timeout: Duration,
    max_line: usize,
) -> Result<Vec<u8>, ImapError> {
    let mut line = Vec::new();
    let fut = async {
        let mut limited = (&mut *r).take(max_line as u64 + 1);
        limited.read_until(b'\n', &mut line).await
    };
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(0)) => Err(ImapError::Network),
        Ok(Ok(_)) if line.len() > max_line => Err(ImapError::Protocol("response line too long")),
        Ok(Ok(_)) if !line.ends_with(b"\n") => Err(ImapError::Network),
        Ok(Ok(_)) => {
            while line.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
                line.pop();
            }
            Ok(line)
        }
        _ => Err(ImapError::Network),
    }
}

/// Literal announcement at the end of a line: `{123}` or `{123+}`.
fn literal_len(line: &[u8]) -> Option<usize> {
    if !line.ends_with(b"}") {
        return None;
    }
    let open = line.iter().rposition(|b| *b == b'{')?;
    let inner = &line[open + 1..line.len() - 1];
    let inner = inner.strip_suffix(b"+").unwrap_or(inner);
    if inner.is_empty() || !inner.iter().all(u8::is_ascii_digit) || inner.len() > 12 {
        return None;
    }
    std::str::from_utf8(inner).ok()?.parse().ok()
}

impl ImapSession {
    /// Connects, establishes verified TLS (implicit or STARTTLS without fallback), checks capabilities and logs in.
    /// Refuses servers without `IMAP4rev1` or `UIDPLUS`.
    pub async fn connect(
        connector: &ImapConnector,
        ep: &ServerEndpoint,
        creds: &Credentials,
        timeout: Duration,
    ) -> Result<Self, ImapError> {
        let tcp = connector.tcp(ep, timeout).await?;
        let io: Box<dyn Io> = if connector.is_plaintext() {
            Box::new(tcp)
        } else {
            match ep.tls {
                TlsMode::Implicit => connector.tls(tcp, ep, timeout).await?,
                TlsMode::StartTls => {
                    let mut r = BufReader::new(tcp);
                    Self::expect_greeting(&mut r, timeout).await?;
                    let line = format!("s0 {}\r\n", ImapOp::StartTls.render().text());
                    tokio::time::timeout(timeout, r.get_mut().write_all(line.as_bytes()))
                        .await
                        .map_err(|_| ImapError::Network)?
                        .map_err(|_| ImapError::Network)?;
                    loop {
                        let line = read_raw_line(&mut r, timeout, MAX_LINE).await?;
                        if line.starts_with(b"* ") {
                            continue;
                        }
                        if !line.to_ascii_uppercase().starts_with(b"S0 OK") {
                            return Err(ImapError::Tls);
                        }
                        break;
                    }
                    // Bytes after the OK and before the handshake would be injected plaintext.
                    if !r.buffer().is_empty() {
                        return Err(ImapError::Tls);
                    }
                    connector.tls(r.into_inner(), ep, timeout).await?
                }
            }
        };
        let mut s = Self {
            io: BufReader::new(io),
            tag: 0,
            caps: Vec::new(),
            timeout,
            drafts: None,
            sent: None,
            selected: None,
            qresync: false,
        };
        if connector.is_plaintext() || ep.tls == TlsMode::Implicit {
            Self::expect_greeting(&mut s.io, timeout).await?;
        }
        s.refresh_caps().await?;
        if !s.has_cap("IMAP4REV1") && !s.has_cap("IMAP4REV2") {
            return Err(ImapError::Capability("IMAP4rev1"));
        }
        s.login(creds).await?;
        if !s.has_cap("UIDPLUS") {
            return Err(ImapError::Capability("UIDPLUS"));
        }
        Ok(s)
    }

    async fn expect_greeting<R: tokio::io::AsyncBufRead + Unpin>(
        r: &mut R,
        timeout: Duration,
    ) -> Result<(), ImapError> {
        let line = read_raw_line(r, timeout, MAX_LINE).await?.to_ascii_uppercase();
        if line.starts_with(b"* OK") {
            Ok(())
        } else if line.starts_with(b"* PREAUTH") {
            // Dove always authenticates explicitly; a pre-authenticated session is not what was configured.
            Err(ImapError::Protocol("unexpected PREAUTH greeting"))
        } else {
            Err(ImapError::Network)
        }
    }

    async fn refresh_caps(&mut self) -> Result<(), ImapError> {
        let d = self.exec(ImapOp::Capability, SMALL_LITERAL).await?;
        if d.status != Status::Ok {
            return Err(ImapError::Protocol("CAPABILITY failed"));
        }
        let mut caps = Vec::new();
        for Untagged(t) in &d.untagged {
            if t.first().and_then(Tok::atom).is_some_and(|a| a.eq_ignore_ascii_case("CAPABILITY")) {
                caps.extend(t[1..].iter().filter_map(Tok::atom).map(str::to_ascii_uppercase));
            }
        }
        self.caps = caps;
        Ok(())
    }

    async fn login(&mut self, creds: &Credentials) -> Result<(), ImapError> {
        let (u, p) = (creds.username.as_str(), creds.password.as_str());
        let op = if self.has_cap("AUTH=PLAIN") {
            ImapOp::AuthenticatePlain { username: u, password: p }
        } else if self.has_cap("LOGINDISABLED") {
            return Err(ImapError::Capability("LOGIN or AUTH=PLAIN"));
        } else {
            ImapOp::Login { username: u, password: p }
        };
        let d = self.exec(op, SMALL_LITERAL).await?;
        match d.status {
            Status::Ok => {}
            Status::No => {
                // Temporary server trouble is not a credential problem (no reauth for it).
                return match d.code_name().as_deref() {
                    Some("UNAVAILABLE" | "SERVERBUG" | "LIMIT" | "INUSE") => Err(ImapError::Network),
                    _ => Err(ImapError::Auth),
                };
            }
            Status::Bad => return Err(ImapError::Protocol("login rejected as malformed")),
        }
        // Capabilities can change after login; prefer the ones in the OK response code.
        if d.code_name().as_deref() == Some("CAPABILITY") {
            self.caps = d.code[1..].iter().filter_map(Tok::atom).map(str::to_ascii_uppercase).collect();
        } else {
            self.refresh_caps().await?;
        }
        Ok(())
    }

    pub fn capabilities(&self) -> &[String] {
        &self.caps
    }

    pub fn has_cap(&self, cap: &str) -> bool {
        self.caps.iter().any(|c| c.eq_ignore_ascii_case(cap))
    }

    fn condstore(&self) -> bool {
        self.has_cap("CONDSTORE") || self.has_cap("QRESYNC")
    }

    /// Sets the folder names behind [`AppendTarget::Drafts`] and [`AppendTarget::Sent`] (from the account settings).
    pub fn set_append_targets(&mut self, drafts: Option<String>, sent: Option<String>) {
        self.drafts = drafts;
        self.sent = sent;
    }

    /// Enables QRESYNC when offered; later `changed_since` calls then report expunged UIDs.
    pub async fn enable_qresync(&mut self) -> Result<bool, ImapError> {
        if self.qresync {
            return Ok(true);
        }
        if !self.has_cap("QRESYNC") {
            return Ok(false);
        }
        let d = self.exec(ImapOp::EnableQresync, SMALL_LITERAL).await?;
        self.qresync = d.status == Status::Ok;
        Ok(self.qresync)
    }

    // ------------------------------------------------------------------ wire

    async fn write(&mut self, bytes: &[u8]) -> Result<(), ImapError> {
        let w = self.io.get_mut();
        match tokio::time::timeout(self.timeout, async {
            w.write_all(bytes).await?;
            w.flush().await
        })
        .await
        {
            Ok(Ok(())) => Ok(()),
            _ => Err(ImapError::Network),
        }
    }

    /// Reads one response with its literals (each at most `max_literal` bytes), charging every byte to `budget`.
    async fn read_response(
        &mut self,
        max_literal: usize,
        max_line: usize,
        budget: &mut usize,
    ) -> Result<Vec<Seg>, ImapError> {
        let mut segs = Vec::new();
        let mut total = 0usize;
        loop {
            let line = read_raw_line(&mut self.io, self.timeout, max_line).await?;
            total += line.len();
            *budget = budget.checked_sub(line.len()).ok_or(ImapError::Protocol("response over the size limit"))?;
            if total > max_line * 4 {
                return Err(ImapError::Protocol("response too long"));
            }
            match literal_len(&line) {
                Some(n) => {
                    if n > max_literal || n > *budget {
                        return Err(ImapError::Protocol("response literal over the size limit"));
                    }
                    *budget -= n;
                    let open = line.iter().rposition(|b| *b == b'{').expect("checked");
                    segs.push(Seg::Text(line[..open].to_vec()));
                    let mut buf = vec![0u8; n];
                    match tokio::time::timeout(self.timeout, self.io.read_exact(&mut buf)).await {
                        Ok(Ok(_)) => segs.push(Seg::Lit(buf)),
                        _ => return Err(ImapError::Network),
                    }
                }
                None => {
                    segs.push(Seg::Text(line));
                    return Ok(segs);
                }
            }
        }
    }

    /// Sends one allowlisted command and collects its untagged responses until the tagged completion.
    async fn exec(&mut self, op: ImapOp<'_>, max_literal: usize) -> Result<Done, ExecError> {
        let max_line = match op {
            ImapOp::UidSearchAll | ImapOp::UidSearchFrom(_) | ImapOp::UidFetchChangedSince { .. } => BIG_LINE,
            _ => MAX_LINE,
        };
        let fail = |err| ExecError { err, sent_all: false };
        self.tag += 1;
        let tag = format!("d{}", self.tag);
        let cmd = op.render();
        if !IMAP_VERBS.contains(&cmd.verb) {
            return Err(fail(ImapError::Protocol("command not allowlisted")));
        }
        let mut untagged = Vec::new();
        let mut budget = max_literal.saturating_add(max_line).saturating_add(COMMAND_OVERHEAD);
        let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(format!("{tag} ").into_bytes());
        let mut sasl = None;
        for part in cmd.parts {
            match part {
                Part::Text(t) => buf.extend_from_slice(t.as_bytes()),
                Part::Literal(bytes) => {
                    buf.extend_from_slice(format!("{{{}}}\r\n", bytes.len()).as_bytes());
                    self.write(&buf).await.map_err(fail)?;
                    buf.clear();
                    if let Some(d) = self.await_continuation(&tag, &mut untagged, &mut budget).await.map_err(fail)? {
                        return Ok(d);
                    }
                    self.write(&bytes).await.map_err(fail)?;
                }
                Part::Sasl(line) => sasl = Some(line),
            }
        }
        buf.extend_from_slice(b"\r\n");
        self.write(&buf).await.map_err(fail)?;
        if let Some(line) = sasl {
            if let Some(d) = self.await_continuation(&tag, &mut untagged, &mut budget).await.map_err(fail)? {
                return Ok(d);
            }
            let mut l = Zeroizing::new(line.as_bytes().to_vec());
            l.extend_from_slice(b"\r\n");
            self.write(&l).await.map_err(fail)?;
        }
        let sent = |err| ExecError { err, sent_all: true };
        loop {
            let segs = self.read_response(max_literal, max_line, &mut budget).await.map_err(sent)?;
            match self.classify(&tag, segs).map_err(sent)? {
                Resp::Untagged(u) => {
                    if untagged.len() >= MAX_UNTAGGED {
                        return Err(sent(ImapError::Protocol("too many responses")));
                    }
                    untagged.push(u)
                }
                Resp::Continuation => return Err(sent(ImapError::Protocol("unexpected continuation"))),
                Resp::Tagged(status, code) => return Ok(Done { status, code, untagged }),
            }
        }
    }

    /// Waits for `+`. Returns `Some(done)` if the server answered the command (NO/BAD) instead.
    async fn await_continuation(
        &mut self,
        tag: &str,
        untagged: &mut Vec<Untagged>,
        budget: &mut usize,
    ) -> Result<Option<Done>, ImapError> {
        loop {
            let segs = self.read_response(SMALL_LITERAL, MAX_LINE, budget).await?;
            match self.classify(tag, segs)? {
                Resp::Continuation => return Ok(None),
                Resp::Untagged(_) if untagged.len() >= MAX_UNTAGGED => {
                    return Err(ImapError::Protocol("too many responses"));
                }
                Resp::Untagged(u) => untagged.push(u),
                Resp::Tagged(status, code) => {
                    return Ok(Some(Done { status, code, untagged: std::mem::take(untagged) }));
                }
            }
        }
    }

    fn classify(&self, tag: &str, segs: Vec<Seg>) -> Result<Resp, ImapError> {
        let first = match segs.first() {
            Some(Seg::Text(t)) => t.clone(),
            _ => return Err(ImapError::Protocol("malformed response")),
        };
        if first.starts_with(b"+") {
            return Ok(Resp::Continuation);
        }
        let toks = tokenize(segs).ok_or(ImapError::Protocol("response nested too deeply"))?;
        let head = toks.first().and_then(Tok::atom).unwrap_or_default().to_string();
        if head == "*" {
            if toks.get(1).and_then(Tok::atom).is_some_and(|a| a.eq_ignore_ascii_case("BYE")) {
                return Err(ImapError::Network);
            }
            return Ok(Resp::Untagged(Untagged(toks[1..].to_vec())));
        }
        if head == tag {
            let status = match toks.get(1).and_then(Tok::atom).map(str::to_ascii_uppercase).as_deref() {
                Some("OK") => Status::Ok,
                Some("NO") => Status::No,
                Some("BAD") => Status::Bad,
                _ => return Err(ImapError::Protocol("malformed status")),
            };
            let code = match toks.get(2) {
                Some(Tok::Code(c)) => c.clone(),
                _ => Vec::new(),
            };
            return Ok(Resp::Tagged(status, code));
        }
        Err(ImapError::Protocol("response for an unknown tag"))
    }

    async fn simple(&mut self, op: ImapOp<'_>, max_literal: usize) -> Result<Done, ImapError> {
        let d = self.exec(op, max_literal).await?;
        match d.status {
            Status::Ok => Ok(d),
            Status::No => Err(ImapError::Missing),
            Status::Bad => Err(ImapError::Protocol("command rejected as malformed")),
        }
    }

    fn selected(&self) -> Result<&(String, bool, FolderStatus), ImapError> {
        self.selected.as_ref().ok_or(ImapError::Protocol("no folder selected"))
    }

    // ------------------------------------------------------------------ typed calls

    pub async fn noop(&mut self) -> Result<(), ImapError> {
        self.simple(ImapOp::Noop, SMALL_LITERAL).await.map(|_| ())
    }

    pub async fn list_folders(&mut self) -> Result<Vec<FolderInfo>, ImapError> {
        let d = self.simple(ImapOp::List { special_use: self.has_cap("SPECIAL-USE") }, SMALL_LITERAL).await?;
        let mut out = Vec::new();
        for Untagged(t) in &d.untagged {
            if !t.first().and_then(Tok::atom).is_some_and(|a| a.eq_ignore_ascii_case("LIST")) {
                continue;
            }
            let (Some(Tok::List(attrs)), Some(delim), Some(name)) = (t.get(1), t.get(2), t.get(3)) else { continue };
            let attrs: Vec<String> = attrs.iter().filter_map(Tok::atom).map(str::to_ascii_lowercase).collect();
            let raw = match name.text() {
                Some(n) => n.into_owned(),
                None => continue,
            };
            let special = attrs.iter().find_map(|a| match a.as_str() {
                "\\drafts" => Some(Special::Drafts),
                "\\sent" => Some(Special::Sent),
                "\\junk" => Some(Special::Junk),
                "\\trash" => Some(Special::Trash),
                _ => None,
            });
            let delimiter = if delim.is_nil() { None } else { delim.text().and_then(|d| d.chars().next()) };
            out.push(FolderInfo {
                name_utf8: utf7::decode(&raw).unwrap_or_else(|| raw.clone()),
                raw_name: raw,
                delimiter,
                special,
                selectable: !attrs.iter().any(|a| a == "\\noselect" || a == "\\nonexistent"),
            });
        }
        Ok(out)
    }

    /// `STATUS` without selecting: (messages, uidnext, uidvalidity).
    pub async fn status(&mut self, folder: &str) -> Result<FolderStatus, ImapError> {
        let d = self.simple(ImapOp::Status { mailbox: folder }, SMALL_LITERAL).await?;
        let mut st = FolderStatus::default();
        for Untagged(t) in &d.untagged {
            if !t.first().and_then(Tok::atom).is_some_and(|a| a.eq_ignore_ascii_case("STATUS")) {
                continue;
            }
            if let Some(Tok::List(items)) = t.get(2) {
                for kv in items.chunks(2) {
                    let (Some(k), Some(v)) = (kv.first().and_then(Tok::atom), kv.get(1)) else { continue };
                    match k.to_ascii_uppercase().as_str() {
                        "MESSAGES" => st.exists = v.num().unwrap_or(0),
                        "UIDNEXT" => st.uidnext = v.num().unwrap_or(0),
                        "UIDVALIDITY" => st.uidvalidity = v.num().unwrap_or(0),
                        _ => {}
                    }
                }
            }
        }
        Ok(st)
    }

    /// `SELECT` (read-write) or `EXAMINE` (read-only). A missing folder is [`ImapError::Missing`].
    pub async fn select(&mut self, folder: &str, readonly: bool) -> Result<FolderStatus, ImapError> {
        self.selected = None;
        let condstore = self.condstore();
        let d = self.simple(ImapOp::Select { mailbox: folder, readonly, condstore }, SMALL_LITERAL).await?;
        let mut st = FolderStatus::default();
        for Untagged(t) in &d.untagged {
            match (t.first(), t.get(1)) {
                (Some(Tok::Atom(n)), Some(Tok::Atom(k))) if k.eq_ignore_ascii_case("EXISTS") => {
                    st.exists = n.parse().unwrap_or(0)
                }
                (Some(Tok::Atom(ok)), Some(Tok::Code(code))) if ok.eq_ignore_ascii_case("OK") => {
                    let name = code.first().and_then(Tok::atom).map(str::to_ascii_uppercase);
                    let val = code.get(1);
                    match name.as_deref() {
                        Some("UIDVALIDITY") => st.uidvalidity = val.and_then(Tok::num).unwrap_or(0),
                        Some("UIDNEXT") => st.uidnext = val.and_then(Tok::num).unwrap_or(0),
                        Some("HIGHESTMODSEQ") => st.highestmodseq = val.and_then(Tok::num),
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        if st.uidvalidity == 0 {
            return Err(ImapError::Protocol("SELECT without UIDVALIDITY"));
        }
        self.selected = Some((folder.to_string(), readonly, st));
        Ok(st)
    }

    fn search_result(d: &Done) -> Vec<u32> {
        let mut out = Vec::new();
        for Untagged(t) in &d.untagged {
            if t.first().and_then(Tok::atom).is_some_and(|a| a.eq_ignore_ascii_case("SEARCH")) {
                out.extend(t[1..].iter().filter_map(Tok::num::<u32>));
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// All UIDs of the selected folder.
    pub async fn uid_search_all(&mut self) -> Result<Vec<u32>, ImapError> {
        self.selected()?;
        let d = self.simple(ImapOp::UidSearchAll, SMALL_LITERAL).await?;
        Ok(Self::search_result(&d))
    }

    /// UIDs `>= uid` in the selected folder.
    pub async fn uid_search_since_uid(&mut self, uid: u32) -> Result<Vec<u32>, ImapError> {
        self.selected()?;
        let d = self.simple(ImapOp::UidSearchFrom(uid), SMALL_LITERAL).await?;
        // `n:*` always matches the highest UID, even below n.
        Ok(Self::search_result(&d).into_iter().filter(|u| *u >= uid).collect())
    }

    /// FETCH responses as (uid, key/value items).
    fn fetches(d: &Done) -> Vec<(u32, Vec<(String, Tok)>)> {
        let mut out = Vec::new();
        for Untagged(t) in &d.untagged {
            let (Some(Tok::Atom(_)), Some(Tok::Atom(f)), Some(Tok::List(items))) = (t.first(), t.get(1), t.get(2))
            else {
                continue;
            };
            if !f.eq_ignore_ascii_case("FETCH") {
                continue;
            }
            let mut kv = Vec::new();
            let mut it = items.iter();
            while let (Some(k), Some(v)) = (it.next(), it.next()) {
                if let Some(k) = k.atom() {
                    kv.push((k.to_ascii_uppercase(), v.clone()));
                }
            }
            if let Some(uid) = kv.iter().find(|(k, _)| k == "UID").and_then(|(_, v)| v.num()) {
                out.push((uid, kv));
            }
        }
        out
    }

    fn meta_of(uid: u32, kv: &[(String, Tok)]) -> FetchedMeta {
        let mut m = FetchedMeta { uid, ..Default::default() };
        for (k, v) in kv {
            match (k.as_str(), v) {
                ("FLAGS", Tok::List(f)) => m.flags = f.iter().filter_map(Tok::atom).map(str::to_string).collect(),
                ("INTERNALDATE", v) => {
                    m.internal_date_s = v.text().and_then(|s| parse_internal_date(&s)).unwrap_or(0);
                }
                ("RFC822.SIZE", v) => m.size = v.num().unwrap_or(0),
                ("MODSEQ", Tok::List(l)) => m.modseq = l.first().and_then(Tok::num),
                _ => {}
            }
        }
        m
    }

    /// Flags, internal date and size for `uids` of the selected folder (unknown UIDs are skipped).
    pub async fn fetch_meta(&mut self, uids: &[u32]) -> Result<Vec<FetchedMeta>, ImapError> {
        self.selected()?;
        if uids.is_empty() {
            return Ok(Vec::new());
        }
        let modseq = self.condstore();
        let d = self.simple(ImapOp::UidFetchMeta { uids, modseq }, SMALL_LITERAL).await?;
        let mut out: Vec<FetchedMeta> = Vec::new();
        for (uid, kv) in Self::fetches(&d) {
            if !uids.contains(&uid) || !kv.iter().any(|(k, _)| k == "RFC822.SIZE") {
                continue; // unsolicited flag updates
            }
            out.push(Self::meta_of(uid, &kv));
        }
        out.sort_by_key(|m| m.uid);
        out.dedup_by_key(|m| m.uid);
        Ok(out)
    }

    /// Full message bytes via `BODY.PEEK[]` (never sets `\Seen`). `Ok(None)` when the message is larger than
    /// `max_bytes`: then only its size was fetched. A UID that does not exist is [`ImapError::Missing`].
    pub async fn fetch_raw(&mut self, uid: u32, max_bytes: usize) -> Result<Option<Vec<u8>>, ImapError> {
        self.selected()?;
        let d = self.simple(ImapOp::UidFetchSize(uid), SMALL_LITERAL).await?;
        let size: u64 = Self::fetches(&d)
            .into_iter()
            .find(|(u, kv)| *u == uid && kv.iter().any(|(k, _)| k == "RFC822.SIZE"))
            .and_then(|(_, kv)| kv.into_iter().find(|(k, _)| k == "RFC822.SIZE").and_then(|(_, v)| v.num()))
            .ok_or(ImapError::Missing)?;
        if size > max_bytes as u64 {
            return Ok(None);
        }
        let d = self.simple(ImapOp::UidFetchRaw(uid), max_bytes).await?;
        for (u, kv) in Self::fetches(&d) {
            if u != uid {
                continue;
            }
            for (k, v) in kv {
                if k.starts_with("BODY[") {
                    return match v {
                        Tok::Str(b) => Ok(Some(b)),
                        _ => Err(ImapError::Protocol("FETCH without message body")),
                    };
                }
            }
        }
        Err(ImapError::Missing)
    }

    /// Messages of the selected folder changed since `modseq` (CONDSTORE), with expunged UIDs when QRESYNC is on.
    pub async fn changed_since(&mut self, modseq: u64) -> Result<Changes, ImapError> {
        self.selected()?;
        if !self.condstore() {
            return Err(ImapError::Capability("CONDSTORE"));
        }
        let vanished = self.qresync;
        let d = self.simple(ImapOp::UidFetchChangedSince { modseq, vanished }, SMALL_LITERAL).await?;
        let mut changes = Changes { vanished: vanished.then(Vec::new), ..Default::default() };
        for (uid, kv) in Self::fetches(&d) {
            changes.changed.push(Self::meta_of(uid, &kv));
        }
        if let Some(v) = changes.vanished.as_mut() {
            for Untagged(t) in &d.untagged {
                if t.first().and_then(Tok::atom).is_some_and(|a| a.eq_ignore_ascii_case("VANISHED"))
                    && let Some(set) = t.iter().skip(1).rev().find_map(Tok::atom)
                {
                    v.extend(parse_uid_set(set));
                }
            }
            v.sort_unstable();
            v.dedup();
        }
        Ok(changes)
    }

    /// Appends to the Drafts or Sent folder and returns the new UID from `APPENDUID`. A connection lost after the
    /// message was sent, or an `OK` without `APPENDUID`, is [`ImapError::OutcomeUnknown`]; a refusal before that is
    /// definitive.
    pub async fn append(
        &mut self,
        folder: AppendTarget,
        flags: &[AppendFlag],
        bytes: &[u8],
    ) -> Result<AppendUid, ImapError> {
        let target = match folder {
            AppendTarget::Drafts => self.drafts.clone(),
            AppendTarget::Sent => self.sent.clone(),
        }
        .ok_or(ImapError::Missing)?;
        self.selected = None;
        let d = match self.exec(ImapOp::Append { mailbox: &target, flags, message: bytes }, SMALL_LITERAL).await {
            Ok(d) => d,
            Err(ExecError { sent_all: true, .. }) => return Err(ImapError::OutcomeUnknown),
            Err(ExecError { err, sent_all: false }) => {
                return Err(if err == ImapError::Network { ImapError::NotDispatched } else { err });
            }
        };
        match d.status {
            Status::Ok => {}
            Status::No if d.code_name().as_deref() == Some("TRYCREATE") => return Err(ImapError::Missing),
            Status::No => return Err(ImapError::Protocol("APPEND refused")),
            Status::Bad => return Err(ImapError::Protocol("APPEND rejected as malformed")),
        }
        if d.code_name().as_deref() == Some("APPENDUID")
            && let (Some(v), Some(u)) = (d.code.get(1).and_then(Tok::num), d.code.get(2).and_then(Tok::num))
        {
            return Ok(AppendUid { uidvalidity: v, uid: u });
        }
        Err(ImapError::OutcomeUnknown)
    }

    /// Flags one Dove-owned draft `\Deleted` and expunges exactly that UID (`UID EXPUNGE`, UIDPLUS) in Drafts.
    /// A changed UIDVALIDITY is [`ImapError::Missing`]: the UID no longer names Dove's draft.
    pub async fn delete_own(&mut self, own: OwnDraftUid) -> Result<(), ImapError> {
        let drafts = self.drafts.clone().ok_or(ImapError::Missing)?;
        let st = self.select(&drafts, false).await?;
        if st.uidvalidity != own.uidvalidity {
            return Err(ImapError::Missing);
        }
        self.simple(ImapOp::UidStoreDeleted(&own), SMALL_LITERAL).await?;
        self.simple(ImapOp::UidExpunge(&own), SMALL_LITERAL).await?;
        Ok(())
    }

    /// Polite close. Errors are irrelevant: the connection is dropped either way.
    pub async fn logout(mut self) {
        let _ = self.exec(ImapOp::Logout, SMALL_LITERAL).await;
    }

    /// The currently selected folder (wire name) and its status.
    pub fn selected_folder(&self) -> Option<(&str, FolderStatus)> {
        self.selected.as_ref().map(|(n, _, s)| (n.as_str(), *s))
    }
}

enum Resp {
    Untagged(Untagged),
    Continuation,
    Tagged(Status, Vec<Tok>),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(s: &str) -> Vec<Tok> {
        tokenize(vec![Seg::Text(s.as_bytes().to_vec())]).unwrap()
    }

    #[test]
    fn tokenizer_shapes() {
        let t = toks(r#"* LIST (\HasNoChildren \Drafts) "/" "Entw&APw-rfe""#);
        assert_eq!(t[1], Tok::Atom("LIST".into()));
        assert_eq!(t[2], Tok::List(vec![Tok::Atom("\\HasNoChildren".into()), Tok::Atom("\\Drafts".into())]));
        assert_eq!(t[4], Tok::Str(b"Entw&APw-rfe".to_vec()));
        let t = toks("d3 OK [APPENDUID 38505 3955] APPEND completed");
        assert_eq!(
            t[2],
            Tok::Code(vec![Tok::Atom("APPENDUID".into()), Tok::Atom("38505".into()), Tok::Atom("3955".into())])
        );
        let t = tokenize(vec![
            Seg::Text(b"* 1 FETCH (UID 5 BODY[] ".to_vec()),
            Seg::Lit(b"a)b\"c".to_vec()),
            Seg::Text(b")".to_vec()),
        ])
        .unwrap();
        // Deep nesting from a hostile server is refused instead of recursing without bound.
        assert!(tokenize(vec![Seg::Text(format!("* {}", "(".repeat(100_000)).into_bytes())]).is_none());
        assert!(tokenize(vec![Seg::Text(format!("* {}", "[".repeat(100_000)).into_bytes())]).is_none());
        assert_eq!(
            t[3],
            Tok::List(vec![
                Tok::Atom("UID".into()),
                Tok::Atom("5".into()),
                Tok::Atom("BODY[]".into()),
                Tok::Str(b"a)b\"c".to_vec())
            ])
        );
        let t = toks(r#"* LIST () "\\" "a\"b""#);
        assert_eq!(t[3], Tok::Str(b"\\".to_vec()));
        assert_eq!(t[4], Tok::Str(b"a\"b".to_vec()));
    }

    fn over_stream(io: tokio::io::DuplexStream) -> ImapSession {
        ImapSession {
            io: BufReader::new(Box::new(io)),
            tag: 0,
            caps: Vec::new(),
            timeout: Duration::from_secs(5),
            drafts: None,
            sent: None,
            selected: None,
            qresync: false,
        }
    }

    #[tokio::test]
    async fn responses_are_bounded_per_command() {
        // Each literal is under the per-literal cap, but together they exceed the per-command budget.
        let (client, mut server) = tokio::io::duplex(1 << 16);
        let mut s = over_stream(client);
        let feeder = tokio::spawn(async move {
            let mut cmd = vec![0u8; 64];
            let _ = server.read(&mut cmd).await;
            let lit = vec![b'x'; 60 * 1024];
            for _ in 0..400 {
                let head = format!("* OK {{{}}}\r\n", lit.len());
                if server.write_all(head.as_bytes()).await.is_err() || server.write_all(&lit).await.is_err() {
                    return;
                }
                let _ = server.write_all(b"\r\n").await;
            }
            let _ = server.write_all(b"d1 OK done\r\n").await;
        });
        assert_eq!(s.noop().await.unwrap_err(), ImapError::Protocol("response literal over the size limit"));
        feeder.abort();
    }

    #[test]
    fn internal_dates_and_sets() {
        assert_eq!(parse_internal_date("17-Jul-1996 02:44:25 -0700"), Some(837596665));
        assert_eq!(parse_internal_date(" 1-Jan-2026 00:00:00 +0000"), Some(1767225600));
        assert_eq!(parse_internal_date("garbage"), None);
        assert_eq!(parse_internal_date("17-Jul-1996 02:44:25 -\u{e9}00"), None);
        assert_eq!(parse_uid_set("1:3,7,9:8"), vec![1, 2, 3, 7, 8, 9]);
        assert_eq!(literal_len(b"* 1 FETCH (BODY[] {123}"), Some(123));
        assert_eq!(literal_len(b"* OK {weird}"), None);
    }
}
