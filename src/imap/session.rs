//! One logged-in IMAP connection with typed calls. Commands come only from [`super::ops`].
//!
//! Any error leaves the stream in an unknown state; the owner must drop the session (the pool does). Responses are
//! bounded: lines at [`MAX_LINE`] (only `SEARCH`/`VANISHED` number lists, parsed from bytes, up to [`BIG_LINE`]),
//! literals at the per-call cap, bytes per command at the literal cap plus [`COMMAND_OVERHEAD`], and what a command
//! keeps (tokens, FETCH metadata, UIDs) at the literal cap plus [`RETAINED`].

use std::borrow::Cow;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use zeroize::Zeroizing;

use super::ops::{AppendFlag, GmLabel, IMAP_VERBS, ImapOp, Part, StoreFlag};
use super::{Credentials, ImapConnector, ImapError, Io, ServerEndpoint, TlsMode, utf7};

/// Capability of Gmail's IMAP extensions (`X-GM-LABELS`, ...); its presence at connect puts an account in Gmail mode
/// (PLAN A57).
pub const GMAIL_CAP: &str = "X-GM-EXT-1";

const MAX_LINE: usize = 64 * 1024;
/// Most UIDs kept from the `SEARCH` responses of one command.
pub const MAX_SEARCH_UIDS: usize = 1_000_000;
/// Line cap for `* SEARCH` and `* VANISHED`, the only responses that may be longer than [`MAX_LINE`] (they are parsed
/// from bytes and never tokenized): [`MAX_SEARCH_UIDS`] UIDs of up to ten digits and a space each.
const BIG_LINE: usize = 11 * MAX_SEARCH_UIDS + 64;
/// Memory one command may keep from its responses beyond its largest literal: tokens, FETCH metadata, UIDs.
const RETAINED: usize = 32 * 1024 * 1024;
/// Estimated memory of one token beyond its payload (the enum and the allocation), charged against [`RETAINED`].
const TOK_COST: usize = 48;
/// Literal cap for responses that carry no message content (LIST names, flags).
const SMALL_LITERAL: usize = 64 * 1024;
/// Upper bound for the number of untagged responses collected for one command.
const MAX_UNTAGGED: usize = 200_000;
/// Bytes read for one command beyond its largest literal (all lines and small literals together).
const COMMAND_OVERHEAD: usize = 16 * 1024 * 1024;
/// Nesting depth of parenthesized lists in one response.
const MAX_DEPTH: usize = 32;
/// Most UID ranges kept from the `VANISHED` responses of one command. Ranges stay `(lo, hi)` pairs and are never
/// expanded; beyond this many the set is reported incomplete and the caller falls back to the UID diff.
pub const MAX_VANISHED_RANGES: usize = 50_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Special {
    Drafts,
    Sent,
    Junk,
    Trash,
    /// Gmail's All Mail (`\All`, RFC 6154): every message except Spam and Trash.
    All,
}

impl Special {
    pub fn as_str(self) -> &'static str {
        match self {
            Special::Drafts => "drafts",
            Special::Sent => "sent",
            Special::Junk => "junk",
            Special::Trash => "trash",
            Special::All => "all",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "drafts" => Some(Special::Drafts),
            "sent" => Some(Special::Sent),
            "junk" => Some(Special::Junk),
            "trash" => Some(Special::Trash),
            "all" => Some(Special::All),
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
    /// Gmail labels (`X-GM-LABELS`) as the server spells them (`\\Inbox`, modified UTF-7 user labels), when fetched.
    pub gm_labels: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Changes {
    /// Messages whose flags (or existence) changed since the given mod-sequence.
    pub changed: Vec<FetchedMeta>,
    /// UIDs expunged since then, as ranges (a server may include UIDs that never existed, RFC 7162 3.2.10). `None`
    /// when QRESYNC is not enabled or the server sent more than [`MAX_VANISHED_RANGES`] ranges: the caller then
    /// diffs `UID SEARCH ALL` instead.
    pub vanished: Option<UidRanges>,
}

/// A set of UIDs as sorted, disjoint, inclusive ranges. Memory is proportional to the number of ranges, never to
/// their width; callers intersect it with the UIDs they know instead of listing it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UidRanges(Vec<(u32, u32)>);

impl UidRanges {
    /// Sorts and merges overlapping or adjacent ranges.
    pub fn from_ranges(mut v: Vec<(u32, u32)>) -> Self {
        v.sort_unstable();
        let mut out: Vec<(u32, u32)> = Vec::with_capacity(v.len());
        for (lo, hi) in v {
            match out.last_mut() {
                Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
                _ => out.push((lo, hi)),
            }
        }
        out.shrink_to_fit();
        Self(out)
    }

    pub fn contains(&self, uid: u32) -> bool {
        let i = self.0.partition_point(|(_, hi)| *hi < uid);
        self.0.get(i).is_some_and(|(lo, _)| *lo <= uid)
    }

    pub fn ranges(&self) -> &[(u32, u32)] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
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
    /// Only `tools::drafts_imap` may call this, after checking the `own_drafts` record, a fresh content hash and the
    /// Drafts folder (`tests/imap_drafts_e2e.rs` enforces the single caller).
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

/// The source UID of a message whose copy the server confirmed with `COPYUID` during a move on a server without
/// `MOVE`: besides [`OwnDraftUid`], the only message Dove may flag `\Deleted` and expunge. It names the folder and
/// UIDVALIDITY it was copied from; the session refuses it anywhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopiedUid {
    folder: String,
    uidvalidity: u32,
    uid: u32,
}

impl CopiedUid {
    /// Only [`ImapSession::move_uids`] may call this, with a UID the server's `COPYUID` response listed as copied and
    /// that Dove asked to copy (`tests/imap_organize_e2e.rs` enforces the single caller).
    fn confirmed_by_copyuid(folder: &str, uidvalidity: u32, uid: u32) -> Self {
        Self { folder: folder.to_string(), uidvalidity, uid }
    }
    pub fn uid(&self) -> u32 {
        self.uid
    }

    #[cfg(test)]
    pub(crate) fn for_ops_tests(uids: &[u32]) -> Vec<Self> {
        uids.iter().map(|u| Self { folder: "INBOX".into(), uidvalidity: 1, uid: *u }).collect()
    }
}

/// What a move did in one source folder. UIDs Dove asked for that appear in neither list were not moved (they did
/// not exist, or the server did not copy them).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MoveOutcome {
    /// UIDVALIDITY of the destination from `COPYUID`, when reported.
    pub dest_uidvalidity: Option<u32>,
    /// (source UID, destination UID when reported).
    pub moved: Vec<(u32, Option<u32>)>,
    /// Copied (server without MOVE), but the original was not removed: the copy was not confirmed by `COPYUID`, or
    /// flagging or expunging the original failed.
    pub copied_kept: Vec<(u32, Option<u32>)>,
}

/// Parses a `COPYUID <uidvalidity> <source set> <destination set>` response code into (uidvalidity, pairs). Sets are
/// expanded in the order given, at most `max` UIDs each; any malformed or oversized code is `None`.
fn parse_copyuid(code: &[Tok], max: usize) -> Option<(u32, Vec<(u32, u32)>)> {
    if !code.first().and_then(Tok::atom).is_some_and(|a| a.eq_ignore_ascii_case("COPYUID")) {
        return None;
    }
    let v: u32 = code.get(1)?.num()?;
    let expand = |t: &Tok| -> Option<Vec<u32>> {
        let mut out = Vec::new();
        for part in t.atom()?.split(',') {
            let (a, b) = match part.split_once(':') {
                Some((a, b)) => (a.parse::<u32>().ok()?, b.parse::<u32>().ok()?),
                None => {
                    let n = part.parse::<u32>().ok()?;
                    (n, n)
                }
            };
            // Width is checked before expanding: a hostile `1:4294967295` must not allocate.
            if a == 0 || b == 0 || out.len() + a.abs_diff(b) as usize + 1 > max {
                return None;
            }
            if a <= b {
                out.extend(a..=b);
            } else {
                out.extend((b..=a).rev());
            }
        }
        Some(out)
    };
    let (src, dst) = (expand(code.get(2)?)?, expand(code.get(3)?)?);
    if src.len() != dst.len() || v == 0 {
        return None;
    }
    Some((v, src.into_iter().zip(dst).collect()))
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
/// Fails when lists nest deeper than [`MAX_DEPTH`] (a hostile server must not exhaust the stack) or the tokens would
/// need more than `mem` bytes (estimated as [`TOK_COST`] plus payload each); `mem` is reduced by what they use.
fn tokenize(segs: Vec<Seg>, mem: &mut usize) -> Result<Vec<Tok>, ImapError> {
    struct Cur {
        segs: std::vec::IntoIter<Seg>,
        text: Vec<u8>,
        pos: usize,
        pending_lit: Option<Vec<u8>>,
        too_deep: bool,
        mem: usize,
        over: bool,
    }
    impl Cur {
        fn charge(&mut self, n: usize) -> bool {
            match self.mem.checked_sub(n) {
                Some(m) => self.mem = m,
                None => self.over = true,
            }
            !self.over
        }
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
            if c.too_deep || c.over {
                return out;
            }
            if let Some(l) = c.pending_lit.take() {
                if c.charge(TOK_COST + l.len()) {
                    out.push(Tok::Str(l));
                }
                continue;
            }
            match b {
                b' ' => c.pos += 1,
                b'(' => {
                    c.pos += 1;
                    if c.charge(TOK_COST) {
                        out.push(Tok::List(list(c, b')', depth + 1)));
                    }
                }
                b'[' => {
                    c.pos += 1;
                    if c.charge(TOK_COST) {
                        out.push(Tok::Code(list(c, b']', depth + 1)));
                    }
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
                    if c.charge(TOK_COST + s.len()) {
                        out.push(Tok::Str(s));
                    }
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
                    if c.charge(TOK_COST + a.len()) {
                        out.push(Tok::Atom(String::from_utf8_lossy(&a).into_owned()));
                    }
                }
            }
        }
        out
    }
    let mut c = Cur {
        segs: segs.into_iter(),
        text: Vec::new(),
        pos: 0,
        pending_lit: None,
        too_deep: false,
        mem: *mem,
        over: false,
    };
    let toks = list(&mut c, 0, 0);
    if c.too_deep {
        return Err(ImapError::Protocol("response nested too deeply"));
    }
    if c.over {
        return Err(ImapError::Protocol("response over the memory limit"));
    }
    *mem = c.mem;
    Ok(toks)
}

/// The number-list responses parsed straight from bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NumLine {
    Search,
    Vanished,
}

/// `* SEARCH ...` or `* VANISHED ...`: the kind and the bytes after the keyword.
fn number_line(line: &[u8]) -> Option<(NumLine, &[u8])> {
    let rest = line.strip_prefix(b"* ")?;
    let end = rest.iter().position(|b| *b == b' ').unwrap_or(rest.len());
    let word = &rest[..end];
    let kind = if word.eq_ignore_ascii_case(b"SEARCH") {
        NumLine::Search
    } else if word.eq_ignore_ascii_case(b"VANISHED") {
        NumLine::Vanished
    } else {
        return None;
    };
    Some((kind, rest.get(end + 1..).unwrap_or_default()))
}

/// What one command keeps from its responses, charged against one memory budget ([`RETAINED`] plus its literal).
struct Collected {
    untagged: Vec<Untagged>,
    /// Bytes still available for retained data.
    mem: usize,
    /// UIDs of `* SEARCH` lines, in arrival order (at most [`MAX_SEARCH_UIDS`]).
    search: Vec<u32>,
    /// Ranges of `* VANISHED` lines; incomplete once more than [`MAX_VANISHED_RANGES`] arrived.
    vanished: Vec<(u32, u32)>,
    vanished_complete: bool,
    /// For flag/size fetches: FETCH responses converted on arrival (with whether `RFC822.SIZE` was present), so a
    /// large result never exists as tokens.
    metas: Option<Vec<(FetchedMeta, bool)>>,
}

impl Collected {
    fn new(mem: usize, metas: bool) -> Self {
        Self {
            untagged: Vec::new(),
            mem,
            search: Vec::new(),
            vanished: Vec::new(),
            vanished_complete: true,
            metas: metas.then(Vec::new),
        }
    }

    fn charge(&mut self, n: usize) -> Result<(), ImapError> {
        self.mem = self.mem.checked_sub(n).ok_or(ImapError::Protocol("response over the memory limit"))?;
        Ok(())
    }

    /// `rest` of a `* SEARCH` line: numbers separated by spaces. Anything else (a CONDSTORE `(MODSEQ n)`) is skipped.
    fn add_search(&mut self, rest: &[u8]) -> Result<(), ImapError> {
        for w in rest.split(|b| *b == b' ') {
            if w.is_empty() || w.len() > 10 || !w.iter().all(u8::is_ascii_digit) {
                continue;
            }
            let Some(uid) = std::str::from_utf8(w).ok().and_then(|s| s.parse::<u32>().ok()) else { continue };
            if self.search.len() >= MAX_SEARCH_UIDS {
                return Err(ImapError::Protocol("too many UIDs in a SEARCH response"));
            }
            self.charge(std::mem::size_of::<u32>())?;
            self.search.push(uid);
        }
        Ok(())
    }

    /// `rest` of a `* VANISHED` line: an optional `(EARLIER)`, then the UID set (kept as ranges).
    fn add_vanished(&mut self, rest: &[u8]) {
        let set = rest.rsplit(|b| *b == b' ').find(|w| !w.is_empty()).unwrap_or_default();
        if self.vanished_complete
            && let Ok(set) = std::str::from_utf8(set)
        {
            self.vanished_complete = parse_uid_ranges(set, &mut self.vanished, MAX_VANISHED_RANGES);
        }
    }

    fn done(self, status: Status, code: Vec<Tok>) -> Done {
        Done {
            status,
            code,
            untagged: self.untagged,
            search: self.search,
            vanished: self.vanished_complete.then(|| UidRanges::from_ranges(self.vanished)),
            metas: self.metas.unwrap_or_default(),
        }
    }
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
    search: Vec<u32>,
    /// `None` when more ranges arrived than [`MAX_VANISHED_RANGES`].
    vanished: Option<UidRanges>,
    metas: Vec<(FetchedMeta, bool)>,
}

impl Done {
    fn code_name(&self) -> Option<String> {
        self.code.first().and_then(Tok::atom).map(str::to_ascii_uppercase)
    }
}

/// Where a failed command stopped: needed to classify writes.
struct ExecError {
    err: ImapError,
    /// True when the command may have taken effect: all of it was written, or a whole literal may have reached the
    /// server (which can act on an APPEND before reading the final CRLF).
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

/// Parses a UID set (`1:3,7,9:8`) into `out` as `(lo, hi)` pairs without expanding ranges. Returns false (and stops)
/// once `out` holds `max` ranges. Malformed parts are skipped.
fn parse_uid_ranges(s: &str, out: &mut Vec<(u32, u32)>, max: usize) -> bool {
    for part in s.split(',') {
        let range = match part.split_once(':') {
            Some((a, b)) => match (a.parse::<u32>(), b.parse::<u32>()) {
                (Ok(a), Ok(b)) => (a.min(b), a.max(b)),
                _ => continue,
            },
            None => match part.parse::<u32>() {
                Ok(u) => (u, u),
                Err(_) => continue,
            },
        };
        if out.len() >= max {
            return false;
        }
        out.push(range);
    }
    true
}

/// A `FETCH` response (tokens after the `*`) as its UID and upper-cased item names with values; `None` for other
/// responses and FETCHes without a UID.
fn fetch_items(t: &[Tok]) -> Option<(u32, Vec<(String, Tok)>)> {
    let (Some(Tok::Atom(_)), Some(Tok::Atom(f)), Some(Tok::List(items))) = (t.first(), t.get(1), t.get(2)) else {
        return None;
    };
    if !f.eq_ignore_ascii_case("FETCH") {
        return None;
    }
    let mut kv = Vec::new();
    let mut it = items.iter();
    while let (Some(k), Some(v)) = (it.next(), it.next()) {
        if let Some(k) = k.atom() {
            kv.push((k.to_ascii_uppercase(), v.clone()));
        }
    }
    let uid = kv.iter().find(|(k, _)| k == "UID").and_then(|(_, v)| v.num())?;
    Some((uid, kv))
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
    /// Gmail mode (from the account settings): FETCHes add `X-GM-LABELS`, moves never fall back to COPY + EXPUNGE.
    gmail: bool,
    /// Set while an `IDLE` command is in progress (between [`ImapSession::idle_start`] and its completion).
    idle: Option<IdleState>,
}

/// What arrived on an idling connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleEvent {
    /// `EXISTS`, `EXPUNGE`, `FETCH` or `VANISHED`: the selected folder changed.
    Changed,
    /// Any other untagged response (`RECENT`, `OK` keep-alives, stray continuations).
    Other,
    /// The `IDLE` command completed (after `DONE`, or because the server ended it).
    Ended,
}

/// Read state of an `IDLE` command, kept across calls so a dropped [`ImapSession::idle_next`] loses nothing.
struct IdleState {
    tag: String,
    /// Bytes of the current, unfinished line.
    line: Vec<u8>,
    /// Literal bytes still to skip (a literal inside an untagged response).
    skip: usize,
    /// Classification of a response whose first line announced a literal (its continuation lines follow).
    cont: Option<IdleEvent>,
}

/// Classifies the first line of one response read while idling.
fn idle_class(line: &[u8], tag: &str) -> Result<IdleEvent, ImapError> {
    let up = line.to_ascii_uppercase();
    let mut w = up.split(|b| *b == b' ').filter(|p| !p.is_empty());
    let head = w.next().unwrap_or_default();
    if head == b"*" {
        let (a, b) = (w.next().unwrap_or_default(), w.next().unwrap_or_default());
        if a == b"BYE" {
            return Err(ImapError::Network);
        }
        let numbered = !a.is_empty() && a.iter().all(u8::is_ascii_digit);
        if a == b"VANISHED" || (numbered && matches!(b, b"EXISTS" | b"EXPUNGE" | b"FETCH")) {
            return Ok(IdleEvent::Changed);
        }
        return Ok(IdleEvent::Other);
    }
    if head.starts_with(b"+") {
        return Ok(IdleEvent::Other);
    }
    if head == tag.to_ascii_uppercase().as_bytes() {
        return match w.next().unwrap_or_default() {
            b"OK" => Ok(IdleEvent::Ended),
            _ => Err(ImapError::Protocol("IDLE refused")),
        };
    }
    Err(ImapError::Protocol("response for an unknown tag"))
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
            gmail: false,
            idle: None,
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

    /// Puts the session in Gmail mode (the account's `ImapSettings.gmail`).
    pub fn set_gmail(&mut self, on: bool) {
        self.gmail = on;
    }

    pub fn is_gmail(&self) -> bool {
        self.gmail
    }

    /// Whether FETCHes ask for `X-GM-LABELS`: Gmail mode on a server that still offers the extension.
    fn gm_labels(&self) -> bool {
        self.gmail && self.has_cap(GMAIL_CAP)
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
        self.write_staged(bytes).await.map_err(|(e, _)| e)
    }

    /// Writes and flushes. On failure, also whether every byte had been handed to the stream (only the flush failed):
    /// the peer may then have received all of them.
    async fn write_staged(&mut self, bytes: &[u8]) -> Result<(), (ImapError, bool)> {
        let w = self.io.get_mut();
        let mut handed_over = false;
        let r = tokio::time::timeout(self.timeout, async {
            w.write_all(bytes).await?;
            handed_over = true;
            w.flush().await
        })
        .await;
        match r {
            Ok(Ok(())) => Ok(()),
            _ => Err((ImapError::Network, handed_over)),
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
        let (max_line, metas) = match op {
            ImapOp::UidSearchAll | ImapOp::UidSearchFrom(_) => (BIG_LINE, false),
            ImapOp::UidFetchChangedSince { .. } => (BIG_LINE, true),
            ImapOp::UidFetchMeta { .. } => (MAX_LINE, true),
            _ => (MAX_LINE, false),
        };
        let fail = |err| ExecError { err, sent_all: false };
        let mut literal_sent = false;
        if self.idle.is_some() {
            // Only DONE may follow IDLE (`idle_done`); anything else would be read as the end of IDLE.
            return Err(fail(ImapError::Protocol("session is idling")));
        }
        self.tag += 1;
        let tag = format!("d{}", self.tag);
        let cmd = op.render();
        if !IMAP_VERBS.contains(&cmd.verb) {
            return Err(fail(ImapError::Protocol("command not allowlisted")));
        }
        let mut col = Collected::new(max_literal.saturating_add(RETAINED), metas);
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
                    if let Some((st, code)) =
                        self.await_continuation(&tag, &mut col, &mut budget).await.map_err(fail)?
                    {
                        return Ok(col.done(st, code));
                    }
                    // Once a literal may have arrived in full, a server can commit the command (an APPEND) before
                    // it reads the final CRLF: any later failure leaves the outcome unknown.
                    self.write_staged(&bytes).await.map_err(|(err, all)| ExecError { err, sent_all: all })?;
                    literal_sent = true;
                }
                Part::Sasl(line) => sasl = Some(line),
            }
        }
        buf.extend_from_slice(b"\r\n");
        self.write(&buf).await.map_err(|err| ExecError { err, sent_all: literal_sent })?;
        if let Some(line) = sasl {
            if let Some((st, code)) = self.await_continuation(&tag, &mut col, &mut budget).await.map_err(fail)? {
                return Ok(col.done(st, code));
            }
            let mut l = Zeroizing::new(line.as_bytes().to_vec());
            l.extend_from_slice(b"\r\n");
            self.write(&l).await.map_err(fail)?;
        }
        let sent = |err| ExecError { err, sent_all: true };
        loop {
            let segs = self.read_response(max_literal, max_line, &mut budget).await.map_err(sent)?;
            match self.classify(&tag, segs, &mut col).map_err(sent)? {
                Resp::Untagged => {}
                Resp::Continuation => return Err(sent(ImapError::Protocol("unexpected continuation"))),
                Resp::Tagged(status, code) => return Ok(col.done(status, code)),
            }
        }
    }

    /// Waits for `+`. Returns the completion if the server answered the command (NO/BAD) instead.
    async fn await_continuation(
        &mut self,
        tag: &str,
        col: &mut Collected,
        budget: &mut usize,
    ) -> Result<Option<(Status, Vec<Tok>)>, ImapError> {
        loop {
            let segs = self.read_response(SMALL_LITERAL, MAX_LINE, budget).await?;
            match self.classify(tag, segs, col)? {
                Resp::Continuation => return Ok(None),
                Resp::Untagged => {}
                Resp::Tagged(status, code) => return Ok(Some((status, code))),
            }
        }
    }

    /// Classifies one response and keeps what it carries in `col`: number lists parsed from bytes, FETCH metadata
    /// in compact form (when `col` collects it), everything else as tokens. All of it is charged to `col.mem`.
    fn classify(&self, tag: &str, segs: Vec<Seg>, col: &mut Collected) -> Result<Resp, ImapError> {
        let first = match segs.first() {
            Some(Seg::Text(t)) => t,
            _ => return Err(ImapError::Protocol("malformed response")),
        };
        if first.starts_with(b"+") {
            return Ok(Resp::Continuation);
        }
        if segs.len() == 1
            && let Some((kind, rest)) = number_line(first)
        {
            match kind {
                NumLine::Search => col.add_search(rest)?,
                NumLine::Vanished => col.add_vanished(rest),
            }
            return Ok(Resp::Untagged);
        }
        // Only number lists may be longer than an ordinary line.
        if segs.iter().any(|s| matches!(s, Seg::Text(t) if t.len() > MAX_LINE)) {
            return Err(ImapError::Protocol("response line too long"));
        }
        let before = col.mem;
        let mut toks = tokenize(segs, &mut col.mem)?;
        if matches!(toks.first(), Some(Tok::Atom(a)) if a == "*") {
            if toks.get(1).and_then(Tok::atom).is_some_and(|a| a.eq_ignore_ascii_case("BYE")) {
                return Err(ImapError::Network);
            }
            toks.remove(0);
            if col.metas.is_some()
                && let Some((uid, kv)) = fetch_items(&toks)
            {
                // The tokens are dropped; only the compact form is kept and charged.
                let meta = Self::meta_of(uid, &kv);
                let has_size = kv.iter().any(|(k, _)| k == "RFC822.SIZE");
                col.mem = before;
                col.charge(
                    std::mem::size_of::<(FetchedMeta, bool)>()
                        + meta
                            .flags
                            .iter()
                            .chain(meta.gm_labels.iter().flatten())
                            .map(|f| TOK_COST + f.len())
                            .sum::<usize>(),
                )?;
                col.metas.get_or_insert_default().push((meta, has_size));
                return Ok(Resp::Untagged);
            }
            if col.untagged.len() >= MAX_UNTAGGED {
                return Err(ImapError::Protocol("too many responses"));
            }
            col.untagged.push(Untagged(toks));
            return Ok(Resp::Untagged);
        }
        let head = toks.first().and_then(Tok::atom).unwrap_or_default().to_string();
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
                "\\all" => Some(Special::All),
                _ => None,
            });
            let delimiter = if delim.is_nil() { None } else { delim.text().and_then(|d| d.chars().next()) };
            out.push(FolderInfo {
                name_utf8: utf7::display_name(&raw),
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

    fn search_result(d: Done) -> Vec<u32> {
        let mut out = d.search;
        out.sort_unstable();
        out.dedup();
        out
    }

    /// All UIDs of the selected folder.
    pub async fn uid_search_all(&mut self) -> Result<Vec<u32>, ImapError> {
        self.selected()?;
        let d = self.simple(ImapOp::UidSearchAll, SMALL_LITERAL).await?;
        Ok(Self::search_result(d))
    }

    /// UIDs `>= uid` in the selected folder.
    pub async fn uid_search_since_uid(&mut self, uid: u32) -> Result<Vec<u32>, ImapError> {
        self.selected()?;
        let d = self.simple(ImapOp::UidSearchFrom(uid), SMALL_LITERAL).await?;
        // `n:*` always matches the highest UID, even below n.
        Ok(Self::search_result(d).into_iter().filter(|u| *u >= uid).collect())
    }

    /// FETCH responses as (uid, key/value items).
    fn fetches(d: &Done) -> Vec<(u32, Vec<(String, Tok)>)> {
        d.untagged.iter().filter_map(|Untagged(t)| fetch_items(t)).collect()
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
                // Atoms (`\\Inbox`) or strings (`"\\\\Inbox"`, `"My label"`, literals): the text either way.
                ("X-GM-LABELS", Tok::List(l)) => {
                    m.gm_labels = Some(l.iter().filter_map(Tok::text).map(Cow::into_owned).collect())
                }
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
        let (modseq, gm_labels) = (self.condstore(), self.gm_labels());
        let d = self.simple(ImapOp::UidFetchMeta { uids, modseq, gm_labels }, SMALL_LITERAL).await?;
        let mut out: Vec<FetchedMeta> = d
            .metas
            .into_iter()
            // Unsolicited flag updates carry no size.
            .filter(|(m, has_size)| *has_size && uids.contains(&m.uid))
            .map(|(m, _)| m)
            .collect();
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
        self.fetch_raw_sized(uid, size, max_bytes).await
    }

    /// [`Self::fetch_raw`] for a message whose `RFC822.SIZE` the caller already fetched (with [`Self::fetch_meta`]
    /// in the same selected folder), saving the size probe. The literal cap still bounds what the server sends.
    pub async fn fetch_raw_sized(
        &mut self,
        uid: u32,
        size: u64,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, ImapError> {
        self.selected()?;
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
        let (vanished, gm_labels) = (self.qresync, self.gm_labels());
        let d = self.simple(ImapOp::UidFetchChangedSince { modseq, vanished, gm_labels }, SMALL_LITERAL).await?;
        Ok(Changes {
            changed: d.metas.into_iter().map(|(m, _)| m).collect(),
            vanished: if vanished { d.vanished } else { None },
        })
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

    // ------------------------------------------------------------------ organize

    /// Selects `folder` read-write and checks its UIDVALIDITY (a change is [`ImapError::Missing`]).
    async fn select_checked(&mut self, folder: &str, uidvalidity: u32) -> Result<(), ImapError> {
        let st = self.select(folder, false).await?;
        if st.uidvalidity != uidvalidity {
            return Err(ImapError::Missing);
        }
        Ok(())
    }

    /// Adds and removes organize flags on `uids` of `folder` and returns the current metadata of the UIDs that exist
    /// (the others are skipped by the server and absent from the result).
    pub async fn store_flags(
        &mut self,
        folder: &str,
        uidvalidity: u32,
        uids: &[u32],
        add: &[StoreFlag],
        remove: &[StoreFlag],
    ) -> Result<Vec<FetchedMeta>, ImapError> {
        self.select_checked(folder, uidvalidity).await?;
        let present: Vec<u32> = self.fetch_meta(uids).await?.into_iter().map(|m| m.uid).collect();
        if present.is_empty() {
            return Ok(Vec::new());
        }
        let mut ops = Vec::new();
        if !add.is_empty() {
            ops.push(ImapOp::UidStoreFlags { uids: &present, add: true, flags: add });
        }
        if !remove.is_empty() {
            ops.push(ImapOp::UidStoreFlags { uids: &present, add: false, flags: remove });
        }
        self.stores_then_fetch(ops, &present).await
    }

    /// Adds and removes Gmail labels (`X-GM-LABELS`) on `uids` of `folder` (Gmail mode) and returns the current
    /// metadata of the UIDs that exist. The message ids do not change.
    pub async fn store_gm_labels(
        &mut self,
        folder: &str,
        uidvalidity: u32,
        uids: &[u32],
        add: &[GmLabel],
        remove: &[GmLabel],
    ) -> Result<Vec<FetchedMeta>, ImapError> {
        if !self.gm_labels() {
            return Err(ImapError::Capability("X-GM-EXT-1"));
        }
        self.select_checked(folder, uidvalidity).await?;
        let present: Vec<u32> = self.fetch_meta(uids).await?.into_iter().map(|m| m.uid).collect();
        if present.is_empty() {
            return Ok(Vec::new());
        }
        let mut ops = Vec::new();
        if !add.is_empty() {
            ops.push(ImapOp::UidStoreGmLabels { uids: &present, add: true, labels: add });
        }
        if !remove.is_empty() {
            ops.push(ImapOp::UidStoreGmLabels { uids: &present, add: false, labels: remove });
        }
        self.stores_then_fetch(ops, &present).await
    }

    /// Runs organize STOREs in order, then reads the UIDs' metadata back. A STORE fully sent whose reply is lost is
    /// [`ImapError::OutcomeUnknown`]; so is any failure after a STORE went through, because part of the change is in
    /// place. Only a failure before the first STORE reached the server is definitive (organize refunds those).
    async fn stores_then_fetch(
        &mut self,
        ops: Vec<ImapOp<'_>>,
        present: &[u32],
    ) -> Result<Vec<FetchedMeta>, ImapError> {
        let mut written = false;
        for op in ops {
            if let Err(e) = self.write_simple(op).await {
                return Err(if written { ImapError::OutcomeUnknown } else { e });
            }
            written = true;
        }
        let metas = self.fetch_meta(present).await;
        if written { metas.map_err(|_| ImapError::OutcomeUnknown) } else { metas }
    }

    /// [`Self::simple`] for a write: a command that was fully sent but got no answer may have been applied
    /// ([`ImapError::OutcomeUnknown`]); one that never left completely is [`ImapError::NotDispatched`].
    async fn write_simple(&mut self, op: ImapOp<'_>) -> Result<Done, ImapError> {
        let d = match self.exec(op, SMALL_LITERAL).await {
            Ok(d) => d,
            Err(ExecError { sent_all: true, .. }) => return Err(ImapError::OutcomeUnknown),
            Err(ExecError { err, sent_all: false }) => {
                return Err(if err == ImapError::Network { ImapError::NotDispatched } else { err });
            }
        };
        match d.status {
            Status::Ok => Ok(d),
            Status::No => Err(ImapError::Missing),
            Status::Bad => Err(ImapError::Protocol("command rejected as malformed")),
        }
    }

    /// Moves `uids` of `src` to `dest`: `UID MOVE` (RFC 6851) when offered, else `UID COPY`, then `\Deleted` and
    /// `UID EXPUNGE` of exactly the sources the server's `COPYUID` confirmed as copied (a [`CopiedUid`] each).
    /// Without a confirmation nothing is flagged or expunged. A lost connection after the command was sent is
    /// [`ImapError::OutcomeUnknown`].
    ///
    /// In Gmail mode only `UID MOVE` is used: there `\Deleted` + `EXPUNGE` can delete a message for good (depending
    /// on the account's settings), so a server without `MOVE` is a [`ImapError::Capability`] error before any command.
    pub async fn move_uids(
        &mut self,
        src: &str,
        uidvalidity: u32,
        uids: &[u32],
        dest: &str,
    ) -> Result<MoveOutcome, ImapError> {
        if self.gmail && !self.has_cap("MOVE") {
            return Err(ImapError::Capability("MOVE"));
        }
        self.select_checked(src, uidvalidity).await?;
        let present: Vec<u32> = self.fetch_meta(uids).await?.into_iter().map(|m| m.uid).collect();
        if present.is_empty() {
            return Ok(MoveOutcome::default());
        }
        let use_move = self.has_cap("MOVE");
        let op = if use_move {
            ImapOp::UidMove { uids: &present, mailbox: dest }
        } else {
            ImapOp::UidCopy { uids: &present, mailbox: dest }
        };
        let d = match self.exec(op, SMALL_LITERAL).await {
            Ok(d) => d,
            Err(ExecError { sent_all: true, .. }) => return Err(ImapError::OutcomeUnknown),
            Err(ExecError { err, sent_all: false }) => {
                return Err(if err == ImapError::Network { ImapError::NotDispatched } else { err });
            }
        };
        match d.status {
            Status::Ok => {}
            Status::No if d.code_name().as_deref() == Some("TRYCREATE") => return Err(ImapError::Missing),
            Status::No => return Err(ImapError::Protocol("move refused by the server")),
            Status::Bad => return Err(ImapError::Protocol("move rejected as malformed")),
        }
        // RFC 4315 puts COPYUID in the tagged OK; RFC 6851 sends it untagged before the expunges.
        let copyuid = parse_copyuid(&d.code, present.len()).or_else(|| {
            d.untagged.iter().find_map(|Untagged(t)| match (t.first(), t.get(1)) {
                (Some(Tok::Atom(ok)), Some(Tok::Code(c))) if ok.eq_ignore_ascii_case("OK") => {
                    parse_copyuid(c, present.len())
                }
                _ => None,
            })
        });
        // Only UIDs Dove asked for count, whatever else a server lists.
        let pairs: Vec<(u32, u32)> = copyuid
            .as_ref()
            .map(|(_, p)| p.iter().copied().filter(|(s, _)| present.contains(s)).collect())
            .unwrap_or_default();
        let mut out = MoveOutcome { dest_uidvalidity: copyuid.as_ref().map(|(v, _)| *v), ..Default::default() };
        if use_move {
            out.moved = match copyuid {
                Some(_) => pairs.into_iter().map(|(s, d)| (s, Some(d))).collect(),
                // Moved, but the server did not say where to.
                None => present.iter().map(|u| (*u, None)).collect(),
            };
            return Ok(out);
        }
        if copyuid.is_none() {
            out.copied_kept = present.iter().map(|u| (*u, None)).collect();
            return Ok(out);
        }
        let confirmed: Vec<CopiedUid> =
            pairs.iter().map(|(s, _)| CopiedUid::confirmed_by_copyuid(src, uidvalidity, *s)).collect();
        let removed = self.expunge_copied(&confirmed).await;
        let done: Vec<(u32, Option<u32>)> = pairs.into_iter().map(|(s, d)| (s, Some(d))).collect();
        if removed.is_ok() {
            out.moved = done;
        } else {
            out.copied_kept = done;
        }
        Ok(out)
    }

    /// Flags the confirmed copy sources `\Deleted` and expunges exactly them, in their own folder only.
    async fn expunge_copied(&mut self, copied: &[CopiedUid]) -> Result<(), ImapError> {
        let Some(first) = copied.first() else { return Ok(()) };
        if self.gmail {
            return Err(ImapError::Protocol("no expunge outside Drafts in Gmail mode"));
        }
        let (name, readonly, st) = self.selected()?.clone();
        if readonly
            || copied.iter().any(|c| c.folder != name || c.uidvalidity != st.uidvalidity || c.folder != first.folder)
        {
            return Err(ImapError::Protocol("copied UIDs do not belong to the selected folder"));
        }
        self.simple(ImapOp::UidStoreDeletedCopied(copied), SMALL_LITERAL).await?;
        self.simple(ImapOp::UidExpungeCopied(copied), SMALL_LITERAL).await?;
        Ok(())
    }

    // ------------------------------------------------------------------ IDLE (RFC 2177)

    /// Starts `IDLE` on the selected folder. Returns whether change notifications arrived before the server accepted
    /// it. A server without the capability, or one that refuses the command, is [`ImapError::Capability`].
    pub async fn idle_start(&mut self) -> Result<bool, ImapError> {
        self.selected()?;
        if !self.has_cap("IDLE") {
            return Err(ImapError::Capability("IDLE"));
        }
        if self.idle.is_some() {
            return Err(ImapError::Protocol("session is idling"));
        }
        let cmd = ImapOp::Idle.render();
        if !IMAP_VERBS.contains(&cmd.verb) {
            return Err(ImapError::Protocol("command not allowlisted"));
        }
        self.tag += 1;
        let tag = format!("d{}", self.tag);
        self.write(format!("{tag} {}\r\n", cmd.text()).as_bytes()).await?;
        let mut col = Collected::new(RETAINED, false);
        let mut budget = SMALL_LITERAL + MAX_LINE + COMMAND_OVERHEAD;
        if self.await_continuation(&tag, &mut col, &mut budget).await?.is_some() {
            return Err(ImapError::Capability("IDLE"));
        }
        let changed = !col.vanished.is_empty()
            || !col.vanished_complete
            || col.untagged.iter().any(|Untagged(t)| {
                let b = t.get(1).and_then(Tok::atom).unwrap_or_default();
                ["EXISTS", "EXPUNGE", "FETCH"].iter().any(|k| b.eq_ignore_ascii_case(k))
            });
        self.idle = Some(IdleState { tag, line: Vec::new(), skip: 0, cont: None });
        Ok(changed)
    }

    /// Whether an `IDLE` command is in progress.
    pub fn is_idling(&self) -> bool {
        self.idle.is_some()
    }

    /// Waits for the next response while idling. No timeout: the caller bounds the wait (renewal timer). Cancel-safe:
    /// a dropped call keeps the partial line, so it can be used in `select!`. [`IdleEvent::Ended`] means the command
    /// completed (the session is usable again); a `BYE` or a closed connection is [`ImapError::Network`].
    pub async fn idle_next(&mut self) -> Result<IdleEvent, ImapError> {
        let Self { io, idle, .. } = self;
        let st = idle.as_mut().ok_or(ImapError::Protocol("session is not idling"))?;
        loop {
            let buf = io.fill_buf().await.map_err(|_| ImapError::Network)?;
            if buf.is_empty() {
                return Err(ImapError::Network);
            }
            if st.skip > 0 {
                let n = buf.len().min(st.skip);
                io.consume(n);
                st.skip -= n;
                continue;
            }
            let (take, complete) = match buf.iter().position(|b| *b == b'\n') {
                Some(i) => (i + 1, true),
                None => (buf.len(), false),
            };
            if st.line.len() + take > MAX_LINE {
                return Err(ImapError::Protocol("response line too long"));
            }
            st.line.extend_from_slice(&buf[..take]);
            io.consume(take);
            if !complete {
                continue;
            }
            let mut line = std::mem::take(&mut st.line);
            while line.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
                line.pop();
            }
            let ev = match st.cont.take() {
                Some(ev) => ev,
                None => idle_class(&line, &st.tag)?,
            };
            if let Some(n) = literal_len(&line) {
                if n > SMALL_LITERAL {
                    return Err(ImapError::Protocol("response literal over the size limit"));
                }
                st.skip = n;
                st.cont = Some(ev);
                continue;
            }
            if ev == IdleEvent::Ended {
                *idle = None;
            }
            return Ok(ev);
        }
    }

    /// Ends `IDLE` with `DONE` and reads up to its completion. Returns whether change notifications arrived meanwhile.
    /// A no-op when the server already ended the command.
    pub async fn idle_done(&mut self) -> Result<bool, ImapError> {
        if self.idle.is_none() {
            return Ok(false);
        }
        let cmd = ImapOp::Done.render();
        if !IMAP_VERBS.contains(&cmd.verb) {
            return Err(ImapError::Protocol("command not allowlisted"));
        }
        self.write(format!("{}\r\n", cmd.text()).as_bytes()).await?;
        let mut changed = false;
        loop {
            match tokio::time::timeout(self.timeout, self.idle_next()).await {
                Ok(Ok(IdleEvent::Changed)) => changed = true,
                Ok(Ok(IdleEvent::Other)) => {}
                Ok(Ok(IdleEvent::Ended)) => return Ok(changed),
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(ImapError::Network),
            }
        }
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
    /// Kept in the command's [`Collected`].
    Untagged,
    Continuation,
    Tagged(Status, Vec<Tok>),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(s: &str) -> Vec<Tok> {
        tokenize(vec![Seg::Text(s.as_bytes().to_vec())], &mut usize::MAX.clone()).unwrap()
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
        let t = tokenize(
            vec![
                Seg::Text(b"* 1 FETCH (UID 5 BODY[] ".to_vec()),
                Seg::Lit(b"a)b\"c".to_vec()),
                Seg::Text(b")".to_vec()),
            ],
            &mut usize::MAX.clone(),
        )
        .unwrap();
        // Deep nesting from a hostile server is refused instead of recursing without bound.
        let deep = |c: &str| {
            tokenize(vec![Seg::Text(format!("* {}", c.repeat(100_000)).into_bytes())], &mut usize::MAX.clone())
        };
        assert_eq!(deep("(").unwrap_err(), ImapError::Protocol("response nested too deeply"));
        assert_eq!(deep("[").unwrap_err(), ImapError::Protocol("response nested too deeply"));
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

    fn over_stream(io: impl Io + 'static) -> ImapSession {
        ImapSession {
            io: BufReader::new(Box::new(io)),
            tag: 0,
            caps: Vec::new(),
            timeout: Duration::from_secs(5),
            drafts: None,
            sent: None,
            selected: None,
            qresync: false,
            gmail: false,
            idle: None,
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

    /// IDLE reads survive dropped calls (partial lines are kept), skip literals inside untagged responses, classify
    /// change notifications, and end on the tagged completion after DONE. Nothing but `IDLE` and `DONE` is sent.
    #[tokio::test]
    async fn idle_is_cancel_safe_and_classifies_responses() {
        let (client, server) = tokio::io::duplex(1 << 16);
        let mut s = over_stream(client);
        s.caps = vec!["IMAP4REV1".into(), "IDLE".into()];
        s.selected = Some(("INBOX".into(), true, FolderStatus { uidvalidity: 1, ..Default::default() }));
        let (mut sr, mut sw) = tokio::io::split(server);
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        sw.write_all(b"* 2 RECENT\r\n+ idling\r\n").await.unwrap();
        assert!(!s.idle_start().await.unwrap());
        let n = sr.read(&mut buf).await.unwrap();
        got.extend_from_slice(&buf[..n]);
        assert!(s.is_idling());
        // Half a line, then a dropped read: the bytes must not be lost.
        sw.write_all(b"* 3 EXI").await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(50), s.idle_next()).await.is_err());
        sw.write_all(b"STS\r\n* OK still here\r\n* 1 FETCH (UID 2 X {5}\r\nab)cd)\r\n* VANISHED 7\r\n").await.unwrap();
        assert_eq!(s.idle_next().await.unwrap(), IdleEvent::Changed);
        assert_eq!(s.idle_next().await.unwrap(), IdleEvent::Other);
        assert_eq!(s.idle_next().await.unwrap(), IdleEvent::Changed);
        assert_eq!(s.idle_next().await.unwrap(), IdleEvent::Changed);
        // Other commands are refused while idling.
        assert_eq!(s.noop().await.unwrap_err(), ImapError::Protocol("session is idling"));
        sw.write_all(b"* 4 EXISTS\r\nd1 OK idle done\r\n").await.unwrap();
        assert!(s.idle_done().await.unwrap());
        assert!(!s.is_idling());
        let n = sr.read(&mut buf).await.unwrap();
        got.extend_from_slice(&buf[..n]);
        assert_eq!(String::from_utf8_lossy(&got), "d1 IDLE\r\nDONE\r\n");
        // A BYE while idling is a lost connection.
        sw.write_all(b"+ idling\r\n* BYE shutting down\r\n").await.unwrap();
        s.idle_start().await.unwrap();
        assert_eq!(s.idle_next().await.unwrap_err(), ImapError::Network);
    }

    #[tokio::test]
    async fn idle_refused_or_missing_is_a_capability_error() {
        let (client, server) = tokio::io::duplex(1 << 16);
        let mut s = over_stream(client);
        s.selected = Some(("INBOX".into(), true, FolderStatus { uidvalidity: 1, ..Default::default() }));
        assert_eq!(s.idle_start().await.unwrap_err(), ImapError::Capability("IDLE"));
        s.caps = vec!["IDLE".into()];
        let (_sr, mut sw) = tokio::io::split(server);
        sw.write_all(b"d1 BAD unknown command\r\n").await.unwrap();
        assert_eq!(s.idle_start().await.unwrap_err(), ImapError::Capability("IDLE"));
        assert!(!s.is_idling());
    }

    /// VANISHED sets stay ranges: a range wider than any mailbox costs one pair (and is not dropped), and the number
    /// of pairs kept per command is capped.
    #[test]
    fn uid_ranges_are_never_expanded() {
        let mut v = Vec::new();
        assert!(parse_uid_ranges("4294967295:1", &mut v, 1));
        let r = UidRanges::from_ranges(v);
        assert_eq!(r.ranges(), &[(1, u32::MAX)]);
        assert!(r.contains(3_000_000) && r.contains(u32::MAX) && !r.contains(0));
        let r = UidRanges::from_ranges(vec![(5, 9), (1, 3), (4, 4), (20, 30), (25, 26), (1, 2)]);
        assert_eq!(r.ranges(), &[(1, 9), (20, 30)]);
        assert!(r.contains(1) && r.contains(9) && !r.contains(10) && r.contains(20) && !r.contains(31));
        let hostile = ["1:1000000"; 10].join(",");
        let mut v = Vec::new();
        assert!(!parse_uid_ranges(&hostile, &mut v, 4));
        assert_eq!(v.len(), 4);
    }

    fn condstore_session(io: tokio::io::DuplexStream) -> ImapSession {
        let mut s = over_stream(io);
        s.caps = vec!["IMAP4REV1".into(), "CONDSTORE".into(), "QRESYNC".into()];
        s.qresync = true;
        s.selected = Some(("INBOX".into(), true, FolderStatus { uidvalidity: 1, ..Default::default() }));
        s
    }

    /// A `VANISHED (EARLIER)` range wider than a million UIDs still names the UIDs inside it; more ranges than
    /// [`MAX_VANISHED_RANGES`] make the set incomplete (`None`) instead of growing without bound.
    #[tokio::test]
    async fn vanished_ranges_are_kept_and_bounded() {
        let (client, server) = tokio::io::duplex(1 << 20);
        let mut s = condstore_session(client);
        let (_sr, mut sw) = tokio::io::split(server);
        sw.write_all(
            b"* VANISHED (EARLIER) 7,1:3000000\r\n* 1 FETCH (UID 3000001 FLAGS () MODSEQ (9))\r\nd1 OK done\r\n",
        )
        .await
        .unwrap();
        let ch = s.changed_since(1).await.unwrap();
        let v = ch.vanished.unwrap();
        assert_eq!(v.ranges(), &[(1, 3_000_000)]);
        assert!(v.contains(2_500_000) && !v.contains(3_000_001));
        assert_eq!(ch.changed.len(), 1);

        let many: Vec<String> = (0..=MAX_VANISHED_RANGES as u32).map(|i| (2 * i + 1).to_string()).collect();
        let feed = tokio::spawn(async move {
            sw.write_all(format!("* VANISHED (EARLIER) {}\r\nd2 OK done\r\n", many.join(",")).as_bytes())
                .await
                .unwrap();
            sw
        });
        let ch = s.changed_since(1).await.unwrap();
        assert_eq!(ch.vanished, None, "over the cap: incomplete, the caller diffs instead");
        feed.await.unwrap();
    }

    /// A selected CONDSTORE/QRESYNC session whose server answers with `resp` (written up front) and ignores input.
    fn answering(resp: Vec<u8>) -> ImapSession {
        let (client, server) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(server);
            let _ = w.write_all(&resp).await;
            let mut sink = vec![0u8; 4096];
            while matches!(r.read(&mut sink).await, Ok(n) if n > 0) {}
        });
        condstore_session(client)
    }

    fn lines(body: impl IntoIterator<Item = String>, done: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for l in body {
            out.extend_from_slice(l.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(done.as_bytes());
        out
    }

    /// `* SEARCH` lines are parsed from bytes into at most [`MAX_SEARCH_UIDS`] UIDs; only number lists may be longer
    /// than [`MAX_LINE`], and no line longer than [`BIG_LINE`] is read.
    #[tokio::test]
    async fn number_lists_are_parsed_from_bytes_and_bounded() {
        let mut s = answering(b"* SEARCH 3 1 2 3 (MODSEQ 917162500)\r\nd1 OK done\r\n".to_vec());
        assert_eq!(s.uid_search_all().await.unwrap(), vec![1, 2, 3]);

        let over = format!("* SEARCH{}", " 1".repeat(MAX_SEARCH_UIDS + 1));
        let mut s = answering(lines([over], "d1 OK done\r\n"));
        assert_eq!(s.uid_search_all().await.unwrap_err(), ImapError::Protocol("too many UIDs in a SEARCH response"));

        // A FETCH is tokenized, so it must fit an ordinary line even while a SEARCH may use a big one.
        let fetch = format!("* 1 FETCH (FLAGS ({}))", "\\a ".repeat(30_000));
        assert!(fetch.len() > MAX_LINE);
        let mut s = answering(lines([fetch], "d1 OK done\r\n"));
        assert_eq!(s.uid_search_all().await.unwrap_err(), ImapError::Protocol("response line too long"));

        // 1M UIDs of up to ten digits need about 11 MB; a 12 MB line is refused before it is parsed.
        let padded = format!("* SEARCH 1{}", " ".repeat(12_000_000));
        let mut s = answering(lines([padded], "d1 OK done\r\n"));
        assert_eq!(s.uid_search_all().await.unwrap_err(), ImapError::Protocol("response line too long"));
    }

    /// Tokens kept for one command are charged against [`RETAINED`]: many ordinary lines of short atoms fail the
    /// command instead of growing the token list (each line, and all bytes together, are within their caps).
    #[tokio::test]
    async fn retained_tokens_are_bounded_per_command() {
        let line = format!("* OK {}", "a ".repeat(30_000));
        assert!(line.len() < MAX_LINE);
        let n = RETAINED / (TOK_COST * 30_000) + 2;
        assert!(n * line.len() < COMMAND_OVERHEAD);
        let mut s = answering(lines(std::iter::repeat_n(line, n), "d1 OK done\r\n"));
        assert_eq!(s.noop().await.unwrap_err(), ImapError::Protocol("response over the memory limit"));
        let t = tokenize(vec![Seg::Text(b"* a b c".to_vec())], &mut (3 * TOK_COST));
        assert_eq!(t.unwrap_err(), ImapError::Protocol("response over the memory limit"));
    }

    /// A large CHANGEDSINCE result (a mass flag change) fits because FETCH responses are kept as metadata, not as
    /// tokens (as tokens the same responses exceed [`RETAINED`]).
    #[tokio::test]
    async fn changed_since_keeps_compact_metadata() {
        let n = 150_000u32;
        assert!((n as usize) * 11 * TOK_COST > RETAINED);
        let body = (1..=n).map(|u| format!("* {u} FETCH (UID {u} FLAGS (\\Seen) MODSEQ (5))"));
        let mut s = answering(lines(body, "d1 OK done\r\n"));
        let ch = s.changed_since(1).await.unwrap();
        assert_eq!(ch.changed.len(), n as usize);
        assert_eq!(ch.changed[n as usize - 1].flags, vec!["\\Seen".to_string()]);
        assert_eq!(ch.changed[0].modseq, Some(5));
    }

    /// Gmail labels arrive as atoms (`\Inbox`), quoted strings with escapes and literals; all become their text. Without
    /// Gmail mode the item is not requested.
    #[tokio::test]
    async fn gmail_labels_are_parsed_in_every_form() {
        let resp = b"* 1 FETCH (UID 7 FLAGS (\\Seen) RFC822.SIZE 10 MODSEQ (3) X-GM-LABELS (\\Inbox \"\\\\Important\" \"My label\" {9}\r\nK&AOQ-se/ Work))\r\nd1 OK done\r\n";
        let mut s = answering(resp.to_vec());
        s.caps.push(GMAIL_CAP.into());
        s.set_gmail(true);
        assert!(s.gm_labels());
        let m = s.fetch_meta(&[7]).await.unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(
            m[0].gm_labels.as_deref(),
            Some(
                &["\\Inbox".to_string(), "\\Important".into(), "My label".into(), "K&AOQ-se/".into(), "Work".into()][..]
            )
        );
        // Gmail mode on a server without the extension (or the reverse) asks for no labels.
        let mut s = answering(Vec::new());
        s.set_gmail(true);
        assert!(!s.gm_labels());
        s.caps.push(GMAIL_CAP.into());
        s.set_gmail(false);
        assert!(!s.gm_labels());
    }

    /// In Gmail mode a server without MOVE is refused before any command: never the COPY + `\Deleted` + EXPUNGE
    /// fallback, and the confirmed-copy expunge refuses to run at all.
    #[tokio::test]
    async fn gmail_mode_never_falls_back_to_copy_and_expunge() {
        let mut s = answering(Vec::new());
        s.caps.push(GMAIL_CAP.into());
        s.set_gmail(true);
        assert_eq!(s.move_uids("[Gmail]/All Mail", 1, &[3], "[Gmail]/Trash").await, Err(ImapError::Capability("MOVE")));
        // Even with the copy's folder selected read-write.
        s.selected = Some(("INBOX".into(), false, FolderStatus { uidvalidity: 1, ..Default::default() }));
        let copied = CopiedUid::for_ops_tests(&[3]);
        assert!(matches!(s.expunge_copied(&copied).await, Err(ImapError::Protocol(_))));
        assert_eq!(s.tag, 0, "nothing was sent");
    }

    /// A stream that fails any write of exactly `fail_on` (reads come from the duplex peer).
    struct FailWrite {
        inner: tokio::io::DuplexStream,
        fail_on: &'static [u8],
    }

    impl tokio::io::AsyncRead for FailWrite {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for FailWrite {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let me = self.get_mut();
            if buf == me.fail_on {
                return std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
            }
            std::pin::Pin::new(&mut me.inner).poll_write(cx, buf)
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    /// The final CRLF of an APPEND comes after the whole message: a server may already have stored it, so failing to
    /// write the CRLF is `OutcomeUnknown`. Failing inside the message itself is still `NotDispatched`.
    #[tokio::test]
    async fn append_failing_after_the_literal_is_outcome_unknown() {
        for (fail_on, want) in [(&b"\r\n"[..], ImapError::OutcomeUnknown), (&b"hello"[..], ImapError::NotDispatched)] {
            let (client, server) = tokio::io::duplex(1 << 16);
            let mut s = over_stream(FailWrite { inner: client, fail_on });
            s.set_append_targets(Some("Drafts".into()), None);
            let (_sr, mut sw) = tokio::io::split(server);
            sw.write_all(b"+ go ahead\r\n").await.unwrap();
            assert_eq!(s.append(AppendTarget::Drafts, &[], b"hello").await.unwrap_err(), want, "{fail_on:?}");
        }
    }

    #[test]
    fn internal_dates_and_sets() {
        assert_eq!(parse_internal_date("17-Jul-1996 02:44:25 -0700"), Some(837596665));
        assert_eq!(parse_internal_date(" 1-Jan-2026 00:00:00 +0000"), Some(1767225600));
        assert_eq!(parse_internal_date("garbage"), None);
        assert_eq!(parse_internal_date("17-Jul-1996 02:44:25 -\u{e9}00"), None);
        let mut v = Vec::new();
        assert!(parse_uid_ranges("1:3,7,9:8,x,5:y", &mut v, 10));
        assert_eq!(v, vec![(1, 3), (7, 7), (8, 9)]);
        assert_eq!(literal_len(b"* 1 FETCH (BODY[] {123}"), Some(123));
        assert_eq!(literal_len(b"* OK {weird}"), None);
    }

    #[test]
    fn copyuid_is_parsed_strictly_and_bounded() {
        let code = |s: &str| -> Vec<Tok> {
            let t = toks(&format!("d1 OK [{s}] done"));
            match &t[2] {
                Tok::Code(c) => c.clone(),
                other => panic!("{other:?}"),
            }
        };
        assert_eq!(
            parse_copyuid(&code("COPYUID 9 4:6,9 20:23"), 10),
            Some((9, vec![(4, 20), (5, 21), (6, 22), (9, 23)]))
        );
        assert_eq!(parse_copyuid(&code("COPYUID 9 7 31"), 1), Some((9, vec![(7, 31)])));
        // Descending ranges keep their order.
        assert_eq!(parse_copyuid(&code("COPYUID 9 3:2 11:12"), 5), Some((9, vec![(3, 11), (2, 12)])));
        for bad in
            ["COPYUID 9 4:6 20:21", "COPYUID 0 4 5", "COPYUID 9 0 5", "COPYUID 9 x 5", "APPENDUID 9 5", "COPYUID 9 4"]
        {
            assert_eq!(parse_copyuid(&code(bad), 10), None, "{bad}");
        }
        // Wider than what Dove asked for: refused before expanding.
        assert_eq!(parse_copyuid(&code("COPYUID 9 1:4294967295 1:4294967295"), 100), None);
        assert_eq!(parse_copyuid(&code("COPYUID 9 1:3 1:3"), 2), None);
    }
}
