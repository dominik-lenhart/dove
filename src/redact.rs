//! Secret redaction for overview results (PLAN A59, spec 6.5a).
//!
//! Connections with `redact_secrets` on get credentials and one-time codes replaced by [`MARK`] in the short preview
//! text of list and overview results (subjects and snippets of `search_messages`, `digest`, `list_drafts`). Targeted
//! reads (`get_message`, `get_thread`, `get_draft`, attachments) stay unredacted, so an agent that needs the value
//! reads the one message.
//!
//! The detector is a conservative heuristic, not a classifier. It finds:
//!
//! 1. Labeled values. A label word followed by `:` / `=` (optionally `ist`/`is`/`lautet` before it) hides the next
//!    token (or quoted string). Label words: `passwort`, `kennwort`, `password`, `passphrase`, `passcode`, `token`,
//!    `secret`, `zugangscode` (also as the end of a compound such as `WLAN-Passwort`, `Initialpasswort`,
//!    `access_token`), and the whole words `pin`, `puk`, `pw`, `pwd`, `pass`, `passwd`, `apikey`, `api_key`,
//!    `geheimzahl`, plus `api`/`access`/`secret`/`private` + `key`/`schlüssel`. Without `:`/`=` (`Ihr Passwort ist
//!    X`, `your password is X`) the value must look like a secret: at least 4 characters with a digit, a symbol or
//!    a capital right after a lowercase letter. Block labels (`zugangsdaten`, `anmeldedaten`, `logindaten`, `credentials`) with `:` hide the
//!    rest of their line (at most 80 bytes). User names are not hidden.
//! 2. Known key shapes anywhere: `sk-…`, `sk_live_`/`sk_test_`/`rk_live_`/`rk_test_`, `ghp_`/`gho_`/`ghu_`/`ghs_`/
//!    `ghr_`, `github_pat_`, `glpat-`, `xox?-`, `AKIA`/`ASIA` access key ids, `AIza` Google API keys, JWTs (`eyJ…`
//!    with three segments), the token after `Bearer`, and PEM private key blocks (to their END line or the end of the
//!    text, since snippets are cut).
//! 3. One-time codes: a 4 to 8 digit number (or two groups of 3 to 4 digits, `482 913`) at most 32 bytes after or 40
//!    bytes before a code word (`code`, `…code` such as `Bestätigungscode`, `otp`, `tan`, `totp`, `mfa`, `2fa`, `pin`,
//!    `passcode`). Numbers that are part of a date, decimal, time or phone sequence, glued to letters, or 4-digit
//!    years (`19xx`, `20xx`) do not count; nor do `postcode`, `barcode`, `fehlercode` and similar words, or `code`
//!    followed by `review`/`of`/`style`/…. A code word with `:` also hides an alphanumeric value of 4 to 16
//!    characters that contains a digit (`Code: AB12CD`).
//!
//! Cost is linear in the input: one pass to find words and numbers, constant-size look-ahead per word, two-pointer
//! windows for codes, and every key-shape scan resumes after the run it examined.

use serde_json::Value;

/// What replaces each hidden span.
pub const MARK: &str = "[redacted]";
/// Longest value hidden after a label (bytes); longer runs are cut there, the rest stays.
const MAX_VALUE: usize = 128;
/// Longest rest-of-line hidden after a block label (bytes).
const MAX_BLOCK: usize = 80;
/// Words longer than this are never labels (bytes; compounds such as `Datenbankadministratorpasswort` fit).
const MAX_LABEL_WORD: usize = 48;
const CODE_AFTER: usize = 32;
/// Longest key-shaped run examined at once (bytes); a longer run is hidden in pieces.
const MAX_KEY: usize = 4096;
const CODE_BEFORE: usize = 40;

const SUFFIX_LABELS: &[&str] =
    &["passwort", "kennwort", "password", "passphrase", "passcode", "token", "secret", "zugangscode"];
const WORD_LABELS: &[&str] = &["pin", "puk", "pw", "pwd", "pass", "passwd", "apikey", "api_key", "geheimzahl"];
const KEY_PREFIXES: &[&str] = &["api", "access", "secret", "private"];
const KEY_WORDS: &[&str] = &["key", "schlüssel"];
const BLOCK_LABELS: &[&str] = &["zugangsdaten", "anmeldedaten", "logindaten", "credentials"];
const VERBS: &[&str] = &["is", "ist", "lautet", "lauten", "was", "war"];
/// First value words that mean "no value here" (`Passwort: bitte selbst vergeben`).
const STOP_VALUES: &[&str] = &[
    "bitte",
    "please",
    "siehe",
    "see",
    "wird",
    "will",
    "folgt",
    "follows",
    "unverändert",
    "unchanged",
    "ändern",
    "change",
    "vergessen",
    "forgot",
    "zurücksetzen",
    "reset",
    "none",
    "keins",
    "keine",
    "leer",
    "empty",
    "n/a",
    "-",
    "–",
];
const CODE_WORDS: &[&str] = &["otp", "tan", "totp", "mfa", "2fa", "pin", "passcode"];
const CODE_EXCLUDE: &[&str] = &[
    "postcode",
    "zipcode",
    "barcode",
    "qrcode",
    "sourcecode",
    "quellcode",
    "dresscode",
    "statuscode",
    "fehlercode",
    "errorcode",
    "unicode",
    "opcode",
    "farbcode",
    "colorcode",
    "ländercode",
    "countrycode",
    "areacode",
    "bankcode",
    "sortcode",
    "swiftcode",
];
/// Words after a bare `code` that make it about software, not a one-time code.
const CODE_NOT_BEFORE: &[&str] =
    &["review", "reviews", "of", "style", "base", "freeze", "snippet", "snippets", "beispiel", "qualität"];

/// Redacts secrets in `text`. Returns the new text and the number of hidden spans, or `None` when nothing was found.
pub fn redact(text: &str) -> Option<(String, usize)> {
    let mut spans = Vec::new();
    key_shapes(text, &mut spans);
    let words = words(text);
    labels(text, &words, &mut spans);
    codes(text, &words, &mut spans);
    if spans.is_empty() {
        return None;
    }
    spans.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (s, e) in spans {
        match merged.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    let mut out = String::with_capacity(text.len() + merged.len() * MARK.len());
    let mut at = 0;
    for &(s, e) in &merged {
        out.push_str(&text[at..s]);
        out.push_str(MARK);
        at = e;
    }
    out.push_str(&text[at..]);
    Some((out, merged.len()))
}

/// Redacts the string `fields` of a JSON object in place. Returns how many fields changed.
pub fn object_fields(v: &mut Value, fields: &[&str]) -> usize {
    let mut n = 0;
    for f in fields {
        if let Some(Value::String(s)) = v.get_mut(*f)
            && let Some((r, _)) = redact(s)
        {
            *s = r;
            n += 1;
        }
    }
    n
}

// ------------------------------------------------------------------ scanning helpers

#[derive(Debug, Clone, Copy)]
struct Word {
    s: usize,
    e: usize,
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn words(t: &str) -> Vec<Word> {
    let mut v = Vec::new();
    let mut start = None;
    for (i, c) in t.char_indices() {
        if is_word(c) {
            start.get_or_insert(i);
        } else if let Some(s) = start.take() {
            v.push(Word { s, e: i });
        }
    }
    if let Some(s) = start {
        v.push(Word { s, e: t.len() });
    }
    v
}

fn lower(t: &str, w: Word) -> Option<String> {
    (w.e - w.s <= MAX_LABEL_WORD).then(|| t[w.s..w.e].to_lowercase())
}

/// Largest char boundary at or below `p + n`.
fn clamp(t: &str, p: usize, n: usize) -> usize {
    let mut e = p.saturating_add(n).min(t.len());
    while !t.is_char_boundary(e) {
        e -= 1;
    }
    e
}

/// Skips at most `max` whitespace characters (`newlines` decides whether line breaks count).
fn skip_space(t: &str, p: usize, max: usize, newlines: bool) -> usize {
    let mut q = p;
    for c in t[p..].chars().take(max) {
        if !c.is_whitespace() || (!newlines && (c == '\n' || c == '\r')) {
            break;
        }
        q += c.len_utf8();
    }
    q
}

fn prev_char(t: &str, p: usize) -> Option<char> {
    t[..p].chars().next_back()
}

// ------------------------------------------------------------------ 1. labeled values

/// What follows a label: `(strong, value_start, stops_at_ampersand)`. Strong means `:` or `=` was present.
fn separator(t: &str, end: usize) -> Option<(bool, usize, bool)> {
    let mut p = skip_space(t, end, 8, false);
    if t[p..].starts_with('(') {
        let close = t[p..clamp(t, p, 40)].find(')')?;
        p = skip_space(t, p + close + 1, 8, false);
    }
    let sep = |p: usize| -> Option<(usize, bool)> {
        let c = t[p..].chars().next()?;
        matches!(c, ':' | '=' | '：').then(|| (p + c.len_utf8(), c == '='))
    };
    if let Some((v, eq)) = sep(p) {
        return Some((true, v, eq));
    }
    // A short verb: `ist`, `is`, `lautet`, optionally followed by a colon.
    let verb_end = p + t[p..].chars().take(9).take_while(|c| is_word(*c)).map(char::len_utf8).sum::<usize>();
    if verb_end == p || verb_end - p > 8 || !VERBS.contains(&t[p..verb_end].to_lowercase().as_str()) {
        return None;
    }
    let q = skip_space(t, verb_end, 8, false);
    match sep(q) {
        Some((v, eq)) => Some((true, v, eq)),
        None => Some((false, verb_end, false)),
    }
}

/// The value token after a separator: a quoted string, or a run without whitespace (and `&` after `=`).
fn value(t: &str, start: usize, stop_amp: bool) -> Option<(usize, usize)> {
    let p = skip_space(t, start, 16, true);
    let first = t[p..].chars().next()?;
    let close = match first {
        '"' => Some('"'),
        '\'' => Some('\''),
        '„' | '“' => Some('“'),
        '«' => Some('»'),
        _ => None,
    };
    if let Some(close) = close {
        let inner = p + first.len_utf8();
        let off = t[inner..clamp(t, inner, MAX_VALUE)].find(close)?;
        return (off > 0).then_some((inner, inner + off));
    }
    let mut e = p;
    for (i, c) in t[p..].char_indices() {
        if i >= MAX_VALUE || c.is_whitespace() || matches!(c, '<' | '>' | '"') || (stop_amp && c == '&') {
            break;
        }
        e = p + i + c.len_utf8();
    }
    (e > p).then_some((p, e))
}

fn masked(v: &str) -> bool {
    v.chars().all(|c| matches!(c, '*' | '•' | '●' | '·' | '.' | '…' | 'x' | 'X' | '#'))
}

fn stop_value(v: &str) -> bool {
    let core = v.trim_end_matches(['.', ',', '!', '?', ';', ':']).to_lowercase();
    STOP_VALUES.contains(&core.as_str())
}

/// Whether a value after a weak separator (`ist`, `is`) looks like a secret rather than a word.
fn secretish(v: &str) -> bool {
    let core = v.trim_end_matches(['.', ',', '!', '?', ';', ':', ')']);
    core.chars().count() >= 4
        && (core.chars().any(|c| c.is_ascii_digit())
            || core.chars().any(|c| !c.is_alphanumeric() && c != '-')
            || core.chars().zip(core.chars().skip(1)).any(|(a, b)| a.is_lowercase() && b.is_uppercase()))
}

#[derive(PartialEq)]
enum Label {
    Secret,
    Block,
    Code,
}

fn is_code_word(t: &str, words: &[Word], i: usize, lw: &str) -> bool {
    if CODE_WORDS.contains(&lw) {
        return true;
    }
    if !(lw.ends_with("code") || lw.ends_with("codes")) || CODE_EXCLUDE.iter().any(|x| lw.trim_end_matches('s') == *x) {
        return false;
    }
    if lw == "code" || lw == "codes" {
        let next = words.get(i + 1).filter(|n| n.s - words[i].e <= 2).and_then(|n| lower(t, *n));
        if next.is_some_and(|n| CODE_NOT_BEFORE.contains(&n.as_str())) {
            return false;
        }
    }
    true
}

fn classify(t: &str, words: &[Word], i: usize) -> Option<Label> {
    let lw = lower(t, words[i])?;
    if SUFFIX_LABELS.iter().any(|l| lw.ends_with(l)) || WORD_LABELS.contains(&lw.as_str()) {
        return Some(Label::Secret);
    }
    if KEY_WORDS.contains(&lw.as_str())
        && let Some(prev) = i.checked_sub(1).map(|j| words[j])
        && words[i].s - prev.e == 1
        && matches!(t.as_bytes()[prev.e], b' ' | b'-')
        && lower(t, prev).is_some_and(|p| KEY_PREFIXES.contains(&p.as_str()))
    {
        return Some(Label::Secret);
    }
    if BLOCK_LABELS.contains(&lw.as_str()) {
        return Some(Label::Block);
    }
    if is_code_word(t, words, i, &lw) {
        return Some(Label::Code);
    }
    None
}

fn labels(t: &str, words: &[Word], spans: &mut Vec<(usize, usize)>) {
    for i in 0..words.len() {
        let Some(kind) = classify(t, words, i) else { continue };
        let Some((strong, start, eq)) = separator(t, words[i].e) else { continue };
        match kind {
            Label::Block => {
                if !strong {
                    continue;
                }
                let p = skip_space(t, start, 8, false);
                let cap = clamp(t, p, MAX_BLOCK);
                let e = t[p..cap].find(['\n', '\r']).map_or(cap, |o| p + o);
                let e = p + t[p..e].trim_end().len();
                if e > p {
                    spans.push((p, e));
                }
            }
            Label::Secret => {
                let Some((s, e)) = value(t, start, eq) else { continue };
                let v = &t[s..e];
                if masked(v) || stop_value(v) || (!strong && !secretish(v)) {
                    continue;
                }
                // A list separator after the value stays visible.
                spans.push((s, s + v.trim_end_matches([',', ';']).len()));
            }
            Label::Code => {
                let Some((s, e)) = value(t, start, eq) else { continue };
                let v = t[s..e].trim_end_matches(['.', ',', '!', '?', ';', ')']);
                let n = v.chars().count();
                if strong && (4..=16).contains(&n) && v.chars().any(|c| c.is_ascii_digit()) && !masked(v) {
                    spans.push((s, s + v.len()));
                }
            }
        }
    }
}

// ------------------------------------------------------------------ 2. key shapes

/// `(prefix, case-insensitive, charset, min rest, max rest or 0 for unbounded)`.
type Shape = (&'static str, bool, fn(u8) -> bool, usize, usize);

fn alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}
fn alnum_dash_us(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}
fn alnum_us(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
fn alnum_dash(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}
fn upper_digit(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}
fn bearer_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-')
}

const SHAPES: &[Shape] = &[
    ("sk_live_", false, alnum, 16, 0),
    ("sk_test_", false, alnum, 16, 0),
    ("rk_live_", false, alnum, 16, 0),
    ("rk_test_", false, alnum, 16, 0),
    ("sk-", false, alnum_dash_us, 20, 0),
    ("github_pat_", false, alnum_us, 30, 0),
    ("ghp_", false, alnum, 30, 0),
    ("gho_", false, alnum, 30, 0),
    ("ghu_", false, alnum, 30, 0),
    ("ghs_", false, alnum, 30, 0),
    ("ghr_", false, alnum, 30, 0),
    ("glpat-", false, alnum_dash_us, 20, 0),
    ("xoxa-", false, alnum_dash, 10, 0),
    ("xoxb-", false, alnum_dash, 10, 0),
    ("xoxe-", false, alnum_dash, 10, 0),
    ("xoxp-", false, alnum_dash, 10, 0),
    ("xoxr-", false, alnum_dash, 10, 0),
    ("xoxs-", false, alnum_dash, 10, 0),
    ("AKIA", false, upper_digit, 16, 16),
    ("ASIA", false, upper_digit, 16, 16),
    ("AIza", false, alnum_dash_us, 35, 35),
    ("bearer ", true, bearer_char, 16, 0),
];

/// Length of the run of `ok` bytes from `p`, scanning at most `cap` bytes.
fn run(b: &[u8], p: usize, ok: fn(u8) -> bool, cap: usize) -> usize {
    b[p..].iter().take(cap).take_while(|x| ok(**x)).count()
}

fn key_shapes(t: &str, spans: &mut Vec<(usize, usize)>) {
    let b = t.as_bytes();
    let mut i = 0;
    while i < b.len() {
        // Shapes start at a word boundary on an ASCII byte (also a char boundary).
        if (!b[i].is_ascii_alphanumeric() && b[i] != b'-') || prev_char(t, i).is_some_and(is_word) {
            i += 1;
            continue;
        }
        if let Some(e) = pem(t, i) {
            spans.push((i, e));
            i = e;
            continue;
        }
        let (token, examined) = jwt(b, i);
        if let Some(e) = token {
            spans.push((i, e));
            i = e;
            continue;
        }
        let mut next = examined.max(i + 1);
        for &(prefix, ci, ok, min, max) in SHAPES {
            let pl = prefix.len();
            let Some(head) = b.get(i..i + pl) else { continue };
            let matches = if ci { head.eq_ignore_ascii_case(prefix.as_bytes()) } else { head == prefix.as_bytes() };
            if !matches {
                continue;
            }
            let cap = if max == 0 { MAX_KEY } else { max + 1 };
            let n = run(b, i + pl, ok, cap);
            let end = i + pl + n;
            let fits = n >= min && (max == 0 || n == max);
            if fits && (n == MAX_KEY || b.get(end).is_none_or(|c| !c.is_ascii_alphanumeric())) {
                // `Bearer` stays visible; only the token is hidden.
                let s = if ci { i + pl } else { i };
                spans.push((s, end));
            }
            // Resume after the examined run, so a long run is never rescanned from every position in it.
            next = next.max(end);
            break;
        }
        i = next;
    }
}

/// `eyJ<10+>.<10+>.<0+>` in base64url. Returns the token end, and how far the scan looked when there is none.
fn jwt(b: &[u8], i: usize) -> (Option<usize>, usize) {
    if !b[i..].starts_with(b"eyJ") {
        return (None, i);
    }
    let a = run(b, i, alnum_dash_us, MAX_KEY);
    if a < 13 || b.get(i + a) != Some(&b'.') {
        return (None, i + a);
    }
    let p = i + a + 1;
    let c = run(b, p, alnum_dash_us, MAX_KEY);
    if c < 10 || b.get(p + c) != Some(&b'.') {
        return (None, p + c);
    }
    let q = p + c + 1;
    let end = q + run(b, q, alnum_dash_us, MAX_KEY);
    (Some(end), end)
}

/// A PEM private key block from `-----BEGIN … PRIVATE KEY-----` to its END line, or to the end of the text.
fn pem(t: &str, i: usize) -> Option<usize> {
    const BEGIN: &str = "-----BEGIN ";
    const TAIL: &str = "PRIVATE KEY-----";
    if !t[i..].starts_with(BEGIN) {
        return None;
    }
    let head_end = clamp(t, i, BEGIN.len() + 24 + TAIL.len());
    let off = t[i..head_end].find(TAIL)?;
    let body = i + off + TAIL.len();
    Some(match t[body..].find("-----END ") {
        Some(o) => {
            let end_line = body + o;
            match t[end_line..clamp(t, end_line, 60)].find(TAIL) {
                Some(o2) => end_line + o2 + TAIL.len(),
                None => t.len(),
            }
        }
        None => t.len(),
    })
}

// ------------------------------------------------------------------ 3. one-time codes

#[derive(Debug, Clone, Copy)]
struct Num {
    s: usize,
    e: usize,
}

/// Standalone 4-8 digit numbers (or `123 456` / `123-456`), not part of a date, decimal, time, phone number or word.
fn numbers(t: &str) -> Vec<Num> {
    let b = t.as_bytes();
    let n = b.len();
    let joins_digits = |p: usize, q: Option<usize>| -> bool {
        matches!(b[p], b'.' | b',' | b'/' | b':' | b' ' | b'+' | b'-') && q.is_some_and(|q| b[q].is_ascii_digit())
    };
    let mut v = Vec::new();
    let mut i = 0;
    while i < n {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let s = i;
        while i < n && b[i].is_ascii_digit() {
            i += 1;
        }
        let mut e = i;
        let mut digits = e - s;
        if (3..=4).contains(&digits) && e + 1 < n && matches!(b[e], b' ' | b'-') && b[e + 1].is_ascii_digit() {
            let g = run(b, e + 1, |x| x.is_ascii_digit(), 16);
            if (3..=4).contains(&g) {
                e = e + 1 + g;
                digits += g;
                i = e;
            }
        }
        let before_ok = match prev_char(t, s) {
            None => true,
            Some(c) if c.is_alphabetic() => false,
            Some(c) if c.is_ascii() => !(s >= 2 && joins_digits(s - 1, Some(s - 2))),
            Some(_) => true,
        };
        let after_ok = match t[e..].chars().next() {
            None => true,
            Some(c) if c.is_alphabetic() => false,
            Some(c) if c.is_ascii() => !joins_digits(e, (e + 1 < n).then_some(e + 1)),
            Some(_) => true,
        };
        let year = digits == 4 && e - s == 4 && (b[s..s + 2] == *b"19" || b[s..s + 2] == *b"20");
        if (4..=8).contains(&digits) && before_ok && after_ok && !year {
            v.push(Num { s, e });
        }
    }
    v
}

fn codes(t: &str, words: &[Word], spans: &mut Vec<(usize, usize)>) {
    let nums = numbers(t);
    if nums.is_empty() {
        return;
    }
    let mut j = 0;
    for (i, w) in words.iter().enumerate() {
        let Some(lw) = lower(t, *w) else { continue };
        if !is_code_word(t, words, i, &lw) {
            continue;
        }
        let lo = w.s.saturating_sub(CODE_BEFORE);
        let hi = w.e + CODE_AFTER;
        while j < nums.len() && nums[j].e < lo {
            j += 1;
        }
        for num in nums[j..].iter().take_while(|n| n.s <= hi) {
            if num.e <= w.s || num.s >= w.e {
                spans.push((num.s, num.e));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> String {
        redact(s).map_or_else(|| s.to_string(), |(t, _)| t)
    }

    fn unchanged(s: &str) {
        assert_eq!(redact(s), None, "false positive in: {s}");
    }

    #[test]
    fn labeled_values() {
        assert_eq!(
            r("Benutzer: kunde42 / Passwort: Xy7#pq"),
            "Benutzer: kunde42 / Passwort: [redacted]",
            "user names stay, passwords go"
        );
        assert_eq!(
            r("Hallo,\nhier die Zugänge:\nBenutzer: max.mustermann@example.de\nPasswort: S0mmer!2024\nGruß"),
            "Hallo,\nhier die Zugänge:\nBenutzer: max.mustermann@example.de\nPasswort: [redacted]\nGruß"
        );
        assert_eq!(r("Benutzer: x / Passwort:\n   geheim"), "Benutzer: x / Passwort:\n   [redacted]");
        assert_eq!(r("Your password is hunter22."), "Your password is [redacted]");
        assert_eq!(
            r("Ihr neues Kennwort lautet: Ab3$xyz bis morgen"),
            "Ihr neues Kennwort lautet: [redacted] bis morgen"
        );
        assert_eq!(r("WLAN-Passwort: fritzbox1234"), "WLAN-Passwort: [redacted]");
        assert_eq!(r("Initialpasswort (temporär): abc"), "Initialpasswort (temporär): [redacted]");
        assert_eq!(r("PIN: 4711, PUK: 12345678"), "PIN: [redacted], PUK: [redacted]");
        assert_eq!(r(&format!("API key: {}", "abcd-1234")), "API key: [redacted]");
        assert_eq!(r("API-Schlüssel = 'q9 w8 e7'"), "API-Schlüssel = '[redacted]'");
        assert_eq!(
            r("https://x.example/cb?access_token=AbC123xyz&state=1"),
            "https://x.example/cb?access_token=[redacted]&state=1"
        );
        assert_eq!(r("pw: \"two words\" ok"), "pw: \"[redacted]\" ok");
        assert_eq!(r("Zugangsdaten: kunde42 / geheim99\nViele Grüße"), "Zugangsdaten: [redacted]\nViele Grüße");
        assert_eq!(r("Ihr Passwort ist Sommer2024!"), "Ihr Passwort ist [redacted]");
        assert_eq!(r("Bestätigungscode: AB12CD."), "Bestätigungscode: [redacted].");
    }

    #[test]
    fn key_shapes_anywhere() {
        // Prefix and body are joined at run time so secret scanners (gitleaks in CI) do not flag the fixtures.
        let cases = [
            ("sk-", "proj-AbCdEfGhIjKlMnOpQrStUvWx0123"),
            ("sk-", "ant-api03-abcdefghijklmnopqrstuv"),
            ("sk_", "live_4eC39HqLyjWDarjtT1zdp7dc"),
            ("gh", "p_0123456789abcdefghijABCDEFGHIJ012345"),
            ("github", "_pat_11ABCDEFG0123456789_abcdefghijklmnop"),
            ("gl", "pat-abcdefghij0123456789"),
            ("xo", "xb-1234567890-abcdefghij"),
            ("AK", "IAIOSFODNN7EXAMPLE"),
            ("AI", "zaSyA-1234567890abcdefghijklmnopqrstu"),
            ("ey", "JhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
        ];
        for (a, b) in cases {
            let k = format!("{a}{b}");
            assert_eq!(
                r(&format!("Schlüssel im Text {k} und weiter")),
                "Schlüssel im Text [redacted] und weiter",
                "{k}"
            );
        }
        assert_eq!(r("Authorization: Bearer abcdef0123456789ABCD.xyz"), "Authorization: Bearer [redacted]");
        let (begin, end) =
            (format!("-----BEGIN RSA {}-----", "PRIVATE KEY"), format!("-----END RSA {}-----", "PRIVATE KEY"));
        let pem = format!("Key:\n{begin}\nMIIEpAIBAAKCAQEA\n{end}\nDanke");
        assert_eq!(r(&pem), "Key:\n[redacted]\nDanke");
        assert_eq!(r(&format!("x -----BEGIN OPENSSH {}----- b3BlbnNzaC1rZXk", "PRIVATE KEY")), "x [redacted]");
        // Too short or glued into a word: not a key.
        unchanged("task-force sk-8 ghp_short AKIA123 xAKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn one_time_codes() {
        assert_eq!(r("123456 ist dein Bestätigungscode."), "[redacted] ist dein Bestätigungscode.");
        assert_eq!(r("Your verification code is 482 913"), "Your verification code is [redacted]");
        assert_eq!(r("G-123456 is your Google verification code"), "G-[redacted] is your Google verification code");
        assert_eq!(r("Code: 4821"), "Code: [redacted]");
        assert_eq!(r("Ihr Code lautet 93817. Er gilt 10 Minuten."), "Ihr Code lautet [redacted]. Er gilt 10 Minuten.");
        assert_eq!(r("Ihre TAN 556677 für die Überweisung"), "Ihre TAN [redacted] für die Überweisung");
        assert_eq!(r("Use one-time code 7381-2290 to sign in"), "Use one-time code [redacted] to sign in");
    }

    #[test]
    fn ordinary_mail_is_untouched() {
        for s in [
            "Bitte ändern Sie Ihr Passwort regelmäßig. Ihr Passwort ist abgelaufen.",
            "Passwort vergessen? Klicken Sie hier, um es zurückzusetzen.",
            "Das Passwort ist E-Mail-gebunden und muss 12 Zeichen lang sein.",
            "Die Rechnung 2024-11 über 1.234,56 € ist fällig am 13.11.2026.",
            "Ihre Bestellung 123456 wurde versandt. Postleitzahl 80331 München.",
            "Der Postcode 80331 gehört zu München, Fehlercode 50012 bitte ignorieren.",
            "Meeting um 14:30 in Raum 1205, Telefon +49 89 123456 oder 0171 2345678.",
            "Your password was changed. If this wasn't you, reset your password.",
            "Your password is incorrect. Passwords must have at least 8 characters.",
            "We reviewed the code in PR 482 and the code review of PR 12345 is done.",
            "Code of Conduct 2024 und der Quellcode 1.2.3 liegen im Anhang.",
            "Passwort: ********",
            "Kennwort: siehe separate Mail",
            "The token ring network and the secret garden, pin the issue.",
            "Ein neuer Login von Berlin am 12.11.2026 um 08:15 Uhr.",
            "Termin: Dienstag, 10:00 Uhr, Konferenzraum B. Bitte Code of Conduct beachten.",
            "Kontonummer 12345678, BLZ 70010080 – Danke für Ihre Zahlung von 250,00 EUR.",
            "Ihre Kundennummer lautet 4711 0815, Rückfragen gern per Mail.",
            "Unicode 15 bringt 4489 neue Zeichen; der Barcode 40123455 klebt auf dem Paket.",
            "Der Gutscheincode gilt bis Ende 2025.",
            "Der Code gilt für Telefon 089 123456 und Fax 089 123457.",
            "Promo-Code SOMMER gilt für 3 Artikel.",
        ] {
            unchanged(s);
        }
    }

    #[test]
    fn json_fields() {
        let mut v = serde_json::json!({"subject": "PIN: 4711", "snippet": "hallo", "from": "Passwort: x1"});
        assert_eq!(object_fields(&mut v, &["subject", "snippet"]), 1);
        assert_eq!(v["subject"], "PIN: [redacted]");
        assert_eq!(v["snippet"], "hallo");
        assert_eq!(v["from"], "Passwort: x1", "only the named fields");
    }

    #[test]
    fn linear_on_adversarial_input() {
        // Each of these would take minutes if any step rescanned from every position.
        let inputs = [
            "password: ".repeat(40_000),
            "sk-".repeat(100_000),
            "a".repeat(400_000),
            "eyJ".repeat(100_000),
            "-----BEGIN PRIVATE KEY----- ".repeat(10_000),
            "1234 ".repeat(80_000),
            "Passwort (".repeat(40_000),
            "zugangsdaten: ".repeat(40_000),
            "code 4821 ".repeat(100_000),
            "passwort ist ".repeat(40_000),
        ];
        let start = std::time::Instant::now();
        for s in &inputs {
            let _ = redact(s);
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(5), "took {:?}", start.elapsed());
    }
}
