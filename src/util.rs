//! Small shared helpers: randomness, encodings, time.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

/// Fills an array from the OS CSPRNG. Panics only if the OS RNG is unavailable, which is unrecoverable.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("OS random number generator unavailable");
    buf
}

pub fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Standard base64 with padding (SASL, MCP resource blobs).
pub fn b64std(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

/// Decodes the base64url text at `buf[range]` (padding optional) into the start of `buf` itself and truncates `buf`
/// to the decoded bytes, so a large encoded payload is never held twice. Decoded output (3 bytes per 4) always
/// stays behind the unread input, and each input chunk is copied out before its space can be overwritten.
pub fn b64url_decode_in_place(mut buf: Vec<u8>, range: std::ops::Range<usize>) -> Option<Vec<u8>> {
    const CHUNK: usize = 4096; // a multiple of 4: only the last chunk can be a partial quad
    let text = buf.get(range.clone())?;
    let end = range.start + text.iter().rposition(|&b| b != b'=').map_or(0, |p| p + 1);
    let (mut pos, mut out) = (range.start, 0usize);
    let mut tmp = [0u8; CHUNK];
    while pos < end {
        let n = (end - pos).min(CHUNK);
        tmp[..n].copy_from_slice(&buf[pos..pos + n]);
        out += URL_SAFE_NO_PAD.decode_slice(&tmp[..n], &mut buf[out..]).ok()?;
        pos += n;
    }
    buf.truncate(out);
    Some(buf)
}

/// Accepts standard or URL-safe base64, with or without padding.
pub fn b64_decode_any(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    STANDARD.decode(s).ok().or_else(|| b64url_decode(s))
}

pub fn hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// A random opaque identifier (128 bits, URL-safe).
pub fn new_id() -> String {
    b64url(&random_bytes::<16>())
}

pub fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

pub fn now_unix_ms() -> i64 {
    (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}

pub fn rfc3339(ts: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(ts)
        .ok()
        .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
        .unwrap_or_default()
}

pub fn rfc3339_ms(ts_ms: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp_nanos(ts_ms as i128 * 1_000_000)
        .ok()
        .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
        .unwrap_or_default()
}

/// Parses an RFC 3339 instant that carries an explicit offset. Returns unix milliseconds.
pub fn parse_rfc3339_ms(s: &str) -> Option<i64> {
    let t = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()?;
    Some((t.unix_timestamp_nanos() / 1_000_000) as i64)
}

/// Parses a calendar date `YYYY-MM-DD` (exactly that form) as the start of that UTC day, in unix milliseconds.
pub fn parse_date_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i32> {
        let t = &s[r];
        t.bytes().all(|c| c.is_ascii_digit()).then(|| t.parse().ok())?
    };
    let month = time::Month::try_from(u8::try_from(num(5..7)?).ok()?).ok()?;
    let date = time::Date::from_calendar_date(num(0..4)?, month, u8::try_from(num(8..10)?).ok()?).ok()?;
    Some(date.midnight().assume_utc().unix_timestamp() * 1000)
}

/// True for a date and time without a zone (`2026-11-01T10:00:00`, also with a space): ambiguous, so it is refused
/// with a hint instead of being read as UTC.
pub fn looks_like_local_datetime(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 16
        && parse_date_ms(&s[..10]).is_some()
        && (b[10] == b'T' || b[10] == b' ')
        && b[11..13].iter().all(u8::is_ascii_digit)
        && b[13] == b':'
        && !s.ends_with(['Z', 'z'])
        && !s[11..].contains(['+', '-'])
}

/// Parses durations like `90d`, `12h`, `30m`, `45s`.
pub fn parse_duration_secs(s: &str) -> Option<i64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit())?);
    let n: i64 = num.parse().ok()?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 604_800,
        _ => return None,
    };
    n.checked_mul(mult)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_place_base64url_matches_the_plain_decoder() {
        for len in [0usize, 1, 2, 3, 4, 3071, 3072, 3073, 10_000, 50_001] {
            let data: Vec<u8> = (0..len).map(|i| (i * 7919 % 251) as u8).collect();
            let unpadded = b64url(&data);
            let padded = format!("{unpadded}{}", "=".repeat((4 - unpadded.len() % 4) % 4));
            for text in [unpadded, padded] {
                let body = format!("{{\"raw\":\"{text}\",\"x\":1}}").into_bytes();
                let start = 8;
                let got = b64url_decode_in_place(body, start..start + text.len()).unwrap();
                assert_eq!(got, data, "len {len}");
            }
        }
        assert!(b64url_decode_in_place(b"ab*d".to_vec(), 0..4).is_none());
        assert!(b64url_decode_in_place(b"abcd".to_vec(), 2..9).is_none());
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration_secs("90d"), Some(90 * 86_400));
        assert_eq!(parse_duration_secs("15m"), Some(900));
        assert_eq!(parse_duration_secs("15"), None);
        assert_eq!(parse_duration_secs("x5d"), None);
    }

    #[test]
    fn rfc3339_requires_offset_and_roundtrips() {
        let ms = parse_rfc3339_ms("2026-10-01T00:00:00+02:00").unwrap();
        assert_eq!(rfc3339_ms(ms), "2026-09-30T22:00:00Z");
        assert!(parse_rfc3339_ms("2026-10-01T00:00:00").is_none());
    }

    #[test]
    fn dates_are_strict_utc_days() {
        assert_eq!(parse_date_ms("2026-10-01"), parse_rfc3339_ms("2026-10-01T00:00:00Z"));
        for bad in ["2026-1-01", "2026-13-01", "2026-02-30", "20261001", "2026-10-01 ", "+026-10-01", "2026-10-0a"] {
            assert!(parse_date_ms(bad).is_none(), "{bad}");
        }
        assert!(looks_like_local_datetime("2026-10-01T10:00:00"));
        assert!(looks_like_local_datetime("2026-10-01 10:00"));
        assert!(!looks_like_local_datetime("2026-10-01T10:00:00Z"));
        assert!(!looks_like_local_datetime("2026-10-01T10:00:00+02:00"));
        assert!(!looks_like_local_datetime("2026-10-01"));
    }
}
