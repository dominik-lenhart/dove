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

pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
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
}
