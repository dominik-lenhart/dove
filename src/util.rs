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
}
