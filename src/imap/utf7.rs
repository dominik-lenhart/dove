//! Modified UTF-7 for IMAP mailbox names (RFC 3501 5.1.3): `&` starts a modified-base64 run of UTF-16BE code
//! units (`,` instead of `/`), `-` ends it, `&-` is a literal `&`.

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

fn b64_val(c: u8) -> Option<u32> {
    B64.iter().position(|&x| x == c).map(|p| p as u32)
}

/// Decodes a server mailbox name. `None` for malformed input (callers then show the raw name).
pub fn decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c != b'&' {
            if !(0x20..=0x7e).contains(&c) {
                return None;
            }
            out.push(c as char);
            i += 1;
            continue;
        }
        let end = i + 1 + b[i + 1..].iter().position(|&x| x == b'-')?;
        let run = &b[i + 1..end];
        i = end + 1;
        if run.is_empty() {
            out.push('&');
            continue;
        }
        let (mut acc, mut bits) = (0u32, 0u32);
        let mut units = Vec::new();
        for &ch in run {
            acc = (acc << 6) | b64_val(ch)?;
            bits += 6;
            if bits >= 16 {
                bits -= 16;
                units.push(((acc >> bits) & 0xffff) as u16);
            }
        }
        // Leftover bits must be zero padding shorter than one base64 digit pair.
        if bits >= 6 || acc & ((1 << bits) - 1) != 0 {
            return None;
        }
        let decoded = String::from_utf16(&units).ok()?;
        // A run must not encode printable ASCII (it would have a direct form).
        if decoded.chars().any(|c| (' '..='~').contains(&c)) {
            return None;
        }
        out.push_str(&decoded);
    }
    Some(out)
}

/// Encodes a UTF-8 name for use on the wire.
pub fn encode(s: &str) -> String {
    let mut out = String::new();
    let mut pending: Vec<u16> = Vec::new();
    let flush = |pending: &mut Vec<u16>, out: &mut String| {
        if pending.is_empty() {
            return;
        }
        out.push('&');
        let mut bytes = Vec::with_capacity(pending.len() * 2);
        for u in pending.iter() {
            bytes.extend_from_slice(&u.to_be_bytes());
        }
        let (mut acc, mut bits) = (0u32, 0u32);
        for byte in bytes {
            acc = (acc << 8) | byte as u32;
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
        pending.clear();
    };
    for c in s.chars() {
        if (' '..='~').contains(&c) {
            flush(&mut pending, &mut out);
            if c == '&' {
                out.push_str("&-");
            } else {
                out.push(c);
            }
        } else {
            let mut buf = [0u16; 2];
            pending.extend_from_slice(c.encode_utf16(&mut buf));
        }
    }
    flush(&mut pending, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_names() {
        assert_eq!(decode("Entw&APw-rfe").as_deref(), Some("Entwürfe"));
        assert_eq!(encode("Entwürfe"), "Entw&APw-rfe");
        assert_eq!(decode("Tom &- Jerry").as_deref(), Some("Tom & Jerry"));
        assert_eq!(encode("Tom & Jerry"), "Tom &- Jerry");
        // RFC 3501 example.
        assert_eq!(decode("~peter/mail/&U,BTFw-/&ZeVnLIqe-").as_deref(), Some("~peter/mail/台北/日本語"));
        for s in ["INBOX", "Gelöschte Elemente", "📧 Post", "a&b", "Ünïcödé/Sub"] {
            assert_eq!(decode(&encode(s)).as_deref(), Some(s), "{s}");
        }
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(decode("&APw"), None); // unterminated
        assert_eq!(decode("&AGE-"), None); // encodes ASCII 'a'
        assert_eq!(decode("&A*w-"), None);
        assert_eq!(decode("Entw\u{fc}rfe"), None); // raw 8-bit
    }
}
