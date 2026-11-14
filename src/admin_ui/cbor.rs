//! A minimal CBOR decoder (RFC 8949) for WebAuthn attestation objects and COSE keys.
//!
//! Only what CTAP2 authenticators emit is accepted: definite lengths, unsigned and negative integers, byte and text
//! strings, arrays, maps, and the simple values false, true and null. Indefinite lengths, tags, floats, undefined and
//! other simple values are refused, as are duplicate map keys, nesting deeper than [`MAX_DEPTH`] and trailing bytes
//! where a single item is expected. Declared lengths are checked against the remaining input before anything is
//! allocated, so a forged length cannot make the decoder reserve memory.

use std::fmt;

/// Deepest nesting accepted (an attestation object is three levels deep).
pub const MAX_DEPTH: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Major types 0 and 1 (CBOR integers range from -2^64 to 2^64-1).
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Pairs in input order (keys unique).
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Truncated,
    Unsupported,
    TooDeep,
    DuplicateKey,
    InvalidUtf8,
    TrailingBytes,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Truncated => "truncated CBOR",
            Error::Unsupported => "unsupported CBOR item",
            Error::TooDeep => "CBOR nested too deeply",
            Error::DuplicateKey => "duplicate CBOR map key",
            Error::InvalidUtf8 => "CBOR text is not UTF-8",
            Error::TrailingBytes => "bytes after the CBOR item",
        })
    }
}

impl std::error::Error for Error {}

impl Value {
    /// The value under an integer key of a map.
    pub fn get_int_key(&self, key: i128) -> Option<&Value> {
        match self {
            Value::Map(m) => m.iter().find(|(k, _)| *k == Value::Int(key)).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The value under a text key of a map.
    pub fn get_text_key(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(m) => m.iter().find(|(k, _)| matches!(k, Value::Text(t) if t == key)).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i128> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }
}

/// Decodes exactly one item that spans all of `input`.
pub fn decode(input: &[u8]) -> Result<Value, Error> {
    let (v, used) = decode_prefix(input)?;
    if used != input.len() {
        return Err(Error::TrailingBytes);
    }
    Ok(v)
}

/// Decodes one item at the start of `input` and returns it with the number of bytes it took (authenticator data
/// holds a COSE key followed by optional extension data).
pub fn decode_prefix(input: &[u8]) -> Result<(Value, usize), Error> {
    let mut r = Reader { buf: input, pos: 0 };
    let v = r.item(0)?;
    Ok((v, r.pos))
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        if end > self.buf.len() {
            return Err(Error::Truncated);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// The argument of an initial byte with additional information `info` (0-27); 28-31 are refused (reserved, or
    /// indefinite length).
    fn argument(&mut self, info: u8) -> Result<u64, Error> {
        Ok(match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(self.take(2)?.try_into().expect("2 bytes"))),
            26 => u64::from(u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes"))),
            27 => u64::from_be_bytes(self.take(8)?.try_into().expect("8 bytes")),
            _ => return Err(Error::Unsupported),
        })
    }

    /// A length that must fit in what is left of the input, each element taking at least `min_each` bytes.
    fn length(&mut self, info: u8, min_each: usize) -> Result<usize, Error> {
        let n = self.argument(info)?;
        let n = usize::try_from(n).map_err(|_| Error::Truncated)?;
        if n.checked_mul(min_each).is_none_or(|need| need > self.remaining()) {
            return Err(Error::Truncated);
        }
        Ok(n)
    }

    fn item(&mut self, depth: usize) -> Result<Value, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        let ib = self.take(1)?[0];
        let (major, info) = (ib >> 5, ib & 0x1f);
        match major {
            0 => Ok(Value::Int(i128::from(self.argument(info)?))),
            1 => Ok(Value::Int(-1 - i128::from(self.argument(info)?))),
            2 => {
                let n = self.length(info, 1)?;
                Ok(Value::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = self.length(info, 1)?;
                let s = std::str::from_utf8(self.take(n)?).map_err(|_| Error::InvalidUtf8)?;
                Ok(Value::Text(s.to_string()))
            }
            4 => {
                let n = self.length(info, 1)?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(v))
            }
            5 => {
                let n = self.length(info, 2)?;
                let mut m: Vec<(Value, Value)> = Vec::with_capacity(n);
                for _ in 0..n {
                    let k = self.item(depth + 1)?;
                    if m.iter().any(|(e, _)| *e == k) {
                        return Err(Error::DuplicateKey);
                    }
                    let v = self.item(depth + 1)?;
                    m.push((k, v));
                }
                Ok(Value::Map(m))
            }
            // Tags are not used by CTAP2 for anything Dove reads.
            6 => Err(Error::Unsupported),
            _ => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => Err(Error::Unsupported),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn d(s: &str) -> Result<Value, Error> {
        decode(&hex(s))
    }

    /// RFC 8949 Appendix A examples for every supported item.
    #[test]
    fn rfc8949_examples() {
        use Value::*;
        let ints: &[(&str, i128)] = &[
            ("00", 0),
            ("01", 1),
            ("0a", 10),
            ("17", 23),
            ("1818", 24),
            ("1819", 25),
            ("1864", 100),
            ("1903e8", 1000),
            ("1a000f4240", 1_000_000),
            ("1b000000e8d4a51000", 1_000_000_000_000),
            ("1bffffffffffffffff", 18_446_744_073_709_551_615),
            ("3bffffffffffffffff", -18_446_744_073_709_551_616),
            ("20", -1),
            ("29", -10),
            ("3863", -100),
            ("3903e7", -1000),
        ];
        for (h, want) in ints {
            assert_eq!(d(h), Ok(Int(*want)), "{h}");
        }
        assert_eq!(d("f4"), Ok(Bool(false)));
        assert_eq!(d("f5"), Ok(Bool(true)));
        assert_eq!(d("f6"), Ok(Null));
        assert_eq!(d("40"), Ok(Bytes(vec![])));
        assert_eq!(d("4401020304"), Ok(Bytes(vec![1, 2, 3, 4])));
        assert_eq!(d("60"), Ok(Text(String::new())));
        assert_eq!(d("6161"), Ok(Text("a".into())));
        assert_eq!(d("6449455446"), Ok(Text("IETF".into())));
        assert_eq!(d("62225c"), Ok(Text("\"\\".into())));
        assert_eq!(d("62c3bc"), Ok(Text("\u{fc}".into())));
        assert_eq!(d("63e6b0b4"), Ok(Text("\u{6c34}".into())));
        assert_eq!(d("64f0908591"), Ok(Text("\u{10151}".into())));
        assert_eq!(d("80"), Ok(Array(vec![])));
        assert_eq!(d("83010203"), Ok(Array(vec![Int(1), Int(2), Int(3)])));
        assert_eq!(
            d("8301820203820405"),
            Ok(Array(vec![Int(1), Array(vec![Int(2), Int(3)]), Array(vec![Int(4), Int(5)])]))
        );
        let big = d("98190102030405060708090a0b0c0d0e0f101112131415161718181819").unwrap();
        assert_eq!(big, Array((1..=25).map(Int).collect()));
        assert_eq!(d("a0"), Ok(Map(vec![])));
        assert_eq!(d("a201020304"), Ok(Map(vec![(Int(1), Int(2)), (Int(3), Int(4))])));
        assert_eq!(
            d("a26161016162820203"),
            Ok(Map(vec![(Text("a".into()), Int(1)), (Text("b".into()), Array(vec![Int(2), Int(3)]))]))
        );
        assert_eq!(
            d("826161a161626163"),
            Ok(Array(vec![Text("a".into()), Map(vec![(Text("b".into()), Text("c".into()))])]))
        );
    }

    #[test]
    fn unsupported_items_are_refused() {
        // Floats (half, single, double), undefined, simple(16), simple(255), tags, indefinite lengths.
        for h in ["f90000", "fa47c35000", "fb3ff199999999999a", "f7", "f0", "f8ff", "c11a514b67b0", "5f42010243030405ff"]
        {
            assert_eq!(d(h), Err(Error::Unsupported), "{h}");
        }
        for h in ["7f657374726561646d696e67ff", "9fff", "bf6346756ef563416d7421ff"] {
            assert_eq!(d(h), Err(Error::Unsupported), "{h}");
        }
        // Reserved additional information 28-30.
        assert_eq!(d("1c"), Err(Error::Unsupported));
        assert_eq!(d("62c3"), Err(Error::Truncated));
        assert_eq!(d("62ff00"), Err(Error::InvalidUtf8));
    }

    #[test]
    fn structure_is_checked() {
        assert_eq!(d("a2010201ff"), Err(Error::DuplicateKey), "a repeated key");
        assert_eq!(d("0000"), Err(Error::TrailingBytes));
        assert_eq!(decode_prefix(&hex("0000")), Ok((Value::Int(0), 1)));
        // Declared lengths larger than the input are refused before any allocation.
        assert_eq!(d("5bffffffffffffffff"), Err(Error::Truncated));
        assert_eq!(d("9bffffffffffffffff"), Err(Error::Truncated));
        assert_eq!(d("bbffffffffffffffff"), Err(Error::Truncated));
        assert_eq!(d("83"), Err(Error::Truncated));
        assert_eq!(d(""), Err(Error::Truncated));
        // Nesting: MAX_DEPTH arrays inside the top level are fine, one more is not.
        let ok = format!("{}00", "81".repeat(MAX_DEPTH));
        assert!(d(&ok).is_ok());
        let deep = format!("{}00", "81".repeat(MAX_DEPTH + 1));
        assert_eq!(d(&deep), Err(Error::TooDeep));
    }
}
