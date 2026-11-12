//! Structured JSON logs with a redaction layer (spec 6.2, 8.3).
//!
//! The primary rule is that call sites never log content. As defense in depth, every formatted log line passes
//! through [`redact`], which masks bearer secrets, Google tokens and OAuth query parameters.

use std::io::Write;
use std::sync::{Arc, Mutex};

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

/// Masks secrets that might slip into a log string.
pub fn redact(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    'outer: while i < bytes.len() {
        // Dove secrets: dove_, dovei_, doveat_, dovert_, dovec_ followed by base64url.
        for prefix in [
            "dove_", "dovei_", "doveat_", "dovert_", "dovec_", "ya29.", "1//",
        ] {
            if input[i..].starts_with(prefix) {
                let start = i + prefix.len();
                let end = start
                    + input[start..]
                        .bytes()
                        .take_while(|b| {
                            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')
                        })
                        .count();
                if end - start >= 16 {
                    out.push_str(prefix);
                    out.push_str("[REDACTED]");
                    i = end;
                    continue 'outer;
                }
            }
        }
        for key in [
            "Bearer ",
            "bearer ",
            "code=",
            "state=",
            "refresh_token=",
            "access_token=",
            "code_verifier=",
        ] {
            if input[i..].starts_with(key) {
                out.push_str(key);
                out.push_str("[REDACTED]");
                i += key.len();
                i += input[i..]
                    .bytes()
                    .take_while(|b| !matches!(b, b' ' | b'&' | b'"' | b'\'' | b','))
                    .count();
                continue 'outer;
            }
        }
        let ch = input[i..].chars().next().expect("in bounds");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// A writer that redacts each buffered log record before writing it.
#[derive(Clone)]
pub struct RedactingWriter<W: Write + Send + 'static> {
    inner: Arc<Mutex<W>>,
}

impl<W: Write + Send + 'static> RedactingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

pub struct RedactingGuard<W: Write + Send + 'static> {
    inner: Arc<Mutex<W>>,
    buf: Vec<u8>,
}

impl<W: Write + Send + 'static> Write for RedactingGuard<W> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<W: Write + Send + 'static> Drop for RedactingGuard<W> {
    fn drop(&mut self) {
        let text = String::from_utf8_lossy(&self.buf);
        let clean = redact(&text);
        if let Ok(mut w) = self.inner.lock() {
            let _ = w.write_all(clean.as_bytes());
            let _ = w.flush();
        }
    }
}

impl<'a, W: Write + Send + 'static> MakeWriter<'a> for RedactingWriter<W> {
    type Writer = RedactingGuard<W>;
    fn make_writer(&'a self) -> Self::Writer {
        RedactingGuard {
            inner: self.inner.clone(),
            buf: Vec::with_capacity(256),
        }
    }
}

/// Installs JSON logging to stderr. `RUST_LOG` style filtering via `DOVE_LOG`.
pub fn init_service_logging() {
    let filter = EnvFilter::try_from_env("DOVE_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .with_env_filter(filter)
        .with_writer(RedactingWriter::new(std::io::stderr()))
        .try_init();
}

/// Plain stderr logging for CLI commands (warnings only by default).
pub fn init_cli_logging() {
    let filter = EnvFilter::try_from_env("DOVE_LOG").unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(RedactingWriter::new(std::io::stderr()))
        .without_time()
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_known_secret_shapes() {
        let token = crate::tokens::generate("dove_");
        let line = format!(
            "auth Bearer {token} url=/cb?code=4/abc&state=xyz refresh 1//0gLongRefreshTokenValue123 at ya29.a0AfB_byLongAccess"
        );
        let r = redact(&line);
        assert!(!r.contains(&token[5..]), "{r}");
        assert!(!r.contains("4/abc"));
        assert!(!r.contains("xyz"));
        assert!(!r.contains("0gLongRefreshTokenValue123"));
        assert!(!r.contains("a0AfB_byLongAccess"));
        assert_eq!(redact("plain text ümlaut"), "plain text ümlaut");
    }
}
