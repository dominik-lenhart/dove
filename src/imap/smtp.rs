//! Minimal SMTP submission client (RFC 5321/6409 with AUTH PLAIN/LOGIN), hand-written for exact outcome
//! classification: anything that fails before the final `.` of `DATA` was certainly not sent; a lost connection
//! after it is an unknown outcome and must never be retried.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use super::ops::{SMTP_VERBS, SmtpOp};
use super::{Credentials, ImapConnector, ImapError, Io, ServerEndpoint, TlsMode};

const MAX_REPLY_LINE: usize = 4096;
const MAX_REPLY_LINES: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{kind}")]
pub struct SmtpError {
    pub kind: ImapError,
    /// True once the terminating `.` of `DATA` was written: the server may have accepted the message.
    pub data_terminator_sent: bool,
    /// The SMTP reply code when the server answered with a refusal.
    pub code: Option<u16>,
}

impl SmtpError {
    fn before(kind: ImapError) -> Self {
        Self { kind, data_terminator_sent: false, code: None }
    }
}

struct Conn {
    io: BufReader<Box<dyn Io>>,
    timeout: Duration,
}

struct Reply {
    code: u16,
    lines: Vec<String>,
}

async fn read_reply_from<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R, timeout: Duration) -> Result<Reply, ImapError> {
    let mut lines = Vec::new();
    loop {
        let mut line = Vec::new();
        let fut = async {
            let mut limited = (&mut *r).take(MAX_REPLY_LINE as u64 + 1);
            limited.read_until(b'\n', &mut line).await
        };
        match tokio::time::timeout(timeout, fut).await {
            Ok(Ok(n)) if n > 0 && line.ends_with(b"\n") && line.len() <= MAX_REPLY_LINE => {}
            _ => return Err(ImapError::Network),
        }
        let text = String::from_utf8_lossy(&line).trim_end().to_string();
        if text.len() < 3 || !text.as_bytes()[..3].iter().all(u8::is_ascii_digit) {
            return Err(ImapError::Protocol("malformed SMTP reply"));
        }
        let code: u16 = text[..3].parse().map_err(|_| ImapError::Protocol("malformed SMTP reply"))?;
        let more = text.as_bytes().get(3) == Some(&b'-');
        lines.push(text.get(4..).unwrap_or_default().to_string());
        if lines.len() > MAX_REPLY_LINES {
            return Err(ImapError::Protocol("SMTP reply too long"));
        }
        if !more {
            return Ok(Reply { code, lines });
        }
    }
}

impl Conn {
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

    async fn reply(&mut self) -> Result<Reply, ImapError> {
        read_reply_from(&mut self.io, self.timeout).await
    }

    async fn cmd(&mut self, op: SmtpOp<'_>) -> Result<Reply, ImapError> {
        if !SMTP_VERBS.contains(&op.verb()) {
            return Err(ImapError::Protocol("command not allowlisted"));
        }
        let line = op.render()?;
        self.write(line.as_bytes()).await?;
        self.reply().await
    }

    async fn ehlo(&mut self) -> Result<Vec<String>, ImapError> {
        let r = self.cmd(SmtpOp::Ehlo).await?;
        if r.code != 250 {
            return Err(ImapError::Protocol("EHLO refused"));
        }
        Ok(r.lines.iter().map(|l| l.to_ascii_uppercase()).collect())
    }
}

fn has_ext(ehlo: &[String], name: &str) -> bool {
    ehlo.iter().any(|l| l.split_whitespace().next() == Some(name))
}

fn auth_mechs(ehlo: &[String]) -> Vec<String> {
    ehlo.iter()
        .filter_map(|l| {
            l.strip_prefix("AUTH").map(|r| r.trim_start_matches('=').split_whitespace().map(str::to_string))
        })
        .flatten()
        .collect()
}

/// Connects, establishes TLS (STARTTLS required when configured; no downgrade) and authenticates.
async fn open(
    connector: &ImapConnector,
    ep: &ServerEndpoint,
    creds: &Credentials,
    timeout: Duration,
) -> Result<Conn, ImapError> {
    let tcp = connector.tcp(ep, timeout).await?;
    let mut conn = if connector.is_plaintext() {
        let mut c = Conn { io: BufReader::new(Box::new(tcp)), timeout };
        greeting(&mut c).await?;
        c
    } else {
        match ep.tls {
            TlsMode::Implicit => {
                let io = connector.tls(tcp, ep, timeout).await?;
                let mut c = Conn { io: BufReader::new(io), timeout };
                greeting(&mut c).await?;
                c
            }
            TlsMode::StartTls => {
                let mut r = BufReader::new(tcp);
                let g = read_reply_from(&mut r, timeout).await?;
                if g.code != 220 {
                    return Err(ImapError::Network);
                }
                send_plain(&mut r, SmtpOp::Ehlo, timeout).await?;
                let e = read_reply_from(&mut r, timeout).await?;
                let lines: Vec<String> = e.lines.iter().map(|l| l.to_ascii_uppercase()).collect();
                if e.code != 250 || !has_ext(&lines, "STARTTLS") {
                    return Err(ImapError::Tls);
                }
                send_plain(&mut r, SmtpOp::StartTls, timeout).await?;
                if read_reply_from(&mut r, timeout).await?.code != 220 || !r.buffer().is_empty() {
                    return Err(ImapError::Tls);
                }
                let io = connector.tls(r.into_inner(), ep, timeout).await?;
                Conn { io: BufReader::new(io), timeout }
            }
        }
    };
    // Extensions are read fresh after TLS; anything seen before it is discarded.
    let ehlo = conn.ehlo().await?;
    let mechs = auth_mechs(&ehlo);
    let r = if mechs.iter().any(|m| m == "PLAIN") {
        conn.cmd(SmtpOp::AuthPlain { username: &creds.username, password: &creds.password }).await?
    } else if mechs.iter().any(|m| m == "LOGIN") {
        let r = conn.cmd(SmtpOp::AuthLogin).await?;
        if r.code != 334 {
            return Err(auth_error(r.code));
        }
        let r = conn.cmd(SmtpOp::LoginLine(&creds.username)).await?;
        if r.code != 334 {
            return Err(auth_error(r.code));
        }
        conn.cmd(SmtpOp::LoginLine(&creds.password)).await?
    } else {
        return Err(ImapError::Capability("AUTH PLAIN or LOGIN"));
    };
    if r.code != 235 {
        return Err(auth_error(r.code));
    }
    Ok(conn)
}

/// Writes a command on the pre-TLS stream (STARTTLS negotiation only; never credentials).
async fn send_plain(
    r: &mut BufReader<tokio::net::TcpStream>,
    op: SmtpOp<'_>,
    timeout: Duration,
) -> Result<(), ImapError> {
    let line = op.render()?;
    tokio::time::timeout(timeout, r.get_mut().write_all(line.as_bytes()))
        .await
        .map_err(|_| ImapError::Network)?
        .map_err(|_| ImapError::Network)
}

async fn greeting(c: &mut Conn) -> Result<(), ImapError> {
    let g = c.reply().await?;
    if g.code != 220 {
        return Err(ImapError::Network);
    }
    Ok(())
}

fn auth_error(code: u16) -> ImapError {
    // 4xx is temporary server trouble, not a credential problem.
    if (400..500).contains(&code) { ImapError::Network } else { ImapError::Auth }
}

/// Logs in and quits (connect verification and `accounts check`).
pub async fn verify_login(
    connector: &ImapConnector,
    endpoint: &ServerEndpoint,
    creds: &Credentials,
    deadline: Instant,
) -> Result<(), SmtpError> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    let fut = async {
        let mut c = open(connector, endpoint, creds, timeout).await?;
        let _ = c.cmd(SmtpOp::Quit).await;
        Ok(())
    };
    match tokio::time::timeout_at(deadline.into(), fut).await {
        Ok(r) => r.map_err(SmtpError::before),
        Err(_) => Err(SmtpError::before(ImapError::Network)),
    }
}

/// CRLF-normalizes (bare CR and bare LF both become CRLF, so no line ending can be smuggled past the server's
/// parser), dot-stuffs every line and ends with CRLF.
fn data_payload(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + bytes.len() / 50 + 8);
    let mut at_line_start = true;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\r' || b == b'\n' {
            out.extend_from_slice(b"\r\n");
            i += if b == b'\r' && bytes.get(i + 1) == Some(&b'\n') { 2 } else { 1 };
            at_line_start = true;
            continue;
        }
        if at_line_start && b == b'.' {
            out.push(b'.');
        }
        out.push(b);
        at_line_start = false;
        i += 1;
    }
    if !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Submits `bytes` to `rcpts` with envelope sender `from`. Errors before the `DATA` terminator are definitive
/// (`data_terminator_sent == false`); a lost connection or timeout after it is [`ImapError::OutcomeUnknown`].
pub async fn submit(
    connector: &ImapConnector,
    endpoint: &ServerEndpoint,
    creds: &Credentials,
    from: &str,
    rcpts: &[String],
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), SmtpError> {
    if rcpts.is_empty() {
        return Err(SmtpError::before(ImapError::Protocol("no recipients")));
    }
    let terminator_sent = AtomicBool::new(false);
    let timeout = deadline.saturating_duration_since(Instant::now());
    let fut = async {
        let refused = |code: u16| SmtpError {
            kind: ImapError::Protocol("refused by the SMTP server"),
            data_terminator_sent: false,
            code: Some(code),
        };
        let mut c = open(connector, endpoint, creds, timeout).await.map_err(SmtpError::before)?;
        let r = c.cmd(SmtpOp::MailFrom(from)).await.map_err(SmtpError::before)?;
        if r.code != 250 {
            return Err(refused(r.code));
        }
        for rcpt in rcpts {
            let r = c.cmd(SmtpOp::RcptTo(rcpt)).await.map_err(SmtpError::before)?;
            if r.code != 250 && r.code != 251 {
                let _ = c.cmd(SmtpOp::Rset).await;
                return Err(refused(r.code));
            }
        }
        let r = c.cmd(SmtpOp::Data).await.map_err(SmtpError::before)?;
        if r.code != 354 {
            return Err(refused(r.code));
        }
        let mut payload = data_payload(bytes);
        payload.extend_from_slice(b".\r\n");
        // From here on a write may have reached the server.
        terminator_sent.store(true, Ordering::SeqCst);
        let unknown = |_| SmtpError { kind: ImapError::OutcomeUnknown, data_terminator_sent: true, code: None };
        c.write(&payload).await.map_err(unknown)?;
        let r = c.reply().await.map_err(unknown)?;
        if r.code != 250 {
            return Err(SmtpError {
                kind: ImapError::Protocol("message refused by the SMTP server"),
                data_terminator_sent: true,
                code: Some(r.code),
            });
        }
        let _ = c.cmd(SmtpOp::Quit).await;
        Ok(())
    };
    match tokio::time::timeout_at(deadline.into(), fut).await {
        Ok(r) => r,
        Err(_) if terminator_sent.load(Ordering::SeqCst) => {
            Err(SmtpError { kind: ImapError::OutcomeUnknown, data_terminator_sent: true, code: None })
        }
        Err(_) => Err(SmtpError::before(ImapError::Network)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_stuffing_and_line_endings() {
        assert_eq!(data_payload(b"a\n.b\r\n..c"), b"a\r\n..b\r\n...c\r\n");
        assert_eq!(data_payload(b".\r\n"), b"..\r\n");
        // Bare CR is a line ending too: "\r.\r" cannot smuggle an end-of-data marker.
        assert_eq!(data_payload(b"a\r.\rMAIL FROM:<x@y.z>\r\n"), b"a\r\n..\r\nMAIL FROM:<x@y.z>\r\n");
        assert_eq!(data_payload(b"a\n\n.\n"), b"a\r\n\r\n..\r\n");
        let ehlo = vec!["LOCALHOST".to_string(), "AUTH=LOGIN PLAIN".into(), "STARTTLS".into()];
        assert_eq!(auth_mechs(&ehlo), vec!["LOGIN", "PLAIN"]);
        assert!(has_ext(&ehlo, "STARTTLS"));
    }
}
