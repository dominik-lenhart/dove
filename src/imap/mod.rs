//! IMAP/SMTP provider: the only IMAP and SMTP wire code (design `docs/superpowers/specs/2026-11-12-imap-smtp-design.md`).
//!
//! [`ops`] is the typed command allowlist and the only place that builds command strings. [`session`] speaks IMAP
//! over verified TLS (rustls with the platform verifier, the stack reqwest uses), [`pool`] keeps a few logged-in
//! sessions per account, [`smtp`] submits mail. Plaintext exists only through
//! [`ImapConnector::plaintext_for_tests`], which is compiled only with the `testing` feature.

pub mod ids;
pub(crate) mod ops;
pub mod pool;
pub mod session;
pub mod smtp;
pub mod utf7;

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::error::{ErrorCode, ToolError};

pub use ids::ImapMsgId;
pub use ops::AppendFlag;
pub use pool::ImapPool;
pub use session::{
    AppendTarget, AppendUid, Changes, FetchedMeta, FolderInfo, FolderStatus, ImapSession, OwnDraftUid, Special,
};
pub use smtp::SmtpError;

/// How TLS is established with a server. There is no plaintext mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// TLS from the first byte (IMAP 993, SMTP 465).
    Implicit,
    /// Plain greeting, then `STARTTLS`; refusing or failing the upgrade aborts the connection (no downgrade).
    #[serde(rename = "starttls")]
    StartTls,
}

impl TlsMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "implicit" | "tls" | "ssl" => Some(TlsMode::Implicit),
            "starttls" => Some(TlsMode::StartTls),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerEndpoint {
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
}

impl ServerEndpoint {
    /// Host names are restricted to DNS names and IP literals; nothing that could smuggle a path or a port.
    pub fn validate(&self) -> Result<(), String> {
        let h = self.host.trim();
        let ok = (1..=253).contains(&h.len())
            && h.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'));
        if !ok || self.port == 0 {
            return Err(format!("invalid server address '{}:{}'", h.chars().take(80).collect::<String>(), self.port));
        }
        Ok(())
    }
}

/// Login credentials. The password is zeroized on drop and never printed.
#[derive(Clone)]
pub struct Credentials {
    pub username: String,
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials").field("username", &self.username).field("password", &"[redacted]").finish()
    }
}

/// IMAP/SMTP failures. Messages are fixed strings: server response text (which can echo input) is never included.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImapError {
    /// The server rejected the credentials (`NO [AUTHENTICATIONFAILED]`, SMTP 535).
    #[error("authentication failed")]
    Auth,
    /// TLS handshake or certificate verification failed, or STARTTLS was refused.
    #[error("TLS failed")]
    Tls,
    /// Connection refused, lost or timed out.
    #[error("network error")]
    Network,
    #[error("protocol error: {0}")]
    Protocol(&'static str),
    /// No such folder or message (or a stale UIDVALIDITY).
    #[error("not found")]
    Missing,
    /// A required server capability is missing.
    #[error("missing server capability {0}")]
    Capability(&'static str),
    /// The command certainly never reached the server (safe to retry).
    #[error("not dispatched")]
    NotDispatched,
    /// A write may or may not have been applied (lost connection after the data was sent).
    #[error("outcome unknown")]
    OutcomeUnknown,
}

impl From<ImapError> for ToolError {
    /// `Auth` maps to `account_unavailable`; the caller marks the account `reauth_required` (see `imap::account`).
    fn from(e: ImapError) -> Self {
        match e {
            ImapError::Auth => ToolError::unavailable(),
            ImapError::Missing => ToolError::not_found(),
            ImapError::Network | ImapError::NotDispatched => ToolError::upstream("the mail server is unreachable"),
            ImapError::Tls => ToolError::upstream("the TLS connection to the mail server failed"),
            ImapError::Protocol(_) => ToolError::upstream("unexpected mail server response"),
            ImapError::Capability(_) => ToolError::upstream("the mail server lacks a required capability"),
            ImapError::OutcomeUnknown => {
                ToolError::new(ErrorCode::OutcomeUnknown, "the mail server write may or may not have been applied")
            }
        }
    }
}

/// Byte stream of one connection (TLS, or plaintext in tests).
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

#[derive(Clone)]
enum Mode {
    Verified(Arc<OnceLock<Result<Arc<rustls::ClientConfig>, String>>>),
    #[cfg(any(test, feature = "testing"))]
    Plaintext,
}

/// Opens connections to IMAP and SMTP servers. Release builds can only build the verifying connector.
#[derive(Clone)]
pub struct ImapConnector {
    mode: Mode,
}

impl Default for ImapConnector {
    fn default() -> Self {
        Self::verified()
    }
}

impl ImapConnector {
    /// TLS verified against the platform roots. No option disables verification.
    pub fn verified() -> Self {
        Self { mode: Mode::Verified(Arc::new(OnceLock::new())) }
    }

    /// Plain TCP without TLS, for the fake server in tests. STARTTLS is skipped.
    #[cfg(any(test, feature = "testing"))]
    pub fn plaintext_for_tests() -> Self {
        Self { mode: Mode::Plaintext }
    }

    pub(crate) fn is_plaintext(&self) -> bool {
        match self.mode {
            Mode::Verified(_) => false,
            #[cfg(any(test, feature = "testing"))]
            Mode::Plaintext => true,
        }
    }

    fn tls_config(&self) -> Result<Arc<rustls::ClientConfig>, ImapError> {
        #[allow(irrefutable_let_patterns)] // refutable only with the test-only plaintext mode
        let Mode::Verified(cell) = &self.mode else { return Err(ImapError::Tls) };
        cell.get_or_init(|| {
            use rustls_platform_verifier::BuilderVerifierExt;
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .and_then(|b| b.with_platform_verifier())
                .map(|b| Arc::new(b.with_no_client_auth()))
                .map_err(|e| e.to_string())
        })
        .clone()
        .map_err(|e| {
            tracing::error!(error = %e, "TLS configuration failed");
            ImapError::Tls
        })
    }

    pub(crate) async fn tcp(&self, ep: &ServerEndpoint, timeout: Duration) -> Result<TcpStream, ImapError> {
        ep.validate().map_err(|_| ImapError::Protocol("invalid server address"))?;
        let host = ep.host.trim().trim_start_matches('[').trim_end_matches(']').to_string();
        match tokio::time::timeout(timeout, TcpStream::connect((host.as_str(), ep.port))).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                Ok(s)
            }
            _ => Err(ImapError::NotDispatched),
        }
    }

    /// TLS handshake with certificate and host name verification.
    pub(crate) async fn tls(
        &self,
        tcp: TcpStream,
        ep: &ServerEndpoint,
        timeout: Duration,
    ) -> Result<Box<dyn Io>, ImapError> {
        let cfg = self.tls_config()?;
        let host = ep.host.trim().trim_start_matches('[').trim_end_matches(']').to_string();
        let name = rustls::pki_types::ServerName::try_from(host).map_err(|_| ImapError::Tls)?;
        let connector = tokio_rustls::TlsConnector::from(cfg);
        match tokio::time::timeout(timeout, connector.connect(name, tcp)).await {
            Ok(Ok(s)) => Ok(Box::new(s)),
            Ok(Err(_)) => Err(ImapError::Tls),
            Err(_) => Err(ImapError::Network),
        }
    }
}
