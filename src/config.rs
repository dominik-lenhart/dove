//! Service configuration (spec 8.4). Non-secret settings live in one TOML file; secrets only as file paths.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;

use crate::secrets;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Public HTTPS base URL, for example `https://dove.example.com`.
    pub public_url: String,
    /// Loopback listen address. Non-loopback addresses are refused.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Directory owned by the service user (`0700`) holding the state store and index.
    pub data_dir: PathBuf,
    /// Browser origins allowed to call the MCP endpoint. Empty by default (spec 6.2).
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Instance gate for `send_draft` (spec 6.3). Deployment-owner configuration only.
    #[serde(default)]
    pub allow_send: bool,
    pub admin: AdminConfig,
    /// Google OAuth client for Gmail mailboxes. Optional: an instance with only IMAP mailboxes needs none.
    #[serde(default)]
    pub google: Option<GoogleConfig>,
    pub secrets: SecretPaths,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub notifier: NotifierConfig,
    #[serde(default)]
    pub index: IndexConfig,
    /// Downstream OAuth for MCP hosts and invitation redemption (spec 5.6).
    #[serde(default)]
    pub oauth: OAuthConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OAuthConfig {
    pub access_token_ttl_secs: i64,
    pub refresh_token_ttl_secs: i64,
    pub code_ttl_secs: i64,
    /// Upper bound on dynamically registered applications (spec 5.6: bounded registration).
    pub max_dynamic_clients: usize,
    /// Per source IP.
    pub registrations_per_hour: u32,
    /// Per source IP, for `/connect/redeem` and invitation checks on the approval page.
    pub redeem_per_minute: u32,
    /// Per source IP, for the token, revocation and authorize endpoints.
    pub token_requests_per_minute: u32,
    /// Pre-registered applications (alternative to dynamic registration).
    pub clients: Vec<PreregisteredClient>,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            access_token_ttl_secs: 3600,
            refresh_token_ttl_secs: 30 * 86_400,
            code_ttl_secs: 60,
            max_dynamic_clients: 200,
            registrations_per_hour: 20,
            redeem_per_minute: 10,
            token_requests_per_minute: 60,
            clients: Vec::new(),
        }
    }
}

/// An application registered by the operator. Confidential when `secret_file` is set (client_secret_basic or
/// client_secret_post), otherwise public with PKCE only. Registration grants no mailbox access by itself.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreregisteredClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub secret_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    #[serde(default = "default_socket")]
    pub socket_path: PathBuf,
    /// The only non-root uid allowed to use the admin socket.
    pub operator_uid: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoogleConfig {
    pub client_id: String,
    pub client_secret_file: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretPaths {
    pub kek_file: PathBuf,
    pub pepper_file: PathBuf,
    pub index_key_file: PathBuf,
    /// Shared secret the reverse proxy sends in `X-Dove-Proxy-Auth`. When set, `X-Forwarded-For` is trusted only on
    /// loopback requests that carry it; any other local process is seen as the loopback address (spec 6.6).
    #[serde(default)]
    pub proxy_secret_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub body_bytes: usize,
    /// Per-client token bucket: sustained requests per minute and burst.
    pub client_requests_per_minute: u32,
    pub client_burst: u32,
    pub client_sends_per_hour: u32,
    pub upstream_total_inflight: usize,
    pub upstream_per_mailbox: usize,
    pub upstream_search_mailboxes: usize,
    pub upstream_request_timeout_secs: u64,
    pub tool_call_timeout_secs: u64,
    /// Largest attachment `get_attachment` returns (decoded bytes).
    pub attachment_bytes: usize,
    /// Largest total of attachments in one draft (decoded bytes, at most 16 MiB). Authenticated callers with `draft`
    /// get a request body limit large enough for this much inline base64 ([`Limits::draft_body_bytes`]).
    pub draft_attachment_bytes: usize,
}

/// Upper bound for `limits.draft_attachment_bytes`: a draft must stay below the 25 MiB MIME parse limit once
/// base64 encoded.
pub const MAX_DRAFT_ATTACHMENT_BYTES: usize = 16 * 1024 * 1024;

impl Limits {
    /// Request body limit for authenticated callers with `draft` on some mailbox: room for
    /// `draft_attachment_bytes` as base64 plus 2 MiB for the body text and JSON. Everyone else gets `body_bytes`.
    pub fn draft_body_bytes(&self) -> usize {
        self.body_bytes.max(self.draft_attachment_bytes.div_ceil(3) * 4 + 2 * 1024 * 1024)
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            body_bytes: 1024 * 1024,
            client_requests_per_minute: 120,
            client_burst: 40,
            client_sends_per_hour: 20,
            upstream_total_inflight: 16,
            upstream_per_mailbox: 4,
            upstream_search_mailboxes: 8,
            upstream_request_timeout_secs: 10,
            tool_call_timeout_secs: 30,
            attachment_bytes: 10 * 1024 * 1024,
            draft_attachment_bytes: 10 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuditConfig {
    pub retention_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self { retention_days: 180 }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NotifierConfig {
    /// HTTP webhook (for example ntfy). Messages carry no mail content. Must be HTTPS.
    pub webhook_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct IndexConfig {
    pub poll_interval_secs: u64,
    pub sql_heap_limit_mib: i64,
    pub page_cache_kib: i64,
    pub reader_connections: usize,
    pub body_jobs: usize,
    /// Largest raw message whose body is indexed; larger ones are indexed from metadata only. 22 MiB keeps one
    /// body job within the 32 MiB budget of spec 8.1a (the download is about 4/3 of the message).
    pub max_message_bytes: usize,
    pub max_body_chars: usize,
    /// Message ids per messages.list page during backfill (Gmail allows up to 500).
    pub list_page_size: u32,
    /// IMAP IDLE push on INBOX for index-enabled IMAP mailboxes (one extra connection each, `index::imap_idle`).
    pub imap_idle: bool,
    /// Seconds after which IDLE is ended and re-issued (clamped to 1..=1500, RFC 2177 asks for under 29 min).
    pub idle_renew_secs: u64,
    /// Wall-clock limit of one IMAP sync step (a scan of all folders, or one fetch batch). Work finished before it is
    /// kept; the job then fails and retries at the next poll.
    pub imap_step_timeout_secs: u64,
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: 60,
            sql_heap_limit_mib: 96,
            page_cache_kib: 8 * 1024,
            reader_connections: 3,
            body_jobs: 2,
            max_message_bytes: 22 * 1024 * 1024,
            max_body_chars: 200_000,
            list_page_size: 500,
            imap_idle: true,
            idle_renew_secs: 1500,
            imap_step_timeout_secs: 300,
        }
    }
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:8787".parse().expect("valid")
}

fn default_socket() -> PathBuf {
    PathBuf::from(DEFAULT_ADMIN_SOCKET)
}

pub const DEFAULT_ADMIN_SOCKET: &str = "/run/dove/admin.sock";

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("cannot read config {}", path.display()))?;
        let cfg: Config = toml::from_str(&text).context("invalid config file")?;
        Ok(cfg)
    }

    /// Startup checks that do not need the secrets loaded (spec 8.4, AC15).
    pub fn validate(&self) -> anyhow::Result<()> {
        let url = url::Url::parse(&self.public_url).context("public_url is not a URL")?;
        if url.scheme() != "https" {
            bail!("public_url must use https");
        }
        if url.host_str().is_none() || url.path() != "/" || url.query().is_some() {
            bail!("public_url must be an origin like https://dove.example.com");
        }
        if !self.listen.ip().is_loopback() {
            bail!("listen must be a loopback address; put a TLS reverse proxy in front (spec 6.6)");
        }
        for o in &self.allowed_origins {
            let u = url::Url::parse(o).with_context(|| format!("allowed origin {o} is not a URL"))?;
            if u.origin().ascii_serialization() != *o {
                bail!("allowed origin {o} must be a bare origin");
            }
        }
        if let Some(w) = &self.notifier.webhook_url
            && !w.starts_with("https://")
        {
            bail!("notifier.webhook_url must use https");
        }
        if let Some(g) = &self.google {
            if g.client_id.trim().is_empty() {
                bail!("google.client_id is empty");
            }
            secrets::check_secret_file_mode(&g.client_secret_file)?;
        }
        self.validate_oauth()?;
        if self.limits.draft_attachment_bytes > MAX_DRAFT_ATTACHMENT_BYTES {
            bail!("limits.draft_attachment_bytes must be at most {MAX_DRAFT_ATTACHMENT_BYTES}");
        }
        for p in [&self.secrets.kek_file, &self.secrets.pepper_file, &self.secrets.index_key_file] {
            secrets::check_secret_file_mode(p)?;
        }
        if let Some(p) = &self.secrets.proxy_secret_file {
            secrets::check_secret_file_mode(p)?;
        }
        Ok(())
    }

    /// Host (with port when not default) that requests must carry (spec 6.2, DNS rebinding).
    pub fn public_host(&self) -> String {
        let url = url::Url::parse(&self.public_url).expect("validated");
        match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_string(),
        }
    }

    fn validate_oauth(&self) -> anyhow::Result<()> {
        let o = &self.oauth;
        if o.access_token_ttl_secs < 60 || o.refresh_token_ttl_secs < o.access_token_ttl_secs {
            bail!("oauth: access_token_ttl_secs must be >= 60 and refresh_token_ttl_secs >= access_token_ttl_secs");
        }
        if !(10..=600).contains(&o.code_ttl_secs) {
            bail!("oauth.code_ttl_secs must be between 10 and 600");
        }
        let mut seen = std::collections::HashSet::new();
        for c in &o.clients {
            let id_ok = (3..=64).contains(&c.client_id.len())
                && c.client_id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
            if !id_ok || c.client_id.starts_with("dcr-") {
                bail!("oauth client id '{}' must be 3-64 of [A-Za-z0-9._-] and not start with dcr-", c.client_id);
            }
            if !seen.insert(c.client_id.clone()) {
                bail!("oauth client id '{}' is listed twice", c.client_id);
            }
            if c.redirect_uris.is_empty() {
                bail!("oauth client '{}' needs at least one redirect URI", c.client_id);
            }
            for u in &c.redirect_uris {
                crate::oauth::validate_redirect_uri(u)
                    .map_err(|e| anyhow::anyhow!("oauth client '{}': {e}", c.client_id))?;
            }
            if let Some(f) = &c.secret_file {
                secrets::check_secret_file_mode(f)?;
            }
        }
        Ok(())
    }

    /// The Google OAuth client id, or an error naming the missing `[google]` section (Gmail connect, doctor).
    pub fn google_client_id(&self) -> anyhow::Result<&str> {
        match &self.google {
            Some(g) => Ok(&g.client_id),
            None => bail!(
                "Gmail is not configured: add a [google] section with client_id and client_secret_file to the \
                 config file (IMAP mailboxes do not need it)"
            ),
        }
    }

    pub fn public_base(&self) -> String {
        self.public_url.trim_end_matches('/').to_string()
    }

    pub fn state_db_path(&self) -> PathBuf {
        self.data_dir.join("state.db")
    }

    pub fn index_db_path(&self) -> PathBuf {
        self.data_dir.join("index.db")
    }
}

/// Example configuration, printed by `dove config example`. No real hostnames, ids or secrets.
pub const EXAMPLE: &str = r#"# Dove service configuration. Secrets are referenced by path only.
public_url = "https://dove.example.com"
listen = "127.0.0.1:8787"
data_dir = "/var/lib/dove"
allowed_origins = []
allow_send = false

[admin]
socket_path = "/run/dove/admin.sock"
operator_uid = 1000

[google]
client_id = "000000000000-example.apps.googleusercontent.com"
client_secret_file = "/run/credentials/dove.service/google_client_secret"

[secrets]
kek_file = "/run/credentials/dove.service/kek"
pepper_file = "/run/credentials/dove.service/pepper"
index_key_file = "/run/credentials/dove.service/index_key"
# Shared with the reverse proxy, which sends it as X-Dove-Proxy-Auth (docs/deployment.md). Without it, any local
# process can forge X-Forwarded-For and bypass allow_ip lists and per-IP limits.
proxy_secret_file = "/run/credentials/dove.service/proxy_secret"

[audit]
retention_days = 180

[notifier]
# webhook_url = "https://ntfy.example.com/dove-alerts"

[oauth]
# Downstream OAuth for MCP hosts (ChatGPT, Claude). Defaults shown.
# access_token_ttl_secs = 3600
# refresh_token_ttl_secs = 2592000
# Optional pre-registered application instead of dynamic registration:
# [[oauth.clients]]
# client_id = "claude-web"
# client_name = "Claude"
# redirect_uris = ["https://claude.ai/api/mcp/auth_callback"]
# secret_file = "/run/credentials/dove.service/oauth_claude_secret"
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    pub(crate) fn write_secret(dir: &Path, name: &str, content: &str, mode: u32) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    fn config(dir: &Path, public_url: &str, kek_mode: u32) -> Config {
        let line = secrets::generate_key_line(1);
        let text = EXAMPLE
            .replace("https://dove.example.com", public_url)
            .replace("/run/credentials/dove.service/kek", write_secret(dir, "kek", &line, kek_mode).to_str().unwrap())
            .replace(
                "/run/credentials/dove.service/pepper",
                write_secret(dir, "pepper", &line, 0o400).to_str().unwrap(),
            )
            .replace(
                "/run/credentials/dove.service/index_key",
                write_secret(dir, "index_key", &line, 0o400).to_str().unwrap(),
            )
            .replace(
                "/run/credentials/dove.service/google_client_secret",
                write_secret(dir, "gcs", "secret", 0o400).to_str().unwrap(),
            )
            .replace(
                "/run/credentials/dove.service/proxy_secret",
                write_secret(dir, "proxy_secret", &"p".repeat(64), 0o400).to_str().unwrap(),
            );
        toml::from_str(&text).unwrap()
    }

    #[test]
    fn example_config_validates_with_strict_secrets() {
        let dir = tempfile::tempdir().unwrap();
        config(dir.path(), "https://dove.example.com", 0o400).validate().unwrap();
    }

    #[test]
    fn startup_refusals() {
        let dir = tempfile::tempdir().unwrap();
        // AC15: HTTP public URL.
        assert!(config(dir.path(), "http://dove.example.com", 0o400).validate().is_err());
        // AC15: world-readable secret file.
        let dir2 = tempfile::tempdir().unwrap();
        assert!(config(dir2.path(), "https://dove.example.com", 0o644).validate().is_err());
        // AC15: missing KEK.
        let dir3 = tempfile::tempdir().unwrap();
        let cfg = config(dir3.path(), "https://dove.example.com", 0o400);
        std::fs::remove_file(&cfg.secrets.kek_file).unwrap();
        assert!(cfg.validate().is_err());
        // Non-loopback listen.
        let dir4 = tempfile::tempdir().unwrap();
        let mut cfg = config(dir4.path(), "https://dove.example.com", 0o400);
        cfg.listen = "0.0.0.0:8787".parse().unwrap();
        assert!(cfg.validate().is_err());
        // Draft attachments must stay below the MIME parse limit once encoded.
        let dir5 = tempfile::tempdir().unwrap();
        let mut cfg = config(dir5.path(), "https://dove.example.com", 0o400);
        cfg.limits.draft_attachment_bytes = MAX_DRAFT_ATTACHMENT_BYTES;
        cfg.validate().unwrap();
        assert!(cfg.limits.draft_body_bytes() > MAX_DRAFT_ATTACHMENT_BYTES / 3 * 4);
        cfg.limits.draft_attachment_bytes = MAX_DRAFT_ATTACHMENT_BYTES + 1;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn google_section_is_optional() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config(dir.path(), "https://dove.example.com", 0o400);
        let text = EXAMPLE.split("[google]").next().unwrap().to_string()
            + "[secrets]"
            + EXAMPLE.split("[secrets]").nth(1).unwrap();
        let parsed: Config = toml::from_str(&text).unwrap();
        assert!(parsed.google.is_none());
        cfg.google = None;
        cfg.validate().unwrap();
        assert!(cfg.google_client_id().unwrap_err().to_string().contains("[google]"));
    }
}
