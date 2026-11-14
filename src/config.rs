//! Service configuration (spec 8.4). Non-secret settings live in one TOML file; secrets only as file paths.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;

use crate::secrets;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// `server` (default): behind a TLS reverse proxy for remote MCP hosts. `local`: on the desktop user's own
    /// computer for MCP hosts on the same machine (PLAN A58).
    #[serde(default)]
    pub mode: Mode,
    /// Public HTTPS base URL, for example `https://dove.example.com`. In local mode exactly `http://<listen>`, for
    /// example `http://127.0.0.1:8787` (an IP literal, never `localhost`).
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
    /// Defaults for new connections (PLAN A66).
    #[serde(default)]
    pub clients: ClientsConfig,
    /// Agent requests: scheduled sends the operator approves (design 2026-11-14 section 4).
    #[serde(default)]
    pub requests: RequestsConfig,
    /// The admin web UI under `/admin` (design 2026-11-14 section 5, PLAN A74). Off by default.
    #[serde(default)]
    pub admin_ui: AdminUiConfig,
}

/// `[admin_ui]`: the owner's web UI on the same listener, reached over the tailnet only and signed in with a passkey.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AdminUiConfig {
    /// Serve `/admin`. Off: every `/admin` request is 404 and `dove admin passkey add` refuses.
    pub enabled: bool,
    /// The exact browser origin of the UI, `https://<name>` or `https://<name>:<port>`, for example the node's
    /// tailnet name. Requests to `/admin` with another `Host` are 404; the host is the passkeys' RP ID, so changing
    /// it means enrolling the passkeys again.
    pub origin: Option<String>,
    /// Requests per minute per client address under `/admin`.
    pub requests_per_minute: u32,
    /// Failed passkey sign-ins and enrolments per hour per client address; after that, failures answer 429. A valid
    /// passkey always signs in (PLAN A74 (i)).
    pub login_failures_per_hour: u32,
}

impl Default for AdminUiConfig {
    fn default() -> Self {
        Self { enabled: false, origin: None, requests_per_minute: 120, login_failures_per_hour: 10 }
    }
}

impl AdminUiConfig {
    /// The validated origin (`None` when the UI is off).
    pub fn origin(&self) -> Option<&str> {
        if self.enabled { self.origin.as_deref() } else { None }
    }

    /// `host[:port]` that `/admin` requests must carry.
    pub fn host(&self) -> Option<String> {
        let url = url::Url::parse(self.origin()?).ok()?;
        let host = url.host_str()?;
        Some(match url.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.to_string(),
        })
    }

    /// The WebAuthn RP ID: the origin's host without the port.
    pub fn rp_id(&self) -> Option<String> {
        Some(url::Url::parse(self.origin()?).ok()?.host_str()?.to_string())
    }

    fn validate(&self, local: bool) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if local {
            bail!("admin_ui is not available in local mode (use the dove CLI; design 2026-11-14 section 2)");
        }
        let Some(origin) = &self.origin else {
            bail!(
                "admin_ui.origin is required when admin_ui.enabled = true (for example https://dove-host.tail1234.ts.net)"
            );
        };
        let url = url::Url::parse(origin).context("admin_ui.origin is not a URL")?;
        if url.scheme() != "https" || url.origin().ascii_serialization() != *origin {
            bail!(
                "admin_ui.origin must be a bare https origin like https://dove-host.tail1234.ts.net (no path, no slash)"
            );
        }
        // WebAuthn needs a registrable domain name as RP ID; an IP literal cannot hold passkeys.
        if !matches!(url.host(), Some(url::Host::Domain(_))) {
            bail!("admin_ui.origin must use a DNS name, not an IP address (passkeys are bound to a name)");
        }
        if self.requests_per_minute == 0 || self.login_failures_per_hour == 0 {
            bail!("admin_ui.requests_per_minute and admin_ui.login_failures_per_hour must be at least 1");
        }
        Ok(())
    }
}

/// `[requests]`: agents ask, the operator approves (`dove requests approve`), Dove sends the approved revision.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RequestsConfig {
    /// The request tools (`request_send`, `list_requests`, `cancel_request`) exist. Off: they are hidden and refused
    /// like `send_draft` without `allow_send`, and approved items are not sent.
    pub enabled: bool,
    /// An approved item that could not be sent within this many minutes after its time ends as `missed` and is never
    /// sent.
    pub late_grace_minutes: i64,
    /// A pending request expires after this many days without a decision.
    pub pending_days: i64,
    /// Closed requests (denied, cancelled, expired, done) are deleted this many days after they closed. Each client
    /// also keeps at most `requests::MAX_CLOSED_PER_CLIENT` of them; older ones go first.
    pub retention_days: i64,
}

impl Default for RequestsConfig {
    fn default() -> Self {
        Self { enabled: true, late_grace_minutes: 60, pending_days: 7, retention_days: 90 }
    }
}

impl RequestsConfig {
    pub fn grace_secs(&self) -> i64 {
        self.late_grace_minutes * 60
    }
}

/// Defaults for connections created from now on (`clients create`, `clients invite`, and through an invitation also
/// `/connect/redeem` and the OAuth approval page). Existing connections and open invitations keep their settings.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ClientsConfig {
    /// New connections hide secrets in overview results (PLAN A60) unless the operator passes `--no-redact-secrets`.
    pub redact_secrets_default: bool,
}

/// Deployment mode (PLAN A58).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Server,
    Local,
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
    /// Unix socket path. On Windows the name of the admin pipe (`\\.\pipe\dove-admin-<user SID>` by default).
    #[serde(default = "default_socket")]
    pub socket_path: PathBuf,
    /// The only non-root uid allowed to use the admin socket. Not used on Windows, where the admin pipe accepts only
    /// the user the service runs as.
    #[cfg_attr(windows, serde(default))]
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
    /// Failed bearer authentications on `/mcp` per source address (IPv6 by /64) and minute, also the burst. Once
    /// used up, further failures from that address get 429 instead of 401; valid tokens are always accepted, since
    /// MCP hosts share egress addresses.
    pub auth_failures_per_minute: u32,
    /// Messages a client may change per hour with update_messages and move_messages (each id counts once).
    pub client_organize_per_hour: u32,
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
    /// Open (pending or approved) requests per client.
    pub client_open_requests: u32,
    /// Items (drafts) in one send request.
    pub request_items: u32,
    /// Server-wide cap on scheduled sends per UTC day; an approval that would exceed it on any day is refused.
    pub scheduled_sends_per_day: u32,
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
            auth_failures_per_minute: 60,
            client_organize_per_hour: 500,
            upstream_total_inflight: 16,
            upstream_per_mailbox: 4,
            upstream_search_mailboxes: 8,
            upstream_request_timeout_secs: 10,
            tool_call_timeout_secs: 30,
            attachment_bytes: 10 * 1024 * 1024,
            draft_attachment_bytes: 10 * 1024 * 1024,
            client_open_requests: 20,
            request_items: 50,
            scheduled_sends_per_day: 200,
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
    /// Index the text of PDF, DOCX, ODT, plain-text and CSV attachments (found by `text` and `attachment_text`
    /// searches). The attachments are already in memory when the message is indexed, so this costs CPU and a
    /// short-lived copy of the attachment, no extra Gmail or IMAP traffic.
    pub attachment_text: bool,
    /// Largest decoded attachment that is opened for text extraction; larger ones are skipped and the message
    /// counts as incomplete for `attachment_text` queries. Bounded by `max_message_bytes` anyway.
    pub attachment_text_max_bytes: usize,
    /// Characters of attachment text indexed per message.
    pub attachment_text_max_chars: usize,
    /// Wall-clock budget of all attachment extraction for one message.
    pub attachment_text_timeout_secs: u64,
}

impl IndexConfig {
    /// Limits of ingest-time attachment text extraction.
    pub fn attachment_cfg(&self) -> crate::attachment_text::Cfg {
        crate::attachment_text::Cfg {
            enabled: self.attachment_text,
            max_attachment_bytes: self.attachment_text_max_bytes,
            max_chars: self.attachment_text_max_chars,
            budget: std::time::Duration::from_secs(self.attachment_text_timeout_secs.max(1)),
        }
    }
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
            attachment_text: true,
            attachment_text_max_bytes: 8 * 1024 * 1024,
            attachment_text_max_chars: 100_000,
            attachment_text_timeout_secs: 10,
        }
    }
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:8787".parse().expect("valid")
}

fn default_socket() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from(DEFAULT_ADMIN_SOCKET)
    }
    #[cfg(windows)]
    {
        PathBuf::from(crate::platform::paths::default_admin_pipe())
    }
}

/// The admin socket of a server-mode installation (systemd `RuntimeDirectory=dove`).
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
        match (self.mode, url.scheme()) {
            (Mode::Server, "https") => {}
            (Mode::Server, _) => bail!("public_url must use https"),
            (Mode::Local, "http") => self.check_local_http_url(&url)?,
            // HTTPS would mean a proxy in front, which local mode does not trust or expect (PLAN A58).
            (Mode::Local, _) => bail!("public_url must be http://{} in local mode (the listen address)", self.listen),
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
        if self.limits.client_organize_per_hour == 0 {
            bail!("limits.client_organize_per_hour must be at least 1 (remove organize from grants to turn it off)");
        }
        if self.limits.client_open_requests == 0 || !(1..=500).contains(&self.limits.request_items) {
            bail!("limits.client_open_requests must be at least 1 and limits.request_items between 1 and 500");
        }
        if !(1..=1440).contains(&self.requests.late_grace_minutes) || !(1..=30).contains(&self.requests.pending_days) {
            bail!("requests.late_grace_minutes must be between 1 and 1440 and requests.pending_days between 1 and 30");
        }
        self.admin_ui.validate(self.is_local())?;
        if !(1..=3650).contains(&self.requests.retention_days) {
            bail!("requests.retention_days must be between 1 and 3650");
        }
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

    /// Local mode serves exactly `http://<listen ip>:<listen port>`. The host must be the IP literal Dove binds, never a
    /// name: `localhost` resolves to `::1` first on Windows and macOS, where another local user could listen and
    /// receive tokens while Dove holds only `127.0.0.1` (PLAN A58). The Host check then accepts exactly that origin.
    fn check_local_http_url(&self, url: &url::Url) -> anyhow::Result<()> {
        let ip = match url.host() {
            Some(url::Host::Ipv4(ip)) => std::net::IpAddr::V4(ip),
            Some(url::Host::Ipv6(ip)) => std::net::IpAddr::V6(ip),
            _ => bail!("public_url must use the listen IP address, not a name, in local mode: http://{}", self.listen),
        };
        if ip != self.listen.ip() || url.port() != Some(self.listen.port()) {
            bail!("public_url must be exactly the listen address in local mode: http://{}", self.listen);
        }
        Ok(())
    }

    pub fn is_local(&self) -> bool {
        self.mode == Mode::Local
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

[clients]
# true: new connections (clients create, clients invite, and OAuth connections made from an invitation) hide
# passwords, keys and one-time codes in overview results unless created with --no-redact-secrets. Existing
# connections keep their setting (dove clients set-redaction).
redact_secrets_default = false

[requests]
# Agents may ask for a scheduled send of their own drafts (request_send); nothing is sent before the operator
# approves it with `dove requests approve`. Defaults shown.
# enabled = true
# late_grace_minutes = 60
# pending_days = 7
# retention_days = 90

[admin_ui]
# The owner's web UI under /admin (passkey sign-in). Reach it over the tailnet only, never through the public proxy
# (docs/deployment.md). Enrol a passkey with `sudo dove admin passkey add --name <label>`.
# enabled = false
# origin = "https://dove-host.tail1234.ts.net"
# requests_per_minute = 120
# login_failures_per_hour = 10

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

    /// Writes a secret file. `mode` applies on Unix; on Windows a mode with group/other bits grants Everyone read.
    pub(crate) fn write_secret(dir: &Path, name: &str, content: &str, mode: u32) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(windows)]
        {
            crate::platform::restrict_file(&p).unwrap();
            if mode & 0o077 != 0 {
                crate::platform::windows::tests::grant_everyone_read(&p);
            }
        }
        p
    }

    fn config(dir: &Path, public_url: &str, kek_mode: u32) -> Config {
        let line = secrets::generate_key_line(1);
        let text = EXAMPLE
            .replace("https://dove.example.com", public_url)
            .replace(
                "/run/credentials/dove.service/kek",
                &crate::testing::toml_path(&write_secret(dir, "kek", &line, kek_mode)),
            )
            .replace(
                "/run/credentials/dove.service/pepper",
                &crate::testing::toml_path(&write_secret(dir, "pepper", &line, 0o400)),
            )
            .replace(
                "/run/credentials/dove.service/index_key",
                &crate::testing::toml_path(&write_secret(dir, "index_key", &line, 0o400)),
            )
            .replace(
                "/run/credentials/dove.service/google_client_secret",
                &crate::testing::toml_path(&write_secret(dir, "gcs", "secret", 0o400)),
            )
            .replace(
                "/run/credentials/dove.service/proxy_secret",
                &crate::testing::toml_path(&write_secret(dir, "proxy_secret", &"p".repeat(64), 0o400)),
            );
        toml::from_str(&text).unwrap()
    }

    /// Test configs put paths into TOML strings; Windows paths (`C:\Users\RUNNER~1\...`) carry backslashes that TOML
    /// would read as escapes. A Unix directory name with a backslash shows the same on every platform.
    #[test]
    fn test_configs_survive_backslashes_in_paths() {
        let dir = tempfile::tempdir().unwrap();
        let odd = dir.path().join(if cfg!(windows) { "Users" } else { r"C:\Users\RUNNER~1" });
        std::fs::create_dir_all(&odd).unwrap();
        let cfg = crate::testing::test_config(&odd, 0);
        assert_eq!(cfg.data_dir, odd.join("data"));
        assert_eq!(cfg.secrets.kek_file, odd.join("secrets").join("kek"));
        let cfg = config(&odd, "https://dove.example.com", 0o400);
        assert_eq!(cfg.secrets.pepper_file, odd.join("pepper"));
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

    /// A local-mode config with its own secrets directory (kept alive by the returned guard).
    fn local(public_url: &str) -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config(dir.path(), public_url, 0o400);
        cfg.mode = Mode::Local;
        (dir, cfg)
    }

    fn server(public_url: &str) -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path(), public_url, 0o400);
        (dir, cfg)
    }

    #[test]
    fn mode_defaults_to_server_and_parses_local() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(config(dir.path(), "https://dove.example.com", 0o400).mode, Mode::Server);
        let parsed: Config = toml::from_str(&format!("mode = \"local\"\n{EXAMPLE}")).unwrap();
        assert_eq!(parsed.mode, Mode::Local);
        assert!(toml::from_str::<Config>(&format!("mode = \"desktop\"\n{EXAMPLE}")).is_err());
    }

    /// Local mode accepts exactly `http://<listen>`: an IP literal, the listen IP and port, never HTTPS. Server mode
    /// never accepts plain HTTP. Each refusal below is caught by exactly one rule.
    #[test]
    fn local_mode_allows_only_the_loopback_http_origin() {
        for ok in ["http://127.0.0.1:8787", "http://127.0.0.1:8787/"] {
            local(ok).1.validate().unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        // An IPv6 loopback listener with its own literal.
        let (_d, mut cfg) = local("http://[::1]:8787");
        cfg.listen = "[::1]:8787".parse().unwrap();
        cfg.validate().unwrap();
        // Server mode never accepts plain HTTP, loopback or not.
        for url in ["http://127.0.0.1:8787", "http://localhost:8787"] {
            let err = server(url).1.validate().unwrap_err().to_string();
            assert_eq!(err, "public_url must use https", "{url}");
        }
        for (url, why) in [
            // A name, even one that resolves to loopback: localhost may resolve to ::1, which Dove does not hold.
            ("http://localhost:8787", "not a name"),
            ("http://dove.example.com:8787", "not a name"),
            ("http://localhost.example.com:8787", "not a name"),
            ("http://192.168.1.20:8787", "exactly the listen address"),
            ("http://[::1]:8787", "exactly the listen address"),
            ("http://127.0.0.2:8787", "exactly the listen address"),
            ("http://127.0.0.1:9999", "exactly the listen address"),
            ("http://127.0.0.1", "exactly the listen address"),
            ("http://127.0.0.1:8787/mcp", "must be an origin"),
            // No HTTPS in local mode: it would mean a proxy, whose X-Forwarded-For local mode ignores.
            ("https://dove.example.com", "in local mode"),
            ("https://127.0.0.1:8787", "in local mode"),
            ("ftp://127.0.0.1:8787", "in local mode"),
        ] {
            let err = local(url).1.validate().unwrap_err().to_string();
            assert!(err.contains(why), "{url}: {err}");
        }
        // Local mode keeps the loopback-only listener.
        let (_d, mut cfg) = local("http://0.0.0.0:8787");
        cfg.listen = "0.0.0.0:8787".parse().unwrap();
        assert!(cfg.validate().unwrap_err().to_string().contains("loopback"));
        // The Host check then accepts exactly the configured loopback origin.
        assert_eq!(local("http://127.0.0.1:8787").1.public_host(), "127.0.0.1:8787");
    }
}
