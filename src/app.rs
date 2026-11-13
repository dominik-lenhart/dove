//! Shared service state.

use std::sync::Arc;

use anyhow::Context;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::gmail::Google;
use crate::gmail::gateway::{Gateway, Upstream};
use crate::gmail::tokens::TokenManager;
use crate::imap::{ImapConnector, ImapPool};
use crate::notifier::Notifier;
use crate::secrets::{self, KeyRing};
use crate::store::Store;
use crate::tokens::Pepper;
use crate::vault::Vault;

pub struct App {
    pub cfg: Config,
    pub store: Store,
    pub vault: Vault,
    pub pepper: Pepper,
    pub notifier: Notifier,
    /// None when the config has no `[google]` section (IMAP-only instance).
    pub google_client_secret: Option<Zeroizing<String>>,
    /// Secret the reverse proxy sends in `X-Dove-Proxy-Auth` (see [`crate::http::client_ip`]).
    pub proxy_secret: Option<Zeroizing<String>>,
    pub index_key: Arc<KeyRing>,
    pub google: Google,
    /// Logged-in IMAP sessions per account; the connector decides TLS (verified in production).
    pub imap: ImapPool,
    pub started_at: std::time::Instant,
    pub rate_limiter: crate::mcp::RateLimiter,
    pub denials: crate::mcp::DenialTracker,
    pub draft_locks: crate::tools::drafts::DraftLocks,
    pub index: crate::index::Index,
    pub oauth: crate::oauth::OAuthState,
    /// Watch event worker state (`crate::watch`).
    pub watch: crate::watch::Runtime,
    /// Graceful stop requested over the admin channel (local mode's `Shutdown`).
    pub shutdown: tokio::sync::Notify,
}

impl App {
    /// Loads secrets and opens the state store. Fails closed on any startup check (spec 8.4).
    pub fn from_config(cfg: Config) -> anyhow::Result<Arc<Self>> {
        Self::from_config_with(cfg, Upstream::google(), ImapConnector::verified())
    }

    /// Like [`App::from_config`] with explicit upstream origins and IMAP connector (tests use fake servers).
    pub fn from_config_with(
        cfg: Config,
        upstream: Upstream,
        imap_connector: ImapConnector,
    ) -> anyhow::Result<Arc<Self>> {
        cfg.validate()?;
        let kek = KeyRing::load(&cfg.secrets.kek_file).context("loading KEK")?;
        let pepper = KeyRing::load(&cfg.secrets.pepper_file).context("loading pepper")?;
        let index_key = Arc::new(KeyRing::load(&cfg.secrets.index_key_file).context("loading index key")?);
        let google_client_secret = match &cfg.google {
            Some(g) => Some(secrets::read_secret_string(&g.client_secret_file)?),
            None => None,
        };
        let proxy_secret = match &cfg.secrets.proxy_secret_file {
            Some(p) => Some(secrets::read_proxy_secret(p).context("loading proxy secret")?),
            None => None,
        };
        let store = Store::open(&cfg.state_db_path())?;
        let notifier = Notifier::new(cfg.notifier.webhook_url.clone(), store.clone());
        let vault = Vault::new(kek);
        let gateway = Arc::new(Gateway::new(upstream, &cfg.limits));
        // Webhook sinks are the only non-Google destinations; the operator's list is the allowlist.
        gateway.set_sink_allowlist(store.call_blocking(|c| crate::watch::sinks::registered_urls(c, false))?);
        let tokens = TokenManager::new(
            store.clone(),
            vault.clone(),
            gateway.clone(),
            cfg.google.as_ref().map(|g| g.client_id.clone()).unwrap_or_default(),
            google_client_secret.clone().unwrap_or_default(),
            notifier.clone(),
        );
        let imap =
            ImapPool::new(imap_connector, std::time::Duration::from_secs(cfg.limits.upstream_request_timeout_secs))
                .with_global_limit(gateway.global_limit(), gateway.background_limit());
        Ok(Arc::new(Self {
            google: Google::new(gateway, tokens),
            imap,
            started_at: std::time::Instant::now(),
            rate_limiter: Default::default(),
            denials: Default::default(),
            draft_locks: Default::default(),
            oauth: crate::oauth::OAuthState::load(&cfg.oauth)?,
            watch: Default::default(),
            shutdown: Default::default(),
            vault,
            pepper: Pepper::new(pepper),
            index: crate::index::Index::new(cfg.index_db_path(), index_key.clone(), cfg.index.clone()),
            index_key,
            notifier,
            google_client_secret,
            proxy_secret,
            store,
            cfg,
        }))
    }
}
