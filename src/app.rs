//! Shared service state.

use std::sync::Arc;

use anyhow::Context;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::gmail::Google;
use crate::gmail::gateway::{Gateway, Upstream};
use crate::gmail::tokens::TokenManager;
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
    pub google_client_secret: Zeroizing<String>,
    /// Secret the reverse proxy sends in `X-Dove-Proxy-Auth` (see [`crate::http::client_ip`]).
    pub proxy_secret: Option<Zeroizing<String>>,
    pub index_key: Arc<KeyRing>,
    pub google: Google,
    pub started_at: std::time::Instant,
    pub rate_limiter: crate::mcp::RateLimiter,
    pub denials: crate::mcp::DenialTracker,
    pub draft_locks: crate::tools::drafts::DraftLocks,
    pub index: crate::index::Index,
    pub oauth: crate::oauth::OAuthState,
}

impl App {
    /// Loads secrets and opens the state store. Fails closed on any startup check (spec 8.4).
    pub fn from_config(cfg: Config) -> anyhow::Result<Arc<Self>> {
        Self::from_config_with(cfg, Upstream::google())
    }

    /// Like [`App::from_config`] with explicit upstream origins (tests use a fake Google server).
    pub fn from_config_with(cfg: Config, upstream: Upstream) -> anyhow::Result<Arc<Self>> {
        cfg.validate()?;
        let kek = KeyRing::load(&cfg.secrets.kek_file).context("loading KEK")?;
        let pepper = KeyRing::load(&cfg.secrets.pepper_file).context("loading pepper")?;
        let index_key = Arc::new(KeyRing::load(&cfg.secrets.index_key_file).context("loading index key")?);
        let google_client_secret = secrets::read_secret_string(&cfg.google.client_secret_file)?;
        let proxy_secret = match &cfg.secrets.proxy_secret_file {
            Some(p) => Some(secrets::read_proxy_secret(p).context("loading proxy secret")?),
            None => None,
        };
        let store = Store::open(&cfg.state_db_path())?;
        let notifier = Notifier::new(cfg.notifier.webhook_url.clone(), store.clone());
        let vault = Vault::new(kek);
        let gateway = Arc::new(Gateway::new(upstream, &cfg.limits));
        let tokens = TokenManager::new(
            store.clone(),
            vault.clone(),
            gateway.clone(),
            cfg.google.client_id.clone(),
            google_client_secret.clone(),
            notifier.clone(),
        );
        Ok(Arc::new(Self {
            google: Google::new(gateway, tokens),
            started_at: std::time::Instant::now(),
            rate_limiter: Default::default(),
            denials: Default::default(),
            draft_locks: Default::default(),
            oauth: crate::oauth::OAuthState::load(&cfg.oauth)?,
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
