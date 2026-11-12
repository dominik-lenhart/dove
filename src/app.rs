//! Shared service state.

use std::sync::Arc;

use anyhow::Context;
use zeroize::Zeroizing;

use crate::config::Config;
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
    pub index_key: Arc<KeyRing>,
}

impl App {
    /// Loads secrets and opens the state store. Fails closed on any startup check (spec 8.4).
    pub fn from_config(cfg: Config) -> anyhow::Result<Arc<Self>> {
        cfg.validate()?;
        let kek = KeyRing::load(&cfg.secrets.kek_file).context("loading KEK")?;
        let pepper = KeyRing::load(&cfg.secrets.pepper_file).context("loading pepper")?;
        let index_key = KeyRing::load(&cfg.secrets.index_key_file).context("loading index key")?;
        let google_client_secret = secrets::read_secret_string(&cfg.google.client_secret_file)?;
        let store = Store::open(&cfg.state_db_path())?;
        let notifier = Notifier::new(cfg.notifier.webhook_url.clone(), store.clone());
        Ok(Arc::new(Self {
            vault: Vault::new(kek),
            pepper: Pepper::new(pepper),
            index_key: Arc::new(index_key),
            notifier,
            google_client_secret,
            store,
            cfg,
        }))
    }
}
