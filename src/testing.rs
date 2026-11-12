//! Test support: a self-contained environment with secret files, config and state store in a temp directory.
//! Used by unit and integration tests. Never used by the service binary.
#![doc(hidden)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::app::App;
use crate::config::{Config, EXAMPLE};
use crate::secrets;

pub struct TestEnv {
    pub dir: tempfile::TempDir,
    pub app: Arc<App>,
}

fn write_secret(dir: &Path, name: &str, content: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
    p
}

/// Builds a config whose secrets live in `dir/secrets` and data in `dir/data`.
pub fn test_config(dir: &Path, operator_uid: u32) -> Config {
    let sdir = dir.join("secrets");
    std::fs::create_dir_all(&sdir).unwrap();
    let text = EXAMPLE
        .replace("/var/lib/dove", dir.join("data").to_str().unwrap())
        .replace("/run/dove/admin.sock", dir.join("admin.sock").to_str().unwrap())
        .replace("operator_uid = 1000", &format!("operator_uid = {operator_uid}"))
        .replace(
            "/run/credentials/dove.service/kek",
            write_secret(&sdir, "kek", &secrets::generate_key_line(1)).to_str().unwrap(),
        )
        .replace(
            "/run/credentials/dove.service/pepper",
            write_secret(&sdir, "pepper", &secrets::generate_key_line(1)).to_str().unwrap(),
        )
        .replace(
            "/run/credentials/dove.service/index_key",
            write_secret(&sdir, "index_key", &secrets::generate_key_line(1)).to_str().unwrap(),
        )
        .replace(
            "/run/credentials/dove.service/google_client_secret",
            write_secret(&sdir, "google_client_secret", "test-client-secret").to_str().unwrap(),
        );
    toml::from_str(&text).unwrap()
}

impl TestEnv {
    pub fn new() -> Self {
        Self::with(|_| {})
    }

    pub fn with(customize: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let uid = nix::unistd::getuid().as_raw();
        let mut cfg = test_config(dir.path(), uid);
        customize(&mut cfg);
        let app = App::from_config(cfg).unwrap();
        Self { dir, app }
    }

    /// Inserts an active account with a sealed fake refresh token, as a completed connect would.
    pub fn add_account(&self, alias: &str, email: &str, refresh_token: &str) -> String {
        let id = crate::util::new_id();
        let sealed = self.app.vault.seal_grant(&id, refresh_token).unwrap();
        let (alias, email, id2) = (alias.to_string(), email.to_string(), id.clone());
        self.app
            .store
            .call_blocking(move |c| {
                let now = crate::util::now_unix();
                c.execute(
                    "INSERT INTO accounts(id, alias, email, status, granted_scopes, google_sub, connected_at) \
                     VALUES (?1, ?2, ?3, 'active', ?4, ?5, ?6)",
                    rusqlite::params![id2, alias, email, crate::gmail::REQUIRED_SCOPES.join(" "), format!("sub-{alias}"), now],
                )?;
                c.execute(
                    "INSERT INTO grants(account_id, dek_wrapped, kek_version, refresh_token_ciphertext, nonce, created_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![id2, sealed.dek_wrapped, sealed.kek_version, sealed.ciphertext, sealed.nonce, now],
                )?;
                Ok(())
            })
            .unwrap();
        id
    }
}

impl Default for TestEnv {
    fn default() -> Self {
        Self::new()
    }
}
