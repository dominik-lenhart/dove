//! Local client profiles and credentials (spec 5.6).
//!
//! A profile holds a server URL, the connection name and a credential reference, never the credential itself.
//! The credential is the connection's opaque `dove_` token, stored in the OS credential store (Keychain, Windows
//! Credential Manager, Secret Service) or, only when the user explicitly chooses it, in a `0600` secret file.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const KEYRING_SERVICE: &str = "dove-mcp";

/// Where the connection token lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialRef {
    Keyring,
    File(PathBuf),
}

impl CredentialRef {
    pub fn describe(&self) -> String {
        match self {
            CredentialRef::Keyring => "OS credential store".into(),
            CredentialRef::File(p) => format!("secret file {}", p.display()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub server: String,
    pub connection: String,
    /// `keyring` or `file:<absolute path>`.
    pub credential: String,
}

impl Profile {
    pub fn credential_ref(&self) -> anyhow::Result<CredentialRef> {
        match self.credential.as_str() {
            "keyring" => Ok(CredentialRef::Keyring),
            other => match other.strip_prefix("file:") {
                Some(p) if Path::new(p).is_absolute() => Ok(CredentialRef::File(PathBuf::from(p))),
                _ => bail!("profile has an invalid credential reference"),
            },
        }
    }

    pub fn mcp_url(&self) -> String {
        format!("{}/mcp", self.server)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileFile {
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

/// `$DOVE_CONFIG_DIR`, else `$XDG_CONFIG_HOME/dove`, else `~/.config/dove` (`%APPDATA%\dove` on Windows).
pub fn config_dir() -> anyhow::Result<PathBuf> {
    if let Some(d) = std::env::var_os("DOVE_CONFIG_DIR").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(d));
    }
    if let Some(d) = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).filter(|d| d.is_absolute()) {
        return Ok(d.join("dove"));
    }
    #[cfg(windows)]
    if let Some(d) = std::env::var_os("APPDATA") {
        return Ok(PathBuf::from(d).join("dove"));
    }
    Ok(home_dir()?.join(".config").join("dove"))
}

pub fn home_dir() -> anyhow::Result<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var).map(PathBuf::from).filter(|p| p.is_absolute()).ok_or_else(|| anyhow!("{var} is not set"))
}

pub fn profiles_path() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join("profiles.toml"))
}

pub fn valid_profile_name(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

impl ProfileFile {
    pub fn load() -> anyhow::Result<Self> {
        let path = profiles_path()?;
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                toml::from_str(&text).with_context(|| format!("{} is not a valid profile file", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = profiles_path()?;
        let dir = path.parent().expect("has parent");
        create_private_dir(dir)?;
        let text = toml::to_string_pretty(self)?;
        atomic_write(&path, text.as_bytes(), 0o600)
    }

    /// Resolves `--profile`, or the only profile when there is exactly one.
    pub fn resolve(&self, name: Option<&str>) -> anyhow::Result<(String, Profile)> {
        match name {
            Some(n) => self
                .profiles
                .get(n)
                .map(|p| (n.to_string(), p.clone()))
                .ok_or_else(|| anyhow!("no profile '{n}'; run `dove login --server <url> --profile {n}` first")),
            None if self.profiles.len() == 1 => {
                let (n, p) = self.profiles.iter().next().expect("one");
                Ok((n.clone(), p.clone()))
            }
            None if self.profiles.is_empty() => {
                bail!("no profile yet; run `dove login --server <url> --profile <name>`")
            }
            None => bail!("several profiles exist; choose one with --profile"),
        }
    }
}

fn create_private_dir(dir: &Path) -> anyhow::Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

/// Writes `data` to a temporary file next to `path` with `mode`, syncs it and renames it into place. A symlink at
/// `path` is resolved first so the link itself survives.
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> anyhow::Result<()> {
    let target = match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => std::fs::canonicalize(path)?,
        _ => path.to_path_buf(),
    };
    let dir = target.parent().ok_or_else(|| anyhow!("{} has no parent directory", target.display()))?;
    let name = target.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!(".{name}.dove-tmp-{}", crate::util::new_id()));
    let result = (|| -> anyhow::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        let mut f = opts.open(&tmp).with_context(|| format!("cannot write in {}", dir.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, &target).with_context(|| format!("cannot replace {}", target.display()))?;
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn keyring_entry(profile: &str, server: &str) -> anyhow::Result<keyring::Entry> {
    let host = url::Url::parse(server).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
    keyring::Entry::new(KEYRING_SERVICE, &format!("{profile}@{host}"))
        .map_err(|e| anyhow!("the OS credential store is not available ({e})"))
}

/// Checks that the OS credential store works before anything is redeemed, so a missing store never silently
/// changes where the credential goes.
pub fn keyring_available(profile: &str, server: &str) -> anyhow::Result<()> {
    let entry = keyring_entry(profile, server)?;
    match entry.get_password() {
        Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(anyhow!("the OS credential store is not available ({e})")),
    }
}

/// Validates an explicitly chosen secret file location: absolute after resolution, parent exists, and if the
/// file exists it is a regular file.
pub fn secret_file_path(p: &Path) -> anyhow::Result<PathBuf> {
    let abs = if p.is_absolute() { p.to_path_buf() } else { std::env::current_dir()?.join(p) };
    let parent = abs.parent().ok_or_else(|| anyhow!("invalid secret file path"))?;
    if !parent.is_dir() {
        bail!("directory {} does not exist", parent.display());
    }
    if let Ok(m) = std::fs::symlink_metadata(&abs)
        && !m.is_file()
    {
        bail!("{} exists and is not a regular file", abs.display());
    }
    Ok(abs)
}

pub fn store_token(r: &CredentialRef, profile: &str, server: &str, token: &str) -> anyhow::Result<()> {
    match r {
        CredentialRef::Keyring => keyring_entry(profile, server)?
            .set_password(token)
            .map_err(|e| anyhow!("cannot store the credential in the OS credential store ({e})")),
        CredentialRef::File(p) => {
            let _ = std::fs::remove_file(p);
            atomic_write(p, format!("{token}\n").as_bytes(), 0o600)
        }
    }
}

pub fn load_token(r: &CredentialRef, profile: &str, server: &str) -> anyhow::Result<Zeroizing<String>> {
    let raw = match r {
        CredentialRef::Keyring => {
            Zeroizing::new(keyring_entry(profile, server)?.get_password().map_err(|e| match e {
                keyring::Error::NoEntry => anyhow!("no credential stored for profile '{profile}'; run `dove login`"),
                e => anyhow!("cannot read the OS credential store ({e})"),
            })?)
        }
        CredentialRef::File(p) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let m = std::fs::metadata(p)
                    .with_context(|| format!("credential file {} is missing; run `dove login`", p.display()))?;
                if m.permissions().mode() & 0o077 != 0 {
                    bail!("credential file {} is accessible by other users; chmod 600 it", p.display());
                }
            }
            Zeroizing::new(std::fs::read_to_string(p).with_context(|| format!("cannot read {}", p.display()))?)
        }
    };
    let t = Zeroizing::new(raw.trim().to_string());
    if !crate::tokens::looks_valid(crate::tokens::CLIENT_TOKEN_PREFIX, &t) {
        bail!("the stored credential for profile '{profile}' is malformed; run `dove login` again");
    }
    Ok(t)
}

pub fn delete_token(r: &CredentialRef, profile: &str, server: &str) -> anyhow::Result<()> {
    match r {
        CredentialRef::Keyring => match keyring_entry(profile, server)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(anyhow!("cannot delete the credential from the OS credential store ({e})")),
        },
        CredentialRef::File(p) => match std::fs::remove_file(p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("cannot delete {}", p.display())),
        },
    }
}

/// Server URLs must be HTTPS origins; plain HTTP is accepted only for loopback hosts (local testing).
pub fn normalize_server(s: &str) -> anyhow::Result<String> {
    let u = url::Url::parse(s.trim()).map_err(|_| anyhow!("--server must be a URL like https://dove.example.com"))?;
    let host = u.host_str().unwrap_or("");
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    if !(u.scheme() == "https" || (u.scheme() == "http" && loopback)) || host.is_empty() {
        bail!("--server must use https (plain http only for localhost)");
    }
    if (u.path() != "/" && !u.path().is_empty()) || u.query().is_some() || !u.username().is_empty() {
        bail!("--server must be an origin like https://dove.example.com (without /mcp)");
    }
    Ok(u.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_urls() {
        assert_eq!(normalize_server("https://dove.example.com/").unwrap(), "https://dove.example.com");
        assert_eq!(normalize_server("http://127.0.0.1:8080").unwrap(), "http://127.0.0.1:8080");
        assert!(normalize_server("http://dove.example.com").is_err());
        assert!(normalize_server("https://dove.example.com/mcp").is_err());
        assert!(normalize_server("ftp://x").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_keeps_symlink_and_mode() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real.json");
        std::fs::write(&real, "{}").unwrap();
        let link = d.path().join("link.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        atomic_write(&link, b"{\"a\":1}", 0o600).unwrap();
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "{\"a\":1}");
        assert_eq!(std::fs::metadata(&real).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
