//! Secret files (spec 6.4, 8.4).
//!
//! Secrets are only ever read from files whose mode grants nothing to group or others. Key files use one line per
//! key version: `<version> <base64 32-byte key>`. Lines starting with `#` are ignored. A single bare base64 line is
//! accepted as version 1.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, bail};
use zeroize::{Zeroize, Zeroizing};

use crate::util;

pub type Key32 = Zeroizing<[u8; 32]>;

/// Fails unless `path` is a regular file with no group/other permission bits.
pub fn check_secret_file_mode(path: &Path) -> anyhow::Result<()> {
    let meta = std::fs::metadata(path).with_context(|| format!("secret file {} is missing", path.display()))?;
    if !meta.is_file() {
        bail!("secret file {} is not a regular file", path.display());
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "secret file {} has mode {:o}; it must not be readable or writable by group or others (use 0400 or 0600)",
            path.display(),
            mode
        );
    }
    Ok(())
}

/// Reads a secret file after checking its mode.
pub fn read_secret_file(path: &Path) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    check_secret_file_mode(path)?;
    let data = std::fs::read(path).with_context(|| format!("cannot read secret file {}", path.display()))?;
    Ok(Zeroizing::new(data))
}

/// Reads a secret string (for example the Google client secret), trimming surrounding whitespace.
pub fn read_secret_string(path: &Path) -> anyhow::Result<Zeroizing<String>> {
    let raw = read_secret_file(path)?;
    let s = std::str::from_utf8(&raw).context("secret file is not UTF-8")?.trim().to_string();
    if s.is_empty() {
        bail!("secret file {} is empty", path.display());
    }
    Ok(Zeroizing::new(s))
}

/// A set of versioned 256-bit keys loaded from one file.
pub struct KeyRing {
    keys: BTreeMap<u32, Key32>,
}

impl KeyRing {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = read_secret_file(path)?;
        let text = std::str::from_utf8(&raw).context("key file is not UTF-8")?;
        Self::parse(text).with_context(|| format!("invalid key file {}", path.display()))
    }

    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let mut keys = BTreeMap::new();
        let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
        for line in &lines {
            let (version, b64) = match line.split_once(char::is_whitespace) {
                Some((v, k)) => (v.trim().trim_start_matches('v').parse::<u32>().context("bad key version")?, k.trim()),
                None if lines.len() == 1 => (1, *line),
                None => bail!("key line without version"),
            };
            let mut bytes = util::b64_decode_any(b64).context("key is not base64")?;
            if bytes.len() != 32 {
                bytes.zeroize();
                bail!("key version {version} is not 32 bytes");
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&bytes);
            bytes.zeroize();
            if version == 0 || keys.insert(version, key).is_some() {
                bail!("duplicate or zero key version {version}");
            }
        }
        if keys.is_empty() {
            bail!("no key in key file");
        }
        Ok(Self { keys })
    }

    pub fn single(version: u32, key: [u8; 32]) -> Self {
        let mut keys = BTreeMap::new();
        keys.insert(version, Zeroizing::new(key));
        Self { keys }
    }

    /// The newest version, used for new encryptions.
    pub fn current(&self) -> (u32, &[u8; 32]) {
        let (v, k) = self.keys.iter().next_back().expect("non-empty");
        (*v, k)
    }

    pub fn get(&self, version: u32) -> Option<&[u8; 32]> {
        self.keys.get(&version).map(|k| &**k)
    }

    pub fn versions(&self) -> Vec<u32> {
        self.keys.keys().copied().collect()
    }
}

/// Generates a new key line for a key file (used by `dove keys generate`).
pub fn generate_key_line(version: u32) -> String {
    let key = Zeroizing::new(util::random_bytes::<32>());
    format!("{version} {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, *key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn rejects_group_or_world_readable() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("kek");
        std::fs::write(&p, generate_key_line(1)).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(KeyRing::load(&p).is_err());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(KeyRing::load(&p).is_err());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(KeyRing::load(&p).is_ok());
    }

    #[test]
    fn parses_versions_and_picks_newest() {
        let text = format!("# comment\n{}\n{}\n", generate_key_line(1), generate_key_line(3));
        let ring = KeyRing::parse(&text).unwrap();
        assert_eq!(ring.current().0, 3);
        assert_eq!(ring.versions(), vec![1, 3]);
        assert!(KeyRing::parse("1 AAAA").is_err(), "short key must be rejected");
        assert!(KeyRing::parse("").is_err());
    }
}
