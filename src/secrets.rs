//! Secret files (spec 6.4, 8.4).
//!
//! Secrets are only ever read from files whose mode grants nothing to group or others, with one exception: a file
//! owned by root:root may be group-readable (systemd 259 `LoadCredential=` copies are 0440 root:root and reach the
//! service user through an ACL; PLAN A44). Key files use one line per
//! key version: `<version> <base64 32-byte key>`. Lines starting with `#` are ignored. A single bare base64 line is
//! accepted as version 1.
//!
//! On Windows the mode check is an ACL check (owner = the current user, no other account in the DACL; PLAN A58), and a
//! secret file may hold a DPAPI blob of the current user instead of the plaintext (`dove local init` writes those):
//! the file then starts with [`DPAPI_MAGIC`] followed by the base64 blob.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, bail};
use zeroize::{Zeroize, Zeroizing};

use crate::util;

pub type Key32 = Zeroizing<[u8; 32]>;

/// Whether a secret file's permission bits are acceptable: nothing for group or others, or, for a file owned by
/// root:root, group read only (the group is root, so this grants no unprivileged user anything).
pub fn secret_mode_ok(mode: u32, uid: u32, gid: u32) -> bool {
    let mode = mode & 0o777;
    mode & 0o077 == 0 || (uid == 0 && gid == 0 && mode & 0o037 == 0)
}

/// First line of a secret file that holds a DPAPI (CurrentUser) blob instead of the secret itself (Windows only).
pub const DPAPI_MAGIC: &str = "dove-dpapi-v1";

/// Fails unless `path` is a regular file whose mode passes [`secret_mode_ok`] (Unix) or that is private to the
/// current user (Windows: [`crate::platform::windows::check_private`]).
pub fn check_secret_file_mode(path: &Path) -> anyhow::Result<()> {
    let meta = std::fs::metadata(path).with_context(|| format!("secret file {} is missing", path.display()))?;
    if !meta.is_file() {
        bail!("secret file {} is not a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode() & 0o777;
        if !secret_mode_ok(mode, meta.uid(), meta.gid()) {
            bail!(
                "secret file {} has mode {:o}; it must not be readable or writable by group or others (use 0400 or \
                 0600)",
                path.display(),
                mode
            );
        }
    }
    #[cfg(windows)]
    if let Err(why) = crate::platform::windows::check_private(path) {
        bail!("secret file {} is not private to the current user: {why}", path.display());
    }
    Ok(())
}

/// Reads a secret file after checking its mode. A DPAPI-protected file is decrypted (Windows only).
pub fn read_secret_file(path: &Path) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    check_secret_file_mode(path)?;
    let data =
        Zeroizing::new(std::fs::read(path).with_context(|| format!("cannot read secret file {}", path.display()))?);
    match dpapi_payload(&data) {
        None => Ok(data),
        Some(b64) => unprotect(b64).with_context(|| format!("cannot decrypt secret file {}", path.display())),
    }
}

/// The base64 blob of a DPAPI secret file, or `None` for a plain one.
fn dpapi_payload(data: &[u8]) -> Option<&[u8]> {
    let rest = data.strip_prefix(DPAPI_MAGIC.as_bytes())?;
    let rest = rest.strip_prefix(b"\r").unwrap_or(rest);
    rest.strip_prefix(b"\n")
}

#[cfg(windows)]
fn unprotect(b64: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let text = std::str::from_utf8(b64).context("not UTF-8")?;
    let blob = util::b64_decode_any(text.trim()).context("the DPAPI blob is not base64")?;
    crate::platform::windows::dpapi_unprotect(&blob)
        .context("DPAPI refused it (it was protected by another Windows user or on another computer)")
}

#[cfg(not(windows))]
fn unprotect(_: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    bail!("it is protected with Windows DPAPI, which works only on the Windows account that wrote it")
}

/// The content of a secret file for `secret`: DPAPI-protected on Windows, the secret itself elsewhere.
pub fn encode_secret_file(secret: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    #[cfg(windows)]
    {
        let blob = crate::platform::windows::dpapi_protect(secret).context("DPAPI protect failed")?;
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, blob);
        Ok(Zeroizing::new(format!("{DPAPI_MAGIC}\n{b64}\n").into_bytes()))
    }
    #[cfg(not(windows))]
    {
        Ok(Zeroizing::new(secret.to_vec()))
    }
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

/// Reads the reverse-proxy secret: at least 32 visible ASCII characters, so it fits an HTTP header unchanged.
pub fn read_proxy_secret(path: &Path) -> anyhow::Result<Zeroizing<String>> {
    let s = read_secret_string(path)?;
    if s.len() < 32 || !s.bytes().all(|b| b.is_ascii_graphic()) {
        bail!(
            "proxy secret file {} must hold at least 32 visible ASCII characters (for example openssl rand -hex 32)",
            path.display()
        );
    }
    Ok(s)
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
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn dpapi_files_are_recognised_by_their_first_line() {
        assert_eq!(dpapi_payload(b"dove-dpapi-v1\nQUJD\n"), Some(&b"QUJD\n"[..]));
        assert_eq!(dpapi_payload(b"dove-dpapi-v1\r\nQUJD"), Some(&b"QUJD"[..]));
        assert_eq!(dpapi_payload(b"1 dove-dpapi-v1\n"), None);
        assert_eq!(dpapi_payload(b"dove-dpapi-v1x\n"), None);
    }

    #[cfg(unix)]
    #[test]
    fn dpapi_files_are_refused_off_windows() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("kek");
        std::fs::write(&p, "dove-dpapi-v1\nQUJD\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let err = KeyRing::load(&p).err().unwrap();
        assert!(format!("{err:#}").contains("DPAPI"), "{err:#}");
    }

    /// The local-mode secret files round-trip through the reader (DPAPI on Windows, plain elsewhere).
    #[test]
    fn encoded_secret_files_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("kek");
        let line = generate_key_line(1);
        crate::platform::write_private_new(&p, &encode_secret_file(line.as_bytes()).unwrap()).unwrap();
        let raw = std::fs::read(&p).unwrap();
        assert_eq!(raw.starts_with(DPAPI_MAGIC.as_bytes()), cfg!(windows));
        assert_eq!(&**read_secret_file(&p).unwrap(), line.as_bytes());
        KeyRing::load(&p).unwrap();
    }

    #[cfg(unix)]
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
    fn only_root_owned_files_may_be_group_readable() {
        // systemd 259 credential copies: 0440 root:root plus an ACL for the service user.
        assert!(secret_mode_ok(0o440, 0, 0));
        assert!(secret_mode_ok(0o400, 981, 981));
        assert!(secret_mode_ok(0o600, 981, 981));
        assert!(!secret_mode_ok(0o440, 981, 981), "group-readable files of other owners stay rejected");
        assert!(!secret_mode_ok(0o440, 0, 981), "a non-root group could read it");
        assert!(!secret_mode_ok(0o460, 0, 0), "group write stays rejected");
        assert!(!secret_mode_ok(0o444, 0, 0), "world read stays rejected");
        assert!(!secret_mode_ok(0o404, 981, 981));
    }

    #[cfg(unix)]
    #[test]
    fn proxy_secret_must_be_long_and_header_safe() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("proxy");
        for (content, ok) in [("short", false), (&*"a b".repeat(20), false), (&*format!("{}\n", "x".repeat(40)), true)]
        {
            std::fs::write(&p, content).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(read_proxy_secret(&p).is_ok(), ok, "{content:?}");
        }
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
