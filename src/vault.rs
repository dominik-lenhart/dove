//! Envelope encryption for Google grants (spec 6.4).
//!
//! Each account has a random DEK. The DEK is wrapped by the KEK (versioned) and the refresh token is encrypted with
//! the DEK. Both use XChaCha20-Poly1305 with a fresh random 192-bit nonce. Associated data binds every ciphertext to
//! its account id, record type and key version, so a ciphertext moved to another row fails to decrypt.

use std::sync::Arc;

use anyhow::{anyhow, bail};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use zeroize::Zeroizing;

use crate::secrets::KeyRing;
use crate::util;

const NONCE_LEN: usize = 24;

/// Stored form of one grant secret.
#[derive(Debug, Clone)]
pub struct SealedGrant {
    pub dek_wrapped: Vec<u8>,
    pub kek_version: u32,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Clone)]
pub struct Vault {
    kek: Arc<KeyRing>,
}

fn aad(kind: &str, scope: &str, version: u32) -> Vec<u8> {
    format!("dove/v1|{kind}|{scope}|kek:{version}").into_bytes()
}

fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = util::random_bytes::<NONCE_LEN>();
    let ct =
        cipher.encrypt((&nonce).into(), Payload { msg: plaintext, aad }).map_err(|_| anyhow!("encryption failed"))?;
    Ok((nonce.to_vec(), ct))
}

fn open(key: &[u8; 32], aad: &[u8], nonce: &[u8], ct: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_LEN {
        bail!("bad nonce length");
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("checked length");
    cipher
        .decrypt((&nonce).into(), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("decryption failed"))
}

impl Vault {
    pub fn new(kek: KeyRing) -> Self {
        Self { kek: Arc::new(kek) }
    }

    pub fn kek_versions(&self) -> Vec<u32> {
        self.kek.versions()
    }

    pub fn current_kek_version(&self) -> u32 {
        self.kek.current().0
    }

    /// Encrypts a refresh token for `account_id` under a fresh DEK.
    pub fn seal_grant(&self, account_id: &str, refresh_token: &str) -> anyhow::Result<SealedGrant> {
        let (kek_version, kek) = self.kek.current();
        let dek = Zeroizing::new(util::random_bytes::<32>());
        let (dek_nonce, dek_ct) = seal(kek, &aad("dek", account_id, kek_version), &dek[..])?;
        let mut dek_wrapped = dek_nonce;
        dek_wrapped.extend_from_slice(&dek_ct);
        let (nonce, ciphertext) = seal(&dek, &aad("refresh_token", account_id, kek_version), refresh_token.as_bytes())?;
        Ok(SealedGrant { dek_wrapped, kek_version, ciphertext, nonce })
    }

    fn unwrap_dek(&self, account_id: &str, sealed: &SealedGrant) -> anyhow::Result<Zeroizing<[u8; 32]>> {
        let kek =
            self.kek.get(sealed.kek_version).ok_or_else(|| anyhow!("KEK version {} not loaded", sealed.kek_version))?;
        if sealed.dek_wrapped.len() <= NONCE_LEN {
            bail!("wrapped DEK too short");
        }
        let (n, ct) = sealed.dek_wrapped.split_at(NONCE_LEN);
        let dek = open(kek, &aad("dek", account_id, sealed.kek_version), n, ct)?;
        let mut out = Zeroizing::new([0u8; 32]);
        if dek.len() != 32 {
            bail!("DEK has wrong length");
        }
        out.copy_from_slice(&dek);
        Ok(out)
    }

    /// Decrypts the refresh token. Fails if the row was moved to another account or tampered with.
    pub fn open_grant(&self, account_id: &str, sealed: &SealedGrant) -> anyhow::Result<Zeroizing<String>> {
        let dek = self.unwrap_dek(account_id, sealed)?;
        let pt = open(&dek, &aad("refresh_token", account_id, sealed.kek_version), &sealed.nonce, &sealed.ciphertext)?;
        let s = String::from_utf8(pt.to_vec()).map_err(|_| anyhow!("grant is not UTF-8"))?;
        Ok(Zeroizing::new(s))
    }

    /// Re-wraps a grant under the current KEK version (`dove keys rotate`). The DEK itself is kept; the refresh token
    /// ciphertext is re-encrypted because its AAD carries the key version.
    pub fn rewrap(&self, account_id: &str, sealed: &SealedGrant) -> anyhow::Result<SealedGrant> {
        let token = self.open_grant(account_id, sealed)?;
        self.seal_grant(account_id, &token)
    }

    /// Encrypts a small non-account secret (for example a PKCE verifier) bound to `scope`.
    pub fn seal_aux(&self, kind: &str, scope: &str, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (v, kek) = self.kek.current();
        let (nonce, ct) = seal(kek, &aad(kind, scope, v), plaintext)?;
        let mut out = v.to_be_bytes().to_vec();
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn open_aux(&self, kind: &str, scope: &str, blob: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        if blob.len() < 4 + NONCE_LEN {
            bail!("sealed blob too short");
        }
        let v = u32::from_be_bytes(blob[..4].try_into().expect("4 bytes"));
        let kek = self.kek.get(v).ok_or_else(|| anyhow!("KEK version {v} not loaded"))?;
        open(kek, &aad(kind, scope, v), &blob[4..4 + NONCE_LEN], &blob[4 + NONCE_LEN..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault() -> Vault {
        Vault::new(KeyRing::single(1, util::random_bytes()))
    }

    #[test]
    fn roundtrip_and_binding() {
        let v = vault();
        let sealed = v.seal_grant("acct-a", "1//refresh-secret").unwrap();
        assert_eq!(&**v.open_grant("acct-a", &sealed).unwrap(), "1//refresh-secret");
        // A grant row copied to another account must not decrypt (AC8).
        assert!(v.open_grant("acct-b", &sealed).is_err());
        // The plaintext never appears in the stored bytes.
        let needle = b"refresh-secret";
        for blob in [&sealed.ciphertext, &sealed.dek_wrapped] {
            assert!(!blob.windows(needle.len()).any(|w| w == needle));
        }
    }

    #[test]
    fn tamper_and_wrong_key_version_fail() {
        let v = vault();
        let mut sealed = v.seal_grant("a", "tok").unwrap();
        sealed.ciphertext[0] ^= 1;
        assert!(v.open_grant("a", &sealed).is_err());
        let mut sealed = v.seal_grant("a", "tok").unwrap();
        sealed.kek_version = 2;
        assert!(v.open_grant("a", &sealed).is_err());
    }

    #[test]
    fn rotation_rewraps_to_new_version() {
        let k1 = util::random_bytes::<32>();
        let old = Vault::new(KeyRing::single(1, k1));
        let sealed = old.seal_grant("a", "tok").unwrap();
        let text = format!("1 {}\n2 {}", util::b64url(&k1), util::b64url(&util::random_bytes::<32>()));
        let both = Vault::new(KeyRing::parse(&text).unwrap());
        let rewrapped = both.rewrap("a", &sealed).unwrap();
        assert_eq!(rewrapped.kek_version, 2);
        assert_eq!(&**both.open_grant("a", &rewrapped).unwrap(), "tok");
        // The old-only vault cannot open the new version.
        assert!(old.open_grant("a", &rewrapped).is_err());
    }

    #[test]
    fn aux_binding() {
        let v = vault();
        let blob = v.seal_aux("pkce", "state1", b"verifier").unwrap();
        assert_eq!(&v.open_aux("pkce", "state1", &blob).unwrap()[..], b"verifier");
        assert!(v.open_aux("pkce", "state2", &blob).is_err());
    }
}
