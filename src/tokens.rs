//! Opaque bearer secrets: client tokens, invitations, OAuth codes and tokens (spec 6.4, 5.6).
//!
//! Secrets are `<prefix>` + 32 random bytes in base64url. Only an HMAC-SHA-256 with the server-side pepper is
//! stored. Lookups go by that hash, so no secret comparison happens in application code.

use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::secrets::KeyRing;
use crate::util;

pub const CLIENT_TOKEN_PREFIX: &str = "dove_";
pub const INVITE_PREFIX: &str = "dovei_";
pub const OAUTH_ACCESS_PREFIX: &str = "doveat_";
pub const OAUTH_REFRESH_PREFIX: &str = "dovert_";
pub const OAUTH_CODE_PREFIX: &str = "dovec_";

#[derive(Clone)]
pub struct Pepper {
    ring: Arc<KeyRing>,
}

impl Pepper {
    pub fn new(ring: KeyRing) -> Self {
        Self { ring: Arc::new(ring) }
    }

    pub fn version(&self) -> u32 {
        self.ring.current().0
    }

    /// Keyed hash with domain separation by `purpose`.
    pub fn hash(&self, purpose: &str, secret: &str) -> Vec<u8> {
        let (_, key) = self.ring.current();
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("any key length");
        mac.update(purpose.as_bytes());
        mac.update(&[0]);
        mac.update(secret.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// Keyed hash for audit query fingerprints (spec 6.7): repeated queries are detectable without storing text.
    pub fn fingerprint(&self, data: &str) -> String {
        util::hex(&self.hash("audit-query", data)[..16])
    }
}

/// Generates a new secret with the given prefix.
pub fn generate(prefix: &str) -> String {
    format!("{prefix}{}", util::b64url(&util::random_bytes::<32>()))
}

/// Syntactic check before hashing, so obviously malformed input is rejected cheaply.
pub fn looks_valid(prefix: &str, token: &str) -> bool {
    token.strip_prefix(prefix).is_some_and(|rest| {
        rest.len() == 43 && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_format_and_hashing() {
        let t = generate(CLIENT_TOKEN_PREFIX);
        assert!(looks_valid(CLIENT_TOKEN_PREFIX, &t), "{t}");
        assert!(!looks_valid(CLIENT_TOKEN_PREFIX, &t[..t.len() - 1]));
        assert!(!looks_valid(INVITE_PREFIX, &t));
        let p = Pepper::new(KeyRing::single(1, [7; 32]));
        let other = Pepper::new(KeyRing::single(1, [8; 32]));
        assert_eq!(p.hash("client", &t), p.hash("client", &t));
        assert_ne!(p.hash("client", &t), p.hash("invite", &t), "purpose separates hashes");
        assert_ne!(p.hash("client", &t), other.hash("client", &t), "pepper is part of the hash");
    }
}
