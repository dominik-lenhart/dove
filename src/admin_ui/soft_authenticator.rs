//! A software WebAuthn authenticator and client for tests (cfg `test`/`testing` only): it generates a key, builds
//! clientDataJSON, authenticator data and attestation objects like a browser plus authenticator would, and signs.
//! Every field can be bent to test one check at a time.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};

use super::webauthn::{ALG_EDDSA, ALG_ES256};

enum Key {
    Es256(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
}

/// One credential on a software authenticator, used through a software client for `origin`.
pub struct SoftAuthenticator {
    key: Key,
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    /// The RP ID whose hash goes into authenticator data.
    pub rp_id: String,
    /// The origin the client writes into clientDataJSON.
    pub origin: String,
    pub sign_count: u32,
    /// Added to the counter before each assertion (0 = a synced passkey that always reports 0).
    pub counter_step: u32,
    pub user_present: bool,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    /// Overrides clientDataJSON `type` when set.
    pub type_override: Option<String>,
}

/// What `navigator.credentials.create` returns, in the JSON shape the admin UI's script posts.
pub struct Registration {
    pub credential_id: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

/// What `navigator.credentials.get` returns.
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

impl Registration {
    /// The body of `POST /admin/enroll/finish`.
    pub fn to_json(&self) -> serde_json::Value {
        let b = crate::util::b64url;
        serde_json::json!({
            "id": b(&self.credential_id),
            "clientDataJSON": b(&self.client_data_json),
            "attestationObject": b(&self.attestation_object),
        })
    }
}

impl Assertion {
    /// The `credential` object of `POST /admin/login/finish` and `/admin/stepup`.
    pub fn to_json(&self) -> serde_json::Value {
        let b = crate::util::b64url;
        serde_json::json!({
            "id": b(&self.credential_id),
            "clientDataJSON": b(&self.client_data_json),
            "authenticatorData": b(&self.authenticator_data),
            "signature": b(&self.signature),
            "userHandle": b(&self.user_handle),
        })
    }
}

impl SoftAuthenticator {
    /// A new ES256 credential for `origin` (`https://host[:port]`), RP ID = its host, with UP and UV.
    pub fn es256(origin: &str) -> Self {
        Self::new(Key::Es256(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).expect("key")), origin)
    }

    /// A new Ed25519 credential.
    pub fn ed25519(origin: &str) -> Self {
        Self::new(Key::Ed25519(Ed25519KeyPair::generate().expect("key")), origin)
    }

    fn new(key: Key, origin: &str) -> Self {
        let rp_id = url::Url::parse(origin).expect("origin").host_str().expect("host").to_string();
        Self {
            key,
            credential_id: crate::util::random_bytes::<32>().to_vec(),
            user_handle: vec![],
            rp_id,
            origin: origin.to_string(),
            sign_count: 0,
            counter_step: 1,
            user_present: true,
            user_verified: true,
            backup_eligible: false,
            backup_state: false,
            type_override: None,
        }
    }

    fn client_data(&self, kind: &str, challenge: &[u8]) -> Vec<u8> {
        let t = self.type_override.clone().unwrap_or_else(|| kind.to_string());
        serde_json::to_vec(&serde_json::json!({
            "type": t,
            "challenge": crate::util::b64url(challenge),
            "origin": self.origin,
            "crossOrigin": false,
        }))
        .expect("json")
    }

    fn flags(&self, attested: bool) -> u8 {
        let mut f = 0;
        if self.user_present {
            f |= 0x01;
        }
        if self.user_verified {
            f |= 0x04;
        }
        if self.backup_eligible {
            f |= 0x08;
        }
        if self.backup_state {
            f |= 0x10;
        }
        if attested {
            f |= 0x40;
        }
        f
    }

    fn cose_key(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match &self.key {
            Key::Es256(k) => {
                let pk = k.public_key().as_ref();
                cbor_head(&mut out, 5, 5);
                cbor_int(&mut out, 1);
                cbor_int(&mut out, 2);
                cbor_int(&mut out, 3);
                cbor_int(&mut out, ALG_ES256);
                cbor_int(&mut out, -1);
                cbor_int(&mut out, 1);
                cbor_int(&mut out, -2);
                cbor_bytes(&mut out, &pk[1..33]);
                cbor_int(&mut out, -3);
                cbor_bytes(&mut out, &pk[33..65]);
            }
            Key::Ed25519(k) => {
                cbor_head(&mut out, 5, 4);
                cbor_int(&mut out, 1);
                cbor_int(&mut out, 1);
                cbor_int(&mut out, 3);
                cbor_int(&mut out, ALG_EDDSA);
                cbor_int(&mut out, -1);
                cbor_int(&mut out, 6);
                cbor_int(&mut out, -2);
                cbor_bytes(&mut out, k.public_key().as_ref());
            }
        }
        out
    }

    fn auth_data(&self, attested: bool) -> Vec<u8> {
        let mut ad = Sha256::digest(self.rp_id.as_bytes()).to_vec();
        ad.push(self.flags(attested));
        ad.extend_from_slice(&self.sign_count.to_be_bytes());
        if attested {
            ad.extend_from_slice(&[0u8; 16]);
            ad.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
            ad.extend_from_slice(&self.credential_id);
            ad.extend_from_slice(&self.cose_key());
        }
        ad
    }

    /// `navigator.credentials.create` for `challenge` with user handle `user_handle` (attestation `none`).
    pub fn register(&mut self, challenge: &[u8], user_handle: &[u8]) -> Registration {
        self.user_handle = user_handle.to_vec();
        let client_data_json = self.client_data("webauthn.create", challenge);
        let auth_data = self.auth_data(true);
        let mut ao = Vec::new();
        cbor_head(&mut ao, 5, 3);
        cbor_text(&mut ao, "fmt");
        cbor_text(&mut ao, "none");
        cbor_text(&mut ao, "attStmt");
        cbor_head(&mut ao, 5, 0);
        cbor_text(&mut ao, "authData");
        cbor_bytes(&mut ao, &auth_data);
        Registration { credential_id: self.credential_id.clone(), client_data_json, attestation_object: ao }
    }

    /// `navigator.credentials.get` for `challenge`.
    pub fn assert(&mut self, challenge: &[u8]) -> Assertion {
        self.sign_count = self.sign_count.wrapping_add(self.counter_step);
        let client_data_json = self.client_data("webauthn.get", challenge);
        let authenticator_data = self.auth_data(false);
        let signature = self.sign(&authenticator_data, &client_data_json);
        Assertion {
            credential_id: self.credential_id.clone(),
            client_data_json,
            authenticator_data,
            signature,
            user_handle: self.user_handle.clone(),
        }
    }

    /// Signs `authenticator_data || SHA-256(client_data_json)` (tests that tamper re-sign with this).
    pub fn sign(&self, authenticator_data: &[u8], client_data_json: &[u8]) -> Vec<u8> {
        let mut msg = authenticator_data.to_vec();
        msg.extend_from_slice(&Sha256::digest(client_data_json));
        match &self.key {
            Key::Es256(k) => k.sign(&SystemRandom::new(), &msg).expect("sign").as_ref().to_vec(),
            Key::Ed25519(k) => k.sign(&msg).as_ref().to_vec(),
        }
    }
}

fn cbor_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        _ => {
            out.push(m | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }
}

fn cbor_int(out: &mut Vec<u8>, v: i64) {
    if v >= 0 { cbor_head(out, 0, v as u64) } else { cbor_head(out, 1, (-1 - v) as u64) }
}

fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    cbor_head(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}

fn cbor_text(out: &mut Vec<u8>, s: &str) {
    cbor_head(out, 3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::super::webauthn::*;
    use super::*;

    const ORIGIN: &str = "https://dove.tail1234.ts.net";

    fn rp() -> RelyingParty<'static> {
        RelyingParty { id: "dove.tail1234.ts.net", origin: ORIGIN }
    }

    /// A full registration and two assertions per algorithm, with the counter moving forward.
    #[test]
    fn software_authenticator_round_trip() {
        for mut a in [SoftAuthenticator::es256(ORIGIN), SoftAuthenticator::ed25519(ORIGIN)] {
            let reg = a.register(&[1; 32], &[9; 16]);
            let cred = verify_registration(rp(), &[1; 32], &reg.client_data_json, &reg.attestation_object).unwrap();
            assert_eq!(cred.credential_id, a.credential_id);
            let mut count = cred.sign_count;
            for ch in [[2u8; 32], [3u8; 32]] {
                let s = a.assert(&ch);
                let stored = StoredCredential {
                    alg: cred.alg,
                    public_key: &cred.public_key,
                    sign_count: count,
                    backup_eligible: cred.backup_eligible,
                };
                let r = verify_assertion(rp(), &ch, stored, &s.client_data_json, &s.authenticator_data, &s.signature)
                    .unwrap();
                assert!(r.sign_count > count);
                count = r.sign_count;
            }
        }
    }

    #[test]
    fn missing_uv_and_wrong_rp_are_refused_even_when_signed() {
        let mut a = SoftAuthenticator::es256(ORIGIN);
        a.user_verified = false;
        let reg = a.register(&[1; 32], &[9; 16]);
        assert_eq!(
            verify_registration(rp(), &[1; 32], &reg.client_data_json, &reg.attestation_object),
            Err(Error::UserVerified)
        );
        let mut b = SoftAuthenticator::es256(ORIGIN);
        b.rp_id = "evil.example".into();
        let reg = b.register(&[1; 32], &[9; 16]);
        assert_eq!(
            verify_registration(rp(), &[1; 32], &reg.client_data_json, &reg.attestation_object),
            Err(Error::RpIdHash)
        );
    }
}
