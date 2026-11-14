//! WebAuthn registration and assertion checks for the admin UI's passkeys (design 5.2, PLAN A74).
//!
//! Scope: attestation `none` (any `fmt` is accepted and its statement ignored, because Dove never relies on it),
//! ES256 and EdDSA (Ed25519) credentials, user presence and user verification required, exact origin, no cross-origin
//! use. Every error is a fixed code: nothing from the client's data is echoed.

use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, ED25519, ParsedPublicKey, UnparsedPublicKey};
use sha2::{Digest, Sha256};

use super::cbor::{self, Value};

/// COSE algorithm identifiers Dove accepts.
pub const ALG_ES256: i64 = -7;
pub const ALG_EDDSA: i64 = -8;

/// Longest credential id WebAuthn allows.
pub const MAX_CREDENTIAL_ID: usize = 1023;

const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
const AT: u8 = 0x40;
const ED: u8 = 0x80;

/// The relying party: `id` is the host of the admin origin, `origin` the exact origin (`https://host[:port]`).
#[derive(Debug, Clone, Copy)]
pub struct RelyingParty<'a> {
    pub id: &'a str,
    pub origin: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    ClientData,
    Type,
    Challenge,
    Origin,
    CrossOrigin,
    Attestation,
    AuthData,
    RpIdHash,
    UserPresent,
    UserVerified,
    Algorithm,
    PublicKey,
    Signature,
    Counter,
    BackupEligibility,
    CredentialId,
}

impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Error::ClientData => "client_data",
            Error::Type => "type",
            Error::Challenge => "challenge",
            Error::Origin => "origin",
            Error::CrossOrigin => "cross_origin",
            Error::Attestation => "attestation",
            Error::AuthData => "authenticator_data",
            Error::RpIdHash => "rp_id",
            Error::UserPresent => "user_presence",
            Error::UserVerified => "user_verification",
            Error::Algorithm => "algorithm",
            Error::PublicKey => "public_key",
            Error::Signature => "signature",
            Error::Counter => "sign_count",
            Error::BackupEligibility => "backup_eligibility",
            Error::CredentialId => "credential_id",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "passkey check failed ({})", self.code())
    }
}

impl std::error::Error for Error {}

/// A credential that passed registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCredential {
    pub credential_id: Vec<u8>,
    pub alg: i64,
    /// ES256: the uncompressed SEC1 point (65 bytes). EdDSA: the 32-byte Ed25519 key.
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

/// What Dove stored about a credential.
#[derive(Debug, Clone, Copy)]
pub struct StoredCredential<'a> {
    pub alg: i64,
    pub public_key: &'a [u8],
    pub sign_count: u32,
    pub backup_eligible: bool,
}

/// The result of a valid assertion: the values to store back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asserted {
    pub sign_count: u32,
    pub backup_state: bool,
}

/// Checks a registration (`navigator.credentials.create`) answered for `challenge`.
pub fn verify_registration(
    rp: RelyingParty<'_>,
    challenge: &[u8],
    client_data_json: &[u8],
    attestation_object: &[u8],
) -> Result<NewCredential, Error> {
    verify_registration_inner(rp, challenge, client_data_json, attestation_object, true)
}

/// Checks an assertion (`navigator.credentials.get`) of `stored` answered for `challenge`.
pub fn verify_assertion(
    rp: RelyingParty<'_>,
    challenge: &[u8],
    stored: StoredCredential<'_>,
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
) -> Result<Asserted, Error> {
    verify_assertion_inner(rp, challenge, stored, client_data_json, authenticator_data, signature, true)
}

/// `require_uv` is false only for the published test vectors, which were made without user verification.
fn verify_registration_inner(
    rp: RelyingParty<'_>,
    challenge: &[u8],
    client_data_json: &[u8],
    attestation_object: &[u8],
    require_uv: bool,
) -> Result<NewCredential, Error> {
    check_client_data(client_data_json, "webauthn.create", challenge, rp.origin)?;
    let att = cbor::decode(attestation_object).map_err(|_| Error::Attestation)?;
    // `fmt` and `attStmt` must be present and well-formed; their content is not used (attestation none).
    let fmt_ok = att.get_text_key("fmt").and_then(Value::as_text).is_some_and(|f| !f.is_empty());
    let stmt_ok = matches!(att.get_text_key("attStmt"), Some(Value::Map(_)));
    let auth_data = att.get_text_key("authData").and_then(Value::as_bytes).ok_or(Error::Attestation)?;
    if !fmt_ok || !stmt_ok {
        return Err(Error::Attestation);
    }
    let ad = parse_auth_data(auth_data, rp.id, require_uv)?;
    let Some(attested) = ad.attested else {
        return Err(Error::AuthData);
    };
    Ok(NewCredential {
        credential_id: attested.credential_id,
        alg: attested.alg,
        public_key: attested.public_key,
        sign_count: ad.sign_count,
        backup_eligible: ad.flags & BE != 0,
        backup_state: ad.flags & BS != 0,
    })
}

fn verify_assertion_inner(
    rp: RelyingParty<'_>,
    challenge: &[u8],
    stored: StoredCredential<'_>,
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
    require_uv: bool,
) -> Result<Asserted, Error> {
    check_client_data(client_data_json, "webauthn.get", challenge, rp.origin)?;
    let ad = parse_auth_data(authenticator_data, rp.id, require_uv)?;
    if ad.attested.is_some() {
        return Err(Error::AuthData);
    }
    if (ad.flags & BE != 0) != stored.backup_eligible {
        return Err(Error::BackupEligibility);
    }
    let mut msg = Vec::with_capacity(authenticator_data.len() + 32);
    msg.extend_from_slice(authenticator_data);
    msg.extend_from_slice(&Sha256::digest(client_data_json));
    let verified = match stored.alg {
        ALG_ES256 => UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, stored.public_key).verify(&msg, signature),
        ALG_EDDSA => UnparsedPublicKey::new(&ED25519, stored.public_key).verify(&msg, signature),
        _ => return Err(Error::Algorithm),
    };
    verified.map_err(|_| Error::Signature)?;
    if (ad.sign_count != 0 || stored.sign_count != 0) && ad.sign_count <= stored.sign_count {
        return Err(Error::Counter);
    }
    Ok(Asserted { sign_count: ad.sign_count, backup_state: ad.flags & BS != 0 })
}

/// clientDataJSON: exact type, exact challenge (base64url without padding, as browsers write it), exact origin, and
/// no cross-origin use.
fn check_client_data(json: &[u8], want_type: &str, challenge: &[u8], origin: &str) -> Result<(), Error> {
    let v: serde_json::Value = serde_json::from_slice(json).map_err(|_| Error::ClientData)?;
    let obj = v.as_object().ok_or(Error::ClientData)?;
    if obj.get("type").and_then(|t| t.as_str()) != Some(want_type) {
        return Err(Error::Type);
    }
    let want_challenge = crate::util::b64url(challenge);
    if obj.get("challenge").and_then(|c| c.as_str()) != Some(want_challenge.as_str()) {
        return Err(Error::Challenge);
    }
    if obj.get("origin").and_then(|o| o.as_str()) != Some(origin) {
        return Err(Error::Origin);
    }
    match obj.get("crossOrigin") {
        None | Some(serde_json::Value::Bool(false)) => {}
        Some(_) => return Err(Error::CrossOrigin),
    }
    if obj.contains_key("topOrigin") {
        return Err(Error::CrossOrigin);
    }
    Ok(())
}

struct AuthData {
    flags: u8,
    sign_count: u32,
    attested: Option<Attested>,
}

struct Attested {
    credential_id: Vec<u8>,
    alg: i64,
    public_key: Vec<u8>,
}

fn parse_auth_data(ad: &[u8], rp_id: &str, require_uv: bool) -> Result<AuthData, Error> {
    if ad.len() < 37 {
        return Err(Error::AuthData);
    }
    let rp_hash = Sha256::digest(rp_id.as_bytes());
    if !bool::from(subtle::ConstantTimeEq::ct_eq(&ad[..32], rp_hash.as_slice())) {
        return Err(Error::RpIdHash);
    }
    let flags = ad[32];
    if flags & UP == 0 {
        return Err(Error::UserPresent);
    }
    if require_uv && flags & UV == 0 {
        return Err(Error::UserVerified);
    }
    if flags & BS != 0 && flags & BE == 0 {
        return Err(Error::AuthData);
    }
    let sign_count = u32::from_be_bytes(ad[33..37].try_into().expect("4 bytes"));
    let mut rest = &ad[37..];
    let attested = if flags & AT != 0 {
        if rest.len() < 18 {
            return Err(Error::AuthData);
        }
        let len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
        if len == 0 || len > MAX_CREDENTIAL_ID {
            return Err(Error::CredentialId);
        }
        rest = &rest[18..];
        if rest.len() < len {
            return Err(Error::AuthData);
        }
        let credential_id = rest[..len].to_vec();
        rest = &rest[len..];
        let (key, used) = cbor::decode_prefix(rest).map_err(|_| Error::PublicKey)?;
        rest = &rest[used..];
        let (alg, public_key) = parse_cose_key(&key)?;
        Some(Attested { credential_id, alg, public_key })
    } else {
        None
    };
    if flags & ED != 0 {
        match cbor::decode(rest) {
            Ok(Value::Map(_)) => {}
            _ => return Err(Error::AuthData),
        }
    } else if !rest.is_empty() {
        return Err(Error::AuthData);
    }
    Ok(AuthData { flags, sign_count, attested })
}

/// A COSE_Key: EC2 P-256 with alg ES256, or OKP Ed25519 with alg EdDSA. The key is checked to be a valid point.
fn parse_cose_key(key: &Value) -> Result<(i64, Vec<u8>), Error> {
    let int = |k: i128| key.get_int_key(k).and_then(Value::as_int);
    let bytes = |k: i128| key.get_int_key(k).and_then(Value::as_bytes);
    let (kty, alg, crv) = (int(1), int(3), int(-1));
    let (alg, public_key) = match (kty, alg, crv) {
        (Some(2), Some(-7), Some(1)) => {
            let (Some(x), Some(y)) = (bytes(-2), bytes(-3)) else { return Err(Error::PublicKey) };
            if x.len() != 32 || y.len() != 32 {
                return Err(Error::PublicKey);
            }
            let mut pk = Vec::with_capacity(65);
            pk.push(0x04);
            pk.extend_from_slice(x);
            pk.extend_from_slice(y);
            ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &pk).map_err(|_| Error::PublicKey)?;
            (ALG_ES256, pk)
        }
        (Some(1), Some(-8), Some(6)) => {
            let Some(x) = bytes(-2) else { return Err(Error::PublicKey) };
            if x.len() != 32 {
                return Err(Error::PublicKey);
            }
            ParsedPublicKey::new(&ED25519, x).map_err(|_| Error::PublicKey)?;
            (ALG_EDDSA, x.to_vec())
        }
        _ => return Err(Error::Algorithm),
    };
    Ok((alg, public_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn vectors() -> HashMap<String, Vec<u8>> {
        include_str!("../../tests/fixtures/webauthn/w3c-vectors.txt")
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(|l| {
                let (k, v) = l.split_once(" = ").unwrap();
                (k.to_string(), hex(v))
            })
            .collect()
    }

    const RP: RelyingParty<'static> = RelyingParty { id: "example.org", origin: "https://example.org" };

    struct Vector {
        v: HashMap<String, Vec<u8>>,
        name: &'static str,
    }

    impl Vector {
        fn get(&self, k: &str) -> Vec<u8> {
            self.v[&format!("{}.{k}", self.name)].clone()
        }
        fn register(&self, rp: RelyingParty<'_>, uv: bool) -> Result<NewCredential, Error> {
            verify_registration_inner(
                rp,
                &self.get("reg.challenge"),
                &self.get("reg.clientDataJSON"),
                &self.get("reg.attestationObject"),
                uv,
            )
        }
        fn assert_with<'k>(
            &self,
            cred: &'k NewCredential,
            f: impl FnOnce(&mut StoredCredential<'k>, &mut Vec<u8>, &mut Vec<u8>, &mut Vec<u8>, &mut Vec<u8>),
        ) -> Result<Asserted, Error> {
            let mut stored = StoredCredential {
                alg: cred.alg,
                public_key: &cred.public_key,
                sign_count: cred.sign_count,
                backup_eligible: cred.backup_eligible,
            };
            let (mut ch, mut cd, mut ad, mut sig) = (
                self.get("get.challenge"),
                self.get("get.clientDataJSON"),
                self.get("get.authenticatorData"),
                self.get("get.signature"),
            );
            f(&mut stored, &mut ch, &mut cd, &mut ad, &mut sig);
            verify_assertion_inner(RP, &ch, stored, &cd, &ad, &sig, false)
        }
    }

    fn vector(name: &'static str) -> Vector {
        Vector { v: vectors(), name }
    }

    /// The W3C Level 3 vectors register and authenticate (ES256 with attestation none, a 1023-byte credential id,
    /// and Ed25519 with a packed attestation statement that is ignored).
    #[test]
    fn w3c_vectors_register_and_authenticate() {
        for (name, alg) in
            [("none-es256", ALG_ES256), ("none-es256-long-credential-id", ALG_ES256), ("packed-eddsa", ALG_EDDSA)]
        {
            let v = vector(name);
            let cred = v.register(RP, false).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(cred.credential_id, v.get("reg.credential_id"), "{name}");
            assert_eq!(cred.alg, alg, "{name}");
            let a = v.assert_with(&cred, |_, _, _, _, _| {}).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(a.sign_count, 0, "{name}");
        }
        let es = vector("none-es256").register(RP, false).unwrap();
        assert!(es.backup_eligible && es.backup_state, "flags 0x59 carry BE and BS");
        assert_eq!(vector("none-es256-long-credential-id").get("reg.credential_id").len(), MAX_CREDENTIAL_ID);
    }

    /// The vectors were made without user verification, which Dove requires.
    #[test]
    fn w3c_vectors_without_uv_are_refused() {
        let v = vector("none-es256");
        assert_eq!(v.register(RP, true), Err(Error::UserVerified));
        let cred = v.register(RP, false).unwrap();
        let stored =
            StoredCredential { alg: cred.alg, public_key: &cred.public_key, sign_count: 0, backup_eligible: true };
        assert_eq!(
            verify_assertion(
                RP,
                &v.get("get.challenge"),
                stored,
                &v.get("get.clientDataJSON"),
                &v.get("get.authenticatorData"),
                &v.get("get.signature")
            ),
            Err(Error::UserVerified)
        );
    }

    #[test]
    fn w3c_cross_origin_vector_is_refused() {
        assert_eq!(vector("none-es256-crossorigin").register(RP, false), Err(Error::CrossOrigin));
    }

    #[test]
    fn registration_binds_challenge_origin_rp_and_type() {
        let v = vector("none-es256");
        let other_rp = RelyingParty { id: "example.com", origin: "https://example.org" };
        assert_eq!(v.register(other_rp, false), Err(Error::RpIdHash));
        let other_origin = RelyingParty { id: "example.org", origin: "https://example.org:8443" };
        assert_eq!(v.register(other_origin, false), Err(Error::Origin));
        let wrong_challenge = verify_registration_inner(
            RP,
            &[0u8; 32],
            &v.get("reg.clientDataJSON"),
            &v.get("reg.attestationObject"),
            false,
        );
        assert_eq!(wrong_challenge, Err(Error::Challenge));
        // An assertion's clientDataJSON is not a registration.
        let as_reg = verify_registration_inner(
            RP,
            &v.get("get.challenge"),
            &v.get("get.clientDataJSON"),
            &v.get("reg.attestationObject"),
            false,
        );
        assert_eq!(as_reg, Err(Error::Type));
        // A registration with trailing bytes after the attestation object, or without attestedCredentialData.
        let mut ao = v.get("reg.attestationObject");
        ao.push(0);
        let r = verify_registration_inner(RP, &v.get("reg.challenge"), &v.get("reg.clientDataJSON"), &ao, false);
        assert_eq!(r, Err(Error::Attestation));
    }

    #[test]
    fn assertion_checks() {
        let v = vector("none-es256");
        let cred = v.register(RP, false).unwrap();
        // Tampered signature, tampered authenticator data (a flipped counter byte), wrong challenge.
        assert_eq!(v.assert_with(&cred, |_, _, _, _, s| s[10] ^= 1), Err(Error::Signature));
        assert_eq!(v.assert_with(&cred, |_, _, _, a, _| a[36] ^= 1), Err(Error::Signature));
        assert_eq!(v.assert_with(&cred, |_, c, _, _, _| c[0] ^= 1), Err(Error::Challenge));
        // A different stored key (the credential of another vector).
        let other = vector("none-es256-long-credential-id").register(RP, false).unwrap();
        assert_eq!(v.assert_with(&cred, |st, _, _, _, _| st.public_key = &other.public_key), Err(Error::Signature));
        // Counter: the authenticator reports 0 while Dove has seen 5.
        assert_eq!(v.assert_with(&cred, |st, _, _, _, _| st.sign_count = 5), Err(Error::Counter));
        // The backup-eligible flag of a credential never changes.
        assert_eq!(v.assert_with(&cred, |st, _, _, _, _| st.backup_eligible = false), Err(Error::BackupEligibility));
        // User presence missing (and the signature no longer matters).
        assert_eq!(v.assert_with(&cred, |_, _, _, a, _| a[32] &= !UP), Err(Error::UserPresent));
        // Unknown algorithm.
        assert_eq!(v.assert_with(&cred, |st, _, _, _, _| st.alg = -257), Err(Error::Algorithm));
        // The registration's clientDataJSON is not an assertion.
        assert_eq!(v.assert_with(&cred, |_, _, cd, _, _| *cd = v.get("reg.clientDataJSON")), Err(Error::Type));
        // Extra bytes after the authenticator data without the ED flag.
        assert_eq!(v.assert_with(&cred, |_, _, _, a, _| a.push(0)), Err(Error::AuthData));
    }

    /// Attested credential data belongs to registration only: an assertion that carries it (properly signed) is refused.
    #[test]
    fn attested_data_in_an_assertion_is_refused() {
        use crate::admin_ui::soft_authenticator::SoftAuthenticator;
        let mut a = SoftAuthenticator::es256(RP.origin);
        let reg_challenge = [3u8; 32];
        let reg = a.register(&reg_challenge, &[1; 16]);
        let cred = verify_registration(RP, &reg_challenge, &reg.client_data_json, &reg.attestation_object).unwrap();
        let ao = crate::admin_ui::cbor::decode(&reg.attestation_object).unwrap();
        let reg_auth_data = ao.get_text_key("authData").and_then(|v| v.as_bytes()).unwrap().to_vec();
        assert_ne!(reg_auth_data[32] & AT, 0);
        let ch = [7u8; 32];
        let cdj =
            format!(r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}"}}"#, crate::util::b64url(&ch), RP.origin)
                .into_bytes();
        let sig = a.sign(&reg_auth_data, &cdj);
        let stored = || StoredCredential {
            alg: cred.alg,
            public_key: &cred.public_key,
            sign_count: cred.sign_count,
            backup_eligible: cred.backup_eligible,
        };
        assert_eq!(verify_assertion(RP, &ch, stored(), &cdj, &reg_auth_data, &sig), Err(Error::AuthData));
        // The same authenticator's ordinary assertion passes, so the refusal above is the attested data.
        let ok = a.assert(&ch);
        let r = verify_assertion(RP, &ch, stored(), &ok.client_data_json, &ok.authenticator_data, &ok.signature);
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn client_data_rules() {
        let ch = [7u8; 32];
        let c = crate::util::b64url(&ch);
        let ok = format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"https://example.org"}}"#);
        assert_eq!(check_client_data(ok.as_bytes(), "webauthn.get", &ch, "https://example.org"), Ok(()));
        let cases = [
            (
                format!(r#"{{"type":"webauthn.get","challenge":"{c}=","origin":"https://example.org"}}"#),
                Error::Challenge,
            ),
            (format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"https://example.org/"}}"#), Error::Origin),
            (format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"http://example.org"}}"#), Error::Origin),
            (
                format!(
                    r#"{{"type":"webauthn.get","challenge":"{c}","origin":"https://example.org","crossOrigin":"no"}}"#
                ),
                Error::CrossOrigin,
            ),
            (
                format!(
                    r#"{{"type":"webauthn.get","challenge":"{c}","origin":"https://example.org","topOrigin":"https://example.org"}}"#
                ),
                Error::CrossOrigin,
            ),
            ("[]".to_string(), Error::ClientData),
            ("{".to_string(), Error::ClientData),
        ];
        for (json, want) in cases {
            assert_eq!(
                check_client_data(json.as_bytes(), "webauthn.get", &ch, "https://example.org"),
                Err(want),
                "{json}"
            );
        }
    }

    #[test]
    fn cose_keys() {
        use cbor::Value::*;
        let v = vector("none-es256");
        let cred = v.register(RP, false).unwrap();
        let (x, y) = (cred.public_key[1..33].to_vec(), cred.public_key[33..].to_vec());
        let ec = |alg: i128, crv: i128, x: Vec<u8>, y: Vec<u8>| {
            Map(vec![
                (Int(1), Int(2)),
                (Int(3), Int(alg)),
                (Int(-1), Int(crv)),
                (Int(-2), Bytes(x)),
                (Int(-3), Bytes(y)),
            ])
        };
        assert_eq!(parse_cose_key(&ec(-7, 1, x.clone(), y.clone())).unwrap(), (ALG_ES256, cred.public_key.clone()));
        assert_eq!(parse_cose_key(&ec(-35, 2, x.clone(), y.clone())), Err(Error::Algorithm), "ES384");
        assert_eq!(parse_cose_key(&ec(-7, 1, x.clone(), y[..31].to_vec())), Err(Error::PublicKey));
        let mut off_curve = y.clone();
        off_curve[31] ^= 1;
        assert_eq!(parse_cose_key(&ec(-7, 1, x, off_curve)), Err(Error::PublicKey), "a point off the curve");
        let rsa = Map(vec![(Int(1), Int(3)), (Int(3), Int(-257))]);
        assert_eq!(parse_cose_key(&rsa), Err(Error::Algorithm));
    }
}
