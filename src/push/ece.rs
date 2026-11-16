//! RFC 8291 message encryption for Web Push (`aes128gcm`, RFC 8188), one record, with aws-lc-rs: P-256 ECDH, HKDF-SHA256
//! and AES-128-GCM. Checked against the RFC's own example (Appendix A) in the tests below. Same code as rootnod's hub.

use aws_lc_rs::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, ECDH_P256, PrivateKey, UnparsedPublicKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Prk, Salt};

/// The record size announced in the header; a payload must fit in one record.
const RS: u32 = 4096;
pub const KEY_LEN: usize = 65;

struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand(prk: &Prk, info: &[&[u8]], out: &mut [u8]) -> Result<(), String> {
    prk.expand(info, Len(out.len())).and_then(|o| o.fill(out)).map_err(|_| "hkdf".to_string())
}

/// Content key and nonce from the ECDH secret (RFC 8291 §3.3, §3.4; RFC 8188 §2.2, §2.3).
fn keys(
    ecdh: &[u8],
    auth: &[u8; 16],
    ua_public: &[u8],
    as_public: &[u8],
    salt: &[u8; 16],
) -> Result<([u8; 16], [u8; 12]), String> {
    let prk_key = Salt::new(HKDF_SHA256, auth).extract(ecdh);
    let mut ikm = [0u8; 32];
    expand(&prk_key, &[b"WebPush: info\0", ua_public, as_public], &mut ikm)?;
    let prk = Salt::new(HKDF_SHA256, salt).extract(&ikm);
    let (mut cek, mut nonce) = ([0u8; 16], [0u8; 12]);
    expand(&prk, &[b"Content-Encoding: aes128gcm\0"], &mut cek)?;
    expand(&prk, &[b"Content-Encoding: nonce\0"], &mut nonce)?;
    Ok((cek, nonce))
}

fn ecdh(private: &PrivateKey, public: &[u8]) -> Result<Vec<u8>, String> {
    agreement::agree(private, UnparsedPublicKey::new(&ECDH_P256, public), "bad P-256 key".to_string(), |s| {
        Ok(s.to_vec())
    })
}

/// Whether `key` is a usable P-256 public key (uncompressed point).
pub fn valid_public_key(key: &[u8]) -> bool {
    key.len() == KEY_LEN && PrivateKey::generate(&ECDH_P256).is_ok_and(|k| ecdh(&k, key).is_ok())
}

/// Encrypts for the browser's key `ua_public` and secret `auth` with a fresh key and salt.
pub fn encrypt(plaintext: &[u8], ua_public: &[u8], auth: &[u8; 16]) -> Result<Vec<u8>, String> {
    let as_private = PrivateKey::generate(&ECDH_P256).map_err(|_| "keygen")?;
    let salt = crate::util::random_bytes::<16>();
    encrypt_with(&as_private, &salt, plaintext, ua_public, auth)
}

fn encrypt_with(
    as_private: &PrivateKey,
    salt: &[u8; 16],
    plaintext: &[u8],
    ua_public: &[u8],
    auth: &[u8; 16],
) -> Result<Vec<u8>, String> {
    if plaintext.len() + 17 > RS as usize {
        return Err("payload too large".into());
    }
    let as_public = as_private.compute_public_key().map_err(|_| "public key")?;
    let as_public = as_public.as_ref();
    let (cek, nonce) = keys(&ecdh(as_private, ua_public)?, auth, ua_public, as_public, salt)?;
    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &cek).map_err(|_| "aes key")?);
    let mut record = plaintext.to_vec();
    record.push(2); // the last (only) record's delimiter
    key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut record).map_err(|_| "seal")?;
    let mut out = Vec::with_capacity(16 + 4 + 1 + as_public.len() + record.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&RS.to_be_bytes());
    out.push(u8::try_from(as_public.len()).map_err(|_| "key id")?);
    out.extend_from_slice(as_public);
    out.extend_from_slice(&record);
    Ok(out)
}

/// The browser's side (tests and the fake push service): decrypts with its private key (32 bytes) and secret.
pub fn decrypt(body: &[u8], ua_private: &[u8], auth: &[u8; 16]) -> Result<Vec<u8>, String> {
    let ua = PrivateKey::from_private_key(&ECDH_P256, ua_private).map_err(|_| "bad private key")?;
    let ua_public = ua.compute_public_key().map_err(|_| "public key")?;
    let salt: [u8; 16] = body.get(..16).and_then(|s| s.try_into().ok()).ok_or("short")?;
    let idlen = usize::from(*body.get(20).ok_or("short")?);
    let as_public = body.get(21..21 + idlen).ok_or("short")?;
    let (cek, nonce) = keys(&ecdh(&ua, as_public)?, auth, ua_public.as_ref(), as_public, &salt)?;
    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &cek).map_err(|_| "aes key")?);
    let mut record = body.get(21 + idlen..).ok_or("short")?.to_vec();
    let plain =
        key.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut record).map_err(|_| "open")?;
    match plain.iter().rposition(|&b| b != 0) {
        Some(i) if plain[i] == 2 => Ok(plain[..i].to_vec()),
        _ => Err("bad padding".into()),
    }
}

/// The public key for a raw P-256 private key (tests and the fake push service).
pub fn public_key(private: &[u8]) -> Result<Vec<u8>, String> {
    let k = PrivateKey::from_private_key(&ECDH_P256, private).map_err(|_| "bad private key")?;
    Ok(k.compute_public_key().map_err(|_| "public key")?.as_ref().to_vec())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::*;

    fn b(s: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(s).unwrap()
    }

    /// RFC 8291, Appendix A.
    #[test]
    fn the_rfc_example() {
        let plaintext = b"When I grow up, I want to be a watermelon";
        let as_private =
            PrivateKey::from_private_key(&ECDH_P256, &b("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")).unwrap();
        let ua_private = b("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94");
        let ua_public = b("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4");
        assert_eq!(public_key(&ua_private).unwrap(), ua_public);
        let auth: [u8; 16] = b("BTBZMqHH6r4Tts7J_aSIgg").try_into().unwrap();
        let salt: [u8; 16] = b("DGv6ra1nlYgDCS1FRnbzlw").try_into().unwrap();
        let out = encrypt_with(&as_private, &salt, plaintext, &ua_public, &auth).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&out),
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
        );
        assert_eq!(decrypt(&out, &ua_private, &auth).unwrap(), plaintext);
    }

    #[test]
    fn round_trip_and_tampering() {
        let ua_private = [7u8; 32];
        let ua_public = public_key(&ua_private).unwrap();
        assert!(valid_public_key(&ua_public));
        assert!(!valid_public_key(&[4; 65]) && !valid_public_key(&ua_public[..64]));
        let auth = [9u8; 16];
        let out = encrypt(b"hello", &ua_public, &auth).unwrap();
        assert_eq!(decrypt(&out, &ua_private, &auth).unwrap(), b"hello");
        assert!(decrypt(&out, &ua_private, &[8; 16]).is_err());
        let mut bad = out.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(decrypt(&bad, &ua_private, &auth).is_err());
        assert!(encrypt(&[0; 4080], &ua_public, &auth).is_err());
    }
}
