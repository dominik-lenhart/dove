//! Admin web UI under `/admin` (design 2026-11-14 section 5, PLAN A73).

pub mod cbor;
#[cfg(any(test, feature = "testing"))]
pub mod soft_authenticator;
pub mod webauthn;
