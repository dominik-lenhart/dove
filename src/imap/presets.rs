//! Compiled-in server presets by email domain (design "Account model and connect"). No network autodiscovery.
//! Strato and iCloud are decided in the design; further presets are deliberately left out until verified.

use super::{ServerEndpoint, TlsMode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preset {
    pub name: &'static str,
    pub imap: ServerEndpoint,
    pub smtp: ServerEndpoint,
    /// False where the provider stores a Sent copy itself on SMTP submission.
    pub save_sent_copy: bool,
}

fn ep(host: &str, port: u16, tls: TlsMode) -> ServerEndpoint {
    ServerEndpoint { host: host.into(), port, tls }
}

/// A preset by name (`--preset strato|icloud`), for custom domains hosted by that provider.
pub fn by_name(name: &str) -> Option<Preset> {
    match name.trim().to_ascii_lowercase().as_str() {
        "strato" => Some(Preset {
            name: "strato",
            imap: ep("imap.strato.de", 993, TlsMode::Implicit),
            smtp: ep("smtp.strato.de", 465, TlsMode::Implicit),
            save_sent_copy: true,
        }),
        "icloud" => Some(Preset {
            name: "icloud",
            imap: ep("imap.mail.me.com", 993, TlsMode::Implicit),
            smtp: ep("smtp.mail.me.com", 587, TlsMode::StartTls),
            // iCloud is expected to file submitted mail into Sent itself (unverified until the first real send).
            save_sent_copy: false,
        }),
        _ => None,
    }
}

/// The preset for an address's domain, if known.
pub fn for_email(email: &str) -> Option<Preset> {
    let domain = email.rsplit_once('@')?.1.trim().to_ascii_lowercase();
    match domain.as_str() {
        "strato.de" => by_name("strato"),
        "icloud.com" | "me.com" | "mac.com" => by_name("icloud"),
        _ => None,
    }
}
