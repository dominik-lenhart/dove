//! Local administration over a Unix socket (spec 5.5, FR-C1).
//!
//! Authority comes only from the kernel-reported peer uid of the socket connection (operator uid or root). The CLI
//! binary carries no authority; agent bearer tokens are never accepted here.

pub mod client;
pub mod ops;
pub mod server;
pub mod transport;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::audit::SearchFilter;
use crate::imap::ServerEndpoint;
use ops::GrantSpec;

/// A mailbox password inside an admin request: zeroized on drop, never printed by `Debug`.
#[derive(Clone, Default)]
pub struct Password(pub Zeroizing<String>);

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

impl Serialize for Password {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Password {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self(Zeroizing::new(String::deserialize(d)?)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminRequest {
    ProjectsCreate {
        name: String,
    },
    ProjectsAddAccount {
        project: String,
        account: String,
    },
    ProjectsRemoveAccount {
        project: String,
        account: String,
    },
    ProjectsList,
    ProjectsShow {
        name: String,
    },

    AccountsList,
    AccountsConnect {
        alias: String,
        email: String,
    },
    AccountsReconnect {
        alias: String,
    },
    /// Connects an IMAP/SMTP mailbox after verifying both logins (design "Account model and connect").
    AccountsConnectImap {
        alias: String,
        email: String,
        username: Option<String>,
        smtp_username: Option<String>,
        password: Password,
        imap: Option<ServerEndpoint>,
        smtp: Option<ServerEndpoint>,
        drafts_folder: Option<String>,
        preset: Option<String>,
    },
    /// Replaces an IMAP mailbox's password after verifying it.
    AccountsReconnectImap {
        alias: String,
        password: Password,
    },
    AccountsRemove {
        alias: String,
    },
    AccountsDisable {
        alias: String,
    },
    AccountsEnable {
        alias: String,
    },
    AccountsCheck {
        alias: Option<String>,
    },
    /// Adds a send-as alias to an IMAP mailbox (`envelope`: the SMTP server accepts it as envelope sender).
    AccountsAliasAdd {
        account: String,
        address: String,
        name: Option<String>,
        #[serde(default)]
        envelope: bool,
    },
    AccountsAliasList {
        account: String,
    },
    AccountsAliasRemove {
        account: String,
        address: String,
    },
    /// Sets (`Some`) or clears (`None`) the plain-text signature of a mailbox, or of one of its aliases.
    AccountsSignatureSet {
        account: String,
        alias: Option<String>,
        signature: Option<String>,
    },
    AccountsSignatureShow {
        account: String,
        alias: Option<String>,
    },
    /// The mailbox's named signatures (design 2026-11-17 "html signatures").
    AccountsSignaturesList {
        account: String,
        #[serde(default)]
        include_html: bool,
    },
    /// Creates or changes named signature `name`; `None` fields keep their value, `images` replaces all images.
    AccountsSignaturePut {
        account: String,
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        html: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        images: Option<Vec<SignatureImage>>,
    },
    AccountsSignatureDelete {
        account: String,
        name: String,
    },
    /// Makes `name` the default of the mailbox or of `alias` (a send-as address); `None` removes that default.
    AccountsSignatureDefault {
        account: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        alias: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },

    ClientsCreate {
        name: String,
        project: String,
        grants: Vec<GrantSpec>,
        expires: Option<String>,
        #[serde(default)]
        allow_ip: Vec<String>,
        /// Hide secrets in overview results (PLAN A60). `None`: the server's `clients.redact_secrets_default` (A66).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        redact_secrets: Option<bool>,
    },
    ClientsSetGrants {
        name: String,
        grants: Vec<GrantSpec>,
    },
    ClientsRotate {
        name: String,
    },
    ClientsRevoke {
        name: String,
    },
    ClientsShow {
        name: String,
    },
    /// Turns secret redaction in overview results on or off for a connection, or for an open invitation of that
    /// connection name (PLAN A60).
    ClientsSetRedaction {
        name: String,
        enabled: bool,
    },
    ClientsList,
    ClientsInvite {
        name: String,
        project: String,
        /// `all` or explicit aliases.
        accounts: Vec<String>,
        capabilities: String,
        expires: Option<String>,
        #[serde(default)]
        allow_ip: Vec<String>,
        /// The redeemed connection hides secrets in overview results (PLAN A60). `None`: the server's
        /// `clients.redact_secrets_default` (A66).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        redact_secrets: Option<bool>,
    },

    AuditTail {
        limit: Option<i64>,
    },
    AuditSearch {
        filter: SearchFilter,
    },
    AuditVerify,
    AuditPrune,
    /// Agent activity per day and per connection, and the values in the log (the admin UI's overview and search).
    AuditStats,

    KeysRotate,
    Doctor,
    /// The running service's version (`dove upgrade` compares it with the new binary).
    Version,
    /// Local mode only: stop the service gracefully (`dove local stop`, uninstall). A Windows logon task cannot stop
    /// it reliably: `schtasks /End` ends `conhost`, not necessarily the `dove.exe` it started.
    Shutdown,
    Export,

    IndexEnable {
        alias: String,
    },
    IndexDisable {
        alias: String,
    },
    IndexStatus {
        alias: Option<String>,
    },
    IndexRebuild {
        alias: String,
    },

    /// Registers a webhook sink for watch push delivery (design 0.2 section 3). The secret is sealed by the service.
    SinksAdd {
        name: String,
        project: String,
        url: String,
        secret: Password,
    },
    SinksList,
    SinksRemove {
        name: String,
    },
    /// Moves a sink to a project (sinks from before 0.6 have none and serve no client).
    SinksSetProject {
        name: String,
        project: String,
    },
    /// Lists the watches of every client for the owner: ids, client, mailbox, kind and times. Filters and threads
    /// are not shown.
    WatchesList,
    /// Deletes one watch; its events and queued pushes go with it.
    WatchesRemove {
        id: String,
    },

    OperationsList,
    OperationsRemove {
        client: String,
        account: String,
        request_key: String,
    },

    /// Agent requests (design 2026-11-14 section 4.7): every client's requests, optionally with one status.
    RequestsList {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<String>,
    },
    /// One request with its note and each draft as it is now (operator only).
    RequestsShow {
        id: String,
    },
    /// Approves the chosen pending items (`None`: all) at the revisions the operator was shown.
    RequestsApprove {
        id: String,
        shown: Vec<ShownItem>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        items: Option<Vec<u32>>,
        #[serde(default)]
        late: Late,
        /// Access requests: grant for this many minutes instead of what the agent asked (shorter only; on a request
        /// for a permanent grant it makes the grant temporary). Optional so a CLI from before stage 2 still parses.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_minutes: Option<u32>,
    },
    RequestsDeny {
        id: String,
    },
    /// Stops unsent items (all, or the chosen ones).
    RequestsCancel {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        items: Option<Vec<u32>>,
    },

    /// Admin UI (design 2026-11-14 section 5.2): a one-time link (5 minutes) that enrols a passkey named `name`.
    PasskeysAdd {
        name: String,
    },
    PasskeysList,
    /// Removes a passkey and ends its sessions.
    PasskeysRemove {
        name: String,
    },
    /// Signed-in admin UI sessions.
    SessionsList,
    /// Ends one admin UI session (`id`) or all of them.
    SessionsRevoke {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },

    /// Web Push (design 2026-11-16): registers this browser's subscription as a device named `name`.
    PushAdd {
        name: String,
        subscription: crate::push::Subscription,
    },
    /// Devices that receive pushes.
    PushList,
    /// Stops pushing to a device.
    PushRemove {
        id: String,
    },
    /// Sends a test notification to one device (`id`) or all of them, and reports each outcome.
    PushTest {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
}

/// The revision of one item's draft as `requests show` printed it; approval is refused when it changed since.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShownItem {
    pub idx: u32,
    pub revision: String,
}

/// What to do with approved items whose time has already passed: skip them (default) or send them now.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Late {
    #[default]
    Skip,
    Send,
}

impl AdminRequest {
    /// Audit fields: (action, project, account, object ids).
    pub fn audit_fields(&self) -> (&'static str, Option<String>, Option<String>, Vec<String>) {
        use AdminRequest::*;
        match self {
            ProjectsCreate { name } => ("projects.create", Some(name.clone()), None, vec![]),
            ProjectsAddAccount { project, account } => {
                ("projects.add_account", Some(project.clone()), Some(account.clone()), vec![])
            }
            ProjectsRemoveAccount { project, account } => {
                ("projects.remove_account", Some(project.clone()), Some(account.clone()), vec![])
            }
            ProjectsList => ("projects.list", None, None, vec![]),
            ProjectsShow { name } => ("projects.show", Some(name.clone()), None, vec![]),
            AccountsList => ("accounts.list", None, None, vec![]),
            AccountsConnect { alias, .. } => ("accounts.connect", None, Some(alias.clone()), vec![]),
            AccountsReconnect { alias } => ("accounts.reconnect", None, Some(alias.clone()), vec![]),
            AccountsConnectImap { alias, .. } => ("accounts.connect_imap", None, Some(alias.clone()), vec![]),
            AccountsReconnectImap { alias, .. } => ("accounts.reconnect_imap", None, Some(alias.clone()), vec![]),
            AccountsRemove { alias } => ("accounts.remove", None, Some(alias.clone()), vec![]),
            AccountsDisable { alias } => ("accounts.disable", None, Some(alias.clone()), vec![]),
            AccountsEnable { alias } => ("accounts.enable", None, Some(alias.clone()), vec![]),
            AccountsCheck { alias } => ("accounts.check", None, alias.clone(), vec![]),
            // Alias addresses and signature text are configuration, but stay out of the audit log anyway.
            AccountsAliasAdd { account, .. } => ("accounts.alias_add", None, Some(account.clone()), vec![]),
            AccountsAliasList { account } => ("accounts.alias_list", None, Some(account.clone()), vec![]),
            AccountsAliasRemove { account, .. } => ("accounts.alias_remove", None, Some(account.clone()), vec![]),
            AccountsSignatureSet { account, signature, .. } => (
                if signature.is_some() { "accounts.signature_set" } else { "accounts.signature_clear" },
                None,
                Some(account.clone()),
                vec![],
            ),
            AccountsSignatureShow { account, .. } => ("accounts.signature_show", None, Some(account.clone()), vec![]),
            AccountsSignaturesList { account, .. } => ("accounts.signatures_list", None, Some(account.clone()), vec![]),
            AccountsSignaturePut { account, name, .. } => {
                ("accounts.signature_put", None, Some(account.clone()), vec![format!("signature:{name}")])
            }
            AccountsSignatureDelete { account, name } => {
                ("accounts.signature_delete", None, Some(account.clone()), vec![format!("signature:{name}")])
            }
            AccountsSignatureDefault { account, name, .. } => (
                "accounts.signature_default",
                None,
                Some(account.clone()),
                name.iter().map(|n| format!("signature:{n}")).collect(),
            ),
            ClientsCreate { name, project, .. } => ("clients.create", Some(project.clone()), None, vec![name.clone()]),
            ClientsSetGrants { name, .. } => ("clients.set_grants", None, None, vec![name.clone()]),
            ClientsRotate { name } => ("clients.rotate", None, None, vec![name.clone()]),
            ClientsRevoke { name } => ("clients.revoke", None, None, vec![name.clone()]),
            ClientsShow { name } => ("clients.show", None, None, vec![name.clone()]),
            ClientsSetRedaction { name, enabled } => (
                if *enabled { "clients.redaction_on" } else { "clients.redaction_off" },
                None,
                None,
                vec![name.clone()],
            ),
            ClientsList => ("clients.list", None, None, vec![]),
            ClientsInvite { name, project, .. } => ("clients.invite", Some(project.clone()), None, vec![name.clone()]),
            AuditTail { .. } => ("audit.tail", None, None, vec![]),
            AuditSearch { .. } => ("audit.search", None, None, vec![]),
            AuditVerify => ("audit.verify", None, None, vec![]),
            AuditStats => ("audit.stats", None, None, vec![]),
            AuditPrune => ("audit.prune_request", None, None, vec![]),
            KeysRotate => ("keys.rotate", None, None, vec![]),
            Doctor => ("doctor", None, None, vec![]),
            Version => ("version", None, None, vec![]),
            Shutdown => ("service.shutdown", None, None, vec![]),
            Export => ("export", None, None, vec![]),
            IndexEnable { alias } => ("index.enable", None, Some(alias.clone()), vec![]),
            IndexDisable { alias } => ("index.disable", None, Some(alias.clone()), vec![]),
            IndexStatus { alias } => ("index.status", None, alias.clone(), vec![]),
            IndexRebuild { alias } => ("index.rebuild", None, Some(alias.clone()), vec![]),
            SinksAdd { name, project, .. } => ("sinks.add", Some(project.clone()), None, vec![name.clone()]),
            SinksSetProject { name, project } => ("sinks.set_project", Some(project.clone()), None, vec![name.clone()]),
            SinksList => ("sinks.list", None, None, vec![]),
            SinksRemove { name } => ("sinks.remove", None, None, vec![name.clone()]),
            WatchesList => ("watches.list", None, None, vec![]),
            WatchesRemove { id } => ("watches.remove", None, None, vec![id.clone()]),
            OperationsList => ("operations.list", None, None, vec![]),
            OperationsRemove { client, account, request_key } => {
                ("operations.remove", None, Some(account.clone()), vec![client.clone(), request_key.clone()])
            }
            // Request ids only: the note and the drafts' content never reach the audit log.
            RequestsList { .. } => ("requests.list", None, None, vec![]),
            RequestsShow { id } => ("requests.show", None, None, vec![id.clone()]),
            RequestsApprove { id, .. } => ("requests.approve", None, None, vec![id.clone()]),
            RequestsDeny { id } => ("requests.deny", None, None, vec![id.clone()]),
            RequestsCancel { id, .. } => ("requests.cancel", None, None, vec![id.clone()]),
            // Passkey names are operator-chosen labels; session ids are opaque. Enrolment tokens never appear here.
            PasskeysAdd { name } => ("passkeys.add", None, None, vec![name.clone()]),
            PasskeysList => ("passkeys.list", None, None, vec![]),
            PasskeysRemove { name } => ("passkeys.remove", None, None, vec![name.clone()]),
            SessionsList => ("sessions.list", None, None, vec![]),
            SessionsRevoke { id } => ("sessions.revoke", None, None, id.iter().cloned().collect()),
            // Device names are operator-chosen labels; the subscription (a capability URL and keys) never appears.
            PushAdd { name, .. } => ("push.add", None, None, vec![name.clone()]),
            PushList => ("push.list", None, None, vec![]),
            PushRemove { id } => ("push.remove", None, None, vec![id.clone()]),
            PushTest { id } => ("push.test", None, None, id.iter().cloned().collect()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AdminResponse {
    pub fn ok(v: Value) -> Self {
        Self { ok: true, result: Some(v), error: None }
    }
    pub fn err(e: impl std::fmt::Display) -> Self {
        Self { ok: false, result: None, error: Some(e.to_string()) }
    }
}

/// One inline image of [`AdminRequest::AccountsSignaturePut`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignatureImage {
    pub cid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    pub data_base64: String,
}

/// Maximum size of one admin request line: large enough for a signature with its images (512 KiB as base64 plus
/// 64 KiB of HTML, JSON-escaped).
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;
