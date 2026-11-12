//! Local administration over a Unix socket (spec 5.5, FR-C1).
//!
//! Authority comes only from the kernel-reported peer uid of the socket connection (operator uid or root). The CLI
//! binary carries no authority; agent bearer tokens are never accepted here.

pub mod client;
pub mod ops;
pub mod server;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audit::SearchFilter;
use ops::GrantSpec;

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

    ClientsCreate {
        name: String,
        project: String,
        grants: Vec<GrantSpec>,
        expires: Option<String>,
        #[serde(default)]
        allow_ip: Vec<String>,
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
    },

    AuditTail {
        limit: Option<i64>,
    },
    AuditSearch {
        filter: SearchFilter,
    },
    AuditVerify,
    AuditPrune,

    KeysRotate,
    Doctor,
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

    OperationsList,
    OperationsRemove {
        client: String,
        account: String,
        request_key: String,
    },
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
            AccountsRemove { alias } => ("accounts.remove", None, Some(alias.clone()), vec![]),
            AccountsDisable { alias } => ("accounts.disable", None, Some(alias.clone()), vec![]),
            AccountsEnable { alias } => ("accounts.enable", None, Some(alias.clone()), vec![]),
            AccountsCheck { alias } => ("accounts.check", None, alias.clone(), vec![]),
            ClientsCreate { name, project, .. } => ("clients.create", Some(project.clone()), None, vec![name.clone()]),
            ClientsSetGrants { name, .. } => ("clients.set_grants", None, None, vec![name.clone()]),
            ClientsRotate { name } => ("clients.rotate", None, None, vec![name.clone()]),
            ClientsRevoke { name } => ("clients.revoke", None, None, vec![name.clone()]),
            ClientsShow { name } => ("clients.show", None, None, vec![name.clone()]),
            ClientsList => ("clients.list", None, None, vec![]),
            ClientsInvite { name, project, .. } => ("clients.invite", Some(project.clone()), None, vec![name.clone()]),
            AuditTail { .. } => ("audit.tail", None, None, vec![]),
            AuditSearch { .. } => ("audit.search", None, None, vec![]),
            AuditVerify => ("audit.verify", None, None, vec![]),
            AuditPrune => ("audit.prune_request", None, None, vec![]),
            KeysRotate => ("keys.rotate", None, None, vec![]),
            Doctor => ("doctor", None, None, vec![]),
            Export => ("export", None, None, vec![]),
            IndexEnable { alias } => ("index.enable", None, Some(alias.clone()), vec![]),
            IndexDisable { alias } => ("index.disable", None, Some(alias.clone()), vec![]),
            IndexStatus { alias } => ("index.status", None, alias.clone(), vec![]),
            IndexRebuild { alias } => ("index.rebuild", None, Some(alias.clone()), vec![]),
            OperationsList => ("operations.list", None, None, vec![]),
            OperationsRemove { client, account, request_key } => {
                ("operations.remove", None, Some(account.clone()), vec![client.clone(), request_key.clone()])
            }
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

/// Maximum size of one admin request line.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
