//! Draft tools: create_draft, update_draft, send_draft (spec 5.3, 6.3, 7.6, 7.7).
//!
//! Writes are never replayed automatically. create_draft is idempotent per request_key; update and send re-read the
//! draft fresh, compare it with the last Dove-written revision and the caller's expected revision, and are
//! serialized per draft. A draft changed outside Dove is human-owned from then on.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};

use super::read::{fmt_addrs, from_meta};
use super::{
    AuditInfo, ToolCx, ToolDef, ToolOutput, account_arg, account_schema, arg_str, compose, detached, gmail_id_arg,
    object_schema, only_keys, opt_bool, opt_str,
};
use crate::error::{ErrorCode, ToolError};
use crate::gmail::WriteError;
use crate::gmail::gateway::{GmailOp, Priority, SendPermit};
use crate::mime::{self, Addr, DraftFields};
use crate::policy::{Capability, Mailbox, Provider};
use crate::util;

/// Per-(account, draft) async locks so Dove operations on one draft never interleave.
type DraftLock = Arc<tokio::sync::Mutex<()>>;

#[derive(Default)]
pub struct DraftLocks(Mutex<HashMap<(String, String), DraftLock>>);

impl DraftLocks {
    pub fn get(&self, account_id: &str, draft_id: &str) -> DraftLock {
        let mut m = self.0.lock().expect("lock");
        // Opportunistic cleanup of idle locks.
        if m.len() > 1024 {
            m.retain(|_, v| Arc::strong_count(v) > 1);
        }
        m.entry((account_id.to_string(), draft_id.to_string())).or_default().clone()
    }
}

fn attachments_schema() -> Value {
    json!({ "type": "array", "maxItems": mime::MAX_DRAFT_ATTACHMENTS, "description": concat!(
        "Files to attach. Either a reference {ref | account + message_id, attachment_id} to an attachment of a message ",
        "you can read, or inline {filename, mime_type, content_base64}."
    ), "items": { "type": "object", "properties": {
        "ref": { "type": "string" }, "account": { "type": "string" }, "message_id": { "type": "string" },
        "attachment_id": { "type": "string", "description": "From get_message attachments[].attachment_id." },
        "filename": { "type": "string" }, "mime_type": { "type": "string", "description": "type/subtype, e.g. application/pdf" },
        "content_base64": { "type": "string" }
    }, "additionalProperties": false } })
}

pub fn defs() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "create_draft",
            title: "Create draft",
            description: concat!(
                "Create a new draft, a threaded reply (reply_to_message_id, quotes the original by default) or a ",
                "forward (forward_message_id or forward_ref, includes the original's attachments by default) in a ",
                "mailbox's server Drafts. Attach files by reference to a message you can read (bytes stay on the ",
                "server) or inline as base64: at most 10 per draft, 10 MiB in total by default. Recipients are never ",
                "inferred. If the operator set a signature for the sender it is appended after body_text (before a ",
                "quote or forward block) unless you pass signature: false; update_draft never adds it again. ",
                "Generate a fresh UUID request_key per intent and reuse it only to retry the same request. ",
                "The owner reviews and sends it in Apple Mail unless send rights exist."
            ),
            capability: Capability::Draft,
            read_only: false,
            destructive: false,
            input_schema: || {
                let r = json!({ "type": "array", "items": { "type": "string" }, "maxItems": 50 });
                json!({ "type": "object", "properties": {
                    "account": account_schema(),
                    "request_key": { "type": "string", "description": "Client-generated UUID for idempotent retries." },
                    "to": r, "cc": r, "bcc": r,
                    "subject": { "type": "string" },
                    "body_text": { "type": "string" },
                    "reply_to_message_id": { "type": "string" },
                    "quote_original": { "type": "boolean", "description": "Replies: quote the original's text below body_text (default true when you have read on this mailbox)." },
                    "forward_message_id": { "type": "string", "description": "Forward this message of `account` (needs read)." },
                    "forward_ref": { "type": "string", "description": "Forward the message of this ref from search_messages (any mailbox you can read)." },
                    "include_attachments": { "type": "boolean", "description": "Forwards: attach the original's attachments (default true)." },
                    "attachments": attachments_schema(),
                    "from_address": { "type": "string", "description": "The mailbox address or one of its send-as aliases (list_accounts shows from_addresses for IMAP mailboxes; Gmail uses the account's send-as list)." },
                    "signature": { "type": "boolean", "description": "Append the sender's signature after body_text (default true; nothing happens when none is set)." }
                }, "required": ["account", "request_key", "body_text"], "additionalProperties": false })
            },
            output_schema: || {
                object_schema(
                    json!({ "account": {"type":"string"}, "draft_id": {"type":"string"}, "message_id": {"type":"string"}, "thread_id": {"type":"string"}, "revision": {"type":"string"} }),
                )
            },
            handler: |cx, args| detached(cx, args, |cx, args| Box::pin(create_draft(cx, args))),
        },
        ToolDef {
            name: "update_draft",
            title: "Revise draft",
            description: concat!(
                "Patch a draft this project created, conditional on expected_revision. Omitted fields are kept, ",
                "including attachments; changes.attachments replaces the whole list ([] removes all). ",
                "Fails with draft_conflict if the draft changed elsewhere (for example saved in Apple Mail)."
            ),
            capability: Capability::Draft,
            read_only: false,
            destructive: true,
            input_schema: || {
                let r = json!({ "type": "array", "items": { "type": "string" }, "maxItems": 50 });
                json!({ "type": "object", "properties": {
                    "account": account_schema(),
                    "draft_id": { "type": "string" },
                    "expected_revision": { "type": "string" },
                    "changes": { "type": "object", "properties": {
                        "to": r, "cc": r, "bcc": r, "subject": { "type": "string" }, "body_text": { "type": "string" },
                        "attachments": attachments_schema()
                    }, "additionalProperties": false }
                }, "required": ["account", "draft_id", "expected_revision", "changes"], "additionalProperties": false })
            },
            output_schema: || object_schema(json!({ "draft_id": {"type":"string"}, "revision": {"type":"string"} })),
            handler: |cx, args| detached(cx, args, |cx, args| Box::pin(update_draft(cx, args))),
        },
        ToolDef {
            name: "send_draft",
            title: "Send draft",
            description: concat!(
                "Send one existing draft this project created, unchanged since expected_revision. Only available when ",
                "the operator enabled sending and granted send on this mailbox. Accepts no recipients or content."
            ),
            capability: Capability::Send,
            read_only: false,
            destructive: true,
            input_schema: || {
                json!({ "type": "object", "properties": {
                    "account": account_schema(), "draft_id": { "type": "string" }, "expected_revision": { "type": "string" }
                }, "required": ["account", "draft_id", "expected_revision"], "additionalProperties": false })
            },
            output_schema: || {
                object_schema(
                    json!({ "sent_message_id": {"type":["string","null"]}, "thread_id": {"type":["string","null"]} }),
                )
            },
            handler: |cx, args| detached(cx, args, |cx, args| Box::pin(send_draft(cx, args))),
        },
    ]
}

// ------------------------------------------------------------------ helpers

fn addr_list(args: &Value, key: &str) -> Result<Vec<Addr>, ToolError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(a)) if a.len() <= 50 => a
            .iter()
            .map(|v| {
                let s = v.as_str().ok_or_else(|| ToolError::invalid(format!("'{key}' must contain strings")))?;
                mime::parse_address(s).map_err(|_| ToolError::invalid(format!("invalid address in '{key}'")))
            })
            .collect(),
        Some(_) => Err(ToolError::invalid(format!("'{key}' must be a list of at most 50 addresses"))),
    }
}

fn header_text(s: &str, field: &str) -> Result<(), ToolError> {
    mime::validate_header_text(s).map_err(|_| ToolError::invalid(format!("'{field}' contains forbidden characters")))
}

/// Strips reply/forward prefixes and case-folds, for "same conversation" checks.
pub fn normalize_subject(s: &str) -> String {
    let mut t = s.trim();
    loop {
        let lower = t.to_lowercase();
        let stripped = ["re:", "aw:", "fwd:", "fw:", "wg:", "sv:", "antw:"]
            .iter()
            .find(|p| lower.starts_with(*p))
            .map(|p| t[p.len()..].trim_start());
        match stripped {
            Some(rest) => t = rest,
            None => break,
        }
    }
    t.to_lowercase()
}

fn mime_err(e: mime::MimeError) -> ToolError {
    match e {
        mime::MimeError::Invalid(m) => ToolError::invalid(m),
        mime::MimeError::TooLarge => ToolError::new(ErrorCode::TooLarge, "the draft exceeds the message size limit"),
        mime::MimeError::Unparseable => ToolError::invalid("draft could not be built"),
    }
}

fn domain_of(email: &str) -> &str {
    email.rsplit_once('@').map(|(_, d)| d).unwrap_or("localhost")
}

fn new_message_id(from: &Addr) -> String {
    format!("<{}@{}>", util::b64url(&util::random_bytes::<18>()), domain_of(&from.email))
}

async fn send_as_addresses(cx: &ToolCx, mb: &Mailbox) -> Result<Vec<Addr>, ToolError> {
    let v =
        cx.app.google.call(&mb.account_id, || GmailOp::SendAs, &[], None, Priority::Interactive, cx.deadline).await?;
    Ok(v["sendAs"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| {
                    Some(Addr {
                        email: s["sendAsEmail"].as_str()?.to_lowercase(),
                        name: s["displayName"].as_str().filter(|n| !n.is_empty()).map(str::to_string),
                    })
                })
                .collect()
        })
        .unwrap_or_default())
}

// ------------------------------------------------------------------ create

enum OpState {
    New,
    Done(Value),
    Failed(Value),
    Unknown,
}

async fn create_draft(cx: &ToolCx, args: Value) -> Result<ToolOutput, ToolError> {
    only_keys(
        &args,
        &[
            "account",
            "request_key",
            "to",
            "cc",
            "bcc",
            "subject",
            "body_text",
            "reply_to_message_id",
            "quote_original",
            "forward_message_id",
            "forward_ref",
            "include_attachments",
            "attachments",
            "from_address",
            "signature",
        ],
    )?;
    let mb = account_arg(cx, &args, Capability::Draft)?.clone();
    let request_key = arg_str(&args, "request_key")?;
    if uuid::Uuid::parse_str(request_key).is_err() {
        return Err(ToolError::invalid("request_key must be a UUID"));
    }
    let to = addr_list(&args, "to")?;
    let cc = addr_list(&args, "cc")?;
    let bcc = addr_list(&args, "bcc")?;
    if to.len() + cc.len() + bcc.len() > 50 {
        return Err(ToolError::invalid("at most 50 recipients in total"));
    }
    let subject_arg = opt_str(&args, "subject")?.map(str::to_string);
    if let Some(s) = &subject_arg {
        header_text(s, "subject")?;
    }
    let body = arg_str(&args, "body_text")?.to_string();
    if body.len() > 500 * 1024 {
        return Err(ToolError::invalid("body_text exceeds 500 KB"));
    }
    let reply_to = match opt_str(&args, "reply_to_message_id")? {
        Some(id) if crate::gmail::gateway::valid_id(id) => Some(id.to_string()),
        Some(_) => return Err(ToolError::not_found()),
        None => None,
    };
    let from_arg = match opt_str(&args, "from_address")? {
        Some(f) => Some(mime::parse_address(f).map_err(|_| ToolError::invalid("invalid from_address"))?),
        None => None,
    };
    let signature = opt_bool(&args, "signature", true)?;
    // Every referenced message is authorized here, before any upstream call (identical not_found without read).
    let limit = cx.app.cfg.limits.draft_attachment_bytes;
    let attachments = compose::parse_attachments(cx, args.get("attachments"), limit)?.unwrap_or_default();
    let forward = match (opt_str(&args, "forward_message_id")?, opt_str(&args, "forward_ref")?) {
        (Some(_), Some(_)) => return Err(ToolError::invalid("pass either forward_message_id or forward_ref")),
        (Some(id), None) => Some(compose::readable_message(cx, None, Some(arg_str(&args, "account")?), Some(id))?),
        (None, Some(r)) => Some(compose::readable_message(cx, Some(r), None, None)?),
        (None, None) => None,
    }
    .map(|(m, id)| (m.account_id.clone(), id));
    if forward.is_some() && reply_to.is_some() {
        return Err(ToolError::invalid("a draft is either a reply or a forward, not both"));
    }
    let include_attachments = match args.get("include_attachments") {
        Some(v) if forward.is_none() && !v.is_null() => {
            return Err(ToolError::invalid("include_attachments applies to forwards only"));
        }
        _ => opt_bool(&args, "include_attachments", true)?,
    };
    // Quoting copies the original's text into the draft: only for callers who may read this mailbox.
    let quote = match (reply_to.is_some(), args.get("quote_original").filter(|v| !v.is_null())) {
        (false, Some(_)) => return Err(ToolError::invalid("quote_original applies to replies only")),
        (false, None) => false,
        (true, None) => cx.client.authorize_id(Capability::Read, &mb.account_id).is_ok(),
        (true, Some(_)) => {
            let q = opt_bool(&args, "quote_original", true)?;
            if q {
                cx.client.authorize_id(Capability::Read, &mb.account_id)?;
            }
            q
        }
    };

    // Idempotency record (spec 5.3 create_draft): keyed by (client, account, request_key), no content.
    let canonical = json!({
        "to": fmt_addrs(&to), "cc": fmt_addrs(&cc), "bcc": fmt_addrs(&bcc), "subject": subject_arg,
        "body": body, "reply": reply_to, "from": from_arg.as_ref().map(|a| a.email.clone()),
        "attachments": attachments.iter().map(compose::AttachSpec::canonical).collect::<Vec<_>>(),
        "forward": forward, "include_attachments": include_attachments, "quote": quote, "signature": signature,
    });
    let input_hash = cx.app.pepper.hash("create-op", &canonical.to_string());
    let (cid, aid, key) = (cx.client.client_id.clone(), mb.account_id.clone(), request_key.to_string());
    let state = cx
        .app
        .store
        .call(move |c| {
            let tx = c.transaction()?;
            let row: Option<(Vec<u8>, String, Option<String>)> = tx
                .query_row(
                    "SELECT input_hash, state, result_ids FROM create_operations WHERE client_id = ?1 AND account_id = ?2 AND request_key = ?3",
                    params![cid, aid, key],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let st = match row {
                Some((h, _, _)) if h != input_hash => {
                    return Err(ToolError::invalid("request_key was already used with different inputs").into());
                }
                Some((_, s, ids)) if s == "succeeded" => OpState::Done(serde_json::from_str(&ids.unwrap_or_default()).unwrap_or(Value::Null)),
                Some((_, s, ids)) if s == "failed" => OpState::Failed(serde_json::from_str(&ids.unwrap_or_default()).unwrap_or(Value::Null)),
                Some(_) => OpState::Unknown,
                None => {
                    let now = util::now_unix();
                    tx.execute(
                        "INSERT INTO create_operations(client_id, account_id, request_key, input_hash, state, created_at, updated_at) \
                         VALUES (?1, ?2, ?3, ?4, 'in_flight', ?5, ?5)",
                        params![cid, aid, key, input_hash, now],
                    )?;
                    OpState::New
                }
            };
            tx.commit()?;
            Ok(st)
        })
        .await?;
    let audit = |ids: Vec<String>| AuditInfo {
        account: Some(mb.alias.clone()),
        object_ids: ids,
        result_count: Some(1),
        ..Default::default()
    };
    match state {
        OpState::Done(v) => {
            let ids = vec![v["draft_id"].as_str().unwrap_or_default().to_string()];
            return Ok(ToolOutput {
                extra: Vec::new(),
                text: format!(
                    "draft {} already created for this request_key (revision {})",
                    v["draft_id"].as_str().unwrap_or(""),
                    v["revision"].as_str().unwrap_or("")
                ),
                structured: v,
                audit: audit(ids),
            });
        }
        OpState::Failed(v) => {
            let code = v["code"].as_str().unwrap_or("upstream_error");
            return Err(ToolError::new(
                if code == "invalid_argument" { ErrorCode::InvalidArgument } else { ErrorCode::UpstreamError },
                "this request_key already failed; use a new request_key for a new attempt",
            ));
        }
        OpState::Unknown => {
            return Err(ToolError::new(
                ErrorCode::OutcomeUnknown,
                "an earlier attempt with this request_key has an unknown outcome; check the mailbox's Drafts before creating again with a new request_key",
            ));
        }
        OpState::New => {}
    }

    let source_ids: Vec<String> = forward.iter().map(|(_, m)| m.clone()).collect();
    let input = CreateInput {
        to,
        cc,
        bcc,
        subject_arg,
        body,
        reply_to,
        quote,
        forward,
        include_attachments,
        attachments,
        from_arg,
        signature,
    };
    let result = dispatch_create(cx, &mb, input).await;
    let (cid, aid, key) = (cx.client.client_id.clone(), mb.account_id.clone(), request_key.to_string());
    match result {
        Ok((Created { draft_id, message_id, thread_id, content_hash }, stats)) => {
            let out = json!({ "account": mb.alias, "draft_id": draft_id, "message_id": message_id, "thread_id": thread_id, "revision": message_id });
            let (o2, pid, client_id) = (out.clone(), cx.client.project_id.clone(), cx.client.client_id.clone());
            let (d2, m2, t2) = (draft_id.clone(), message_id.clone(), thread_id.clone());
            let commit = cx
                .app
                .store
                .call(move |c| {
                    let tx = c.transaction()?;
                    let now = util::now_unix();
                    tx.execute(
                        "INSERT INTO own_drafts(account_id, draft_id, message_id, thread_id, project_id, client_id, created_at, updated_at, state, content_hash) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 'active', ?8)",
                        params![aid, d2, m2, t2, pid, client_id, now, content_hash],
                    )?;
                    tx.execute(
                        "UPDATE create_operations SET state = 'succeeded', result_ids = ?1, updated_at = ?2 \
                         WHERE client_id = ?3 AND account_id = ?4 AND request_key = ?5",
                        params![o2.to_string(), now, cid, aid, key],
                    )?;
                    tx.commit()?;
                    Ok(())
                })
                .await;
            if commit.is_err() {
                // The provider created the draft but Dove could not record it: the caller must verify the mailbox.
                return Err(ToolError::new(ErrorCode::OutcomeUnknown, "the draft may exist but could not be recorded"));
            }
            crate::index::wake(&cx.app, &mb.account_id);
            Ok(ToolOutput {
                extra: Vec::new(),
                text: format!(
                    "Created draft {draft_id} in {} (revision {message_id}). Review it in the mailbox's Drafts.",
                    mb.alias
                ),
                structured: out,
                audit: audit([vec![draft_id], source_ids, stats.audit_ids()].concat()),
            })
        }
        Err((err, dispatched)) => {
            let new_state = match (err.code, dispatched) {
                (ErrorCode::OutcomeUnknown, _) => Some(("unknown", Value::Null)),
                (_, true) => Some(("failed", err.to_json())),
                // Nothing reached Google: forget the attempt so the same key can be retried.
                (_, false) => None,
            };
            let _ = cx
                .app
                .store
                .call(move |c| {
                    match new_state {
                        Some((s, v)) => c.execute(
                            "UPDATE create_operations SET state = ?1, result_ids = ?2, updated_at = ?3 WHERE client_id = ?4 AND account_id = ?5 AND request_key = ?6",
                            params![s, v.to_string(), util::now_unix(), cid, aid, key],
                        )?,
                        None => c.execute(
                            "DELETE FROM create_operations WHERE client_id = ?1 AND account_id = ?2 AND request_key = ?3 AND state = 'in_flight'",
                            params![cid, aid, key],
                        )?,
                    };
                    Ok(())
                })
                .await;
            Err(err)
        }
    }
}

/// A created draft as recorded in `own_drafts`. `content_hash` is set for IMAP drafts only.
pub(super) struct Created {
    pub draft_id: String,
    pub message_id: String,
    pub thread_id: String,
    pub content_hash: Option<Vec<u8>>,
}

/// Validated create_draft inputs (sources already authorized).
struct CreateInput {
    to: Vec<Addr>,
    cc: Vec<Addr>,
    bcc: Vec<Addr>,
    subject_arg: Option<String>,
    body: String,
    reply_to: Option<String>,
    quote: bool,
    /// (account id, message id) of the message to forward.
    forward: Option<(String, String)>,
    include_attachments: bool,
    attachments: Vec<compose::AttachSpec>,
    from_arg: Option<Addr>,
    /// Append the sender's signature (when one is set).
    signature: bool,
}

/// Count and total size of a new draft's attachments, for the audit record (never names).
#[derive(Default)]
struct AttachStats {
    count: usize,
    bytes: u64,
}

impl AttachStats {
    fn of(list: &[mime::DraftAttachment]) -> Self {
        Self { count: list.len(), bytes: list.iter().map(|a| a.bytes.len() as u64).sum() }
    }

    fn audit_ids(&self) -> Vec<String> {
        if self.count == 0 {
            return vec![];
        }
        vec![format!("attachments:{}", self.count), compose::size_class(self.bytes).to_string()]
    }
}

/// Builds and posts the draft. The bool in the error says whether the create request may have reached the provider.
async fn dispatch_create(
    cx: &ToolCx,
    mb: &Mailbox,
    input: CreateInput,
) -> Result<(Created, AttachStats), (ToolError, bool)> {
    let CreateInput {
        to,
        cc,
        bcc,
        subject_arg,
        mut body,
        reply_to,
        quote,
        forward,
        include_attachments,
        attachments,
        from_arg,
        signature,
    } = input;
    let pre = |e: ToolError| (e, false);
    let limit = cx.app.cfg.limits.draft_attachment_bytes;
    let send_as = match mb.provider {
        Provider::Gmail => send_as_addresses(cx, mb).await.map_err(pre)?,
        // IMAP: the mailbox address and the aliases the operator configured (design 2026-11-13 section 5).
        Provider::Imap => {
            let aid = mb.account_id.clone();
            let aliases =
                cx.app.store.call(move |c| crate::identity::load_aliases(c, &aid)).await.map_err(|e| pre(e.into()))?;
            let mut v = vec![Addr { email: mb.email.to_lowercase(), name: None }];
            v.extend(aliases.into_iter().map(|a| Addr { email: a.address, name: a.name }));
            v
        }
    };
    let from = match from_arg {
        Some(f) => send_as
            .iter()
            .find(|s| s.email.eq_ignore_ascii_case(&f.email))
            .map(|s| Addr { email: s.email.clone(), name: f.name.clone().or(s.name.clone()) })
            .ok_or_else(|| pre(ToolError::invalid("from_address is not a send-as address of this mailbox")))?,
        None => send_as
            .iter()
            .find(|s| s.email.eq_ignore_ascii_case(&mb.email))
            .cloned()
            .unwrap_or(Addr { email: mb.email.clone(), name: None }),
    };
    // The signature follows the agent's text and precedes any quote or forward block added below.
    if signature {
        let (aid, sender) = (mb.account_id.clone(), from.email.clone());
        let sig = cx
            .app
            .store
            .call(move |c| crate::identity::signature_for(c, &aid, &sender))
            .await
            .map_err(|e| pre(e.into()))?;
        if let Some(sig) = sig {
            body = crate::identity::with_signature(&body, &sig);
        }
    }
    let mut subject = subject_arg.clone().unwrap_or_default();
    let mut in_reply_to = None;
    let mut references = Vec::new();
    let mut thread_id = None;
    let mut files = Vec::new();
    if let Some(orig_id) = &reply_to {
        let orig = super::read::fetch_message(cx, mb, orig_id, Priority::Interactive).await.map_err(pre)?;
        let orig_subject = orig.parsed.subject.clone().unwrap_or_default();
        if let Some(mid) = &orig.parsed.message_id_header {
            in_reply_to = Some(mid.clone());
            references = orig.parsed.references.clone();
            references.push(mid.clone());
        }
        match &subject_arg {
            // Default keeps the threading subject (as one clean line: it comes from untrusted mail).
            None => {
                subject = if normalize_subject(&orig_subject) != orig_subject.trim().to_lowercase() {
                    compose::one_line(&orig_subject)
                } else {
                    format!("Re: {}", compose::one_line(&orig_subject))
                };
                thread_id = Some(orig.meta.thread_id.clone()).filter(|t| !t.is_empty());
            }
            Some(s) if normalize_subject(s) == normalize_subject(&orig_subject) => {
                thread_id = Some(orig.meta.thread_id.clone()).filter(|t| !t.is_empty());
            }
            // A different subject starts a new conversation; threadId cannot force grouping (spec 5.3).
            Some(_) => {}
        }
        if quote {
            body = compose::with_quote(&body, &orig);
        }
    }
    if let Some((aid, mid)) = &forward {
        let src = cx.client.resolve_id(aid).map_err(pre)?.clone();
        let orig = crate::mail::fetch_message(cx, &src, mid, Priority::Interactive).await.map_err(pre)?;
        if subject_arg.is_none() {
            subject = compose::forward_subject(orig.parsed.subject.as_deref());
        }
        body = compose::with_forward(&body, &orig);
        if include_attachments {
            files = compose::forward_attachments(&orig, limit).map_err(pre)?;
        }
    }
    let used = (files.len(), files.iter().map(|a| a.bytes.len()).sum());
    files.extend(compose::resolve(cx, attachments, limit, used).await.map_err(pre)?);
    let stats = AttachStats::of(&files);
    let fields = DraftFields {
        message_id: new_message_id(&from),
        from,
        to,
        cc,
        bcc,
        subject,
        body_text: body,
        in_reply_to,
        references,
        date: util::now_unix(),
        attachments: files,
    };
    let raw = mime::build_draft(&fields).map_err(|e| pre(mime_err(e)))?;
    drop(fields);
    // From here on the draft may reach the provider: the rest runs to completion even if the call times out.
    cx.commit().map_err(pre)?;
    if mb.provider == Provider::Imap {
        return super::drafts_imap::append_new(cx, mb, raw).await.map(|c| (c, stats));
    }
    let mut message = json!({ "raw": util::b64url(&raw) });
    if let Some(t) = &thread_id {
        message["threadId"] = json!(t);
    }
    let body = json!({ "message": message });
    let v = cx
        .app
        .google
        .write(&mb.account_id, || GmailOp::CreateDraft, &body, cx.write_deadline())
        .await
        .map_err(|e| (e.error, e.dispatched))?;
    let draft_id = v["id"]
        .as_str()
        .ok_or_else(|| (ToolError::new(ErrorCode::OutcomeUnknown, "unexpected Gmail response"), true))?;
    let message_id = v["message"]["id"].as_str().unwrap_or_default();
    let thread = v["message"]["threadId"].as_str().unwrap_or_default();
    let created = Created {
        draft_id: draft_id.to_string(),
        message_id: message_id.to_string(),
        thread_id: thread.to_string(),
        content_hash: None,
    };
    Ok((created, stats))
}

// ------------------------------------------------------------------ update / send common

pub(super) struct OwnRow {
    pub message_id: String,
    pub state: String,
    /// SHA-256 of the server's bytes (IMAP drafts only).
    pub content_hash: Option<Vec<u8>>,
}

async fn own_row(cx: &ToolCx, mb: &Mailbox, draft_id: &str) -> Result<OwnRow, ToolError> {
    let (aid, did, pid) = (mb.account_id.clone(), draft_id.to_string(), cx.client.project_id.clone());
    let row = cx
        .app
        .store
        .call(move |c| {
            Ok(c.query_row(
                "SELECT message_id, state, content_hash FROM own_drafts WHERE account_id = ?1 AND draft_id = ?2 AND project_id = ?3",
                params![aid, did, pid],
                |r| Ok(OwnRow { message_id: r.get(0)?, state: r.get(1)?, content_hash: r.get(2)? }),
            )
            .optional()?)
        })
        .await?;
    // Other projects' drafts and unknown drafts look the same (FR-P5).
    row.ok_or_else(ToolError::not_found)
}

/// Fresh read bypassing caches, then the two revision comparisons (spec 5.3).
async fn fresh_checked(
    cx: &ToolCx,
    mb: &Mailbox,
    draft_id: &str,
    own: &OwnRow,
    expected: &str,
) -> Result<super::read::Fetched, ToolError> {
    let v = cx
        .app
        .google
        .call(
            &mb.account_id,
            || GmailOp::GetDraft(draft_id),
            &[("format", "raw".into())],
            None,
            Priority::Interactive,
            cx.deadline,
        )
        .await?;
    let f = from_meta(v["message"].clone())?;
    let current = f.meta.id.as_str();
    if current != own.message_id {
        return Err(conflict(&f, "the draft was changed outside Dove; it is now human-owned"));
    }
    if current != expected {
        return Err(conflict(&f, "expected_revision is stale"));
    }
    Ok(f)
}

fn conflict(f: &super::read::Fetched, why: &str) -> ToolError {
    ToolError::new(ErrorCode::DraftConflict, why).with_details(json!({ "current_revision": f.meta.id }))
}

// ------------------------------------------------------------------ update

async fn update_draft(cx: &ToolCx, args: Value) -> Result<ToolOutput, ToolError> {
    only_keys(&args, &["account", "draft_id", "expected_revision", "changes"])?;
    let mb = account_arg(cx, &args, Capability::Draft)?.clone();
    let draft_id = gmail_id_arg(&args, "draft_id")?.to_string();
    let expected = arg_str(&args, "expected_revision")?.to_string();
    let changes = args
        .get("changes")
        .filter(|c| c.is_object())
        .ok_or_else(|| ToolError::invalid("'changes' must be an object"))?;
    only_keys(changes, &["to", "cc", "bcc", "subject", "body_text", "attachments"])?;
    let to = changes.get("to").map(|_| addr_list(changes, "to")).transpose()?;
    let cc = changes.get("cc").map(|_| addr_list(changes, "cc")).transpose()?;
    let bcc = changes.get("bcc").map(|_| addr_list(changes, "bcc")).transpose()?;
    let subject = opt_str(changes, "subject")?.map(str::to_string);
    if let Some(s) = &subject {
        header_text(s, "subject")?;
    }
    let body = opt_str(changes, "body_text")?.map(str::to_string);
    if body.as_ref().is_some_and(|b| b.len() > mime::MAX_BODY_BYTES) {
        return Err(ToolError::invalid("body_text exceeds 500 KB"));
    }
    // Sources are authorized before any upstream call; absent means keep the draft's attachments.
    let limit = cx.app.cfg.limits.draft_attachment_bytes;
    let new_files = compose::parse_attachments(cx, changes.get("attachments"), limit)?;

    let own = own_row(cx, &mb, &draft_id).await?;
    if own.state != "active" {
        return Err(ToolError::new(
            ErrorCode::OutcomeUnknown,
            "an earlier operation on this draft has an unknown outcome; read it with get_draft",
        ));
    }
    // Referenced attachments are fetched before the per-draft lock and the fresh check, keeping that window short.
    let new_files = match new_files {
        Some(specs) => Some(compose::resolve(cx, specs, limit, (0, 0)).await?),
        None => None,
    };
    let lock = cx.app.draft_locks.get(&mb.account_id, &draft_id);
    let _guard = lock.lock().await;
    // Re-read ownership under the lock: a concurrent Dove edit may have moved the revision.
    let own = own_row(cx, &mb, &draft_id).await?;
    let (f, imap_id) = match mb.provider {
        Provider::Gmail => (fresh_checked(cx, &mb, &draft_id, &own, &expected).await?, None),
        Provider::Imap => {
            let c = super::drafts_imap::fresh_checked(cx, &mb, &own, &expected).await?;
            (c.fetched, Some(c.id))
        }
    };
    if !f.parsed.is_draft_shape {
        return Err(conflict(&f, "the draft has parts Dove cannot preserve (HTML or inline parts)"));
    }
    let mut fields =
        mime::read_draft_fields(&f.raw).map_err(|_| conflict(&f, "the draft has a structure Dove cannot preserve"))?;
    match new_files {
        Some(files) => fields.attachments = files,
        // Kept attachments are rebuilt from the stored bytes, names and types re-checked like new ones.
        None => {
            for a in &mut fields.attachments {
                a.filename = super::attachments::sanitize_filename(Some(&a.filename));
                a.mime_type =
                    mime::normalize_mime_type(&a.mime_type).unwrap_or_else(|| "application/octet-stream".into());
            }
        }
    }
    if let Some(v) = to {
        fields.to = v;
    }
    if let Some(v) = cc {
        fields.cc = v;
    }
    if let Some(v) = bcc {
        fields.bcc = v;
    }
    if let Some(v) = subject {
        fields.subject = v;
    }
    if let Some(v) = body {
        fields.body_text = v;
    }
    if fields.to.len() + fields.cc.len() + fields.bcc.len() > 50 {
        return Err(ToolError::invalid("at most 50 recipients in total"));
    }
    fields.date = util::now_unix();
    let raw = mime::build_draft(&fields).map_err(mime_err)?;
    cx.commit()?;
    let res = match imap_id {
        None => gmail_update(cx, &mb, &draft_id, &f, raw).await,
        Some(old) => super::drafts_imap::replace(cx, &mb, &draft_id, old, raw).await.map(|(r, t)| (r, json!(t))),
    };
    let (aid, d2) = (mb.account_id.clone(), draft_id.clone());
    match res {
        Ok((new_rev, thread_id)) => {
            crate::index::wake(&cx.app, &mb.account_id);
            Ok(ToolOutput {
                extra: Vec::new(),
                text: format!("Updated draft {draft_id} (revision {new_rev})."),
                structured: json!({ "account": mb.alias, "draft_id": draft_id, "revision": new_rev, "message_id": new_rev, "thread_id": thread_id }),
                audit: AuditInfo {
                    account: Some(mb.alias.clone()),
                    object_ids: vec![draft_id],
                    result_count: Some(1),
                    ..Default::default()
                },
            })
        }
        Err(e) if e.code == ErrorCode::OutcomeUnknown => {
            let _ = cx
                .app
                .store
                .call(move |c| {
                    Ok(c.execute(
                        "UPDATE own_drafts SET state = 'update_unknown' WHERE account_id = ?1 AND draft_id = ?2",
                        params![aid, d2],
                    )?)
                })
                .await;
            Err(e)
        }
        Err(e) => Err(e),
    }
}

/// Gmail `drafts.update` and the new revision's record. Returns (new revision, thread id).
async fn gmail_update(
    cx: &ToolCx,
    mb: &Mailbox,
    draft_id: &str,
    f: &super::read::Fetched,
    raw: Vec<u8>,
) -> Result<(String, Value), ToolError> {
    let mut message = json!({ "raw": util::b64url(&raw) });
    if !f.meta.thread_id.is_empty() {
        message["threadId"] = json!(f.meta.thread_id);
    }
    let body = json!({ "id": draft_id, "message": message });
    let v = cx
        .app
        .google
        .write(&mb.account_id, || GmailOp::UpdateDraft(draft_id), &body, cx.write_deadline())
        .await
        .map_err(|e| e.error)?;
    let new_rev = v["message"]["id"].as_str().unwrap_or_default().to_string();
    let (nr, aid, d2) = (new_rev.clone(), mb.account_id.clone(), draft_id.to_string());
    let ok = cx
        .app
        .store
        .call(move |c| {
            Ok(c.execute(
                "UPDATE own_drafts SET message_id = ?1, updated_at = ?2 WHERE account_id = ?3 AND draft_id = ?4",
                params![nr, util::now_unix(), aid, d2],
            )?)
        })
        .await;
    if ok.is_err() {
        return Err(ToolError::new(
            ErrorCode::OutcomeUnknown,
            "the draft was updated but the new revision could not be recorded",
        ));
    }
    Ok((new_rev, v["message"]["threadId"].clone()))
}

// ------------------------------------------------------------------ send

async fn send_draft(cx: &ToolCx, args: Value) -> Result<ToolOutput, ToolError> {
    only_keys(&args, &["account", "draft_id", "expected_revision"])?;
    let mb = account_arg(cx, &args, Capability::Send)?.clone();
    let draft_id = gmail_id_arg(&args, "draft_id")?.to_string();
    let expected = arg_str(&args, "expected_revision")?.to_string();
    let own = own_row(cx, &mb, &draft_id).await?;
    match own.state.as_str() {
        "active" => {}
        "sent" => return Err(ToolError::not_found()),
        _ => {
            return Err(ToolError::new(
                ErrorCode::OutcomeUnknown,
                "an earlier send or update of this draft has an unknown outcome; the owner must check Sent",
            ));
        }
    }
    let lock = cx.app.draft_locks.get(&mb.account_id, &draft_id);
    let _guard = lock.lock().await;
    let own = own_row(cx, &mb, &draft_id).await?;
    if own.state != "active" {
        return Err(ToolError::new(
            ErrorCode::OutcomeUnknown,
            "this draft is already being sent or has an unknown outcome",
        ));
    }
    // IMAP: fresh check, envelope and credentials are prepared before the send is claimed.
    let imap = match mb.provider {
        Provider::Gmail => {
            fresh_checked(cx, &mb, &draft_id, &own, &expected).await?;
            None
        }
        Provider::Imap => Some(super::drafts_imap::prepare_send(cx, &mb, &own, &expected).await?),
    };

    // Recheck policy immediately before dispatch from the durable store (spec 6.3).
    let (cid, aid) = (cx.client.client_id.clone(), mb.account_id.clone());
    let allow_send = cx.app.cfg.allow_send;
    let still_allowed = cx
        .app
        .store
        .call(move |c| {
            let mbs = crate::policy::load_mailboxes(c, &cid)?;
            let epoch_ok = crate::policy::current_epoch(c, &cid)?.is_some();
            Ok(epoch_ok
                && allow_send
                && mbs.iter().any(|m| m.account_id == aid && m.actions.send && m.status == "active"))
        })
        .await?;
    if !still_allowed {
        return Err(ToolError::forbidden("send permission is no longer granted"));
    }
    // From here on the send runs to completion even if the call times out (`tools::detached`); too late to start
    // means nothing is charged or claimed.
    cx.commit()?;
    // Separate budget from reads (spec 6.3), charged only for submissions: `client_sends_per_hour`, bursts ≤5.
    let per_hour = cx.app.cfg.limits.client_sends_per_hour;
    if let Some(wait) =
        cx.app.rate_limiter.check_hourly(&format!("send:{}", cx.client.client_id), per_hour, per_hour.clamp(1, 5))
    {
        return Err(ToolError::rate_limited(Some(wait)));
    }
    // Persist the in-flight state atomically before dispatch: at most one submission (spec 6.3).
    let (aid, did, rev) = (mb.account_id.clone(), draft_id.clone(), own.message_id.clone());
    let claimed = cx
        .app
        .store
        .call(move |c| {
            Ok(c.execute(
                "UPDATE own_drafts SET state = 'sending', updated_at = ?1 WHERE account_id = ?2 AND draft_id = ?3 AND state = 'active' AND message_id = ?4",
                params![util::now_unix(), aid, did, rev],
            )?)
        })
        .await?;
    if claimed != 1 {
        return Err(ToolError::new(ErrorCode::DraftConflict, "the draft changed while preparing to send"));
    }
    let res: Result<(Option<String>, Value), ToolError> = match &imap {
        None => {
            let body = json!({ "id": draft_id });
            cx.app
                .google
                .write(&mb.account_id, || GmailOp::SendDraft(SendPermit(())), &body, cx.write_deadline())
                .await
                .map(|v| (v["id"].as_str().map(str::to_string), v["threadId"].clone()))
                .map_err(|WriteError { error, .. }| error)
        }
        Some(p) => super::drafts_imap::submit(cx, &mb, p).await.map(|()| (None, json!(p.thread_id))),
    };
    let (aid, did) = (mb.account_id.clone(), draft_id.clone());
    match res {
        Ok((sent_id, thread_id)) => {
            let s2 = sent_id.clone();
            let _ = cx
                .app
                .store
                .call(move |c| {
                    Ok(c.execute(
                        "UPDATE own_drafts SET state = 'sent', sent_message_id = ?1, updated_at = ?2 WHERE account_id = ?3 AND draft_id = ?4",
                        params![s2, util::now_unix(), aid, did],
                    )?)
                })
                .await;
            // IMAP: the Sent copy and the draft's removal happen only after the send is recorded.
            let sent_id = match imap {
                Some(p) => super::drafts_imap::after_send(cx, &mb, &draft_id, p).await,
                None => sent_id,
            };
            crate::index::wake(&cx.app, &mb.account_id);
            let mut ids = vec![draft_id.clone()];
            ids.extend(sent_id.clone());
            Ok(ToolOutput {
                extra: Vec::new(),
                text: match &sent_id {
                    Some(s) => format!("Sent draft {draft_id} as message {s}."),
                    None => format!("Sent draft {draft_id}."),
                },
                structured: json!({ "account": mb.alias, "draft_id": draft_id, "sent_message_id": sent_id, "thread_id": thread_id }),
                audit: AuditInfo {
                    account: Some(mb.alias.clone()),
                    object_ids: ids,
                    result_count: Some(1),
                    ..Default::default()
                },
            })
        }
        Err(e) => {
            // Not dispatched or definitively rejected: safe to retry. Anything uncertain blocks resubmission.
            let definitive = e.code != ErrorCode::OutcomeUnknown;
            let state = if definitive { "active" } else { "send_unknown" };
            let _ = cx
                .app
                .store
                .call(move |c| Ok(c.execute("UPDATE own_drafts SET state = ?1 WHERE account_id = ?2 AND draft_id = ?3 AND state = 'sending'", params![state, aid, did])?))
                .await;
            if definitive {
                Err(e)
            } else {
                Err(ToolError::new(
                    ErrorCode::OutcomeUnknown,
                    "the send may or may not have happened; check Sent before retrying",
                ))
            }
        }
    }
}

/// Startup recovery: a send interrupted by a crash has an unknown outcome (spec 6.3).
pub fn recover_after_restart(conn: &rusqlite::Connection) -> anyhow::Result<usize> {
    Ok(conn.execute("UPDATE own_drafts SET state = 'send_unknown' WHERE state = 'sending'", [])?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_normalization() {
        assert_eq!(normalize_subject("Re: AW: Invoice"), "invoice");
        assert_eq!(normalize_subject("  Fwd:re:Invoice "), "invoice");
        assert_ne!(normalize_subject("Invoice 2"), normalize_subject("Invoice"));
    }
}
