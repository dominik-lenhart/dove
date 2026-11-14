//! Request tools: request_send, request_access, list_requests, cancel_request (design 2026-11-14 section 4.2, PLAN
//! A71, A73).
//!
//! `request_send` needs `draft` on the mailbox, not `send`, and works with `allow_send = false`: nothing is sent before
//! the operator approved exactly these drafts with `dove requests approve`. Creating a request makes no upstream call;
//! the draft is read fresh at approval and again at send time.
//!
//! `request_access` asks for actions on mailboxes of the client's project, for a while or for good. It changes no
//! right: only the operator's approval on the admin socket does. An unknown alias and an alias outside the project
//! are the identical `not_found`, and no tool lists the mailboxes one could ask for.

use std::collections::HashSet;

use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};

use super::{
    AuditInfo, ToolCx, ToolDef, ToolOutput, account_arg, account_schema, arg_str, object_schema, only_keys, opt_bool,
    opt_str,
};
use crate::error::{ErrorCode, ToolError};
use crate::policy::Capability;
use crate::requests::access::{self, AskedGrant, NewAccess, Payload};
use crate::requests::{self, CreateError, NewItem, NewSend};
use crate::util;

/// The tools that `[requests] enabled = false` hides and refuses.
pub const NAMES: &[&str] = &["request_send", "request_access", "list_requests", "cancel_request"];

pub fn defs() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "request_send",
            title: "Ask to send drafts on a schedule",
            description: concat!(
                "Ask the owner to send drafts this project created, at given times. Nothing is sent until the owner ",
                "approves; the owner sees each draft as it is then, and only that exact revision is ever sent (changing ",
                "a draft afterwards makes its item fail with draft_changed). Needs draft rights on the mailbox, not send ",
                "rights. Give send_at (RFC 3339 with offset, in the future, at most 30 days out) on every item, or one ",
                "window {from, to} and Dove spreads the items evenly over it in the given order. unless_reply: skip an ",
                "item if someone else replied in its thread after this request (drafts must be replies; the mailbox ",
                "must be indexed). A draft can be in one open request only. Follow the outcome with list_requests."
            ),
            capability: Capability::Draft,
            read_only: false,
            destructive: false,
            mail_content: false,
            input_schema: || {
                json!({ "type": "object", "properties": {
                    "account": account_schema(),
                    "items": { "type": "array", "minItems": 1, "description": "Drafts to send, in the order they are scheduled.", "items": { "type": "object", "properties": {
                        "draft_id": { "type": "string", "description": "Draft id from create_draft or list_drafts." },
                        "expected_revision": { "type": "string", "description": "The draft's current revision (from create_draft, update_draft or get_draft)." },
                        "send_at": { "type": "string", "description": "RFC 3339 instant with offset, e.g. 2026-11-17T09:00:00+01:00. Omit when using window." }
                    }, "required": ["draft_id", "expected_revision"], "additionalProperties": false } },
                    "window": { "type": "object", "properties": {
                        "from": { "type": "string", "description": "RFC 3339 instant with offset: the first send time." },
                        "to": { "type": "string", "description": "RFC 3339 instant with offset: the last send time." }
                    }, "required": ["from", "to"], "additionalProperties": false,
                    "description": "Spread the items evenly from `from` to `to` (both included) instead of send_at." },
                    "unless_reply": { "type": "boolean", "description": "Skip an item when its thread got a reply from someone else after this request." },
                    "note": { "type": "string", "maxLength": requests::MAX_NOTE_CHARS, "description": "Short note for the owner (why, what to check)." }
                }, "required": ["account", "items"], "additionalProperties": false })
            },
            output_schema: || {
                object_schema(
                    json!({ "request_id": {"type":"string"}, "status": {"type":"string"}, "items": {"type":"array"} }),
                )
            },
            handler: |cx, args| Box::pin(request_send(cx, args)),
        },
        ToolDef {
            name: "request_access",
            title: "Ask for more access",
            description: concat!(
                "Ask the owner for rights on mailboxes of this project: read, draft, organize, delete, send or a preset ",
                "(reader, drafter, assistant, full), e.g. actions \"read,draft\". With duration_minutes (1 to 43200, ",
                "30 days) the rights end on their own; without it the request is for a permanent grant. Nothing changes ",
                "until the owner approves; the owner may shorten the time or leave out mailboxes. The owner tells you ",
                "the mailbox alias; there is no list of mailboxes you could ask for. An approved temporary request counts as open until its ",
                "rights end. Follow the outcome with list_requests."
            ),
            capability: Capability::Read,
            read_only: false,
            destructive: false,
            mail_content: false,
            input_schema: || {
                json!({ "type": "object", "properties": {
                    "grants": { "type": "array", "minItems": 1, "description": "Mailboxes and the rights asked for on each.", "items": { "type": "object", "properties": {
                        "account": { "type": "string", "description": "Mailbox alias or address, as the owner named it." },
                        "actions": { "type": "string", "description": "Comma list of actions or presets, e.g. read,draft or assistant." }
                    }, "required": ["account", "actions"], "additionalProperties": false } },
                    "duration_minutes": { "type": "integer", "minimum": 1, "maximum": access::MAX_DURATION_MINUTES,
                        "description": "How long the rights should last. Omit to ask for a permanent grant." },
                    "note": { "type": "string", "maxLength": requests::MAX_NOTE_CHARS, "description": "Short note for the owner (why you need it)." }
                }, "required": ["grants"], "additionalProperties": false })
            },
            output_schema: || {
                object_schema(
                    json!({ "request_id": {"type":"string"}, "status": {"type":"string"}, "grants": {"type":"array"} }),
                )
            },
            handler: |cx, args| Box::pin(request_access(cx, args)),
        },
        ToolDef {
            name: "list_requests",
            title: "List my requests",
            description: concat!(
                "List the send and access requests this connection made, newest first; status filters them. Use it ",
                "to see whether the operator approved a request_send or request_access. Each request has its status ",
                "(pending, approved, denied, cancelled, expired, done) and, per item, ",
                "its state (pending, scheduled, sending, sent, skipped, failed, missed, send_unknown, cancelled, denied) ",
                "and reason code. send_unknown means the send may have happened: never retry it, check Sent. Access ",
                "requests list each asked grant (pending, granted, active, ended, not_approved) and when temporary ",
                "rights end."
            ),
            capability: Capability::Read,
            read_only: true,
            destructive: false,
            mail_content: false,
            input_schema: || {
                json!({ "type": "object", "properties": {
                    "status": { "type": "string", "enum": requests::STATUSES, "description": "Only requests with this status." }
                }, "additionalProperties": false })
            },
            output_schema: || object_schema(json!({ "requests": {"type":"array"} })),
            handler: |cx, args| Box::pin(list_requests(cx, args)),
        },
        ToolDef {
            name: "cancel_request",
            title: "Cancel a request",
            description: concat!(
                "Cancel a pending request, or the items of an approved request that were not sent yet; sent items ",
                "stay sent. Cancelling an approved temporary access request gives its rights back at once. Get ",
                "request_id from list_requests. A request that is already finished is returned unchanged; unknown ids ",
                "return not_found."
            ),
            capability: Capability::Read,
            read_only: false,
            destructive: true,
            mail_content: false,
            input_schema: || {
                json!({ "type": "object", "properties": { "request_id": { "type": "string", "description": "Request id from request_send, request_access or list_requests." } },
                        "required": ["request_id"], "additionalProperties": false })
            },
            output_schema: || {
                object_schema(
                    json!({ "request_id": {"type":"string"}, "status": {"type":"string"}, "items": {"type":"array"} }),
                )
            },
            handler: |cx, args| Box::pin(cancel_request(cx, args)),
        },
    ]
}

/// An RFC 3339 instant with an explicit offset, in unix seconds (date-only and offset-less forms are refused).
fn instant(s: Option<&Value>, path: &str) -> Result<Option<i64>, ToolError> {
    match s {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => util::parse_rfc3339_ms(s).map(|ms| Some(ms.div_euclid(1000))).ok_or_else(|| {
            ToolError::invalid_at(path, "must be an RFC 3339 instant with an offset, e.g. 2026-11-17T09:00:00+01:00")
        }),
        Some(_) => Err(ToolError::invalid_at(path, "must be a string")),
    }
}

fn in_bounds(t: i64, now: i64, path: &str) -> Result<i64, ToolError> {
    if t <= now || t > now + requests::MAX_AHEAD_SECS {
        return Err(ToolError::invalid_at(path, "must be in the future and at most 30 days from now"));
    }
    Ok(t)
}

/// One parsed item of `request_send`.
struct ItemArg {
    draft_id: String,
    expected: String,
    send_at: Option<i64>,
}

fn parse_items(args: &Value, max: usize) -> Result<Vec<ItemArg>, ToolError> {
    let items = match args.get("items") {
        Some(Value::Array(a)) if !a.is_empty() && a.len() <= max => a,
        _ => return Err(ToolError::invalid_at("items", format!("must be a list of 1 to {max} items"))),
    };
    let mut out: Vec<ItemArg> = Vec::with_capacity(items.len());
    for (i, it) in items.iter().enumerate() {
        let path = format!("items[{i}]");
        let Some(obj) = it.as_object() else {
            return Err(ToolError::invalid_at(path, "must be an object {draft_id, expected_revision, send_at?}"));
        };
        if obj.keys().any(|k| !matches!(k.as_str(), "draft_id" | "expected_revision" | "send_at")) {
            return Err(ToolError::invalid_at(path, "takes only draft_id, expected_revision and send_at"));
        }
        let draft_id = arg_str(it, "draft_id")
            .map_err(|_| ToolError::invalid_at(format!("{path}.draft_id"), "is required and must be a string"))?;
        let expected = arg_str(it, "expected_revision").map_err(|_| {
            ToolError::invalid_at(format!("{path}.expected_revision"), "is required and must be a string")
        })?;
        // Malformed draft ids are indistinguishable from unknown ones.
        if !crate::gmail::gateway::valid_id(draft_id) {
            return Err(ToolError::not_found());
        }
        let send_at = instant(it.get("send_at"), &format!("{path}.send_at"))?;
        out.push(ItemArg { draft_id: draft_id.to_string(), expected: expected.to_string(), send_at });
    }
    Ok(out)
}

/// Assigns each item its time: every item's `send_at`, or the `window` spread evenly in input order.
fn assign_times(args: &Value, items: &[ItemArg], now: i64) -> Result<Vec<i64>, ToolError> {
    let window = match args.get("window") {
        None | Some(Value::Null) => None,
        Some(w @ Value::Object(o)) => {
            if o.keys().any(|k| k != "from" && k != "to") {
                return Err(ToolError::invalid_at("window", "takes only from and to"));
            }
            let from = instant(w.get("from"), "window.from")?
                .ok_or_else(|| ToolError::invalid_at("window.from", "is required"))?;
            let to =
                instant(w.get("to"), "window.to")?.ok_or_else(|| ToolError::invalid_at("window.to", "is required"))?;
            in_bounds(from, now, "window.from")?;
            in_bounds(to, now, "window.to")?;
            if from >= to {
                return Err(ToolError::invalid_at("window", "from must be earlier than to"));
            }
            Some((from, to))
        }
        Some(_) => return Err(ToolError::invalid_at("window", "must be an object {from, to}")),
    };
    match window {
        Some((from, to)) => {
            if let Some(i) = items.iter().position(|it| it.send_at.is_some()) {
                return Err(ToolError::invalid_at(
                    format!("items[{i}].send_at"),
                    "pass either send_at on every item or one window, not both",
                ));
            }
            Ok(requests::spread(from, to, items.len()))
        }
        None => items
            .iter()
            .enumerate()
            .map(|(i, it)| {
                let path = format!("items[{i}].send_at");
                let t =
                    it.send_at.ok_or_else(|| ToolError::invalid_at(&path, "is required unless a window is given"))?;
                in_bounds(t, now, &path)
            })
            .collect(),
    }
}

async fn request_send(cx: &ToolCx, args: Value) -> Result<ToolOutput, ToolError> {
    only_keys(&args, &["account", "items", "window", "unless_reply", "note"])?;
    let mb = account_arg(cx, &args, Capability::Draft)?.clone();
    let now = util::now_unix();
    let items = parse_items(&args, cx.app.cfg.limits.request_items as usize)?;
    let times = assign_times(&args, &items, now)?;
    let note = opt_str(&args, "note")?.map(str::to_string);
    if note.as_ref().is_some_and(|n| n.chars().count() > requests::MAX_NOTE_CHARS) {
        return Err(ToolError::invalid_at("note", format!("must be at most {} characters", requests::MAX_NOTE_CHARS)));
    }
    let unless_reply = opt_bool(&args, "unless_reply", false)?;

    // Every draft must be this project's own, unchanged since Dove wrote it, at the named revision (the send_draft
    // rule). Other projects' drafts and unknown drafts are the same not_found.
    let (aid, pid) = (mb.account_id.clone(), cx.client.project_id.clone());
    let ids: Vec<String> = items.iter().map(|i| i.draft_id.clone()).collect();
    let rows: Vec<Option<(String, String, String)>> = cx
        .app
        .store
        .call(move |c| {
            let mut st = c.prepare(
                "SELECT message_id, state, thread_id FROM own_drafts WHERE account_id = ?1 AND draft_id = ?2 AND project_id = ?3",
            )?;
            let mut out = Vec::new();
            for d in &ids {
                out.push(st.query_row(params![aid, d, pid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional()?);
            }
            Ok(out)
        })
        .await?;
    let mut threads = Vec::with_capacity(items.len());
    for (it, row) in items.iter().zip(rows) {
        let Some((message_id, state, thread_id)) = row else { return Err(ToolError::not_found()) };
        match state.as_str() {
            "active" => {}
            "sent" => return Err(ToolError::not_found()),
            _ => {
                return Err(ToolError::new(
                    ErrorCode::OutcomeUnknown,
                    "an earlier send or update of this draft has an unknown outcome; the owner must check it",
                ));
            }
        }
        if message_id != it.expected {
            return Err(ToolError::new(ErrorCode::DraftConflict, "expected_revision is stale")
                .with_details(json!({ "current_revision": message_id })));
        }
        threads.push(thread_id);
    }

    // unless_reply: the baseline is now; the thread's messages that exist now never count as a reply.
    let mut baselines: Vec<Option<Vec<String>>> = vec![None; items.len()];
    if unless_reply {
        if !mb.index_enabled {
            return Err(ToolError::invalid_at(
                "unless_reply",
                "needs an indexed mailbox; ask the owner to enable indexing",
            ));
        }
        let (aid, th) = (mb.account_id.clone(), threads.clone());
        let found: Option<Vec<(usize, Vec<String>)>> = cx
            .app
            .index
            .read(cx.deadline, move |c| {
                let Some(g) = crate::index::sync::load_state(c, &aid)?.and_then(|s| s.serving_gen()) else {
                    return Ok(None);
                };
                let mut st = c.prepare("SELECT gmail_id, is_draft FROM messages WHERE gen = ?1 AND thread_id = ?2")?;
                let mut out = Vec::new();
                for t in &th {
                    let rows: Vec<(String, bool)> =
                        st.query_map(params![g, t], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
                    let others = rows.iter().filter(|(_, d)| !d).count();
                    out.push((others, rows.into_iter().map(|(id, _)| id).collect()));
                }
                Ok(Some(out))
            })
            .await?;
        let Some(found) = found else {
            return Err(ToolError::invalid_at("unless_reply", "needs an indexed mailbox; its index is not built yet"));
        };
        for (i, (others, ids)) in found.into_iter().enumerate() {
            if threads[i].is_empty() || others == 0 {
                return Err(ToolError::invalid_at(
                    "unless_reply",
                    format!("item {i} is not a reply in an indexed thread, so there is nothing to wait for"),
                ));
            }
            baselines[i] = Some(ids);
        }
    }

    let id = requests::new_request_id();
    let note_sealed = match &note {
        Some(n) => {
            Some(cx.app.vault.seal_aux(requests::NOTE_KIND, &id, n.as_bytes()).map_err(crate::error::internal_from)?)
        }
        None => None,
    };
    let new = NewSend {
        id: id.clone(),
        client_id: cx.client.client_id.clone(),
        project_id: cx.client.project_id.clone(),
        account_id: mb.account_id.clone(),
        unless_reply,
        note_sealed,
        items: items
            .iter()
            .zip(&times)
            .zip(threads.iter().zip(baselines))
            .map(|((it, &send_at), (thread, base))| NewItem {
                draft_id: it.draft_id.clone(),
                requested_rev: it.expected.clone(),
                send_at,
                thread_id: unless_reply.then(|| thread.clone()),
                baseline_ms: unless_reply.then_some(now * 1000),
                baseline_ids: base,
            })
            .collect(),
    };
    let app = cx.app.clone();
    let created = cx
        .app
        .store
        .call(move |c| {
            let tx = c.transaction()?;
            let r = requests::create_send(&tx, &app.cfg, new, now);
            if r.is_ok() {
                tx.commit()?;
            }
            Ok(r)
        })
        .await?;
    match created {
        Ok(_) => {}
        Err(CreateError::TooManyOpen) => {
            return Err(ToolError::invalid(format!(
                "this connection already has {} open requests; wait for decisions or cancel one",
                cx.app.cfg.limits.client_open_requests
            )));
        }
        Err(CreateError::DraftAlreadyRequested(i)) => {
            return Err(ToolError::invalid_at(format!("items[{i}].draft_id"), "is already in an open request"));
        }
        Err(CreateError::Store(e)) => return Err(crate::error::internal_from(e)),
    }
    let out_items: Vec<Value> = items
        .iter()
        .zip(&times)
        .enumerate()
        .map(|(i, (it, t))| json!({ "idx": i, "draft_id": it.draft_id, "send_at": util::rfc3339(*t) }))
        .collect();
    Ok(ToolOutput {
        text: format!(
            "Request {id} is pending: {} draft(s) wait for the owner's approval. Nothing is sent before that; follow it with list_requests.",
            items.len()
        ),
        structured: json!({ "request_id": id, "status": "pending", "items": out_items }),
        audit: AuditInfo {
            account: Some(mb.alias.clone()),
            object_ids: vec![id.clone(), format!("items:{}", items.len())],
            result_count: Some(items.len() as i64),
            ..Default::default()
        },
        extra: vec![],
    })
}

/// Seals an agent's note with the request id as scope, after checking its length.
fn seal_note(cx: &ToolCx, id: &str, note: Option<&str>) -> Result<Option<Vec<u8>>, ToolError> {
    let Some(n) = note else { return Ok(None) };
    if n.chars().count() > requests::MAX_NOTE_CHARS {
        return Err(ToolError::invalid_at("note", format!("must be at most {} characters", requests::MAX_NOTE_CHARS)));
    }
    cx.app.vault.seal_aux(requests::NOTE_KIND, id, n.as_bytes()).map(Some).map_err(crate::error::internal_from)
}

/// One parsed grant of `request_access`: the account as named and the expanded actions.
struct GrantArg {
    account: String,
    actions: crate::policy::Actions,
}

fn parse_grants(args: &Value, max: usize, allow_send: bool) -> Result<Vec<GrantArg>, ToolError> {
    let grants = match args.get("grants") {
        Some(Value::Array(a)) if !a.is_empty() && a.len() <= max => a,
        _ => return Err(ToolError::invalid_at("grants", format!("must be a list of 1 to {max} grants"))),
    };
    let mut out = Vec::with_capacity(grants.len());
    for (i, g) in grants.iter().enumerate() {
        let path = format!("grants[{i}]");
        let Some(obj) = g.as_object() else {
            return Err(ToolError::invalid_at(path, "must be an object {account, actions}"));
        };
        if obj.keys().any(|k| k != "account" && k != "actions") {
            return Err(ToolError::invalid_at(path, "takes only account and actions"));
        }
        let account = arg_str(g, "account")
            .map_err(|_| ToolError::invalid_at(format!("{path}.account"), "is required and must be a string"))?;
        let words = arg_str(g, "actions")
            .map_err(|_| ToolError::invalid_at(format!("{path}.actions"), "is required and must be a string"))?;
        // The grant syntax of `clients set-grants`; the parser's message names only the accepted words.
        let actions = crate::policy::Actions::parse_grant(words)
            .map_err(|e| ToolError::invalid_at(format!("{path}.actions"), e))?;
        if actions.send && !allow_send {
            return Err(ToolError::invalid_at(
                format!("{path}.actions"),
                "send cannot be granted on this server (allow_send is off); ask for draft and use request_send",
            ));
        }
        out.push(GrantArg { account: account.trim().to_string(), actions });
    }
    Ok(out)
}

async fn request_access(cx: &ToolCx, args: Value) -> Result<ToolOutput, ToolError> {
    only_keys(&args, &["grants", "duration_minutes", "note"])?;
    let grants = parse_grants(&args, cx.app.cfg.limits.request_items as usize, cx.app.cfg.allow_send)?;
    let duration = match args.get("duration_minutes") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_i64() {
            Some(m) if (1..=access::MAX_DURATION_MINUTES).contains(&m) => Some(m),
            _ => {
                return Err(ToolError::invalid_at(
                    "duration_minutes",
                    format!(
                        "must be an integer from 1 to {} (30 days); omit it for a permanent grant",
                        access::MAX_DURATION_MINUTES
                    ),
                ));
            }
        },
    };
    let note = opt_str(&args, "note")?.map(str::to_string);
    // Everything that can refuse the call without leaving a request the owner sees is checked before any mailbox
    // name is resolved, so an answer other than not_found never tells whether a name is in the project.
    if note.as_deref().is_some_and(|n| n.chars().count() > requests::MAX_NOTE_CHARS) {
        return Err(ToolError::invalid_at("note", format!("must be at most {} characters", requests::MAX_NOTE_CHARS)));
    }
    let too_many = || {
        ToolError::invalid(format!(
            "this connection already has {} open requests; wait for decisions or cancel one",
            cx.app.cfg.limits.client_open_requests
        ))
    };

    // Accounts are looked up in the client's project only, by alias or address: an unknown name and a name outside
    // the project are the same not_found. The client's own grants play no part (asking is for what it lacks).
    let pid = cx.client.project_id.clone();
    let cid = cx.client.client_id.clone();
    let limit = cx.app.cfg.limits.client_open_requests;
    let names: Vec<String> = grants.iter().map(|g| g.account.clone()).collect();
    let found: Option<Vec<Option<(String, String)>>> = cx
        .app
        .store
        .call(move |c| {
            if !access::has_room(c, &cid, limit)? {
                return Ok(None);
            }
            let mut st = c.prepare(
                "SELECT a.id, a.alias FROM accounts a JOIN project_accounts pa ON pa.account_id = a.id \
                 WHERE pa.project_id = ?1 AND (a.alias = ?2 OR a.email = ?2)",
            )?;
            let mut out = Vec::with_capacity(names.len());
            for n in &names {
                out.push(st.query_row(params![pid, n], |r| Ok((r.get(0)?, r.get(1)?))).optional()?);
            }
            Ok(Some(out))
        })
        .await?;
    let Some(found) = found else { return Err(too_many()) };
    // A mailbox named twice (also once by alias and once by address) is one grant with the actions of both: an
    // error here would tell that both names are in the project.
    let mut merged: Vec<(String, String, crate::policy::Actions)> = Vec::with_capacity(grants.len());
    for (g, f) in grants.iter().zip(found) {
        let Some((account_id, alias)) = f else { return Err(ToolError::not_found()) };
        match merged.iter_mut().find(|m| m.0 == account_id) {
            Some(m) => m.2 = m.2.union(&g.actions),
            None => merged.push((account_id, alias, g.actions)),
        }
    }
    let mut asked: Vec<AskedGrant> = Vec::with_capacity(merged.len());
    let mut aliases: Vec<String> = Vec::with_capacity(merged.len());
    for (account_id, alias, actions) in merged {
        asked.push(AskedGrant { account_id, actions: actions.to_string() });
        aliases.push(alias);
    }

    let id = requests::new_request_id();
    let note_sealed = seal_note(cx, &id, note.as_deref())?;
    let new = NewAccess {
        id: id.clone(),
        client_id: cx.client.client_id.clone(),
        project_id: cx.client.project_id.clone(),
        note_sealed,
        payload: Payload { grants: asked.clone(), duration_secs: duration.map(|m| m * 60), decision: None },
    };
    let app = cx.app.clone();
    let now = util::now_unix();
    let created = cx
        .app
        .store
        .call(move |c| {
            let tx = c.transaction()?;
            let r = access::create(&tx, &app.cfg, new, now);
            if r.is_ok() {
                tx.commit()?;
            }
            Ok(r)
        })
        .await?;
    match created {
        Ok(_) => {}
        Err(CreateError::TooManyOpen) => return Err(too_many()),
        Err(CreateError::DraftAlreadyRequested(_)) => return Err(ToolError::internal()),
        Err(CreateError::Store(e)) => return Err(crate::error::internal_from(e)),
    }
    let out: Vec<Value> = asked
        .iter()
        .zip(&aliases)
        .enumerate()
        .map(|(i, (g, alias))| json!({ "idx": i, "account": alias, "actions": g.actions }))
        .collect();
    let how = match duration {
        Some(m) => format!("for {m} minute(s) from approval"),
        None => "permanently".to_string(),
    };
    Ok(ToolOutput {
        text: format!(
            "Request {id} is pending: {} grant(s) {how}, waiting for the owner's approval. Nothing changes before that; follow it with list_requests.",
            asked.len()
        ),
        structured: json!({ "request_id": id, "status": "pending", "duration_minutes": duration, "grants": out }),
        audit: AuditInfo {
            object_ids: vec![id.clone(), format!("grants:{}", asked.len())],
            result_count: Some(asked.len() as i64),
            ..Default::default()
        },
        extra: vec![],
    })
}

async fn list_requests(cx: &ToolCx, args: Value) -> Result<ToolOutput, ToolError> {
    only_keys(&args, &["status"])?;
    let status = opt_str(&args, "status")?.map(str::to_string);
    if let Some(s) = &status
        && !requests::STATUSES.contains(&s.as_str())
    {
        return Err(ToolError::invalid_at("status", format!("must be one of {}", requests::STATUSES.join(", "))));
    }
    let cid = cx.client.client_id.clone();
    let list = cx.app.store.call(move |c| requests::list_for_client(c, &cid, status.as_deref())).await?;
    let n = list.len();
    let text = if n == 0 {
        "No requests.".to_string()
    } else {
        list.iter()
            .map(|r| {
                let states: Vec<String> = r.items.iter().map(|i| format!("{}:{}", i.idx, i.state)).collect();
                format!("{} {} ({})", r.request_id, r.status, states.join(" "))
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    Ok(ToolOutput {
        text,
        structured: json!({ "requests": list }),
        audit: AuditInfo { result_count: Some(n as i64), ..Default::default() },
        extra: vec![],
    })
}

async fn cancel_request(cx: &ToolCx, args: Value) -> Result<ToolOutput, ToolError> {
    only_keys(&args, &["request_id"])?;
    let id = arg_str(&args, "request_id")?.to_string();
    if !requests::valid_request_id(&id) {
        return Err(ToolError::not_found());
    }
    let (cid, rid) = (cx.client.client_id.clone(), id.clone());
    let view = cx
        .app
        .store
        .call(move |c| {
            let tx = c.transaction()?;
            if !requests::cancel_by_client(&tx, &cid, &rid, util::now_unix())? {
                return Ok(None);
            }
            let v = requests::view_for_client(&tx, &cid, &rid)?;
            tx.commit()?;
            Ok(v)
        })
        .await?
        .ok_or_else(ToolError::not_found)?;
    let unsent: HashSet<&str> = ["pending", "scheduled", "sending"].into_iter().collect();
    let left = view.items.iter().filter(|i| unsent.contains(i.state.as_str())).count();
    Ok(ToolOutput {
        text: format!("Request {id} is {} ({left} item(s) still open).", view.status),
        structured: json!(view),
        audit: AuditInfo { object_ids: vec![id], result_count: Some(1), ..Default::default() },
        extra: vec![],
    })
}
