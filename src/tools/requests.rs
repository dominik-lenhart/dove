//! Request tools: request_send, list_requests, cancel_request (design 2026-11-14 section 4.2, PLAN A71).
//!
//! `request_send` needs `draft` on the mailbox, not `send`, and works with `allow_send = false`: nothing is sent before
//! the operator approved exactly these drafts with `dove requests approve`. Creating a request makes no upstream call;
//! the draft is read fresh at approval and again at send time.

use std::collections::HashSet;

use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};

use super::{
    AuditInfo, ToolCx, ToolDef, ToolOutput, account_arg, account_schema, arg_str, object_schema, only_keys, opt_bool,
    opt_str,
};
use crate::error::{ErrorCode, ToolError};
use crate::policy::Capability;
use crate::requests::{self, CreateError, NewItem, NewSend};
use crate::util;

/// The tools that `[requests] enabled = false` hides and refuses.
pub const NAMES: &[&str] = &["request_send", "list_requests", "cancel_request"];

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
                    "items": { "type": "array", "minItems": 1, "items": { "type": "object", "properties": {
                        "draft_id": { "type": "string" },
                        "expected_revision": { "type": "string", "description": "The draft's current revision (from create_draft, update_draft or get_draft)." },
                        "send_at": { "type": "string", "description": "RFC 3339 instant with offset, e.g. 2026-11-17T09:00:00+01:00. Omit when using window." }
                    }, "required": ["draft_id", "expected_revision"], "additionalProperties": false } },
                    "window": { "type": "object", "properties": {
                        "from": { "type": "string" }, "to": { "type": "string" }
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
            name: "list_requests",
            title: "List my requests",
            description: concat!(
                "Your requests with their status (pending, approved, denied, cancelled, expired, done) and, per item, ",
                "its state (pending, scheduled, sending, sent, skipped, failed, missed, send_unknown, cancelled, denied) ",
                "and reason code. send_unknown means the send may have happened: never retry it, check Sent."
            ),
            capability: Capability::Read,
            read_only: true,
            destructive: false,
            mail_content: false,
            input_schema: || {
                json!({ "type": "object", "properties": {
                    "status": { "type": "string", "enum": requests::STATUSES }
                }, "additionalProperties": false })
            },
            output_schema: || object_schema(json!({ "requests": {"type":"array"} })),
            handler: |cx, args| Box::pin(list_requests(cx, args)),
        },
        ToolDef {
            name: "cancel_request",
            title: "Cancel a request",
            description: "Cancel a pending request, or the items of an approved request that were not sent yet.",
            capability: Capability::Read,
            read_only: false,
            destructive: true,
            mail_content: false,
            input_schema: || {
                json!({ "type": "object", "properties": { "request_id": { "type": "string" } },
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
