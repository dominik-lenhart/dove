//! Watch tools (design 0.2 section 3): `create_watch`, `list_watches`, `delete_watch`, `list_watch_events`.
//!
//! All four need `read` on the watch's mailbox. A watch belongs to the connection that created it: other connections
//! never see or delete it (their attempts are `not_found`, like unknown ids). Events are content-free; the agent
//! reads the message with its own token through the normal read tools.

use rusqlite::{OptionalExtension, params, params_from_iter};
use serde_json::{Value, json};

use super::{
    AuditInfo, ToolCx, ToolDef, ToolOutput, account_schema, arg_str, object_schema, only_keys, opt_str, opt_u64,
};
use crate::error::{ErrorCode, ToolError};
use crate::index::query;
use crate::policy::{Capability, Mailbox};
use crate::util;
use crate::watch::{self, EventRow, Filter, FromMatch, Kind};

pub const DEFAULT_EVENTS: u64 = 50;
pub const MAX_EVENTS: u64 = 200;

pub fn defs() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "create_watch",
            title: "Create watch",
            description: concat!(
                "Watch a mailbox for new mail and get events instead of polling search. kind: thread_reply (a new ",
                "message in thread_id from someone other than the mailbox owner), from (new mail from an address or a ",
                "domain), query (new mail matching a `where` filter, same schema as search_messages, checked against ",
                "newly indexed messages only), no_reply_by (thread_id gets no message from others before `deadline`; ",
                "fires once at the deadline). Needs the search index on the mailbox. Events carry ids only (no subject, ",
                "sender or body): read them with list_watch_events, then fetch the message with get_message. Optional ",
                "`sink` names an operator webhook from list_watches for push delivery. Expires after 30 days by default ",
                "(max 180); at most 50 active watches per connection."
            ),
            capability: Capability::Read,
            read_only: false,
            destructive: false,
            input_schema: || {
                json!({
                    "type": "object",
                    "properties": {
                        "account": account_schema(),
                        "kind": { "type": "string", "enum": Kind::ALL },
                        "thread_id": { "type": "string", "description": "thread_reply, no_reply_by: thread id from search_messages or get_message." },
                        "from": { "type": "string", "description": "from: an address (ann@example.com) or a domain (example.com)." },
                        "where": { "type": "object", "description": "query: a search_messages `where` condition." },
                        "deadline": { "type": "string", "format": "date-time", "description": "no_reply_by: RFC 3339 instant." },
                        "expires_at": { "type": "string", "format": "date-time", "description": "Default 30 days from now, at most 180." },
                        "sink": { "type": "string", "description": "Name of an operator webhook sink (list_watches)." }
                    },
                    "required": ["account", "kind"],
                    "additionalProperties": false
                })
            },
            output_schema: watch_schema,
            handler: |cx, args| Box::pin(create_watch(cx, args)),
        },
        ToolDef {
            name: "list_watches",
            title: "List watches",
            description: "Watches of this connection (active and recently ended, with the reason) and the names of the \
                          operator's webhook sinks a watch may use.",
            capability: Capability::Read,
            read_only: true,
            destructive: false,
            input_schema: || json!({ "type": "object", "properties": {}, "additionalProperties": false }),
            output_schema: || {
                object_schema(json!({
                    "watches": { "type": "array", "items": watch_schema() },
                    "sinks": { "type": "array", "items": { "type": "string" } }
                }))
            },
            handler: |cx, args| Box::pin(list_watches(cx, args)),
        },
        ToolDef {
            name: "delete_watch",
            title: "Delete watch",
            description: "Deletes a watch of this connection and its events.",
            capability: Capability::Read,
            read_only: false,
            destructive: true,
            input_schema: || {
                json!({
                    "type": "object",
                    "properties": { "watch_id": { "type": "string" } },
                    "required": ["watch_id"],
                    "additionalProperties": false
                })
            },
            output_schema: || {
                object_schema(json!({ "watch_id": { "type": "string" }, "deleted": { "type": "boolean" } }))
            },
            handler: |cx, args| Box::pin(delete_watch(cx, args)),
        },
        ToolDef {
            name: "list_watch_events",
            title: "List watch events",
            description: concat!(
                "Events of this connection's watches, oldest first, kept 14 days. Pass the returned `next_cursor` on ",
                "the next call to get only newer events (it is returned even when there are none). Optional watch_id ",
                "narrows to one watch. Each event: event_id, watch_id, kind, account, message_id, thread_id, ",
                "received_at; read the message with get_message(account, message_id)."
            ),
            capability: Capability::Read,
            read_only: true,
            destructive: false,
            input_schema: || {
                json!({
                    "type": "object",
                    "properties": {
                        "cursor": { "type": "string" },
                        "watch_id": { "type": "string" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": MAX_EVENTS, "default": DEFAULT_EVENTS }
                    },
                    "additionalProperties": false
                })
            },
            output_schema: || {
                object_schema(json!({
                    "events": { "type": "array", "items": { "type": "object" } },
                    "next_cursor": { "type": "string" },
                    "has_more": { "type": "boolean" }
                }))
            },
            handler: |cx, args| Box::pin(list_watch_events(cx, args)),
        },
    ]
}

fn watch_schema() -> Value {
    object_schema(json!({
        "watch_id": { "type": "string" },
        "account": { "type": "string" },
        "kind": { "type": "string" },
        "thread_id": { "type": ["string", "null"] },
        "from": { "type": ["string", "null"] },
        "where": { "type": ["object", "null"] },
        "deadline": { "type": ["string", "null"] },
        "sink": { "type": ["string", "null"] },
        "created_at": { "type": "string" },
        "expires_at": { "type": "string" },
        "state": { "type": "string", "enum": ["active", "ended"] },
        "end_reason": { "type": ["string", "null"] },
        "fired": { "type": "integer" },
        "last_fired_at": { "type": ["string", "null"] }
    }))
}

fn instant_arg(args: &Value, key: &str) -> Result<Option<i64>, ToolError> {
    match opt_str(args, key)? {
        None => Ok(None),
        Some(s) => util::parse_rfc3339_ms(s)
            .map(|ms| Some(ms.div_euclid(1000)))
            .ok_or_else(|| ToolError::invalid(format!("'{key}' must be an RFC 3339 instant with an offset"))),
    }
}

/// Watch ids are `w_` + a random URL-safe id; anything else is `not_found`.
fn watch_id_arg(args: &Value) -> Result<String, ToolError> {
    let id = arg_str(args, "watch_id")?;
    let ok = id.strip_prefix("w_").is_some_and(|r| {
        (1..=64).contains(&r.len()) && r.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    if ok { Ok(id.to_string()) } else { Err(ToolError::not_found()) }
}

/// Mailboxes on which this connection currently has `read` (any status): its watches and events are visible there.
fn readable(cx: &ToolCx) -> Vec<&Mailbox> {
    cx.client.with_capability(Capability::Read).collect()
}

async fn create_watch(cx: &ToolCx, args: Value) -> Result<ToolOutput, ToolError> {
    only_keys(&args, &["account", "kind", "thread_id", "from", "where", "deadline", "expires_at", "sink"])?;
    let mb = super::account_arg(cx, &args, Capability::Read)?.clone();
    let kind_s = arg_str(&args, "kind")?;
    let kind = Kind::parse(kind_s)
        .ok_or_else(|| ToolError::invalid("'kind' must be thread_reply, from, query or no_reply_by"))?;
    let allowed: &[&str] = match kind {
        Kind::ThreadReply => &["thread_id"],
        Kind::From => &["from"],
        Kind::Query => &["where"],
        Kind::NoReplyBy => &["thread_id", "deadline"],
    };
    for k in ["thread_id", "from", "where", "deadline"] {
        if args.get(k).is_some_and(|v| !v.is_null()) && !allowed.contains(&k) {
            return Err(ToolError::invalid(format!("'{k}' does not apply to kind {}", kind.as_str())));
        }
    }
    if !mb.index_enabled {
        return Err(ToolError::invalid(
            "watches need the search index on this mailbox; ask the operator to run `dove index enable`",
        ));
    }
    let now = util::now_unix();
    let mut filter = Filter::default();
    let mut audit_query = None;
    let mut thread_id = None;
    let mut deadline = None;
    match kind {
        Kind::ThreadReply | Kind::NoReplyBy => {
            let t = arg_str(&args, "thread_id")?;
            if !crate::gmail::gateway::valid_id(t) {
                return Err(ToolError::not_found());
            }
            thread_id = Some(t.to_string());
        }
        Kind::From => {
            let raw = arg_str(&args, "from")?;
            filter.from = Some(FromMatch::parse(raw).map_err(ToolError::invalid)?);
            audit_query = Some(raw.to_string());
        }
        Kind::Query => {
            let w =
                args.get("where").filter(|v| !v.is_null()).ok_or_else(|| ToolError::invalid("'where' is required"))?;
            let e = query::parse_where(Some(w))?.ok_or_else(|| ToolError::invalid("'where' is required"))?;
            if e.uses_field(query::Field::FromSelf) {
                return Err(ToolError::invalid("'from_self' is not supported in watches"));
            }
            audit_query = Some(w.to_string());
            filter.query = Some(w.clone());
        }
    }
    let expires_at = if kind == Kind::NoReplyBy {
        if args.get("expires_at").is_some_and(|v| !v.is_null()) {
            return Err(ToolError::invalid("a no_reply_by watch ends at its deadline; omit 'expires_at'"));
        }
        let d = instant_arg(&args, "deadline")?.ok_or_else(|| ToolError::invalid("'deadline' is required"))?;
        if d <= now || d > now + watch::MAX_EXPIRY_SECS {
            return Err(ToolError::invalid("'deadline' must be in the future and at most 180 days from now"));
        }
        deadline = Some(d);
        d + watch::NO_REPLY_GRACE_SECS + 60
    } else {
        match instant_arg(&args, "expires_at")? {
            None => now + watch::DEFAULT_EXPIRY_SECS,
            Some(e) if e > now && e <= now + watch::MAX_EXPIRY_SECS => e,
            Some(_) => {
                return Err(ToolError::invalid("'expires_at' must be in the future and at most 180 days from now"));
            }
        }
    };
    // The thread must exist in the mailbox (unknown threads are not_found, like unknown messages). Its newest
    // message is the baseline: only later messages count.
    let mut baseline_ms = None;
    if let Some(t) = thread_id.clone() {
        let aid = mb.account_id.clone();
        baseline_ms = cx
            .app
            .index
            .read(cx.deadline, move |c| {
                let Some(g) = crate::index::sync::load_state(c, &aid)?.and_then(|s| s.serving_gen()) else {
                    return Ok(None);
                };
                Ok(c.query_row(
                    "SELECT max(received_at) FROM messages WHERE thread_id = ?1 AND gen = ?2",
                    params![t, g],
                    |r| r.get::<_, Option<i64>>(0),
                )?)
            })
            .await?;
        if baseline_ms.is_none() {
            return Err(ToolError::not_found());
        }
    }
    let watch_id = format!("w_{}", util::new_id());
    let sealed = match kind {
        Kind::From | Kind::Query => {
            Some(watch::seal_filter(&cx.app.vault, &watch_id, &filter).map_err(crate::error::internal_from)?)
        }
        _ => None,
    };
    let sink = opt_str(&args, "sink")?.map(str::to_string);
    let (client_id, account_id, wid) = (cx.client.client_id.clone(), mb.account_id.clone(), watch_id.clone());
    let row = cx
        .app
        .store
        .call(move |c| {
            let tx = c.transaction()?;
            let sink_id: Option<String> = match &sink {
                Some(name) => match tx
                    .query_row("SELECT id FROM sinks WHERE name = ?1", [name], |r| r.get::<_, String>(0))
                    .optional()?
                {
                    Some(id) => Some(id),
                    None => return Ok(Err(ToolError::invalid("unknown sink; list_watches shows the available ones"))),
                },
                None => None,
            };
            let active: i64 = tx.query_row(
                "SELECT count(*) FROM watches WHERE client_id = ?1 AND state = 'active' AND expires_at > ?2",
                params![client_id, now],
                |r| r.get(0),
            )?;
            if active >= watch::MAX_ACTIVE_PER_CLIENT {
                return Ok(Err(ToolError::invalid(format!(
                    "this connection already has {} active watches; delete one first",
                    watch::MAX_ACTIVE_PER_CLIENT
                ))));
            }
            tx.execute(
                "INSERT INTO watches(id, client_id, account_id, kind, thread_id, baseline_ms, filter, deadline, sink_id, \
                 created_at, expires_at, state) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'active')",
                params![
                    wid,
                    client_id,
                    account_id,
                    kind.as_str(),
                    thread_id,
                    baseline_ms,
                    sealed,
                    deadline,
                    sink_id,
                    now,
                    expires_at
                ],
            )?;
            let row = load_rows(&tx, &client_id, Some(&wid))?.pop();
            tx.commit()?;
            Ok(Ok(row))
        })
        .await
        .map_err(crate::error::internal_from)??
        .ok_or_else(ToolError::internal)?;
    let v = render(cx, &row);
    Ok(ToolOutput {
        text: format!("Watch {watch_id} created ({}).", kind.as_str()),
        structured: v,
        audit: AuditInfo {
            account: Some(mb.alias.clone()),
            object_ids: vec![watch_id],
            result_count: Some(1),
            query: audit_query,
        },
        extra: vec![],
    })
}

/// A stored watch as the tools render it.
struct Row {
    id: String,
    account_id: String,
    kind: String,
    thread_id: Option<String>,
    filter: Option<Vec<u8>>,
    deadline: Option<i64>,
    sink: Option<String>,
    created_at: i64,
    expires_at: i64,
    state: String,
    end_reason: Option<String>,
    fired: i64,
    last_fired_at: Option<i64>,
}

fn load_rows(c: &rusqlite::Connection, client_id: &str, only: Option<&str>) -> anyhow::Result<Vec<Row>> {
    let mut st = c.prepare_cached(
        "SELECT w.id, w.account_id, w.kind, w.thread_id, w.filter, w.deadline, s.name, w.created_at, w.expires_at, \
         w.state, w.end_reason, w.fired, w.last_fired_at FROM watches w LEFT JOIN sinks s ON s.id = w.sink_id \
         WHERE w.client_id = ?1 AND (?2 IS NULL OR w.id = ?2) ORDER BY w.created_at, w.id",
    )?;
    let rows = st.query_map(params![client_id, only], |r| {
        Ok(Row {
            id: r.get(0)?,
            account_id: r.get(1)?,
            kind: r.get(2)?,
            thread_id: r.get(3)?,
            filter: r.get(4)?,
            deadline: r.get(5)?,
            sink: r.get(6)?,
            created_at: r.get(7)?,
            expires_at: r.get(8)?,
            state: r.get(9)?,
            end_reason: r.get(10)?,
            fired: r.get(11)?,
            last_fired_at: r.get(12)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn render(cx: &ToolCx, w: &Row) -> Value {
    let alias = cx.client.resolve_id(&w.account_id).map(|m| m.alias.clone()).unwrap_or_default();
    let f = w.filter.as_deref().and_then(|b| watch::open_filter(&cx.app.vault, &w.id, b).ok()).unwrap_or_default();
    json!({
        "watch_id": w.id,
        "account": alias,
        "kind": w.kind,
        "thread_id": w.thread_id,
        "from": f.from.map(|m| m.display()),
        "where": f.query,
        "deadline": w.deadline.map(util::rfc3339),
        "sink": w.sink,
        "created_at": util::rfc3339(w.created_at),
        "expires_at": util::rfc3339(w.expires_at),
        "state": w.state,
        "end_reason": w.end_reason,
        "fired": w.fired,
        "last_fired_at": w.last_fired_at.map(util::rfc3339),
    })
}

async fn list_watches(cx: &ToolCx, args: Value) -> Result<ToolOutput, ToolError> {
    only_keys(&args, &[])?;
    let client_id = cx.client.client_id.clone();
    let (rows, sinks) = cx
        .app
        .store
        .call(move |c| {
            let rows = load_rows(c, &client_id, None)?;
            let mut st = c.prepare("SELECT name FROM sinks ORDER BY name")?;
            let sinks: Vec<String> = st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
            Ok((rows, sinks))
        })
        .await
        .map_err(crate::error::internal_from)?;
    let visible: Vec<&str> = readable(cx).iter().map(|m| m.account_id.as_str()).collect();
    let watches: Vec<Value> =
        rows.iter().filter(|w| visible.contains(&w.account_id.as_str())).map(|w| render(cx, w)).collect();
    let n = watches.len();
    Ok(ToolOutput {
        text: format!("{n} watch(es)."),
        structured: json!({ "watches": watches, "sinks": sinks }),
        audit: AuditInfo { result_count: Some(n as i64), ..Default::default() },
        extra: vec![],
    })
}

/// The caller's own watch on a mailbox it can read, or `not_found`. Returns its account id.
async fn own_watch(cx: &ToolCx, watch_id: &str) -> Result<String, ToolError> {
    let (client_id, wid) = (cx.client.client_id.clone(), watch_id.to_string());
    let account: Option<String> = cx
        .app
        .store
        .call(move |c| {
            Ok(c.query_row(
                "SELECT account_id FROM watches WHERE id = ?1 AND client_id = ?2",
                params![wid, client_id],
                |r| r.get(0),
            )
            .optional()?)
        })
        .await
        .map_err(crate::error::internal_from)?;
    match account {
        Some(a) if readable(cx).iter().any(|m| m.account_id == a) => Ok(a),
        _ => Err(ToolError::not_found()),
    }
}

async fn delete_watch(cx: &ToolCx, args: Value) -> Result<ToolOutput, ToolError> {
    only_keys(&args, &["watch_id"])?;
    let id = watch_id_arg(&args)?;
    let account_id = own_watch(cx, &id).await?;
    let (wid, client_id) = (id.clone(), cx.client.client_id.clone());
    cx.app
        .store
        .call(move |c| {
            // Events and their queued pushes cascade.
            c.execute("DELETE FROM watches WHERE id = ?1 AND client_id = ?2", params![wid, client_id])?;
            Ok(())
        })
        .await
        .map_err(crate::error::internal_from)?;
    let alias = cx.client.resolve_id(&account_id).map(|m| m.alias.clone()).ok();
    Ok(ToolOutput {
        text: format!("Watch {id} deleted."),
        structured: json!({ "watch_id": id, "deleted": true }),
        audit: AuditInfo { account: alias, object_ids: vec![id], result_count: Some(1), query: None },
        extra: vec![],
    })
}

async fn list_watch_events(cx: &ToolCx, args: Value) -> Result<ToolOutput, ToolError> {
    only_keys(&args, &["cursor", "watch_id", "limit"])?;
    let limit = opt_u64(&args, "limit", DEFAULT_EVENTS, 1, MAX_EVENTS)? as i64;
    let after = match opt_str(&args, "cursor")? {
        Some(c) => watch::decode_cursor(c)
            .ok_or_else(|| ToolError::new(ErrorCode::CursorInvalid, "the cursor is not valid; start without one"))?,
        None => 0,
    };
    let watch_id = match args.get("watch_id").filter(|v| !v.is_null()) {
        Some(_) => {
            let id = watch_id_arg(&args)?;
            own_watch(cx, &id).await?;
            Some(id)
        }
        None => None,
    };
    let accounts: Vec<String> = readable(cx).iter().map(|m| m.account_id.clone()).collect();
    let client_id = cx.client.client_id.clone();
    let (events, more) = if accounts.is_empty() {
        (vec![], false)
    } else {
        cx.app
            .store
            .call(move |c| {
                let marks = vec!["?"; accounts.len()].join(", ");
                let sql = format!(
                    "SELECT {} FROM watch_events e JOIN accounts a ON a.id = e.account_id \
                     WHERE e.client_id = ? AND e.seq > ? AND (? IS NULL OR e.watch_id = ?) AND e.account_id IN ({marks}) \
                     ORDER BY e.seq LIMIT ?",
                    EventRow::COLUMNS
                );
                let mut p: Vec<rusqlite::types::Value> = vec![
                    client_id.into(),
                    after.into(),
                    watch_id.clone().into(),
                    watch_id.into(),
                ];
                p.extend(accounts.into_iter().map(Into::into));
                p.push((limit + 1).into());
                let mut st = c.prepare(&sql)?;
                let mut rows: Vec<EventRow> =
                    st.query_map(params_from_iter(p), EventRow::from_row)?.collect::<Result<_, _>>()?;
                let more = rows.len() as i64 > limit;
                rows.truncate(limit as usize);
                Ok((rows, more))
            })
            .await
            .map_err(crate::error::internal_from)?
    };
    let next = events.last().map(|e| e.seq).unwrap_or(after);
    let n = events.len();
    let items: Vec<Value> = events.iter().map(EventRow::to_json).collect();
    Ok(ToolOutput {
        text: format!("{n} event(s).{}", if more { " More are available; call again with next_cursor." } else { "" }),
        structured: json!({ "events": items, "next_cursor": watch::encode_cursor(next), "has_more": more }),
        audit: AuditInfo { result_count: Some(n as i64), ..Default::default() },
        extra: vec![],
    })
}
