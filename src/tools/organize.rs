//! Organize tools: update_messages and move_messages (design 2026-11-13 sections 1 and 2).
//!
//! Both are write tools: detached, `cx.commit()` right before the first upstream write, one audit record with ids and
//! counts. Every id gets its own result; unknown ids, ids of folders this mailbox does not have and stale ids are the
//! same `not_found`. Moving into Trash or Spam/Junk needs `delete` on top of `organize`; nothing is ever deleted
//! permanently: Gmail only gets `messages.trash`, and on IMAP the only expunge outside Drafts is of the sources of a
//! copy the server confirmed (`imap::CopiedUid`), which completes a move on servers without `MOVE`.
//!
//! Gmail over IMAP (PLAN A57) never expunges outside Drafts: labels, archive and inbox are `X-GM-LABELS` changes on the
//! All Mail message (its id stays), Trash and Spam only `UID MOVE` (a server without `MOVE` is refused).

use std::collections::BTreeMap;

use futures::{StreamExt, stream};
use serde_json::{Value, json};

use super::{
    AuditInfo, ToolCx, ToolDef, ToolOutput, account_arg, account_schema, arg_str, detached, object_schema, only_keys,
};
use crate::error::{ErrorCode, ToolError};
use crate::gmail::gateway::{GmailOp, Priority, valid_id};
use crate::gmail::{SCOPE_MODIFY, WriteError};
use crate::imap::account::{self, Folder};
use crate::imap::connect::{JUNK_NAMES, TRASH_NAMES};
use crate::imap::{GmLabel, ImapMsgId, Keyword, MoveOutcome, Special, StoreFlag, UserLabel};
use crate::mail;
use crate::policy::{Capability, Mailbox, Provider};

/// Most ids per call.
pub const MAX_IDS: usize = 100;
/// Most labels per list argument.
const MAX_LABELS: usize = 20;
/// Concurrent Gmail writes per call (the gateway's per-mailbox limit applies too).
const GMAIL_CONCURRENCY: usize = 4;

fn ids_schema() -> Value {
    json!({ "type": "array", "items": { "type": "string" }, "minItems": 1, "maxItems": MAX_IDS,
            "description": "Message ids of this mailbox (from search_messages or get_message)." })
}

fn results_schema() -> Value {
    object_schema(json!({
        "account": { "type": "string" },
        "succeeded": { "type": "integer" },
        "failed": { "type": "integer" },
        "results": { "type": "array", "items": { "type": "object", "properties": {
            "id": { "type": "string" }, "ok": { "type": "boolean" },
            "new_id": { "type": ["string", "null"], "description": "The message's id after the change (IMAP ids change on move; null when the server did not say)." },
            "labels": { "type": "array", "items": { "type": "string" } },
            "error": { "type": "object" }
        } } }
    }))
}

fn labels_schema() -> Value {
    json!({ "type": "array", "items": { "type": "string" }, "maxItems": MAX_LABELS })
}

pub fn defs() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "update_messages",
            title: "Mark or label messages",
            description: concat!(
                "Mark messages read or unread, star or unstar them, and add or remove labels (Gmail user labels; IMAP ",
                "keywords). Flags: UNREAD, STARRED. At most 100 ids per call; each id gets its own result. ",
                "Labels must already exist on Gmail. To move, archive or trash, use move_messages."
            ),
            capability: Capability::Organize,
            read_only: false,
            destructive: false,
            mail_content: false,
            input_schema: || {
                let flags = json!({ "type": "array", "items": { "type": "string", "enum": ["UNREAD", "STARRED"] }, "maxItems": 2 });
                json!({ "type": "object", "properties": {
                    "account": account_schema(), "ids": ids_schema(),
                    "add_flags": flags, "remove_flags": flags,
                    "add_labels": labels_schema(), "remove_labels": labels_schema()
                }, "required": ["account", "ids"], "additionalProperties": false })
            },
            output_schema: results_schema,
            handler: |cx, args| detached(cx, args, |cx, args| Box::pin(update_messages(cx, args))),
        },
        ToolDef {
            name: "move_messages",
            title: "Move messages",
            description: concat!(
                "Move messages to a folder (IMAP) or label (Gmail), or to one of: archive, inbox, trash, spam. Moving ",
                "into Trash or Spam needs the delete permission; moving out of them only organize. Trash is ",
                "recoverable; Dove never deletes permanently. IMAP message ids change on a move: use new_id. At most ",
                "100 ids per call."
            ),
            capability: Capability::Organize,
            read_only: false,
            destructive: true,
            mail_content: false,
            input_schema: || {
                json!({ "type": "object", "properties": {
                    "account": account_schema(), "ids": ids_schema(),
                    "to": { "type": "string", "description": "archive, inbox, trash, spam, or a folder/label name from list_labels." }
                }, "required": ["account", "ids", "to"], "additionalProperties": false })
            },
            output_schema: results_schema,
            handler: |cx, args| detached(cx, args, |cx, args| Box::pin(move_messages(cx, args))),
        },
    ]
}

// ------------------------------------------------------------------ arguments

fn ids_arg(args: &Value) -> Result<Vec<String>, ToolError> {
    let Some(Value::Array(items)) = args.get("ids") else {
        return Err(ToolError::invalid("'ids' is required"));
    };
    if items.is_empty() || items.len() > MAX_IDS {
        return Err(ToolError::invalid(format!("'ids' must hold 1 to {MAX_IDS} message ids")));
    }
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for i in items {
        let id = i.as_str().ok_or_else(|| ToolError::invalid("'ids' must be a list of strings"))?;
        if !out.iter().any(|x| x == id) {
            out.push(id.to_string());
        }
    }
    Ok(out)
}

fn list_arg(args: &Value, key: &str) -> Result<Vec<String>, ToolError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(a)) if a.len() <= MAX_LABELS => a
            .iter()
            .map(|v| {
                let s = v.as_str().ok_or_else(|| ToolError::invalid(format!("'{key}' must be a list of strings")))?;
                if s.is_empty() || s.chars().count() > 100 || s.chars().any(char::is_control) {
                    return Err(ToolError::invalid(format!("invalid entry in '{key}'")));
                }
                Ok(s.to_string())
            })
            .collect(),
        Some(_) => Err(ToolError::invalid(format!("'{key}' must be a list of at most {MAX_LABELS} strings"))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flag {
    Unread,
    Starred,
}

fn flags_arg(args: &Value, key: &str) -> Result<Vec<Flag>, ToolError> {
    list_arg(args, key)?
        .iter()
        .map(|f| match f.to_ascii_uppercase().as_str() {
            "UNREAD" => Ok(Flag::Unread),
            "STARRED" => Ok(Flag::Starred),
            _ => Err(ToolError::invalid(format!("'{key}' takes UNREAD and STARRED"))),
        })
        .collect()
}

/// One id's outcome.
enum Outcome {
    Done { new_id: Option<String>, labels: Option<Vec<String>> },
    Failed(ToolError),
}

fn output(mb: &Mailbox, verb: &str, ids: &[String], outcomes: Vec<Outcome>) -> ToolOutput {
    let mut ok = 0;
    let results: Vec<Value> = ids
        .iter()
        .zip(outcomes)
        .map(|(id, o)| match o {
            Outcome::Done { new_id, labels } => {
                ok += 1;
                let mut v = json!({ "id": id, "ok": true, "new_id": new_id });
                if let Some(l) = labels {
                    v["labels"] = json!(l);
                }
                v
            }
            Outcome::Failed(e) => json!({ "id": id, "ok": false, "error": e.to_json() }),
        })
        .collect();
    let failed = ids.len() - ok;
    ToolOutput {
        text: format!("{verb} {ok} of {} message(s) in {}; {failed} failed.", ids.len(), mb.alias),
        structured: json!({ "account": mb.alias, "succeeded": ok, "failed": failed, "results": results }),
        audit: AuditInfo {
            account: Some(mb.alias.clone()),
            object_ids: ids.to_vec(),
            result_count: Some(ok as i64),
            ..Default::default()
        },
        extra: Vec::new(),
    }
}

// ------------------------------------------------------------------ Gmail helpers

/// Organize and delete need `gmail.modify`, which grants from before 0.2 lack. Checked from the stored scopes before
/// any upstream call.
pub(crate) async fn require_gmail_modify(cx: &ToolCx, mb: &Mailbox) -> Result<(), ToolError> {
    let aid = mb.account_id.clone();
    let scopes: String = cx
        .app
        .store
        .call(move |c| Ok(c.query_row("SELECT granted_scopes FROM accounts WHERE id = ?1", [aid], |r| r.get(0))?))
        .await?;
    if scopes.split_whitespace().any(|s| s == SCOPE_MODIFY) {
        return Ok(());
    }
    Err(ToolError::new(
        ErrorCode::AccountUnavailable,
        format!(
            "this Gmail mailbox was connected without permission to change messages; the operator must run \
             `dove accounts reconnect {}` before organize or delete work",
            mb.alias
        ),
    )
    .with_details(json!({ "reason": "reauth_required", "missing_scope": "gmail.modify" })))
}

/// Gmail labels by name and id: (name or id) -> (id, type).
async fn gmail_labels(cx: &ToolCx, mb: &Mailbox) -> Result<BTreeMap<String, (String, String)>, ToolError> {
    let v =
        cx.app.google.call(&mb.account_id, || GmailOp::Labels, &[], None, Priority::Interactive, cx.deadline).await?;
    let mut out = BTreeMap::new();
    for l in v["labels"].as_array().into_iter().flatten() {
        let (Some(id), Some(name)) = (l["id"].as_str(), l["name"].as_str()) else { continue };
        let kind = l["type"].as_str().unwrap_or("user").to_string();
        out.insert(name.to_string(), (id.to_string(), kind.clone()));
        out.insert(id.to_string(), (id.to_string(), kind));
    }
    Ok(out)
}

/// A user label's id. System labels are reached through flags and move targets only.
fn user_label(map: &BTreeMap<String, (String, String)>, name: &str) -> Result<String, ToolError> {
    match map.get(name) {
        Some((id, kind)) if kind == "user" => Ok(id.clone()),
        Some(_) => Err(ToolError::invalid(format!(
            "'{}' is a system label; use add_flags/remove_flags or move_messages",
            name.chars().take(64).collect::<String>()
        ))),
        None => Err(ToolError::invalid(format!(
            "unknown label '{}' (Dove does not create labels)",
            name.chars().take(64).collect::<String>()
        ))),
    }
}

/// Runs one Gmail write per id, a few at a time, in id order.
async fn gmail_each<'a, F>(ids: &'a [String], f: F) -> Vec<Outcome>
where
    F: Fn(&'a str) -> BoxFut<'a, Outcome>,
{
    // Boxed up front: a stream of closures borrowing `ids` trips rustc's higher-ranked closure inference.
    let futs: Vec<BoxFut<'a, Outcome>> = ids
        .iter()
        .map(|id| -> BoxFut<'a, Outcome> {
            if !valid_id(id) {
                return Box::pin(async { Outcome::Failed(ToolError::not_found()) });
            }
            f(id)
        })
        .collect();
    stream::iter(futs).buffered(GMAIL_CONCURRENCY).collect().await
}

type BoxFut<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

async fn gmail_write<'a>(
    cx: &ToolCx,
    mb: &Mailbox,
    op: impl Fn() -> GmailOp<'a>,
    body: &Value,
) -> Result<Value, ToolError> {
    cx.app.google.write(&mb.account_id, op, body, cx.write_deadline()).await.map_err(|WriteError { error, .. }| error)
}

// ------------------------------------------------------------------ IMAP helpers

/// Ids grouped by source folder (and UIDVALIDITY); malformed ids and ids of unknown folders are `not_found`.
struct ImapGroups {
    folders: Vec<Folder>,
    /// (folder_id, uidvalidity) -> (index into ids, uid)
    groups: BTreeMap<(i64, u32), Vec<(usize, u32)>>,
    outcomes: Vec<Option<Outcome>>,
}

async fn imap_groups(cx: &ToolCx, mb: &Mailbox, ids: &[String]) -> Result<ImapGroups, ToolError> {
    let aid = mb.account_id.clone();
    let folders = cx.app.store.call(move |c| account::load_folders(c, &aid)).await?;
    let mut groups: BTreeMap<(i64, u32), Vec<(usize, u32)>> = BTreeMap::new();
    let mut outcomes: Vec<Option<Outcome>> = (0..ids.len()).map(|_| None).collect();
    for (i, id) in ids.iter().enumerate() {
        match ImapMsgId::parse(id).filter(|m| folders.iter().any(|f| f.folder_id == m.folder_id)) {
            Some(m) => groups.entry((m.folder_id, m.uidvalidity)).or_default().push((i, m.uid)),
            None => outcomes[i] = Some(Outcome::Failed(ToolError::not_found())),
        }
    }
    Ok(ImapGroups { folders, groups, outcomes })
}

fn folder_of(folders: &[Folder], folder_id: i64) -> &Folder {
    folders.iter().find(|f| f.folder_id == folder_id).expect("grouped ids have a folder")
}

// ------------------------------------------------------------------ update_messages

async fn update_messages(cx: &ToolCx, args: Value) -> Result<ToolOutput, ToolError> {
    only_keys(&args, &["account", "ids", "add_flags", "remove_flags", "add_labels", "remove_labels"])?;
    let mb = account_arg(cx, &args, Capability::Organize)?.clone();
    let ids = ids_arg(&args)?;
    let (add_flags, remove_flags) = (flags_arg(&args, "add_flags")?, flags_arg(&args, "remove_flags")?);
    let (add_labels, remove_labels) = (list_arg(&args, "add_labels")?, list_arg(&args, "remove_labels")?);
    if add_flags.is_empty() && remove_flags.is_empty() && add_labels.is_empty() && remove_labels.is_empty() {
        return Err(ToolError::invalid("nothing to change: pass add_flags, remove_flags, add_labels or remove_labels"));
    }
    if add_flags.iter().any(|f| remove_flags.contains(f)) || add_labels.iter().any(|l| remove_labels.contains(l)) {
        return Err(ToolError::invalid("the same flag or label is both added and removed"));
    }
    let outcomes = match mb.provider {
        Provider::Gmail => gmail_update(cx, &mb, &ids, &add_flags, &remove_flags, &add_labels, &remove_labels).await?,
        Provider::Imap => imap_update(cx, &mb, &ids, &add_flags, &remove_flags, &add_labels, &remove_labels).await?,
    };
    crate::index::wake(&cx.app, &mb.account_id);
    Ok(output(&mb, "Updated", &ids, outcomes))
}

fn gmail_flag(f: Flag) -> &'static str {
    match f {
        Flag::Unread => "UNREAD",
        Flag::Starred => "STARRED",
    }
}

async fn gmail_update(
    cx: &ToolCx,
    mb: &Mailbox,
    ids: &[String],
    add_flags: &[Flag],
    remove_flags: &[Flag],
    add_labels: &[String],
    remove_labels: &[String],
) -> Result<Vec<Outcome>, ToolError> {
    require_gmail_modify(cx, mb).await?;
    let mut add: Vec<String> = add_flags.iter().map(|f| gmail_flag(*f).to_string()).collect();
    let mut remove: Vec<String> = remove_flags.iter().map(|f| gmail_flag(*f).to_string()).collect();
    if !add_labels.is_empty() || !remove_labels.is_empty() {
        let map = gmail_labels(cx, mb).await?;
        for l in add_labels {
            add.push(user_label(&map, l)?);
        }
        for l in remove_labels {
            remove.push(user_label(&map, l)?);
        }
    }
    let body = json!({ "addLabelIds": add, "removeLabelIds": remove });
    cx.commit()?;
    let body = &body;
    Ok(gmail_each(ids, move |id| {
        Box::pin(async move {
            match gmail_write(cx, mb, || GmailOp::ModifyMessage(id), body).await {
                Ok(_) => Outcome::Done { new_id: Some(id.to_string()), labels: None },
                Err(e) => Outcome::Failed(e),
            }
        })
    })
    .await)
}

fn imap_flags(flags: &[Flag], labels: &[String], adding: bool) -> Result<(Vec<StoreFlag>, Vec<StoreFlag>), ToolError> {
    // UNREAD is the absence of \Seen: adding UNREAD removes \Seen.
    let (mut add, mut remove) = (Vec::new(), Vec::new());
    for f in flags {
        match (f, adding) {
            (Flag::Unread, true) => remove.push(StoreFlag::Seen),
            (Flag::Unread, false) => add.push(StoreFlag::Seen),
            (Flag::Starred, true) => add.push(StoreFlag::Flagged),
            (Flag::Starred, false) => remove.push(StoreFlag::Flagged),
        }
    }
    for l in labels {
        let k = Keyword::new(l).ok_or_else(|| {
            ToolError::invalid(format!(
                "'{}' is not a valid IMAP keyword (ASCII letters, digits and -_.$ etc., no spaces or backslash)",
                l.chars().take(64).collect::<String>()
            ))
        })?;
        if adding { add.push(StoreFlag::Keyword(k)) } else { remove.push(StoreFlag::Keyword(k)) }
    }
    Ok((add, remove))
}

async fn imap_update(
    cx: &ToolCx,
    mb: &Mailbox,
    ids: &[String],
    add_flags: &[Flag],
    remove_flags: &[Flag],
    add_labels: &[String],
    remove_labels: &[String],
) -> Result<Vec<Outcome>, ToolError> {
    if account::gmail_mode(&cx.app, &mb.account_id).await? {
        return gmail_imap_update(cx, mb, ids, add_flags, remove_flags, add_labels, remove_labels).await;
    }
    let (mut add, mut remove) = imap_flags(add_flags, add_labels, true)?;
    let (a2, r2) = imap_flags(remove_flags, remove_labels, false)?;
    add.extend(a2);
    remove.extend(r2);
    let ImapGroups { folders, groups, mut outcomes } = imap_groups(cx, mb, ids).await?;
    cx.commit()?;
    for ((folder_id, uidvalidity), members) in groups {
        let f = folder_of(&folders, folder_id).clone();
        let uids: Vec<u32> = members.iter().map(|(_, u)| *u).collect();
        let (name, add, remove) = (f.name.clone(), add.clone(), remove.clone());
        let r = account::with_session(&cx.app, &mb.account_id, move |s| {
            Box::pin(async move { s.store_flags(&name, uidvalidity, &uids, &add, &remove).await })
        })
        .await;
        for (i, uid) in members {
            outcomes[i] = Some(match &r {
                Ok(metas) => match metas.iter().find(|m| m.uid == uid) {
                    Some(m) => Outcome::Done {
                        new_id: Some(ids[i].clone()),
                        labels: Some(mail::imap_labels(&f.name_utf8, &m.flags, f.special)),
                    },
                    None => Outcome::Failed(ToolError::not_found()),
                },
                Err(e) => Outcome::Failed(e.clone()),
            });
        }
    }
    Ok(outcomes.into_iter().map(|o| o.unwrap_or_else(|| Outcome::Failed(ToolError::internal()))).collect())
}

// ------------------------------------------------------------------ move_messages

/// Where a move goes, as the agent named it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Archive,
    Inbox,
    Trash,
    Spam,
    Named(String),
}

fn target_arg(args: &Value) -> Result<Target, ToolError> {
    let to = arg_str(args, "to")?.trim();
    if to.is_empty() || to.chars().count() > 200 || to.chars().any(char::is_control) {
        return Err(ToolError::invalid("'to' must be a folder or label name, or archive, inbox, trash or spam"));
    }
    Ok(match to.to_ascii_lowercase().as_str() {
        "archive" => Target::Archive,
        "inbox" => Target::Inbox,
        "trash" => Target::Trash,
        "spam" | "junk" => Target::Spam,
        _ => Target::Named(to.to_string()),
    })
}

async fn move_messages(cx: &ToolCx, args: Value) -> Result<ToolOutput, ToolError> {
    only_keys(&args, &["account", "ids", "to"])?;
    let mb = account_arg(cx, &args, Capability::Organize)?.clone();
    let ids = ids_arg(&args)?;
    let target = target_arg(&args)?;
    let outcomes = match mb.provider {
        Provider::Gmail => gmail_move(cx, &mb, &ids, &target).await?,
        Provider::Imap => imap_move(cx, &mb, &ids, &target).await?,
    };
    crate::index::wake(&cx.app, &mb.account_id);
    Ok(output(&mb, "Moved", &ids, outcomes))
}

/// Moving into Trash or Spam/Junk hides mail and providers purge it: that needs `delete` (design section 1).
fn require_delete(cx: &ToolCx, mb: &Mailbox) -> Result<(), ToolError> {
    cx.client.authorize_id(Capability::Delete, &mb.account_id).map(|_| ()).map_err(|e| {
        if e.code == ErrorCode::Forbidden {
            ToolError::forbidden("moving to Trash or Spam needs the delete permission on this mailbox")
        } else {
            e
        }
    })
}

async fn gmail_move(cx: &ToolCx, mb: &Mailbox, ids: &[String], target: &Target) -> Result<Vec<Outcome>, ToolError> {
    if matches!(target, Target::Trash | Target::Spam) {
        require_delete(cx, mb)?;
    }
    require_gmail_modify(cx, mb).await?;
    let label = match target {
        Target::Named(n) => Some(user_label(&gmail_labels(cx, mb).await?, n)?),
        _ => None,
    };
    // Moving into the inbox or a label also takes a message out of Trash/Spam: read the current labels first (reads
    // happen before the commit).
    let current: Vec<Option<Vec<String>>> = if matches!(target, Target::Inbox | Target::Named(_)) {
        let futs: Vec<BoxFut<'_, Option<Vec<String>>>> = ids
            .iter()
            .map(|id| -> BoxFut<'_, Option<Vec<String>>> {
                Box::pin(async move {
                    if !valid_id(id) {
                        return None;
                    }
                    let q = [("format", "minimal".to_string())];
                    let v = cx
                        .app
                        .google
                        .call(&mb.account_id, || GmailOp::GetMessage(id), &q, None, Priority::Interactive, cx.deadline)
                        .await
                        .ok()?;
                    let labels = v["labelIds"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|l| l.as_str().map(String::from)).collect());
                    Some(labels.unwrap_or_default())
                })
            })
            .collect();
        stream::iter(futs).buffered(GMAIL_CONCURRENCY).collect().await
    } else {
        vec![Some(vec![]); ids.len()]
    };
    cx.commit()?;
    let (label, current) = (&label, &current);
    Ok(gmail_each(ids, move |id| {
        Box::pin(async move {
            let i = ids.iter().position(|x| x == id).unwrap_or_default();
            let Some(labels) = &current[i] else { return Outcome::Failed(ToolError::not_found()) };
            let has = |l: &str| labels.iter().any(|x| x == l);
            let r = async {
                match target {
                    Target::Trash => return gmail_write(cx, mb, || GmailOp::TrashMessage(id), &json!({})).await,
                    Target::Spam => {
                        let body = json!({ "addLabelIds": ["SPAM"], "removeLabelIds": ["INBOX"] });
                        return gmail_write(cx, mb, || GmailOp::ModifyMessage(id), &body).await;
                    }
                    Target::Archive => {
                        let body = json!({ "removeLabelIds": ["INBOX"] });
                        return gmail_write(cx, mb, || GmailOp::ModifyMessage(id), &body).await;
                    }
                    Target::Inbox | Target::Named(_) => {}
                }
                if has("TRASH") {
                    gmail_write(cx, mb, || GmailOp::UntrashMessage(id), &json!({})).await?;
                }
                let mut remove: Vec<&str> = if has("SPAM") { vec!["SPAM"] } else { vec![] };
                let add = match label {
                    Some(l) => {
                        remove.push("INBOX");
                        l.as_str()
                    }
                    None => "INBOX",
                };
                let body = json!({ "addLabelIds": [add], "removeLabelIds": remove });
                gmail_write(cx, mb, || GmailOp::ModifyMessage(id), &body).await
            };
            match r.await {
                Ok(_) => Outcome::Done { new_id: Some(id.to_string()), labels: None },
                Err(e) => Outcome::Failed(e),
            }
        })
    })
    .await)
}

/// Last path segment of a folder name (`/` or `.` delimited).
fn leaf(name: &str) -> &str {
    name.rsplit(['/', '.']).next().unwrap_or(name)
}

/// Whether moving into `f` counts as deleting: it is the Trash or Junk folder (special-use or a well-known name),
/// or lies anywhere below one (`Trash/alt`, `INBOX.Spam`), since providers purge those with their parent.
fn is_trash_or_junk(f: &Folder, folders: &[Folder]) -> bool {
    let purging_name = |seg: &str| TRASH_NAMES.iter().chain(JUNK_NAMES).any(|n| seg.trim().eq_ignore_ascii_case(n));
    let under = |parent: &str| {
        f.name_utf8.len() > parent.len()
            && f.name_utf8[..parent.len()].eq_ignore_ascii_case(parent)
            && f.name_utf8[parent.len()..].starts_with(['/', '.'])
    };
    matches!(f.special, Some(Special::Trash | Special::Junk))
        || f.name_utf8.split(['/', '.']).any(purging_name)
        || folders.iter().any(|p| matches!(p.special, Some(Special::Trash | Special::Junk)) && under(&p.name_utf8))
}

const ARCHIVE_NAMES: &[&str] = &["Archive", "Archives", "Archiv"];

fn imap_target<'a>(folders: &'a [Folder], target: &Target) -> Result<&'a Folder, ToolError> {
    let by_special = |s: Special| folders.iter().find(|f| f.special == Some(s));
    let by_leaf =
        |names: &[&str]| names.iter().find_map(|n| folders.iter().find(|f| leaf(&f.name_utf8).eq_ignore_ascii_case(n)));
    let missing = |what: &str| {
        ToolError::invalid(format!("this mailbox has no {what} folder; pass a folder name from list_labels"))
    };
    match target {
        Target::Inbox => folders.iter().find(|f| f.name.eq_ignore_ascii_case("INBOX")).ok_or_else(|| missing("INBOX")),
        Target::Trash => by_special(Special::Trash).or_else(|| by_leaf(TRASH_NAMES)).ok_or_else(|| missing("Trash")),
        Target::Spam => by_special(Special::Junk).or_else(|| by_leaf(JUNK_NAMES)).ok_or_else(|| missing("Junk")),
        Target::Archive => by_leaf(ARCHIVE_NAMES).ok_or_else(|| missing("Archive")),
        Target::Named(n) => {
            let label = mail::label_text(n);
            folders
                .iter()
                .find(|f| mail::label_text(&f.name_utf8) == label)
                .or_else(|| {
                    let mut it = folders.iter().filter(|f| mail::label_text(&f.name_utf8).eq_ignore_ascii_case(&label));
                    match (it.next(), it.next()) {
                        (Some(f), None) => Some(f),
                        _ => None,
                    }
                })
                .ok_or_else(|| {
                    ToolError::invalid(format!(
                        "unknown folder '{}'; see list_labels",
                        label.chars().take(64).collect::<String>()
                    ))
                })
        }
    }
}

async fn imap_move(cx: &ToolCx, mb: &Mailbox, ids: &[String], target: &Target) -> Result<Vec<Outcome>, ToolError> {
    if account::gmail_mode(&cx.app, &mb.account_id).await? {
        return gmail_imap_move(cx, mb, ids, target).await;
    }
    let ImapGroups { folders, groups, mut outcomes } = imap_groups(cx, mb, ids).await?;
    let dest = imap_target(&folders, target)?.clone();
    if matches!(target, Target::Trash | Target::Spam) || is_trash_or_junk(&dest, &folders) {
        require_delete(cx, mb)?;
    }
    let mut committed = false;
    for ((folder_id, uidvalidity), members) in groups {
        if folder_id == dest.folder_id {
            // Already there: nothing to do, the id stays.
            for (i, _) in members {
                outcomes[i] = Some(Outcome::Done { new_id: Some(ids[i].clone()), labels: None });
            }
            continue;
        }
        if !committed {
            cx.commit()?;
            committed = true;
        }
        let src = folder_of(&folders, folder_id).name.clone();
        move_group(cx, mb, &src, uidvalidity, members, &dest, &mut outcomes).await;
    }
    Ok(outcomes.into_iter().map(|o| o.unwrap_or_else(|| Outcome::Failed(ToolError::internal()))).collect())
}

/// Moves one source folder's members (index into ids, UID) to `dest` and records each one's outcome.
async fn move_group(
    cx: &ToolCx,
    mb: &Mailbox,
    src: &str,
    uidvalidity: u32,
    members: Vec<(usize, u32)>,
    dest: &Folder,
    outcomes: &mut [Option<Outcome>],
) {
    let src = src.to_string();
    let uids: Vec<u32> = members.iter().map(|(_, u)| *u).collect();
    let dest_name = dest.name.clone();
    let r: Result<MoveOutcome, ToolError> = account::with_session(&cx.app, &mb.account_id, move |s| {
        Box::pin(async move { s.move_uids(&src, uidvalidity, &uids, &dest_name).await })
    })
    .await;
    let new_id = |uv: Option<u32>, d: Option<u32>| match (uv, d) {
        (Some(uidvalidity), Some(uid)) => Some(ImapMsgId { folder_id: dest.folder_id, uidvalidity, uid }.encode()),
        _ => None,
    };
    for (i, uid) in members {
        outcomes[i] = Some(match &r {
            Ok(m) => {
                if let Some((_, d)) = m.moved.iter().find(|(s, _)| *s == uid) {
                    Outcome::Done { new_id: new_id(m.dest_uidvalidity, *d), labels: None }
                } else if let Some((_, d)) = m.copied_kept.iter().find(|(s, _)| *s == uid) {
                    Outcome::Failed(
                        ToolError::new(
                            ErrorCode::UpstreamError,
                            "the message was copied but the original could not be removed; it is now in both folders",
                        )
                        .with_details(json!({ "copy_id": new_id(m.dest_uidvalidity, *d) })),
                    )
                } else {
                    Outcome::Failed(ToolError::not_found())
                }
            }
            Err(e) => Outcome::Failed(e.clone()),
        });
    }
}

// ------------------------------------------------------------------ Gmail over IMAP (PLAN A57)

/// Where a message of a Gmail-mode mailbox can be organized from: All Mail (labels, archive, inbox, trash, spam) or
/// Trash/Spam (moved out with `UID MOVE`). Label folders hold copies whose ids search never returns.
fn gmail_source(f: &Folder) -> Result<(), ToolError> {
    match f.special {
        Some(Special::All | Special::Trash | Special::Junk) => Ok(()),
        _ => Err(ToolError::invalid(
            "on Gmail, organize messages by their All Mail, Spam or Trash id (as search_messages returns them)",
        )),
    }
}

/// `[Gmail]/` (or `[Google Mail]/`): the parent of the All Mail folder, under which Gmail lists its system folders.
fn gmail_system_prefix(folders: &[Folder]) -> Option<String> {
    let all = folders.iter().find(|f| f.special == Some(Special::All))?;
    all.name.rsplit_once('/').map(|(p, _)| format!("{p}/"))
}

/// Whether `f` is a user label: no special use, not INBOX and not one of Gmail's system folders.
fn is_gmail_user_label(f: &Folder, folders: &[Folder]) -> bool {
    f.special.is_none()
        && !f.name.eq_ignore_ascii_case("INBOX")
        && !gmail_system_prefix(folders).is_some_and(|p| f.name.starts_with(&p))
}

/// A folder by the name an agent gave (its label text; exact, else the only case-insensitive match).
fn folder_by_label<'a>(folders: &'a [Folder], name: &str) -> Option<&'a Folder> {
    let label = mail::label_text(name);
    folders.iter().find(|f| mail::label_text(&f.name_utf8) == label).or_else(|| {
        let mut it = folders.iter().filter(|f| mail::label_text(&f.name_utf8).eq_ignore_ascii_case(&label));
        match (it.next(), it.next()) {
            (Some(f), None) => Some(f),
            _ => None,
        }
    })
}

/// A user label for `X-GM-LABELS`: it must exist as a folder (Dove creates no labels) and not be a system folder.
fn gmail_user_label(folders: &[Folder], name: &str) -> Result<GmLabel, ToolError> {
    let short = || mail::label_text(name).chars().take(64).collect::<String>();
    let f = folder_by_label(folders, name)
        .ok_or_else(|| ToolError::invalid(format!("unknown label '{}' (Dove does not create labels)", short())))?;
    if !is_gmail_user_label(f, folders) {
        return Err(ToolError::invalid(format!(
            "'{}' is a system label; use add_flags/remove_flags or move_messages",
            short()
        )));
    }
    UserLabel::new(&f.name)
        .map(GmLabel::User)
        .ok_or_else(|| ToolError::invalid(format!("unusable label '{}'", short())))
}

async fn gmail_imap_update(
    cx: &ToolCx,
    mb: &Mailbox,
    ids: &[String],
    add_flags: &[Flag],
    remove_flags: &[Flag],
    add_labels: &[String],
    remove_labels: &[String],
) -> Result<Vec<Outcome>, ToolError> {
    let (mut add, mut remove) = imap_flags(add_flags, &[], true)?;
    let (a2, r2) = imap_flags(remove_flags, &[], false)?;
    add.extend(a2);
    remove.extend(r2);
    let ImapGroups { folders, groups, mut outcomes } = imap_groups(cx, mb, ids).await?;
    let gadd: Vec<GmLabel> = add_labels.iter().map(|l| gmail_user_label(&folders, l)).collect::<Result<_, _>>()?;
    let gremove: Vec<GmLabel> =
        remove_labels.iter().map(|l| gmail_user_label(&folders, l)).collect::<Result<_, _>>()?;
    let mut committed = false;
    for ((folder_id, uidvalidity), members) in groups {
        let f = folder_of(&folders, folder_id).clone();
        let refused = gmail_source(&f).err().or_else(|| {
            (f.special != Some(Special::All) && !(gadd.is_empty() && gremove.is_empty()))
                .then(|| ToolError::invalid("labels cannot change in Trash or Spam; move the message out first"))
        });
        if let Some(e) = refused {
            for (i, _) in members {
                outcomes[i] = Some(Outcome::Failed(e.clone()));
            }
            continue;
        }
        if !committed {
            cx.commit()?;
            committed = true;
        }
        let uids: Vec<u32> = members.iter().map(|(_, u)| *u).collect();
        let (name, add, remove, gadd, gremove) =
            (f.name.clone(), add.clone(), remove.clone(), gadd.clone(), gremove.clone());
        let r = account::with_session(&cx.app, &mb.account_id, move |s| {
            Box::pin(async move {
                let mut metas = Vec::new();
                if !add.is_empty() || !remove.is_empty() {
                    metas = s.store_flags(&name, uidvalidity, &uids, &add, &remove).await?;
                }
                if !gadd.is_empty() || !gremove.is_empty() {
                    metas = s.store_gm_labels(&name, uidvalidity, &uids, &gadd, &gremove).await?;
                }
                Ok(metas)
            })
        })
        .await;
        for (i, uid) in members {
            outcomes[i] = Some(match &r {
                Ok(metas) => match metas.iter().find(|m| m.uid == uid) {
                    Some(m) => {
                        Outcome::Done { new_id: Some(ids[i].clone()), labels: Some(mail::message_labels(&f, m, true)) }
                    }
                    None => Outcome::Failed(ToolError::not_found()),
                },
                Err(e) => Outcome::Failed(e.clone()),
            });
        }
    }
    Ok(outcomes.into_iter().map(|o| o.unwrap_or_else(|| Outcome::Failed(ToolError::internal()))).collect())
}

/// Where a Gmail-mode move goes.
enum GmailDest {
    Archive,
    Inbox,
    Label(Folder, GmLabel),
    /// Trash or Spam: reached only with `UID MOVE`.
    Bin(Folder),
}

fn gmail_dest(folders: &[Folder], target: &Target) -> Result<GmailDest, ToolError> {
    let by_special = |sp: Special, what: &str| {
        folders.iter().find(|f| f.special == Some(sp)).cloned().ok_or_else(|| {
            ToolError::invalid(format!(
                "this Gmail mailbox shows no {what} folder in IMAP; turn on \"Show in IMAP\" for it"
            ))
        })
    };
    match target {
        Target::Archive => Ok(GmailDest::Archive),
        Target::Inbox => Ok(GmailDest::Inbox),
        Target::Trash => Ok(GmailDest::Bin(by_special(Special::Trash, "Trash")?)),
        Target::Spam => Ok(GmailDest::Bin(by_special(Special::Junk, "Spam")?)),
        Target::Named(n) => {
            let f = folder_by_label(folders, n).ok_or_else(|| {
                ToolError::invalid(format!(
                    "unknown label '{}'; see list_labels",
                    mail::label_text(n).chars().take(64).collect::<String>()
                ))
            })?;
            match f.special {
                Some(Special::All) => Ok(GmailDest::Archive),
                Some(Special::Trash | Special::Junk) => Ok(GmailDest::Bin(f.clone())),
                _ if f.name.eq_ignore_ascii_case("INBOX") => Ok(GmailDest::Inbox),
                _ => Ok(GmailDest::Label(f.clone(), gmail_user_label(folders, n)?)),
            }
        }
    }
}

async fn gmail_imap_move(
    cx: &ToolCx,
    mb: &Mailbox,
    ids: &[String],
    target: &Target,
) -> Result<Vec<Outcome>, ToolError> {
    let ImapGroups { folders, groups, mut outcomes } = imap_groups(cx, mb, ids).await?;
    let dest = gmail_dest(&folders, target)?;
    if matches!(dest, GmailDest::Bin(_)) {
        require_delete(cx, mb)?;
    }
    let missing = |what: &str| ToolError::invalid(format!("this Gmail mailbox shows no {what} folder in IMAP"));
    let all = folders.iter().find(|f| f.special == Some(Special::All)).cloned().ok_or_else(|| missing("All Mail"))?;
    let inbox = folders.iter().find(|f| f.name.eq_ignore_ascii_case("INBOX")).cloned();
    let mut committed = false;
    for ((folder_id, uidvalidity), members) in groups {
        let f = folder_of(&folders, folder_id).clone();
        if let Err(e) = gmail_source(&f) {
            for (i, _) in members {
                outcomes[i] = Some(Outcome::Failed(e.clone()));
            }
            continue;
        }
        // What to do: a label change on All Mail (the id stays), or a MOVE into or out of Trash/Spam.
        let in_all = f.special == Some(Special::All);
        let (gadd, gremove, move_to): (Vec<GmLabel>, Vec<GmLabel>, Option<Folder>) = match (&dest, in_all) {
            (GmailDest::Archive, true) => (vec![], vec![GmLabel::Inbox], None),
            (GmailDest::Inbox, true) => (vec![GmLabel::Inbox], vec![], None),
            (GmailDest::Label(_, l), true) => (vec![l.clone()], vec![GmLabel::Inbox], None),
            (GmailDest::Bin(b), _) => (vec![], vec![], Some(b.clone())),
            // Out of Trash/Spam: UID MOVE to All Mail, INBOX or the label's folder.
            (GmailDest::Archive, false) => (vec![], vec![], Some(all.clone())),
            (GmailDest::Inbox, false) => (vec![], vec![], Some(inbox.clone().ok_or_else(|| missing("INBOX"))?)),
            (GmailDest::Label(lf, _), false) => (vec![], vec![], Some(lf.clone())),
        };
        if move_to.as_ref().is_some_and(|d| d.folder_id == folder_id) {
            for (i, _) in members {
                outcomes[i] = Some(Outcome::Done { new_id: Some(ids[i].clone()), labels: None });
            }
            continue;
        }
        if !committed {
            cx.commit()?;
            committed = true;
        }
        if let Some(d) = move_to {
            move_group(cx, mb, &f.name, uidvalidity, members, &d, &mut outcomes).await;
            continue;
        }
        let uids: Vec<u32> = members.iter().map(|(_, u)| *u).collect();
        let name = f.name.clone();
        let r = account::with_session(&cx.app, &mb.account_id, move |s| {
            Box::pin(async move { s.store_gm_labels(&name, uidvalidity, &uids, &gadd, &gremove).await })
        })
        .await;
        for (i, uid) in members {
            outcomes[i] = Some(match &r {
                Ok(metas) => match metas.iter().find(|m| m.uid == uid) {
                    Some(m) => {
                        Outcome::Done { new_id: Some(ids[i].clone()), labels: Some(mail::message_labels(&f, m, true)) }
                    }
                    None => Outcome::Failed(ToolError::not_found()),
                },
                Err(e) => Outcome::Failed(e.clone()),
            });
        }
    }
    Ok(outcomes.into_iter().map(|o| o.unwrap_or_else(|| Outcome::Failed(ToolError::internal()))).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(id: i64, name: &str, special: Option<Special>) -> Folder {
        Folder { folder_id: id, name: name.into(), name_utf8: name.into(), special }
    }

    #[test]
    fn targets_and_trash_detection() {
        let fs = vec![
            folder(1, "INBOX", None),
            folder(2, "Papierkorb", None),
            folder(3, "Spam", Some(Special::Junk)),
            folder(4, "Archiv", None),
            folder(5, "Projekte/Kunden", None),
            folder(6, "Deleted Items", Some(Special::Trash)),
            folder(7, "Deleted Items/2025", None),
            folder(8, "INBOX.Spamverdacht", None),
            folder(9, "Archiv/Trash", None),
            folder(10, "Spam-Filter", None),
            folder(11, "Spam/alt", None),
        ];
        assert_eq!(imap_target(&fs, &Target::Inbox).unwrap().folder_id, 1);
        // The special-use flag wins over a well-known name.
        assert_eq!(imap_target(&fs, &Target::Trash).unwrap().folder_id, 6);
        assert_eq!(imap_target(&fs, &Target::Spam).unwrap().folder_id, 3);
        assert_eq!(imap_target(&fs, &Target::Archive).unwrap().folder_id, 4);
        assert_eq!(imap_target(&fs, &Target::Named("projekte/kunden".into())).unwrap().folder_id, 5);
        assert!(imap_target(&fs, &Target::Named("Nope".into())).is_err());
        // A trash folder by name only (no special-use flag) still needs delete.
        let purging: Vec<i64> = fs.iter().filter(|f| is_trash_or_junk(f, &fs)).map(|f| f.folder_id).collect();
        // Subfolders of Trash/Junk and Strato's `Spamverdacht` count as well.
        assert_eq!(purging, vec![2, 3, 6, 7, 8, 9, 11]);
        assert_eq!(target_arg(&json!({"to": "Junk"})).unwrap(), Target::Spam);
        assert!(target_arg(&json!({"to": "a\nb"})).is_err());
    }

    #[test]
    fn unread_maps_to_seen_inverted() {
        let (add, remove) = imap_flags(&[Flag::Unread, Flag::Starred], &["Work".into()], true).unwrap();
        assert_eq!(add, vec![StoreFlag::Flagged, StoreFlag::Keyword(Keyword::new("Work").unwrap())]);
        assert_eq!(remove, vec![StoreFlag::Seen]);
        let (add, remove) = imap_flags(&[Flag::Unread], &[], false).unwrap();
        assert_eq!((add, remove), (vec![StoreFlag::Seen], vec![]));
        assert!(imap_flags(&[], &["\\Deleted".into()], true).is_err());
        assert!(imap_flags(&[], &["two words".into()], true).is_err());
    }
}
