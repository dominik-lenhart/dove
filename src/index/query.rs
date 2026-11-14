//! Typed search request -> parameterized SQL (spec 5.3 `search_messages`, 7.9 "Query planning").
//!
//! The caller never supplies SQL, FTS syntax or identifiers. Fields and operators are whitelisted, every value is
//! bound, and FTS input is re-tokenized and emitted as quoted string literals. Eligible generations (= authorized,
//! indexed mailboxes) are fixed before any predicate runs and appear in every subquery.
//!
//! Every predicate compiles to a non-NULL 0/1 expression, so `not` is an exact complement within the candidate set.

use std::collections::HashMap;
use std::fmt::Write as _;

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, OptionalExtension, params_from_iter};
use serde::Serialize;
use serde_json::{Map, Value, json};

use super::ingest::{ROLE_BCC, ROLE_CC, ROLE_FROM, ROLE_TO, norm_addr, norm_domain};
use crate::error::ToolError;
use crate::mime::Category;
use crate::util;

pub const MAX_DEPTH: usize = 4;
pub const MAX_PREDICATES: usize = 32;
pub const MAX_LIST: usize = 100;
pub const MAX_STRING: usize = 256;
pub const DEFAULT_LIMIT: usize = 20;
pub const MAX_LIMIT: usize = 100;
/// Prefix tokens shorter than this are refused as too broad (spec 8.1 "wide-prefix FTS").
pub const MIN_PREFIX_CHARS: usize = 2;

pub const SELECTABLE: &[&str] = &[
    "ref",
    "account",
    "message_id",
    "thread_id",
    "received_at",
    "from",
    "to",
    "cc",
    "bcc",
    "subject",
    "labels",
    "snippet",
    "size_bytes",
    "attachment_names",
    "attachment_mime_types",
    "is_unread",
    "is_starred",
    "is_draft",
    "has_attachment",
    "category",
    "from_self",
];
pub const DEFAULT_SELECT: &[&str] = &["ref", "received_at", "from", "subject"];
/// Per-thread columns of `group_by: "thread"` (computed over every message of the thread, see [`thread_page_sql`]).
pub const THREAD_COLUMNS: &[&str] =
    &["message_count", "matched_count", "last_sender_is_self", "last_inbound_at", "last_outbound_at", "awaiting_reply"];
/// Default projection of the thread view: the latest message's handle and headline plus the reply status.
pub const THREAD_DEFAULT_SELECT: &[&str] =
    &["ref", "thread_id", "received_at", "from", "subject", "message_count", "awaiting_reply"];
/// The label Gmail (and Dove's IMAP mapping of the Sent folder) gives to mail sent from the mailbox.
pub const SENT_LABEL: &str = "SENT";

/// Columns selectable in the thread view: every message column (taken from the thread's latest message) and the
/// per-thread columns.
pub fn thread_selectable() -> Vec<&'static str> {
    SELECTABLE.iter().chain(THREAD_COLUMNS).copied().collect()
}
pub const FIELDS: &[&str] = &[
    "from",
    "to",
    "cc",
    "bcc",
    "participant",
    "from_domain",
    "recipient_domain",
    "label",
    "thread_id",
    "message_id",
    "is_unread",
    "is_starred",
    "is_draft",
    "has_attachment",
    "received_at",
    "size_bytes",
    "subject",
    "body_text",
    "text",
    "attachment_name",
    "attachment_mime",
    "attachment_text",
    "category",
    "from_self",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    From,
    To,
    Cc,
    Bcc,
    Participant,
    FromDomain,
    RecipientDomain,
    Label,
    ThreadId,
    MessageId,
    IsUnread,
    IsStarred,
    IsDraft,
    HasAttachment,
    ReceivedAt,
    SizeBytes,
    Subject,
    BodyText,
    Text,
    AttachmentName,
    AttachmentMime,
    AttachmentText,
    Category,
    FromSelf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Eq,
    In,
    Lt,
    Lte,
    Gt,
    Gte,
    Terms,
    Phrase,
    Prefix,
    EndsWith,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Val {
    Str(String),
    List(Vec<String>),
    Bool(bool),
    Int(i64),
}

#[derive(Debug, Clone, Serialize)]
pub struct Pred {
    pub field: Field,
    pub op: Op,
    pub value: Val,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Expr {
    All(Vec<Expr>),
    Any(Vec<Expr>),
    Not(Box<Expr>),
    Pred(Pred),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderField {
    ReceivedAt,
    SizeBytes,
    Subject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Dir {
    Asc,
    Desc,
}

/// A validated index search request. Cursors store it, so a resumed page runs exactly the same query.
#[derive(Debug, Clone, Serialize)]
pub struct SearchReq {
    pub accounts: Option<Vec<String>>,
    pub filter: Option<Expr>,
    pub select: Vec<String>,
    pub order: Vec<(OrderField, Dir)>,
    pub limit: usize,
    pub count_only: bool,
    pub require_complete: bool,
    pub max_lag_seconds: Option<u64>,
    pub include_spam_trash: bool,
    /// `group_by: "thread"`: one row per (mailbox, thread) instead of per message.
    pub group_by_thread: bool,
    /// Thread view only: keep threads whose latest non-draft message is not from self (`true`) or is (`false`).
    pub awaiting_reply: Option<bool>,
}

impl Expr {
    /// True if any predicate in the expression reads `field`.
    pub fn uses_field(&self, field: Field) -> bool {
        match self {
            Expr::All(v) | Expr::Any(v) => v.iter().any(|x| x.uses_field(field)),
            Expr::Not(x) => x.uses_field(field),
            Expr::Pred(p) => p.field == field,
        }
    }
}

impl SearchReq {
    pub fn approx_bytes(&self) -> usize {
        serde_json::to_vec(self).map(|v| v.len()).unwrap_or(4096)
    }

    fn walk<'a>(&'a self, out: &mut Vec<&'a Pred>) {
        fn go<'a>(e: &'a Expr, out: &mut Vec<&'a Pred>) {
            match e {
                Expr::All(v) | Expr::Any(v) => v.iter().for_each(|x| go(x, out)),
                Expr::Not(x) => go(x, out),
                Expr::Pred(p) => out.push(p),
            }
        }
        if let Some(f) = &self.filter {
            go(f, out);
        }
    }

    /// True if a filter reads body text (body coverage matters).
    pub fn uses_body(&self) -> bool {
        let mut v = vec![];
        self.walk(&mut v);
        v.iter().any(|p| matches!(p.field, Field::BodyText | Field::Text))
    }

    /// True if the query needs the mailboxes' own addresses (`from_self`, thread reply status).
    pub fn uses_self(&self) -> bool {
        self.group_by_thread
            || self.filter.as_ref().is_some_and(|f| f.uses_field(Field::FromSelf))
            || self.select.iter().any(|c| c == "from_self")
    }

    /// True if filters, projection or order read MIME-derived metadata (addresses, subject, attachments). The thread
    /// view always does: its reply status reads every message's sender.
    pub fn uses_mime_metadata(&self) -> bool {
        let mut v = vec![];
        self.walk(&mut v);
        let in_filter = v.iter().any(|p| {
            !matches!(
                p.field,
                Field::Label
                    | Field::ThreadId
                    | Field::MessageId
                    | Field::IsUnread
                    | Field::IsStarred
                    | Field::IsDraft
                    | Field::ReceivedAt
                    | Field::SizeBytes
            )
        });
        let in_select = self.select.iter().any(|c| {
            matches!(
                c.as_str(),
                "from"
                    | "to"
                    | "cc"
                    | "bcc"
                    | "subject"
                    | "attachment_names"
                    | "attachment_mime_types"
                    | "has_attachment"
                    | "from_self"
            )
        });
        let in_order = self.order.iter().any(|(f, _)| *f == OrderField::Subject);
        in_filter || in_select || in_order || self.group_by_thread
    }

    /// True if the query touches the FTS table.
    pub fn uses_fts(&self) -> bool {
        let mut v = vec![];
        self.walk(&mut v);
        v.iter().any(|p| matches!(p.field, Field::Subject | Field::BodyText | Field::Text | Field::AttachmentText))
    }

    /// True if a filter reads attachment text (attachment coverage matters).
    pub fn uses_attachment_text(&self) -> bool {
        let mut v = vec![];
        self.walk(&mut v);
        v.iter().any(|p| p.field == Field::AttachmentText)
    }

    /// True if a filter or the projection reads the message category (rows ingested before categories existed
    /// have none).
    pub fn uses_category(&self) -> bool {
        let mut v = vec![];
        self.walk(&mut v);
        v.iter().any(|p| p.field == Field::Category) || self.select.iter().any(|c| c == "category")
    }
}

// ------------------------------------------------------------------ parsing
//
// Every error names the argument path (`where.all[1].op`), says what is expected and, where it helps, carries a
// valid example in `details.example` (PLAN A68). Paths are built from this structure only, never from caller text.
// Readings that have exactly one meaning are accepted: field, operator and enum names in any case, one value where a
// list is expected, `"true"` for `true`, a calendar date for `received_at`. See `tools::lenient` for the argument level.

fn bad(msg: impl AsRef<str>) -> ToolError {
    ToolError::invalid(msg.as_ref())
}

fn bad_at(path: &str, msg: impl AsRef<str>) -> ToolError {
    ToolError::invalid_at(path, msg)
}

fn short(s: &str) -> String {
    s.chars().take(40).collect()
}

fn norm(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

fn parse_field(s: &str) -> Option<Field> {
    Some(match norm(s).as_str() {
        "from" => Field::From,
        "to" => Field::To,
        "cc" => Field::Cc,
        "bcc" => Field::Bcc,
        "participant" => Field::Participant,
        "from_domain" => Field::FromDomain,
        "recipient_domain" => Field::RecipientDomain,
        "label" => Field::Label,
        "thread_id" => Field::ThreadId,
        "message_id" => Field::MessageId,
        "is_unread" => Field::IsUnread,
        "is_starred" => Field::IsStarred,
        "is_draft" => Field::IsDraft,
        "has_attachment" => Field::HasAttachment,
        "received_at" => Field::ReceivedAt,
        "size_bytes" => Field::SizeBytes,
        "subject" => Field::Subject,
        "body_text" => Field::BodyText,
        "text" => Field::Text,
        "attachment_name" => Field::AttachmentName,
        "attachment_mime" => Field::AttachmentMime,
        "attachment_text" => Field::AttachmentText,
        "category" => Field::Category,
        "from_self" => Field::FromSelf,
        _ => return None,
    })
}

/// The field an unknown name most likely meant (agents carry names over from other APIs).
fn field_suggestion(s: &str) -> Option<&'static str> {
    Some(match norm(s).as_str() {
        "sender" | "author" | "from_address" | "from_email" => "from",
        "recipient" | "recipients" | "to_address" | "to_email" => "to",
        "date" | "received" | "time" | "sent" | "sent_at" | "timestamp" | "internal_date" | "when" | "after"
        | "before" | "since" | "until" => "received_at",
        "body" | "body_plain" => "body_text",
        "content" | "fulltext" | "full_text" | "query" | "q" | "search" | "keywords" => "text",
        "title" => "subject",
        "size" | "bytes" => "size_bytes",
        "unread" => "is_unread",
        "starred" | "star" => "is_starred",
        "draft" => "is_draft",
        "attachment" | "attachments" | "has_attachments" | "hasattachment" => "has_attachment",
        "labels" | "folder" | "mailbox" | "tag" | "tags" => "label",
        "domain" | "sender_domain" | "from_host" => "from_domain",
        "to_domain" | "recipients_domain" => "recipient_domain",
        "id" | "msg_id" | "gmail_id" | "messageid" => "message_id",
        "thread" | "threadid" | "conversation" | "conversation_id" => "thread_id",
        "filename" | "file_name" | "attachment_filename" => "attachment_name",
        "mime" | "mime_type" | "attachment_type" | "content_type" => "attachment_mime",
        _ => return None,
    })
}

fn parse_op(s: &str) -> Option<Op> {
    Some(match norm(s).as_str() {
        "eq" => Op::Eq,
        "in" => Op::In,
        "lt" => Op::Lt,
        "lte" => Op::Lte,
        "gt" => Op::Gt,
        "gte" => Op::Gte,
        "terms" => Op::Terms,
        "phrase" => Op::Phrase,
        "prefix" => Op::Prefix,
        "ends_with" => Op::EndsWith,
        _ => return None,
    })
}

fn op_name(op: Op) -> &'static str {
    match op {
        Op::Eq => "eq",
        Op::In => "in",
        Op::Lt => "lt",
        Op::Lte => "lte",
        Op::Gt => "gt",
        Op::Gte => "gte",
        Op::Terms => "terms",
        Op::Phrase => "phrase",
        Op::Prefix => "prefix",
        Op::EndsWith => "ends_with",
    }
}

fn allowed_ops(f: Field) -> &'static [Op] {
    use Field::*;
    match f {
        From | To | Cc | Bcc | Participant | FromDomain | RecipientDomain | Label | ThreadId | MessageId
        | AttachmentMime | Category => &[Op::Eq, Op::In],
        AttachmentName => &[Op::Eq, Op::In, Op::EndsWith],
        IsUnread | IsStarred | IsDraft | HasAttachment | FromSelf => &[Op::Eq],
        ReceivedAt | SizeBytes => &[Op::Eq, Op::Lt, Op::Lte, Op::Gt, Op::Gte],
        Subject | BodyText | Text | AttachmentText => &[Op::Terms, Op::Phrase, Op::Prefix],
    }
}

fn is_text_field(f: Field) -> bool {
    matches!(f, Field::Subject | Field::BodyText | Field::Text | Field::AttachmentText)
}

/// What the operators of a field do, for error messages.
fn ops_help(f: Field) -> String {
    if is_text_field(f) {
        "terms (all words, any order), phrase (exact word sequence) or prefix (one word start); there is no \
         substring match"
            .into()
    } else {
        allowed_ops(f).iter().map(|o| op_name(*o)).collect::<Vec<_>>().join(", ")
    }
}

fn sample_value(f: Field, op: Op) -> Value {
    use Field::*;
    let one = match f {
        From | To | Cc | Bcc | Participant => json!("alice@example.com"),
        FromDomain | RecipientDomain => json!("example.com"),
        Label => json!("INBOX"),
        ThreadId | MessageId => json!("18c2f0a1b2c3d4e5"),
        IsUnread | IsStarred | IsDraft | HasAttachment | FromSelf => return json!(true),
        ReceivedAt => return json!("2026-11-01T00:00:00Z"),
        SizeBytes => return json!(1_000_000),
        Subject | BodyText | Text | AttachmentText => {
            return if op == Op::Prefix { json!("invoic") } else { json!("invoice october") };
        }
        AttachmentName => json!(if op == Op::EndsWith { ".pdf" } else { "invoice.pdf" }),
        AttachmentMime => json!("application/pdf"),
        Category => json!("newsletter"),
    };
    if op == Op::In { json!([one]) } else { one }
}

fn example_pred(f: Field, op: Op) -> Value {
    json!({ "field": field_json(f), "op": op_name(op), "value": sample_value(f, op) })
}

fn field_json(f: Field) -> String {
    serde_json::to_value(f).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

fn default_op(f: Field) -> Op {
    allowed_ops(f)[0]
}

fn check_str(path: &str, s: &str, example: &Value) -> Result<(), ToolError> {
    if s.chars().count() > MAX_STRING {
        return Err(bad_at(path, format!("is limited to {MAX_STRING} characters")).with_example(example.clone()));
    }
    if s.trim().is_empty() {
        return Err(bad_at(path, "must not be empty").with_example(example.clone()));
    }
    Ok(())
}

/// `received_at` bound: an RFC 3339 instant with offset, or a calendar date `YYYY-MM-DD` meaning that whole UTC day.
/// `gte`/`lt` use the day's start; `gt`/`lte` its last millisecond, so "after / up to the day" includes or excludes
/// the whole day. `eq` on a whole day has no single value and is refused.
fn parse_received_at(path: &str, op: Op, v: &Value, example: &Value) -> Result<i64, ToolError> {
    const FORMS: &str = "an RFC 3339 instant with offset (\"2026-11-01T00:00:00Z\") or a UTC date (\"2026-11-01\")";
    let ex = || example.clone();
    let s = v.as_str().ok_or_else(|| bad_at(path, format!("takes a string: {FORMS}")).with_example(ex()))?;
    check_str(path, s, example)?;
    let s = s.trim();
    if let Some(ms) = util::parse_rfc3339_ms(s) {
        return Ok(ms);
    }
    if let Some(day) = util::parse_date_ms(s) {
        const DAY: i64 = 86_400_000;
        return match op {
            Op::Gte | Op::Lt => Ok(day),
            Op::Gt | Op::Lte => Ok(day + DAY - 1),
            _ => Err(bad_at(
                path,
                "a date is a whole day, so 'eq' has no single value; use {\"all\":[gte that date, lt the next date]}",
            )
            .with_example(ex())),
        };
    }
    if util::looks_like_local_datetime(s) {
        return Err(bad_at(path, format!("has no time zone offset; add Z for UTC or an offset like +01:00 ({FORMS})"))
            .with_example(ex()));
    }
    Err(bad_at(path, format!("takes {FORMS}")).with_example(ex()))
}

fn parse_value(f: Field, op: Op, v: Option<&Value>, path: &str) -> Result<Val, ToolError> {
    let example = example_pred(f, op);
    let v = v.ok_or_else(|| bad_at(path, "is required").with_example(example.clone()))?;
    use Field::*;
    match (f, op) {
        (IsUnread | IsStarred | IsDraft | HasAttachment | FromSelf, _) => match v {
            Value::Bool(b) => Ok(Val::Bool(*b)),
            Value::String(s) if crate::tools::lenient::bool_text(s).is_some() => {
                Ok(Val::Bool(crate::tools::lenient::bool_text(s).unwrap_or(false)))
            }
            _ => Err(bad_at(path, "takes true or false (a JSON boolean)").with_example(example)),
        },
        (ReceivedAt, _) => parse_received_at(path, op, v, &example).map(Val::Int),
        (SizeBytes, _) => v
            .as_u64()
            .or_else(|| crate::tools::lenient::int_value(v))
            .and_then(|n| i64::try_from(n).ok())
            .map(Val::Int)
            .ok_or_else(|| bad_at(path, "takes a non-negative integer number of bytes").with_example(example)),
        (_, Op::In) => {
            let parsed;
            let items: &[Value] = match v {
                Value::Array(a) => a,
                Value::String(s) => match crate::tools::lenient::json_text(s, '[') {
                    Some(Value::Array(a)) => {
                        parsed = a;
                        &parsed
                    }
                    _ => std::slice::from_ref(v),
                },
                _ => return Err(bad_at(path, "takes a list of strings").with_example(example)),
            };
            if items.is_empty() {
                return Err(bad_at(path, "needs at least one value").with_example(example));
            }
            if items.len() > MAX_LIST {
                return Err(bad_at(path, format!("is limited to {MAX_LIST} values")).with_example(example));
            }
            let mut out = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                let s = item
                    .as_str()
                    .ok_or_else(|| bad_at(&format!("{path}[{i}]"), "must be a string").with_example(example.clone()))?;
                check_str(&format!("{path}[{i}]"), s, &example)?;
                out.push(s.to_string());
            }
            Ok(Val::List(out))
        }
        _ => {
            // One string; a one-element list is read as that string, a list of words for `terms` as all of them.
            let joined;
            let s = match v {
                Value::String(s) => s.as_str(),
                Value::Array(a) if a.len() == 1 && a[0].is_string() => a[0].as_str().unwrap_or_default(),
                Value::Array(a) if op == Op::Terms && !a.is_empty() && a.iter().all(Value::is_string) => {
                    joined = a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" ");
                    joined.as_str()
                }
                Value::Array(a) if a.len() > 1 && a.iter().all(Value::is_string) => {
                    let hint = if allowed_ops(f).contains(&Op::In) {
                        "takes one string; for several values use op 'in' with a list"
                    } else {
                        "takes one string"
                    };
                    return Err(bad_at(path, hint).with_example(example));
                }
                _ => return Err(bad_at(path, "must be a string").with_example(example)),
            };
            check_str(path, s, &example)?;
            Ok(Val::Str(s.to_string()))
        }
    }
    .and_then(|val| check_category(f, val, path))
}

/// `category` takes only the four known categories (a typo would silently match nothing), in any case.
fn check_category(f: Field, val: Val, path: &str) -> Result<Val, ToolError> {
    if f != Field::Category {
        return Ok(val);
    }
    let fix = |s: &str| {
        let l = norm(s);
        Category::parse(&l).map(|_| l)
    };
    let err = || {
        bad_at(path, "is personal, newsletter, notification or calendar")
            .with_example(example_pred(Field::Category, Op::Eq))
    };
    Ok(match val {
        Val::Str(s) => Val::Str(fix(&s).ok_or_else(err)?),
        Val::List(l) => Val::List(l.iter().map(|s| fix(s).ok_or_else(err)).collect::<Result<_, _>>()?),
        other => other,
    })
}

struct Budget {
    preds: usize,
}

const NODE_FORMS: &str =
    "{\"field\":\"from\",\"op\":\"eq\",\"value\":\"a@b.com\"}, {\"all\":[...]}, {\"any\":[...]} or {\"not\":{...}}";

fn parse_expr(v: &Value, depth: usize, b: &mut Budget, path: &str) -> Result<Expr, ToolError> {
    // A node sent as JSON text has one reading.
    let owned;
    let v = match v {
        Value::String(s) => match crate::tools::lenient::json_text(s, '{') {
            Some(p) => {
                owned = p;
                &owned
            }
            None => v,
        },
        _ => v,
    };
    let Some(obj) = v.as_object() else {
        let what = if v.is_array() {
            "is a list; combine conditions with {\"all\":[...]} (and) or {\"any\":[...]} (or)".to_string()
        } else {
            format!("must be an object: {NODE_FORMS}")
        };
        return Err(bad_at(path, what).with_example(json!({"all": [example_pred(Field::From, Op::Eq)]})));
    };
    let keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    if let Some(kind) = ["all", "any", "not"].into_iter().find(|k| obj.contains_key(*k)) {
        if keys.len() != 1 {
            return Err(bad_at(path, format!("a '{kind}' group has no other keys; put more conditions inside it")));
        }
        if depth >= MAX_DEPTH {
            return Err(bad_at(path, format!("nesting is limited to depth {MAX_DEPTH}; flatten with one all/any")));
        }
        let at = format!("{path}.{kind}");
        return match kind {
            "not" => Ok(Expr::Not(Box::new(parse_expr(&obj["not"], depth + 1, b, &at)?))),
            _ => {
                let items = obj[kind].as_array().ok_or_else(|| {
                    bad_at(&at, "takes a list of conditions")
                        .with_example(json!({kind: [example_pred(Field::From, Op::Eq)]}))
                })?;
                if items.is_empty() {
                    return Err(bad_at(&at, "must not be empty; omit 'where' to match everything"));
                }
                let parsed = items
                    .iter()
                    .enumerate()
                    .map(|(i, x)| parse_expr(x, depth + 1, b, &format!("{at}[{i}]")))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(if kind == "all" { Expr::All(parsed) } else { Expr::Any(parsed) })
            }
        };
    }
    for k in &keys {
        if !["field", "op", "value"].contains(k) {
            // A field name used as a key (`{"from": "a@b.com"}`) is a common shape: show the real one.
            return Err(match parse_field(k) {
                Some(f) => {
                    let name = field_json(f);
                    bad_at(path, format!("a condition is {{field, op, value}}, not {{\"{name}\": ...}}"))
                        .with_example(example_pred(f, default_op(f)))
                }
                None => bad_at(
                    path,
                    format!("a condition has only 'field', 'op' and 'value'; found an unknown key. {NODE_FORMS}"),
                )
                .with_example(example_pred(Field::From, Op::Eq)),
            });
        }
    }
    b.preds += 1;
    if b.preds > MAX_PREDICATES {
        return Err(bad_at("where", format!("is limited to {MAX_PREDICATES} conditions")));
    }
    let fpath = format!("{path}.field");
    let field_text = obj.get("field").and_then(Value::as_str);
    let field = match field_text.and_then(parse_field) {
        Some(f) => f,
        None => {
            let list = FIELDS.join(", ");
            let msg = match field_text {
                None => format!("is required. Fields: {list}"),
                Some(t) => match field_suggestion(t) {
                    Some(s) => format!("unknown field '{}'; did you mean '{s}'? Fields: {list}", short(t)),
                    None => format!("unknown field '{}'. Fields: {list}", short(t)),
                },
            };
            return Err(bad_at(&fpath, msg).with_example(example_pred(Field::From, Op::Eq)));
        }
    };
    let opath = format!("{path}.op");
    let op_text = obj.get("op").and_then(Value::as_str);
    let op = match op_text.and_then(parse_op) {
        Some(o) => o,
        None => {
            let fname = field_json(field);
            let what = match op_text {
                None => format!("is required for '{fname}'"),
                Some(t) => format!("'{}' is not an operator for '{fname}'", short(t)),
            };
            return Err(bad_at(&opath, format!("{what}; use {}", ops_help(field)))
                .with_example(example_pred(field, default_op(field))));
        }
    };
    if !allowed_ops(field).contains(&op) {
        return Err(bad_at(
            &opath,
            format!("'{}' is not supported for '{}'; use {}", op_name(op), field_json(field), ops_help(field)),
        )
        .with_example(example_pred(field, default_op(field))));
    }
    let vpath = format!("{path}.value");
    let value = parse_value(field, op, obj.get("value"), &vpath)?;
    if is_text_field(field) {
        let Val::Str(s) = &value else { unreachable!("text ops take strings") };
        let toks = tokens(s);
        if toks.is_empty() {
            return Err(bad_at(&vpath, "contains no searchable words").with_example(example_pred(field, op)));
        }
        if op == Op::Prefix {
            if toks.len() != 1 {
                return Err(bad_at(&vpath, "'prefix' takes exactly one word; use terms for several words")
                    .with_example(example_pred(field, op)));
            }
            if toks[0].chars().count() < MIN_PREFIX_CHARS {
                return Err(ToolError::new(
                    crate::error::ErrorCode::QueryTooBroad,
                    format!("{vpath}: prefixes need at least {MIN_PREFIX_CHARS} characters"),
                ));
            }
        }
    }
    Ok(Expr::Pred(Pred { field, op, value }))
}

/// Parses a `where` object. `{}` or null means "match all visible rows".
pub fn parse_where(v: Option<&Value>) -> Result<Option<Expr>, ToolError> {
    // The whole `where` sent as JSON text has one reading.
    let parsed = match v {
        Some(Value::String(s)) => crate::tools::lenient::json_text(s, '{'),
        _ => None,
    };
    match parsed.as_ref().or(v) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(o)) if o.is_empty() => Ok(None),
        Some(v) => Ok(Some(parse_expr(v, 0, &mut Budget { preds: 0 }, "where")?)),
    }
}

/// Why a column name is not selectable here, with what to use instead.
fn column_hint(s: &str, thread_view: bool) -> &'static str {
    if THREAD_COLUMNS.contains(&s) && !thread_view {
        " It needs group_by=\"thread\"."
    } else if matches!(s, "body" | "body_text" | "text" | "content" | "html") {
        " Message text is not a column: 'snippet' gives a preview, get_message the full text."
    } else if matches!(s, "id" | "msg_id") {
        " Use 'ref' (the handle for get_message) or 'message_id'."
    } else if matches!(s, "date" | "received" | "sent" | "time" | "timestamp") {
        " Use 'received_at'."
    } else if matches!(s, "sender" | "author") {
        " Use 'from'."
    } else if matches!(s, "recipient" | "recipients") {
        " Use 'to'."
    } else if matches!(s, "size") {
        " Use 'size_bytes'."
    } else {
        ""
    }
}

pub fn parse_select(v: Option<&Value>, allowed: &[&str], default: &[&str]) -> Result<Vec<String>, ToolError> {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(default.iter().map(|s| s.to_string()).collect());
    };
    let example = json!(["ref", "received_at", "from", "subject"]);
    let items =
        v.as_array().ok_or_else(|| bad_at("select", "takes a list of column names").with_example(example.clone()))?;
    if items.is_empty() {
        return Err(bad_at("select", "must name at least one column").with_example(example));
    }
    let thread_view = allowed.contains(&"message_count");
    let mut out: Vec<String> = vec![];
    for (i, item) in items.iter().enumerate() {
        let path = format!("select[{i}]");
        let s = item.as_str().ok_or_else(|| bad_at(&path, "must be a column name").with_example(example.clone()))?;
        let s = norm(s);
        if !allowed.contains(&s.as_str()) {
            return Err(bad_at(
                &path,
                format!(
                    "'{}' cannot be selected.{} Columns: {}",
                    short(&s),
                    column_hint(&s, thread_view),
                    allowed.join(", ")
                ),
            ));
        }
        if out.contains(&s) {
            return Err(bad_at(&path, format!("'{s}' is selected twice; list each column once")));
        }
        out.push(s);
    }
    Ok(out)
}

pub fn parse_order(v: Option<&Value>) -> Result<Vec<(OrderField, Dir)>, ToolError> {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(vec![(OrderField::ReceivedAt, Dir::Desc)]);
    };
    let example = json!([{"field": "received_at", "dir": "desc"}]);
    let items =
        v.as_array().ok_or_else(|| bad_at("order_by", "takes a list of {field, dir}").with_example(example.clone()))?;
    if items.is_empty() || items.len() > 2 {
        return Err(bad_at("order_by", "takes one or two keys").with_example(example));
    }
    let mut out = vec![];
    for (i, item) in items.iter().enumerate() {
        let path = format!("order_by[{i}]");
        // `{field, dir}`, or text such as "received_at" or "received_at desc".
        let (field, dir): (Option<String>, Option<String>) = match item {
            Value::Object(o) => {
                if o.keys().any(|k| k != "field" && k != "dir") {
                    return Err(bad_at(&path, "takes only 'field' and 'dir'").with_example(example.clone()));
                }
                (
                    o.get("field").and_then(Value::as_str).map(norm),
                    o.get("dir").filter(|d| !d.is_null()).map(|d| d.as_str().map(norm).unwrap_or_default()),
                )
            }
            Value::String(s) => {
                let mut parts = s.split_whitespace();
                let f = parts.next().map(norm);
                let d = parts.next().map(norm);
                if parts.next().is_some() { (None, None) } else { (f, d) }
            }
            _ => (None, None),
        };
        let f = match field.as_deref() {
            Some("received_at") => OrderField::ReceivedAt,
            Some("size_bytes") => OrderField::SizeBytes,
            Some("subject") => OrderField::Subject,
            _ => {
                return Err(
                    bad_at(&format!("{path}.field"), "is received_at, size_bytes or subject").with_example(example)
                );
            }
        };
        let d = match dir.as_deref() {
            None => {
                if f == OrderField::Subject {
                    Dir::Asc
                } else {
                    Dir::Desc
                }
            }
            Some("asc" | "ascending") => Dir::Asc,
            Some("desc" | "descending") => Dir::Desc,
            Some(_) => return Err(bad_at(&format!("{path}.dir"), "is asc or desc").with_example(example)),
        };
        if out.iter().any(|(x, _)| *x == f) {
            return Err(bad_at(&path, "repeats an earlier field; sort by each field once"));
        }
        out.push((f, d));
    }
    Ok(out)
}

// ------------------------------------------------------------------ FTS literal encoding

/// Splits text into tokens the way FTS5 unicode61 does (letters and digits; everything else separates).
pub fn tokens(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric()).filter(|t| !t.is_empty()).map(str::to_string).collect()
}

/// FTS5 string literal: double quotes, inner quotes doubled. Tokens never carry syntax.
fn fts_lit(t: &str) -> String {
    format!("\"{}\"", t.replace('"', "\"\""))
}

/// Builds the MATCH expression for one text predicate.
pub fn fts_expr(field: Field, op: Op, text: &str) -> String {
    let toks = tokens(text);
    let body = match op {
        Op::Phrase => fts_lit(&toks.join(" ")),
        Op::Prefix => format!("{} *", fts_lit(&toks[0])),
        _ => toks.iter().map(|t| fts_lit(t)).collect::<Vec<_>>().join(" AND "),
    };
    match field {
        Field::Subject => format!("subject : ({body})"),
        Field::BodyText => format!("body : ({body})"),
        Field::AttachmentText => format!("att : ({body})"),
        _ => format!("({body})"),
    }
}

// ------------------------------------------------------------------ compilation

/// A mailbox that the query may read: its account, alias and the generation it serves.
#[derive(Debug, Clone)]
pub struct Target {
    pub account_id: String,
    pub alias: String,
    pub gen_id: i64,
    /// The generation's FTS table has the attachment text column (generations created before attachment text keep
    /// two columns until they are rebuilt).
    pub att_fts: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum KeyValue {
    Int(i64),
    Text(String),
}

impl KeyValue {
    pub fn approx_bytes(&self) -> usize {
        match self {
            KeyValue::Int(_) => 16,
            KeyValue::Text(s) => s.len() + 16,
        }
    }
    fn sql(&self) -> SqlValue {
        match self {
            KeyValue::Int(i) => SqlValue::Integer(*i),
            KeyValue::Text(s) => SqlValue::Text(s.clone()),
        }
    }
}

struct Sql {
    text: String,
    params: Vec<SqlValue>,
}

impl Sql {
    fn p(&mut self, v: SqlValue) -> &mut Self {
        self.text.push('?');
        self.params.push(v);
        self
    }
    fn s(&mut self, t: &str) -> &mut Self {
        self.text.push_str(t);
        self
    }
    fn list(&mut self, vals: impl IntoIterator<Item = SqlValue>) -> &mut Self {
        self.text.push('(');
        for (i, v) in vals.into_iter().enumerate() {
            if i > 0 {
                self.text.push_str(", ");
            }
            self.p(v);
        }
        self.text.push(')');
        self
    }
}

/// Resolves a mailbox qualifier (`alias:ID`) to the generation it serves within this query, if any.
pub struct Scope<'a> {
    pub targets: &'a [Target],
    /// alias -> account id for every mailbox the caller may name (resolution errors are raised by the caller).
    pub known: &'a HashMap<String, String>,
    /// account id -> the mailbox's own addresses (its address and its sending identities, normalized like
    /// `addrs.addr`). `from_self` and the thread view need an entry for every target; without one they are refused.
    pub selves: &'a HashMap<String, Vec<String>>,
}

impl Scope<'_> {
    /// (generation, own addresses) per target, or `invalid_argument` if a target has no known own addresses.
    fn self_sets(&self) -> Result<Vec<(i64, &[String])>, ToolError> {
        self.targets
            .iter()
            .map(|t| {
                self.selves
                    .get(&t.account_id)
                    .map(|v| (t.gen_id, v.as_slice()))
                    .ok_or_else(|| bad("'from_self' is not available here"))
            })
            .collect()
    }
}

/// `from_self` as a filter: the message has a From address that is one of its mailbox's own addresses, or it carries
/// the `SENT` label. One `IN` over a union of index lookups (`addrs_addr` per mailbox, the labels primary key).
fn compile_from_self(q: &mut Sql, scope: &Scope<'_>) -> Result<(), ToolError> {
    q.s("m.id IN (");
    for (gen_id, addrs) in scope.self_sets()? {
        if addrs.is_empty() {
            continue;
        }
        q.s("SELECT msg FROM addrs WHERE addr IN ")
            .list(addrs.iter().map(|a| SqlValue::Text(a.clone())))
            .s(" AND gen = ")
            .p(SqlValue::Integer(gen_id))
            .s(" AND role = ")
            .p(SqlValue::Integer(ROLE_FROM))
            .s(" UNION ALL ");
    }
    q.s("SELECT msg FROM labels WHERE label = ")
        .p(SqlValue::Text(SENT_LABEL.into()))
        .s(" AND gen IN ")
        .list(gens(scope.targets))
        .s(")");
    Ok(())
}

/// `from_self` of the row `x` as a 0/1 expression, for projections and per-thread aggregates: two correlated lookups
/// by message (`addrs_msg`, the labels primary key), so the cost follows the rows evaluated, not the mailbox size.
fn self_expr(q: &mut Sql, x: &str, scope: &Scope<'_>) -> Result<(), ToolError> {
    q.s(&format!("(EXISTS (SELECT 1 FROM addrs a WHERE a.msg = {x}.id AND a.role = "))
        .p(SqlValue::Integer(ROLE_FROM))
        .s(" AND CASE a.gen");
    for (gen_id, addrs) in scope.self_sets()? {
        q.s(" WHEN ").p(SqlValue::Integer(gen_id)).s(" THEN ");
        if addrs.is_empty() {
            q.s("0");
        } else {
            q.s("a.addr IN ").list(addrs.iter().map(|a| SqlValue::Text(a.clone())));
        }
    }
    q.s(" ELSE 0 END) OR EXISTS (SELECT 1 FROM labels l WHERE l.label = ")
        .p(SqlValue::Text(SENT_LABEL.into()))
        .s(&format!(" AND l.gen = {x}.gen AND l.msg = {x}.id))"));
    Ok(())
}

fn split_qualified<'v>(scope: &Scope<'_>, v: &'v str) -> Result<(Option<i64>, &'v str), ToolError> {
    if let Some((alias, id)) = v.split_once(':') {
        let aid = scope.known.get(alias).ok_or_else(ToolError::not_found)?;
        let gen_id = scope.targets.iter().find(|t| &t.account_id == aid).map(|t| t.gen_id).unwrap_or(-1);
        return Ok((Some(gen_id), id));
    }
    Ok((None, v))
}

fn str_list(v: &Val) -> Vec<String> {
    match v {
        Val::Str(s) => vec![s.clone()],
        Val::List(l) => l.clone(),
        _ => vec![],
    }
}

fn gens(t: &[Target]) -> Vec<SqlValue> {
    t.iter().map(|t| SqlValue::Integer(t.gen_id)).collect()
}

fn compile_pred(q: &mut Sql, p: &Pred, scope: &Scope<'_>) -> Result<(), ToolError> {
    use Field::*;
    let t = scope.targets;
    let addr_sub = |q: &mut Sql, col: &str, vals: Vec<String>, roles: &[i64]| {
        q.s(&format!("m.id IN (SELECT msg FROM addrs WHERE {col} IN "))
            .list(vals.into_iter().map(SqlValue::Text))
            .s(" AND gen IN ")
            .list(gens(t))
            .s(" AND role IN ")
            .list(roles.iter().map(|r| SqlValue::Integer(*r)))
            .s(")");
    };
    match p.field {
        From | To | Cc | Bcc | Participant => {
            let roles: &[i64] = match p.field {
                From => &[ROLE_FROM],
                To => &[ROLE_TO],
                Cc => &[ROLE_CC],
                Bcc => &[ROLE_BCC],
                _ => &[ROLE_FROM, ROLE_TO, ROLE_CC, ROLE_BCC],
            };
            let vals = str_list(&p.value).iter().map(|s| norm_addr(s)).collect();
            addr_sub(q, "addr", vals, roles);
        }
        FromDomain | RecipientDomain => {
            let roles: &[i64] = if p.field == FromDomain { &[ROLE_FROM] } else { &[ROLE_TO, ROLE_CC, ROLE_BCC] };
            let vals = str_list(&p.value).iter().map(|s| norm_domain(s)).collect();
            addr_sub(q, "domain", vals, roles);
        }
        Label | ThreadId | MessageId => {
            // Unqualified values apply to every searched mailbox; `alias:ID` only to that mailbox.
            let mut plain = vec![];
            let mut qualified = vec![];
            for v in str_list(&p.value) {
                match split_qualified(scope, &v)? {
                    (Some(g), id) => qualified.push((g, id.to_string())),
                    (None, id) => plain.push(id.to_string()),
                }
            }
            q.s("(0");
            if p.field == Label {
                if !plain.is_empty() {
                    q.s(" OR m.id IN (SELECT msg FROM labels WHERE label IN ")
                        .list(plain.into_iter().map(SqlValue::Text))
                        .s(" AND gen IN ")
                        .list(gens(t))
                        .s(")");
                }
                for (g, id) in qualified {
                    q.s(" OR m.id IN (SELECT msg FROM labels WHERE label = ")
                        .p(SqlValue::Text(id))
                        .s(" AND gen = ")
                        .p(SqlValue::Integer(g))
                        .s(")");
                }
            } else {
                let col = if p.field == ThreadId { "m.thread_id" } else { "m.gmail_id" };
                if !plain.is_empty() {
                    q.s(&format!(" OR {col} IN ")).list(plain.into_iter().map(SqlValue::Text));
                }
                for (g, id) in qualified {
                    q.s(&format!(" OR ({col} = "))
                        .p(SqlValue::Text(id))
                        .s(" AND m.gen = ")
                        .p(SqlValue::Integer(g))
                        .s(")");
                }
            }
            q.s(")");
        }
        IsUnread | IsStarred | IsDraft => {
            let col = match p.field {
                IsUnread => "m.is_unread",
                IsStarred => "m.is_starred",
                _ => "m.is_draft",
            };
            let Val::Bool(b) = p.value else { unreachable!() };
            q.s(&format!("{col} = ")).p(SqlValue::Integer(b as i64));
        }
        HasAttachment => {
            let Val::Bool(b) = p.value else { unreachable!() };
            // Unknown MIME metadata (NULL) never matches the positive predicate.
            q.s("IFNULL(m.has_attachment = ").p(SqlValue::Integer(b as i64)).s(", 0)");
        }
        ReceivedAt | SizeBytes => {
            let col = if p.field == ReceivedAt { "m.received_at" } else { "m.size_bytes" };
            let op = match p.op {
                Op::Eq => "=",
                Op::Lt => "<",
                Op::Lte => "<=",
                Op::Gt => ">",
                _ => ">=",
            };
            let Val::Int(n) = p.value else { unreachable!() };
            q.s(&format!("{col} {op} ")).p(SqlValue::Integer(n));
        }
        Category => {
            let vals = str_list(&p.value);
            // Unknown (NULL) never matches the positive predicate.
            q.s("IFNULL(m.category IN ").list(vals.into_iter().map(SqlValue::Text)).s(", 0)");
        }
        Subject | BodyText | Text | AttachmentText => {
            let Val::Str(s) = &p.value else { unreachable!() };
            // MATCH runs only on the FTS tables of the eligible generations (spec 7.9), never on other accounts'.
            // Generations without the attachment column have no attachment text to match.
            let usable: Vec<&Target> = t.iter().filter(|x| p.field != AttachmentText || x.att_fts).collect();
            if usable.is_empty() {
                q.s("0");
            } else {
                let expr = fts_expr(p.field, p.op, s);
                q.s("m.id IN (");
                for (i, target) in usable.iter().enumerate() {
                    if i > 0 {
                        q.s(" UNION ALL ");
                    }
                    let fts = super::schema::fts_table(target.gen_id);
                    q.s(&format!("SELECT rowid FROM {fts} WHERE {fts} MATCH ")).p(SqlValue::Text(expr.clone()));
                }
                q.s(")");
            }
        }
        FromSelf => {
            let Val::Bool(b) = p.value else { unreachable!() };
            q.s(if b { "(" } else { "(NOT " });
            compile_from_self(q, scope)?;
            q.s(")");
        }
        AttachmentName | AttachmentMime => {
            let vals = str_list(&p.value).into_iter().map(|s| s.to_lowercase());
            if p.op == Op::EndsWith {
                let rev: String = str_list(&p.value)[0].to_lowercase().chars().rev().collect();
                let upper = format!("{rev}\u{10FFFF}");
                q.s("m.id IN (SELECT msg FROM atts WHERE name_rev >= ")
                    .p(SqlValue::Text(rev))
                    .s(" AND name_rev < ")
                    .p(SqlValue::Text(upper))
                    .s(" AND gen IN ")
                    .list(gens(t))
                    .s(")");
            } else {
                let col = if p.field == AttachmentName { "name_lc" } else { "mime_lc" };
                q.s(&format!("m.id IN (SELECT msg FROM atts WHERE {col} IN "))
                    .list(vals.map(SqlValue::Text))
                    .s(" AND gen IN ")
                    .list(gens(t))
                    .s(")");
            }
        }
    }
    Ok(())
}

fn compile_expr(q: &mut Sql, e: &Expr, scope: &Scope<'_>) -> Result<(), ToolError> {
    match e {
        Expr::All(v) | Expr::Any(v) => {
            let join = if matches!(e, Expr::All(_)) { " AND " } else { " OR " };
            q.s("(");
            for (i, x) in v.iter().enumerate() {
                if i > 0 {
                    q.s(join);
                }
                compile_expr(q, x, scope)?;
            }
            q.s(")");
        }
        Expr::Not(x) => {
            q.s("(NOT ");
            compile_expr(q, x, scope)?;
            q.s(")");
        }
        Expr::Pred(p) => compile_pred(q, p, scope)?,
    }
    Ok(())
}

/// Sort terms: (SQL expression, direction). Missing subjects sort last in both directions; the immutable
/// (account_id, message_id) pair is the final ascending tiebreaker.
fn sort_terms(order: &[(OrderField, Dir)]) -> Vec<(&'static str, Dir)> {
    let mut v = vec![];
    for (f, d) in order {
        match f {
            OrderField::ReceivedAt => v.push(("m.received_at", *d)),
            OrderField::SizeBytes => v.push(("m.size_bytes", *d)),
            OrderField::Subject => {
                v.push(("m.subject_missing", Dir::Asc));
                v.push(("m.subject_key", *d));
            }
        }
    }
    v.push(("m.account_id", Dir::Asc));
    v.push(("m.gmail_id", Dir::Asc));
    v
}

fn where_clause(req: &SearchReq, scope: &Scope<'_>, page: bool) -> Result<Sql, ToolError> {
    let mut q = Sql { text: String::new(), params: vec![] };
    // Newest-first pages over several mailboxes walk `messages_recent` in order and stop after limit + 1 rows; the
    // unary `+` keeps the planner from sorting every row of every mailbox via the gen-prefixed indexes instead.
    let ordered_walk = page
        && scope.targets.len() > 1
        && !req.include_spam_trash
        && req.order.first().is_some_and(|(f, _)| *f == OrderField::ReceivedAt);
    q.s(if ordered_walk { "+m.gen IN " } else { "m.gen IN " }).list(gens(scope.targets));
    // SPAM/TRASH are excluded unless requested; the IN form keeps the (gen, spam_trash, ...) indexes usable.
    if req.include_spam_trash {
        q.s(" AND m.spam_trash IN (0, 1)");
    } else {
        q.s(" AND m.spam_trash = 0");
    }
    if let Some(f) = &req.filter {
        q.s(" AND ");
        compile_expr(&mut q, f, scope)?;
    }
    Ok(q)
}

const ROW_COLS: &str = "m.account_id, m.gmail_id, m.received_at, m.size_bytes, m.subject_missing, m.subject_key, \
    m.thread_id, m.from_list, m.to_list, m.cc_list, m.bcc_list, m.subject, m.labels, m.snippet, m.is_unread, \
    m.is_starred, m.is_draft, m.has_attachment, m.attachment_names, m.attachment_mimes, m.category";

/// Message columns of a row, followed by `from_self` when the projection asks for it (index [`ROW_COL_COUNT`]).
fn row_cols(q: &mut Sql, req: &SearchReq, scope: &Scope<'_>) -> Result<(), ToolError> {
    q.s(ROW_COLS);
    if req.select.iter().any(|c| c == "from_self") {
        q.s(", ");
        self_expr(q, "m", scope)?;
    }
    Ok(())
}

const ROW_COL_COUNT: usize = 21;

/// Keyset seek after `vals` in the order `terms`: (t1 > v1) OR (t1 = v1 AND ((t2 > v2) OR (t2 = v2 AND ...))).
fn seek(q: &mut Sql, terms: &[(&str, Dir)], vals: &[KeyValue]) {
    let (col, dir) = terms[0];
    let op = if dir == Dir::Asc { ">" } else { "<" };
    if terms.len() == 1 {
        q.s(&format!("{col} {op} ")).p(vals[0].sql());
        return;
    }
    q.s(&format!("({col} {op} ")).p(vals[0].sql()).s(&format!(" OR ({col} = ")).p(vals[0].sql()).s(" AND ");
    seek(q, &terms[1..], &vals[1..]);
    q.s("))");
}

fn order_by(q: &mut Sql, terms: &[(&str, Dir)]) {
    q.s(" ORDER BY ");
    for (i, (col, dir)) in terms.iter().enumerate() {
        if i > 0 {
            q.s(", ");
        }
        let _ = write!(q.text, "{col} {}", if *dir == Dir::Asc { "ASC" } else { "DESC" });
    }
}

/// The page query: filters, keyset seek after `after`, order and `limit + 1` rows.
pub fn page_sql(req: &SearchReq, scope: &Scope<'_>, after: &[KeyValue]) -> Result<(String, Vec<SqlValue>), ToolError> {
    if req.group_by_thread {
        return thread_page_sql(req, scope, after);
    }
    let w = where_clause(req, scope, true)?;
    let terms = sort_terms(&req.order);
    let mut q = Sql { text: "SELECT ".into(), params: vec![] };
    row_cols(&mut q, req, scope)?;
    q.s(" FROM messages m WHERE ");
    q.s(&w.text);
    q.params.extend(w.params);
    if !after.is_empty() {
        if after.len() != terms.len() {
            return Err(super::cursor::invalid());
        }
        q.s(" AND ");
        seek(&mut q, &terms, after);
    }
    order_by(&mut q, &terms);
    q.s(" LIMIT ").p(SqlValue::Integer(req.limit as i64 + 1));
    Ok((q.text, q.params))
}

pub fn count_sql(req: &SearchReq, scope: &Scope<'_>) -> Result<(String, Vec<SqlValue>), ToolError> {
    if req.group_by_thread {
        let mut q = threads_cte(req, scope)?;
        q.s(" SELECT count(*) FROM th");
        reply_filter(&mut q, req);
        return Ok((q.text, q.params));
    }
    let w = where_clause(req, scope, false)?;
    Ok((format!("SELECT count(*) FROM messages m WHERE {}", w.text), w.params))
}

// ------------------------------------------------------------------ thread view

/// Thread view order: the thread's latest message time, then (account_id, thread_id) ascending as the tiebreaker.
fn thread_terms(order: &[(OrderField, Dir)]) -> Vec<(&'static str, Dir)> {
    let dir = order.first().map_or(Dir::Desc, |(_, d)| *d);
    vec![("last_at", dir), ("account_id", Dir::Asc), ("thread_id", Dir::Asc)]
}

/// The candidate threads and their reply status, as the CTE `th(gen, account_id, thread_id, matched, n, last_at,
/// last_out, last_in)`.
///
/// * `hit`: threads with at least one message matching the filter (spam/trash policy included), with how many match.
/// * `tm`: every message of those threads under the same spam/trash policy, joined by `messages_thread`
///   `(thread_id, gen)` (never across mailboxes), with its time, draft flag and `from_self`.
/// * `th`: per thread the message count, latest time, latest non-draft time from self (`last_out`) and not from
///   self (`last_in`). The status therefore does not depend on the filter: a reply filed under `SENT` counts even when
///   the filter asks for `INBOX`.
fn threads_cte(req: &SearchReq, scope: &Scope<'_>) -> Result<Sql, ToolError> {
    let w = where_clause(req, scope, false)?;
    let mut q = Sql {
        text: "WITH hit AS (SELECT m.gen AS gen, m.account_id AS account_id, m.thread_id AS thread_id, \
               count(*) AS matched FROM messages m WHERE "
            .into(),
        params: vec![],
    };
    q.s(&w.text);
    q.params.extend(w.params);
    // `tm` is materialized so the self check runs once per message (inlined, SQLite copies it into every use).
    q.s(" GROUP BY m.gen, m.thread_id), \
         tm AS MATERIALIZED (SELECT h.gen AS gen, h.account_id AS account_id, h.thread_id AS thread_id, \
         h.matched AS matched, t.received_at AS at, t.is_draft AS d, ");
    self_expr(&mut q, "t", scope)?;
    q.s(" AS s FROM hit h JOIN messages t ON t.thread_id = h.thread_id AND t.gen = h.gen WHERE ");
    q.s(if req.include_spam_trash { "t.spam_trash IN (0, 1)" } else { "t.spam_trash = 0" });
    q.s("), th AS (SELECT gen, account_id, thread_id, matched, count(*) AS n, max(at) AS last_at, \
         max(CASE WHEN d = 0 AND s THEN at END) AS last_out, max(CASE WHEN d = 0 AND NOT s THEN at END) AS last_in \
         FROM tm GROUP BY gen, thread_id)");
    Ok(q)
}

/// `awaiting_reply`: the latest non-draft message is not from self (`true`) or is from self (`false`). A message
/// from self at the same instant as the latest inbound one counts as the reply (IMAP dates have second precision).
/// Threads that hold only drafts match neither.
fn reply_filter(q: &mut Sql, req: &SearchReq) {
    match req.awaiting_reply {
        None => q.s(" WHERE 1"),
        Some(true) => q.s(" WHERE last_in IS NOT NULL AND (last_out IS NULL OR last_in > last_out)"),
        Some(false) => q.s(" WHERE last_out IS NOT NULL AND (last_in IS NULL OR last_out >= last_in)"),
    };
}

/// The thread page query: candidate threads after `after` in thread order, `limit + 1` of them.
pub fn thread_page_sql(
    req: &SearchReq,
    scope: &Scope<'_>,
    after: &[KeyValue],
) -> Result<(String, Vec<SqlValue>), ToolError> {
    let terms = thread_terms(&req.order);
    let mut q = threads_cte(req, scope)?;
    q.s(" SELECT gen, account_id, thread_id, matched, n, last_at, last_out, last_in FROM th");
    reply_filter(&mut q, req);
    if !after.is_empty() {
        if after.len() != terms.len() {
            return Err(super::cursor::invalid());
        }
        q.s(" AND ");
        seek(&mut q, &terms, after);
    }
    order_by(&mut q, &terms);
    q.s(" LIMIT ").p(SqlValue::Integer(req.limit as i64 + 1));
    Ok((q.text, q.params))
}

/// The latest message of one thread under the spam/trash policy (the row the thread view projects).
fn latest_sql(req: &SearchReq, scope: &Scope<'_>, gen_id: i64, thread_id: &str) -> Result<Sql, ToolError> {
    let mut q = Sql { text: "SELECT ".into(), params: vec![] };
    row_cols(&mut q, req, scope)?;
    q.s(" FROM messages m WHERE m.thread_id = ")
        .p(SqlValue::Text(thread_id.to_string()))
        .s(" AND m.gen = ")
        .p(SqlValue::Integer(gen_id))
        .s(if req.include_spam_trash { " AND m.spam_trash IN (0, 1)" } else { " AND m.spam_trash = 0" })
        .s(" ORDER BY m.received_at DESC, m.gmail_id DESC LIMIT 1");
    Ok(q)
}

// ------------------------------------------------------------------ execution

#[derive(Debug, Clone)]
pub struct Row {
    pub account_id: String,
    pub gmail_id: String,
    pub key: Vec<KeyValue>,
    pub values: Map<String, Value>,
}

fn json_list(s: &str) -> Value {
    serde_json::from_str::<Value>(s).unwrap_or_else(|_| json!([]))
}

/// The selected message columns of a row produced by [`row_cols`] (thread columns are filled in by the caller).
fn message_values(r: &rusqlite::Row<'_>, select: &[String], alias: &str) -> rusqlite::Result<Map<String, Value>> {
    let account_id: String = r.get(0)?;
    let gmail_id: String = r.get(1)?;
    let received: i64 = r.get(2)?;
    let size: i64 = r.get(3)?;
    let mut values = Map::new();
    for col in select {
        let v = match col.as_str() {
            "ref" => json!(crate::tools::make_ref(&account_id, &gmail_id)),
            "account" => json!(alias),
            "message_id" => json!(gmail_id),
            "thread_id" => json!(r.get::<_, String>(6)?),
            "received_at" => json!(util::rfc3339_ms(received)),
            "from" => json_list(&r.get::<_, String>(7)?).get(0).cloned().unwrap_or(Value::Null),
            "to" => json_list(&r.get::<_, String>(8)?),
            "cc" => json_list(&r.get::<_, String>(9)?),
            "bcc" => json_list(&r.get::<_, String>(10)?),
            "subject" => json!(r.get::<_, Option<String>>(11)?),
            "labels" => json_list(&r.get::<_, String>(12)?),
            "snippet" => json!(r.get::<_, Option<String>>(13)?),
            "size_bytes" => json!(size),
            "is_unread" => json!(r.get::<_, i64>(14)? != 0),
            "is_starred" => json!(r.get::<_, i64>(15)? != 0),
            "is_draft" => json!(r.get::<_, i64>(16)? != 0),
            "has_attachment" => json!(r.get::<_, Option<i64>>(17)?.map(|v| v != 0)),
            "attachment_names" => json_list(&r.get::<_, String>(18)?),
            "attachment_mime_types" => json_list(&r.get::<_, String>(19)?),
            "category" => json!(r.get::<_, Option<String>>(20)?),
            "from_self" => json!(r.get::<_, i64>(ROW_COL_COUNT)? != 0),
            _ => continue,
        };
        values.insert(col.clone(), v);
    }
    Ok(values)
}

/// Runs one page. Returns rows (at most `limit`) and whether another page exists.
pub fn run_page(
    conn: &Connection,
    req: &SearchReq,
    scope: &Scope<'_>,
    after: &[KeyValue],
) -> anyhow::Result<(Vec<Row>, bool)> {
    if req.group_by_thread {
        return run_thread_page(conn, req, scope, after);
    }
    let (sql, params) = page_sql(req, scope, after)?;
    let alias: HashMap<&str, &str> = scope.targets.iter().map(|t| (t.account_id.as_str(), t.alias.as_str())).collect();
    let mut st = conn.prepare(&sql)?;
    let mut rows = st.query(params_from_iter(params))?;
    let mut out = vec![];
    while let Some(r) = rows.next()? {
        let account_id: String = r.get(0)?;
        let gmail_id: String = r.get(1)?;
        let mut key = vec![];
        for (f, _) in &req.order {
            match f {
                OrderField::ReceivedAt => key.push(KeyValue::Int(r.get(2)?)),
                OrderField::SizeBytes => key.push(KeyValue::Int(r.get(3)?)),
                OrderField::Subject => {
                    key.push(KeyValue::Int(r.get(4)?));
                    key.push(KeyValue::Text(r.get(5)?));
                }
            }
        }
        key.push(KeyValue::Text(account_id.clone()));
        key.push(KeyValue::Text(gmail_id.clone()));
        let values = message_values(r, &req.select, alias.get(account_id.as_str()).copied().unwrap_or(""))?;
        out.push(Row { account_id, gmail_id, key, values });
    }
    let more = out.len() > req.limit;
    out.truncate(req.limit);
    Ok((out, more))
}

/// One page of the thread view: the threads in thread order, each projected from its latest message plus the
/// per-thread columns. The row key is `(last_at, account_id, thread_id)`.
fn run_thread_page(
    conn: &Connection,
    req: &SearchReq,
    scope: &Scope<'_>,
    after: &[KeyValue],
) -> anyhow::Result<(Vec<Row>, bool)> {
    type Head = (i64, String, String, i64, i64, i64, Option<i64>, Option<i64>);
    let (sql, params) = thread_page_sql(req, scope, after)?;
    let mut st = conn.prepare(&sql)?;
    let heads: Vec<Head> = st
        .query_map(params_from_iter(params), |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?))
        })?
        .collect::<Result<_, _>>()?;
    let more = heads.len() > req.limit;
    let mut out = Vec::with_capacity(heads.len().min(req.limit));
    for (gen_id, account_id, thread_id, matched, n, last_at, last_out, last_in) in heads.into_iter().take(req.limit) {
        let alias = scope.targets.iter().find(|t| t.gen_id == gen_id).map_or("", |t| t.alias.as_str());
        let q = latest_sql(req, scope, gen_id, &thread_id)?;
        let mut lst = conn.prepare_cached(&q.text)?;
        let Some((gmail_id, mut values)) = lst
            .query_row(params_from_iter(q.params), |r| {
                Ok((r.get::<_, String>(1)?, message_values(r, &req.select, alias)?))
            })
            .optional()?
        else {
            // Same read transaction as the thread query: cannot happen; skip defensively.
            continue;
        };
        let self_last = last_out.map(|o| last_in.is_none_or(|i| o >= i));
        for col in &req.select {
            let v = match col.as_str() {
                "message_count" => json!(n),
                "matched_count" => json!(matched),
                "last_sender_is_self" => json!(self_last.or(last_in.map(|_| false))),
                "last_inbound_at" => json!(last_in.map(util::rfc3339_ms)),
                "last_outbound_at" => json!(last_out.map(util::rfc3339_ms)),
                "awaiting_reply" => json!(last_in.is_some() && self_last != Some(true)),
                _ => continue,
            };
            values.insert(col.clone(), v);
        }
        let key = vec![KeyValue::Int(last_at), KeyValue::Text(account_id.clone()), KeyValue::Text(thread_id)];
        out.push(Row { account_id, gmail_id, key, values });
    }
    Ok((out, more))
}

pub fn run_count(conn: &Connection, req: &SearchReq, scope: &Scope<'_>) -> anyhow::Result<i64> {
    let (sql, params) = count_sql(req, scope)?;
    Ok(conn.query_row(&sql, params_from_iter(params), |r| r.get(0))?)
}

/// Index row ids among `rows` that match `filter` (spam and trash excluded, like a default search). Used by `query`
/// watches, which evaluate the agent's typed filter against newly indexed messages only (`crate::watch`).
pub fn matching_rows(conn: &Connection, filter: &Expr, scope: &Scope<'_>, rows: &[i64]) -> anyhow::Result<Vec<i64>> {
    if rows.is_empty() {
        return Ok(vec![]);
    }
    let req = SearchReq {
        accounts: None,
        filter: Some(filter.clone()),
        select: vec![],
        order: vec![],
        limit: rows.len(),
        count_only: false,
        require_complete: false,
        max_lag_seconds: None,
        include_spam_trash: false,
        group_by_thread: false,
        awaiting_reply: None,
    };
    let w = where_clause(&req, scope, false)?;
    let mut q = Sql { text: format!("SELECT m.id FROM messages m WHERE {} AND m.id IN ", w.text), params: w.params };
    q.list(rows.iter().map(|r| SqlValue::Integer(*r)));
    let mut st = conn.prepare(&q.text)?;
    let out = st.query_map(params_from_iter(q.params), |r| r.get(0))?.collect::<Result<_, _>>()?;
    Ok(out)
}

/// EXPLAIN QUERY PLAN lines for the thread view's latest-message lookup in the first target (tests verify it).
pub fn explain_latest(conn: &Connection, req: &SearchReq, scope: &Scope<'_>) -> anyhow::Result<Vec<String>> {
    let gen_id = scope.targets.first().map_or(0, |t| t.gen_id);
    let q = latest_sql(req, scope, gen_id, "t")?;
    let mut st = conn.prepare(&format!("EXPLAIN QUERY PLAN {}", q.text))?;
    let rows = st.query_map(params_from_iter(q.params), |r| r.get::<_, String>(3))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// EXPLAIN QUERY PLAN lines for a page query (tests verify hot paths).
pub fn explain(conn: &Connection, req: &SearchReq, scope: &Scope<'_>) -> anyhow::Result<Vec<String>> {
    let (sql, params) = if req.count_only { count_sql(req, scope)? } else { page_sql(req, scope, &[])? };
    let mut st = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
    let rows = st.query_map(params_from_iter(params), |r| r.get::<_, String>(3))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(v: Value) -> Result<Option<Expr>, ToolError> {
        parse_where(Some(&v))
    }

    #[test]
    fn rejects_malformed_queries() {
        let code = |v: Value| parse(v).unwrap_err().code.as_str();
        assert_eq!(code(json!({"field":"nope","op":"eq","value":"x"})), "invalid_argument");
        assert_eq!(code(json!({"field":"from","op":"terms","value":"x"})), "invalid_argument");
        assert_eq!(code(json!({"all":[]})), "invalid_argument");
        assert_eq!(code(json!({"all":[{"field":"from","op":"eq","value":"a@b.c"}], "x":1})), "invalid_argument");
        assert_eq!(code(json!({"field":"from","op":"eq","value":"x".repeat(257)})), "invalid_argument");
        assert_eq!(code(json!({"field":"from","op":"in","value":vec!["a@b.c"; 101]})), "invalid_argument");
        assert_eq!(code(json!({"field":"received_at","op":"gte","value":"2026-10-01T10:00:00"})), "invalid_argument");
        assert_eq!(code(json!({"field":"received_at","op":"eq","value":"2026-10-01"})), "invalid_argument");
        assert!(parse(json!({"field":"received_at","op":"gte","value":"2026-10-01"})).is_ok());
        assert_eq!(code(json!({"field":"subject","op":"prefix","value":"a"})), "query_too_broad");
        assert_eq!(code(json!({"field":"subject","op":"prefix","value":"two words"})), "invalid_argument");
        let deep = json!({"all":[{"any":[{"not":{"all":[{"not":{"field":"is_unread","op":"eq","value":true}}]}}]}]});
        assert_eq!(code(deep), "invalid_argument");
        let ok_deep = json!({"all":[{"any":[{"not":{"all":[{"field":"is_unread","op":"eq","value":true}]}}]}]});
        assert!(parse(ok_deep).is_ok());
        let many: Vec<Value> = (0..33).map(|_| json!({"field":"is_unread","op":"eq","value":true})).collect();
        assert_eq!(code(json!({"all": many})), "invalid_argument");
        assert!(parse(json!({})).unwrap().is_none());
    }

    #[test]
    fn fts_literals_cannot_inject_syntax() {
        let e = fts_expr(Field::Text, Op::Terms, "a\" OR body:x NEAR(* \"");
        assert_eq!(e, "(\"a\" AND \"OR\" AND \"body\" AND \"x\" AND \"NEAR\")");
        assert_eq!(fts_expr(Field::Subject, Op::Phrase, "Invoice no. 7"), "subject : (\"Invoice no 7\")");
        assert_eq!(fts_expr(Field::BodyText, Op::Prefix, "inv"), "body : (\"inv\" *)");
    }
}
