//! Signature tools (design 2026-11-17 "html signatures"): `list_signatures` (needs `draft`), `set_signature` and
//! `delete_signature` (need `signatures`, which the operator grants separately and which no preset contains).
//!
//! A change by an agent alerts the owner (at most once per signature and day), because a signature is text the owner
//! sends under their name. Validation and storage live in [`crate::signatures`]; this layer only parses arguments.

use serde_json::{Value, json};

use super::{
    AuditInfo, ToolCx, ToolDef, ToolOutput, account_arg, account_schema, arg_str, object_schema, only_keys, opt_bool,
    opt_str,
};
use crate::error::ToolError;
use crate::policy::Capability;
use crate::signatures::{self, Change};
use crate::util;

pub fn defs() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "list_signatures",
            title: "List signatures",
            description: concat!(
                "List a mailbox's named signatures: name, which sender each is the default for (\"mailbox\" or a ",
                "send-as address), the plain-text version, whether it has HTML, and its inline images (cid, type, ",
                "size). include_html adds the cleaned HTML. Pass a name as create_draft's or update_draft's ",
                "signature to use one that is not the default."
            ),
            capability: Capability::Draft,
            read_only: true,
            destructive: false,
            mail_content: false,
            input_schema: || {
                json!({ "type": "object", "properties": {
                    "account": account_schema(),
                    "include_html": { "type": "boolean", "description": "Also return each signature's HTML (default false)." }
                }, "required": ["account"], "additionalProperties": false })
            },
            output_schema: || object_schema(json!({ "account": {"type":"string"}, "signatures": {"type":"array"} })),
            handler: |cx, args| Box::pin(list_signatures(cx, args)),
        },
        ToolDef {
            name: "set_signature",
            title: "Create or change signature",
            description: concat!(
                "Create or change a named signature of a mailbox (needs the signatures permission). Give html, text ",
                "or both: without text, the plain-text version is derived from the HTML. The HTML is cleaned to a safe ",
                "subset (no scripts, forms, event handlers or remote CSS); images are https URLs or inline images ",
                "referenced as cid:<cid> and passed in images (PNG, JPEG or GIF, at most 6 and 512 KB together). ",
                "Omitted fields keep their value; images replaces all images; html \"\" makes it text only. The ",
                "first signature of a mailbox becomes its default; make_default (with for_address for a send-as ",
                "address) changes the default. The owner is notified of every change."
            ),
            capability: Capability::Signatures,
            read_only: false,
            destructive: true,
            mail_content: false,
            input_schema: || {
                json!({ "type": "object", "properties": {
                    "account": account_schema(),
                    "name": { "type": "string", "description": "1 to 40 lowercase letters, digits or '-', e.g. \"behoerden\"." },
                    "html": { "type": "string", "description": "Signature HTML (a fragment, at most 64 KB before cleaning); \"\" removes the HTML." },
                    "text": { "type": "string", "description": "Plain-text version (at most 4 KB, 30 lines); derived from html when omitted." },
                    "images": { "type": "array", "maxItems": signatures::MAX_IMAGES, "description": "Inline images; replaces all images.", "items": {
                        "type": "object", "properties": {
                            "cid": { "type": "string", "description": "Content-ID the HTML uses as cid:<cid>, e.g. \"logo\"." },
                            "data_base64": { "type": "string", "description": "The image file, base64 encoded." },
                            "mime_type": { "type": "string", "description": "image/png, image/jpeg or image/gif (checked against the bytes)." }
                        }, "required": ["cid", "data_base64"], "additionalProperties": false } },
                    "make_default": { "type": "boolean", "description": "Make it the default signature of the mailbox, or of for_address." },
                    "for_address": { "type": "string", "description": "With make_default: a send-as address of the mailbox instead of the whole mailbox." }
                }, "required": ["account", "name"], "additionalProperties": false })
            },
            output_schema: || {
                object_schema(
                    json!({ "account": {"type":"string"}, "name": {"type":"string"}, "created": {"type":"boolean"} }),
                )
            },
            handler: |cx, args| Box::pin(set_signature(cx, args)),
        },
        ToolDef {
            name: "delete_signature",
            title: "Delete signature",
            description: concat!(
                "Delete a named signature of a mailbox (needs the signatures permission). Defaults that pointed to it ",
                "are removed, so new drafts get no signature until another default is set. Existing drafts keep their ",
                "text. The owner is notified."
            ),
            capability: Capability::Signatures,
            read_only: false,
            destructive: true,
            mail_content: false,
            input_schema: || {
                json!({ "type": "object", "properties": {
                    "account": account_schema(),
                    "name": { "type": "string", "description": "Signature name from list_signatures." }
                }, "required": ["account", "name"], "additionalProperties": false })
            },
            output_schema: || {
                object_schema(
                    json!({ "account": {"type":"string"}, "name": {"type":"string"}, "deleted": {"type":"boolean"} }),
                )
            },
            handler: |cx, args| Box::pin(delete_signature(cx, args)),
        },
    ]
}

/// Validation errors from [`crate::signatures`] (plain `bail!` texts naming only the caller's own input) become
/// `invalid_argument` at `field`; database errors stay internal.
fn invalid(field: &'static str) -> impl Fn(anyhow::Error) -> anyhow::Error {
    move |e| {
        if e.downcast_ref::<rusqlite::Error>().is_some() || e.downcast_ref::<ToolError>().is_some() {
            e
        } else {
            anyhow::Error::new(ToolError::invalid_at(field, e.to_string()))
        }
    }
}

fn name_arg(args: &Value) -> Result<String, ToolError> {
    let name = arg_str(args, "name")?;
    if !signatures::valid_name(name) {
        return Err(ToolError::invalid_at(
            "name",
            "1 to 40 lowercase letters, digits or '-', starting with a letter or digit",
        ));
    }
    Ok(name.to_string())
}

fn audit(alias: &str, name: &str) -> AuditInfo {
    AuditInfo {
        account: Some(alias.to_string()),
        object_ids: vec![format!("signature:{name}")],
        result_count: Some(1),
        ..Default::default()
    }
}

/// Alerts the owner of an agent's change or deletion (no deduplication: the caller alerts only on real changes).
async fn alert(cx: &ToolCx, alias: &str, name: &str, deleted: bool) {
    cx.app.notifier.send(crate::notifier::Alert::signature_changed(alias, &cx.client.client_name, name, deleted)).await;
}

async fn list_signatures(cx: &ToolCx, args: Value) -> Result<ToolOutput, ToolError> {
    only_keys(&args, &["account", "include_html"])?;
    let mb = account_arg(cx, &args, Capability::Draft)?.clone();
    let include_html = opt_bool(&args, "include_html", false)?;
    let aid = mb.account_id.clone();
    let list = cx.app.store.call(move |c| signatures::list(c, &aid, include_html)).await?;
    let text = if list.is_empty() {
        format!("{} has no signatures.", mb.alias)
    } else {
        list.iter()
            .map(|s| {
                let defaults: Vec<&str> = s["default_for"]
                    .as_array()
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                format!(
                    "{}{}{}",
                    s["name"].as_str().unwrap_or_default(),
                    if s["has_html"].as_bool() == Some(true) { " (html)" } else { "" },
                    if defaults.is_empty() { String::new() } else { format!(", default for {}", defaults.join(", ")) }
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let n = list.len() as i64;
    Ok(ToolOutput {
        extra: Vec::new(),
        text,
        structured: json!({ "account": mb.alias, "signatures": list }),
        audit: AuditInfo { account: Some(mb.alias.clone()), result_count: Some(n), ..Default::default() },
    })
}

async fn set_signature(cx: &ToolCx, args: Value) -> Result<ToolOutput, ToolError> {
    only_keys(&args, &["account", "name", "html", "text", "images", "make_default", "for_address"])?;
    let mb = account_arg(cx, &args, Capability::Signatures)?.clone();
    let name = name_arg(&args)?;
    let html = opt_str(&args, "html")?.map(str::to_string);
    if html.as_ref().is_some_and(|h| h.len() > signatures::MAX_RAW_HTML_BYTES) {
        return Err(ToolError::invalid_at("html", "longer than 64 KB"));
    }
    let text = opt_str(&args, "text")?.map(str::to_string);
    let images = match args.get("images").filter(|v| !v.is_null()) {
        None => None,
        Some(Value::Array(items)) => {
            if items.len() > signatures::MAX_IMAGES {
                return Err(ToolError::invalid_at("images", "at most 6 images"));
            }
            let mut out = Vec::with_capacity(items.len());
            for (i, it) in items.iter().enumerate() {
                let path = format!("images[{i}]");
                only_keys(it, &["cid", "data_base64", "mime_type"]).map_err(|_| {
                    ToolError::invalid_at(path.clone(), "allowed keys are cid, data_base64 and mime_type")
                })?;
                let cid = it["cid"].as_str().ok_or_else(|| ToolError::invalid_at(format!("{path}.cid"), "required"))?;
                let data = it["data_base64"]
                    .as_str()
                    .ok_or_else(|| ToolError::invalid_at(format!("{path}.data_base64"), "required"))?;
                if data.len() > signatures::MAX_IMAGE_BYTES / 3 * 4 + 8 {
                    return Err(ToolError::invalid_at(
                        format!("{path}.data_base64"),
                        "the image is larger than 512 KB",
                    ));
                }
                let bytes = util::b64_decode_any(data)
                    .ok_or_else(|| ToolError::invalid_at(format!("{path}.data_base64"), "not base64"))?;
                let img = signatures::image(cid, it["mime_type"].as_str(), bytes)
                    .map_err(|e| ToolError::invalid_at(path.clone(), e.to_string()))?;
                out.push(img);
            }
            Some(out)
        }
        Some(_) => return Err(ToolError::invalid_at("images", "must be an array")),
    };
    let make_default = opt_bool(&args, "make_default", false)?;
    let for_address = opt_str(&args, "for_address")?.map(str::to_string);
    if for_address.is_some() && !make_default {
        return Err(ToolError::invalid_at("for_address", "applies only with make_default: true"));
    }
    let actor = format!("client:{}", cx.client.client_name);
    let (alias, n2) = (mb.alias.clone(), name.clone());
    if text.is_some() && html.as_deref().is_some_and(|h| !h.trim().is_empty()) {
        return Err(ToolError::invalid_at(
            "text",
            "a signature with HTML gets its text derived from the HTML, so the owner sees what recipients see; leave text out",
        ));
    }
    let change = Change { name: name.clone(), html, text, images, derive_text: true };
    let mut out = cx
        .app
        .store
        .call(move |c| {
            let tx = c.transaction()?;
            let mut v = signatures::set(&tx, &alias, change, &actor).map_err(invalid("signature"))?;
            if make_default {
                let d = signatures::set_default(&tx, &alias, for_address.as_deref(), Some(&n2))
                    .map_err(invalid("for_address"))?;
                v["default"] = d;
            }
            tx.commit()?;
            Ok(v)
        })
        .await?;
    if let Some(o) = out.as_object_mut() {
        o.remove("text_bytes");
    }
    // Every call that changes the stored signature or a default alerts the owner; a call that changes nothing does not.
    if out["changed"] == true || out["default"]["changed"] == true {
        alert(cx, &mb.alias, &name, false).await;
    }
    let created = out["created"].as_bool() == Some(true);
    Ok(ToolOutput {
        extra: Vec::new(),
        text: format!("{} signature '{name}' of {}.", if created { "Created" } else { "Changed" }, mb.alias),
        structured: out,
        audit: audit(&mb.alias, &name),
    })
}

async fn delete_signature(cx: &ToolCx, args: Value) -> Result<ToolOutput, ToolError> {
    only_keys(&args, &["account", "name"])?;
    let mb = account_arg(cx, &args, Capability::Signatures)?.clone();
    let name = name_arg(&args)?;
    let (alias, n2) = (mb.alias.clone(), name.clone());
    let deleted = cx
        .app
        .store
        .call(move |c| {
            let tx = c.transaction()?;
            let d = signatures::delete(&tx, &alias, &n2)?;
            tx.commit()?;
            Ok(d)
        })
        .await?;
    if !deleted {
        return Err(ToolError::invalid_at(
            "name",
            "this mailbox has no signature by that name; list_signatures shows them",
        ));
    }
    alert(cx, &mb.alias, &name, true).await;
    Ok(ToolOutput {
        extra: Vec::new(),
        text: format!("Deleted signature '{name}' of {}.", mb.alias),
        structured: json!({ "account": mb.alias, "name": name, "deleted": true }),
        audit: audit(&mb.alias, &name),
    })
}
