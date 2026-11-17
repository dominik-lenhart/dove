//! Named HTML signatures (design 2026-11-17 "html signatures", PLAN A79): agents manage them with `set_signature` /
//! `delete_signature` (the `signatures` permission) and pick one in `create_draft` / `update_draft`. A signature with
//! HTML makes the draft `multipart/related` (inline images by Content-ID) around `multipart/alternative` (text, HTML),
//! and in replies and forwards it sits above the quote or forwarded block in both parts.

mod support;

use dove::admin::{AdminRequest, SignatureImage};
use dove::mime;
use mail_parser::MessageParser;
use serde_json::{Value, json};
use support::fake_google::MessageSpec;
use support::fake_imap::encode_utf7;
use support::harness::{FakeImapUser, Harness, g};

const GMAIL: &str = "info@acme.test";
const IMAP: &str = "box@example.org";

const BEHOERDEN: &str = r#"<table cellpadding="0" style="font-family:Arial;font-size:13px"><tr>
<td><img src="cid:keyset-logo" width="48" height="48" alt="Keyset"></td>
<td><b>Dominik Lenhart</b><br>Keyset GmbH<br><a href="https://keyset.cloud" onclick="steal()">keyset.cloud</a></td>
</tr></table><script>alert(1)</script>"#;

const GASTGEBER: &str = r#"<p>Herzliche Grüße<br><b>Dominik</b></p><img src="cid:keyset-logo" width="32" alt="">
<img src="cid:keyset-banner" width="600" alt="Willkommen">"#;

fn key() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn png() -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
    v.extend_from_slice(&[7u8; 300]);
    v
}

fn jpeg() -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
    v.extend_from_slice(&[9u8; 900]);
    v
}

fn b64(b: &[u8]) -> String {
    dove::util::b64std(b)
}

struct Fx {
    h: Harness,
    u: FakeImapUser,
    /// read, draft and signatures on both mailboxes.
    writer: String,
    /// read and draft only.
    drafter: String,
}

async fn fx() -> Fx {
    let h = Harness::start().await;
    h.mailbox("info", GMAIL);
    let u = h.imap_mailbox("box", IMAP).await;
    h.project("p", &["info", "box"]).await;
    let writer =
        h.token("p", "writer", vec![g("info", "read,draft,signatures"), g("box", "read,draft,signatures")]).await;
    let drafter = h.token("p", "drafter", vec![g("info", "read,draft"), g("box", "read,draft")]).await;
    Fx { h, u, writer, drafter }
}

impl Fx {
    /// Creates `behoerden` (logo, becomes the default) and `gastgeber` (logo and banner) on `account`.
    async fn two_signatures(&self, account: &str) {
        let r = self
            .h
            .ok(
                &self.writer,
                "set_signature",
                json!({ "account": account, "name": "behoerden", "html": BEHOERDEN,
                        "images": [{ "cid": "keyset-logo", "data_base64": b64(&png()), "mime_type": "image/png" }] }),
            )
            .await;
        assert_eq!(r["created"], true);
        assert_eq!(r["became_default"], true);
        let r = self
            .h
            .ok(
                &self.writer,
                "set_signature",
                json!({ "account": account, "name": "gastgeber", "html": GASTGEBER, "images": [
                    { "cid": "keyset-logo", "data_base64": b64(&png()) },
                    { "cid": "keyset-banner", "data_base64": b64(&jpeg()) } ] }),
            )
            .await;
        assert_eq!(r["became_default"], false);
    }

    fn draft(&self, account: &str, r: &Value) -> Vec<u8> {
        if account == "box" {
            let uid: u32 = r["revision"].as_str().unwrap().rsplit('-').next().unwrap().parse().unwrap();
            self.h.imap.message_raw(&self.u.user, "Drafts", uid).expect("draft on the server")
        } else {
            self.h.google.draft_raw(GMAIL, r["draft_id"].as_str().unwrap()).expect("draft at Google")
        }
    }

    /// A message in the mailbox to reply to; returns its id.
    async fn original(&self, account: &str) -> String {
        if account == "info" {
            return self.h.google.add_message(
                GMAIL,
                MessageSpec {
                    from: "amt@stadt.example".into(),
                    to: vec![GMAIL.into()],
                    subject: "Antrag".into(),
                    text: Some("Bitte <b>Unterlagen</b> nachreichen.\n".into()),
                    internal_date_ms: 1_700_000_000_000,
                    message_id_header: Some("<antrag@stadt.example>".into()),
                    ..Default::default()
                },
            );
        }
        let raw = b"From: Amt <amt@stadt.example>\r\nTo: box@example.org\r\nSubject: Antrag\r\n\
Message-ID: <antrag@stadt.example>\r\nDate: Tue, 14 Nov 2023 22:13:20 +0000\r\n\r\nBitte <b>Unterlagen</b> nachreichen.\r\n";
        let uid = self.h.imap.add_message(&self.u.user, "INBOX", raw, &[]);
        let (a, n) = (self.u.account_id.clone(), encode_utf7("INBOX"));
        let fid: i64 = self
            .h
            .app()
            .store
            .call(move |c| {
                Ok(c.query_row(
                    "SELECT folder_id FROM imap_folders WHERE account_id = ?1 AND name = ?2",
                    [a, n],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        format!("f{fid}-{}-{uid}", self.h.imap.uidvalidity(&self.u.user, "INBOX"))
    }
}

fn create(account: &str) -> Value {
    json!({ "account": account, "request_key": key(), "to": ["amt@stadt.example"], "subject": "Antrag",
            "body_text": "Guten Tag,\nanbei die Unterlagen." })
}

/// The MIME tree as (depth, content type, Content-ID without <>, disposition) in tree order.
fn tree(raw: &[u8]) -> Vec<(usize, String, Option<String>, Option<String>)> {
    let msg = MessageParser::new().parse(raw).unwrap();
    let mut out = Vec::new();
    let mut stack = vec![(0usize, msg.root().root_part())];
    while let Some((d, p)) = stack.pop() {
        let ct = p.content_type().map(|c| format!("{}/{}", c.ctype(), c.subtype().unwrap_or("plain")));
        out.push((
            d,
            ct.unwrap_or_else(|| "text/plain".into()).to_ascii_lowercase(),
            p.content_id().map(|c| c.trim_matches(['<', '>']).to_string()),
            p.content_disposition().map(|c| c.ctype().to_string()),
        ));
        let kids: Vec<_> = p.children().collect();
        stack.extend(kids.into_iter().rev().map(|k| (d + 1, k)));
    }
    out
}

fn kinds(raw: &[u8]) -> Vec<(usize, String)> {
    tree(raw).into_iter().map(|(d, t, _, _)| (d, t)).collect()
}

fn text_of(raw: &[u8]) -> String {
    mime::read_draft_fields(raw).unwrap().body_text
}

fn html_of(raw: &[u8]) -> String {
    mime::read_draft_fields(raw).unwrap().html.expect("an HTML part").html
}

fn related(images: &[&str]) -> Vec<(usize, String)> {
    let mut v = vec![
        (0, "multipart/related".to_string()),
        (1, "multipart/alternative".into()),
        (2, "text/plain".into()),
        (2, "text/html".into()),
    ];
    v.extend(images.iter().map(|t| (1, t.to_string())));
    v
}

// ------------------------------------------------------------------ permissions

#[tokio::test]
async fn managing_signatures_needs_its_own_permission() {
    let f = fx().await;
    let names = f.h.tool_names(&f.drafter).await;
    assert!(names.contains(&"list_signatures".to_string()));
    assert!(!names.iter().any(|n| n == "set_signature" || n == "delete_signature"), "{names:?}");
    let names = f.h.tool_names(&f.writer).await;
    assert!(names.contains(&"set_signature".to_string()) && names.contains(&"delete_signature".to_string()));

    let (err, _) = f.h.call(&f.drafter, "set_signature", json!({ "account": "box", "name": "x", "text": "x" })).await;
    assert!(err);
    // signatures on one mailbox does not reach another.
    let partial = f.h.token("p", "partial", vec![g("box", "read,draft,signatures"), g("info", "read,draft")]).await;
    assert_eq!(
        f.h.err(&partial, "set_signature", json!({ "account": "info", "name": "x", "text": "x" })).await,
        "forbidden"
    );
    f.h.ok(&partial, "set_signature", json!({ "account": "box", "name": "x", "text": "x" })).await;
    // The grant needs draft (signatures alone is refused).
    let r = f.h.admin(AdminRequest::ClientsCreate {
        name: "bad".into(),
        project: "p".into(),
        grants: vec![g("box", "read,signatures")],
        expires: None,
        allow_ip: vec![],
        redact_secrets: None,
    });
    assert!(r.await.unwrap_err().contains("signatures requires draft"));
}

// ------------------------------------------------------------------ MIME structure

#[tokio::test]
async fn html_signatures_build_related_alternative_drafts_on_both_providers() {
    let f = fx().await;
    for account in ["box", "info"] {
        f.two_signatures(account).await;

        // The default (behoerden): related(alternative(text, html), logo).
        let raw = f.draft(account, &f.h.ok(&f.writer, "create_draft", create(account)).await);
        assert_eq!(kinds(&raw), related(&["image/png"]), "{account}");
        let t = tree(&raw);
        let logo = t.iter().find(|x| x.1 == "image/png").unwrap();
        assert_eq!(logo.2.as_deref(), Some("keyset-logo"));
        assert_eq!(logo.3.as_deref(), Some("inline"));
        let fields = mime::read_draft_fields(&raw).unwrap();
        assert_eq!(fields.html.as_ref().unwrap().images[0].bytes, png(), "image bytes survive");
        let text = text_of(&raw);
        assert_eq!(text, "Guten Tag,\nanbei die Unterlagen.\n\n-- \nDominik Lenhart\nKeyset GmbH\nkeyset.cloud\n");
        let html = html_of(&raw);
        assert!(html.contains("Guten Tag,<br>\nanbei die Unterlagen."), "{html}");
        assert!(html.contains("<b>Dominik Lenhart</b>") && html.contains("src=\"cid:keyset-logo\""), "{html}");
        for gone in ["script", "alert", "onclick", "steal"] {
            assert!(!html.contains(gone), "{gone} in {html}");
        }

        // By name: gastgeber has both images.
        let mut a = create(account);
        a["signature"] = json!("gastgeber");
        let raw = f.draft(account, &f.h.ok(&f.writer, "create_draft", a).await);
        assert_eq!(kinds(&raw), related(&["image/jpeg", "image/png"]), "{account}: images sorted by cid");
        let cids: Vec<_> = tree(&raw).into_iter().filter_map(|x| x.2).collect();
        assert_eq!(cids, ["keyset-banner", "keyset-logo"]);

        // With an attachment: mixed(related(..), attachment).
        let mut a = create(account);
        a["attachments"] =
            json!([{ "filename": "antrag.pdf", "mime_type": "application/pdf", "content_base64": b64(b"%PDF-1.4") }]);
        let raw = f.draft(account, &f.h.ok(&f.writer, "create_draft", a).await);
        let k = kinds(&raw);
        assert_eq!(k[0], (0, "multipart/mixed".into()));
        assert_eq!(k[1], (1, "multipart/related".into()));
        assert_eq!(k.last().unwrap(), &(1, "application/pdf".into()));
        assert_eq!(tree(&raw).last().unwrap().3.as_deref(), Some("attachment"));

        // signature: false is plain text exactly as given.
        let mut a = create(account);
        a["signature"] = json!(false);
        let raw = f.draft(account, &f.h.ok(&f.writer, "create_draft", a).await);
        assert_eq!(kinds(&raw), [(0, "text/plain".to_string())]);
        assert_eq!(text_of(&raw).trim_end(), "Guten Tag,\nanbei die Unterlagen.");
    }
}

#[tokio::test]
async fn an_unknown_signature_name_creates_nothing() {
    let f = fx().await;
    f.two_signatures("box").await;
    let before = f.h.imap.uids(&f.u.user, "Drafts").len();
    let mut a = create("box");
    a["signature"] = json!("urlaub");
    let (err, v) = f.h.call(&f.drafter, "create_draft", a).await;
    assert!(err);
    assert_eq!(v["error"]["code"], "invalid_argument");
    assert_eq!(v["error"]["details"]["field"], "signature");
    let mut a = create("box");
    a["signature"] = json!("Not A Name");
    assert_eq!(f.h.err(&f.drafter, "create_draft", a).await, "invalid_argument");
    assert_eq!(f.h.imap.uids(&f.u.user, "Drafts").len(), before);
    // Another mailbox's signature is not this mailbox's.
    let mut a = create("info");
    a["signature"] = json!("behoerden");
    assert_eq!(f.h.err(&f.drafter, "create_draft", a).await, "invalid_argument");
}

#[tokio::test]
async fn in_replies_the_signature_sits_above_the_quote_in_text_and_html() {
    let f = fx().await;
    for account in ["box", "info"] {
        f.two_signatures(account).await;
        let orig = f.original(account).await;
        let mut a = create(account);
        a["reply_to_message_id"] = json!(orig);
        a["body_text"] = json!("Danke, kommt morgen.");
        let r = f.h.ok(&f.drafter, "create_draft", a).await;
        let raw = f.draft(account, &r);
        let text = text_of(&raw);
        let (sig, quote) = (text.find("-- \nDominik Lenhart").unwrap(), text.find("wrote:").unwrap());
        assert!(text.starts_with("Danke, kommt morgen.\n\n-- \n"), "{text}");
        assert!(sig < quote, "{text}");
        assert!(text.contains("> Bitte <b>Unterlagen</b> nachreichen."), "{text}");
        let html = html_of(&raw);
        let (body, sig, quote) = (
            html.find("Danke, kommt morgen.").unwrap(),
            html.find("<b>Dominik Lenhart</b>").unwrap(),
            html.find("<blockquote").unwrap(),
        );
        assert!(body < sig && sig < quote, "{html}");
        assert!(html.contains("Bitte &lt;b&gt;Unterlagen&lt;/b&gt; nachreichen."), "quoted mail is escaped: {html}");
        assert!(!html[quote..].contains("&gt; Bitte"), "{html}");

        // A forward: signature above the forwarded block.
        let mut a = create(account);
        a["forward_message_id"] = json!(orig);
        a["body_text"] = json!("Zur Info.");
        let raw = f.draft(account, &f.h.ok(&f.drafter, "create_draft", a).await);
        let text = text_of(&raw);
        assert!(text.find("Keyset GmbH").unwrap() < text.find("Forwarded message").unwrap(), "{text}");
        let html = html_of(&raw);
        assert!(html.find("Keyset GmbH").unwrap() < html.find("Forwarded message").unwrap(), "{html}");
    }
}

// ------------------------------------------------------------------ update_draft and get_draft

#[tokio::test]
async fn update_draft_keeps_the_signature_and_quote_and_can_switch_or_drop_it() {
    let f = fx().await;
    for account in ["box", "info"] {
        f.two_signatures(account).await;
        let orig = f.original(account).await;
        let mut a = create(account);
        a["reply_to_message_id"] = json!(orig);
        a["body_text"] = json!("Erster Entwurf.");
        let c = f.h.ok(&f.drafter, "create_draft", a).await;

        let d = f.h.ok(&f.drafter, "get_draft", json!({ "account": account, "draft_id": c["draft_id"] })).await;
        assert_eq!(
            d["composition"],
            json!({ "signature": "behoerden", "has_html": true, "quote_or_forward_below": true }),
            "{account}"
        );

        // body_text replaces only the agent's text.
        let up = |rev: &Value, changes: Value| json!({ "account": account, "draft_id": c["draft_id"], "expected_revision": rev, "changes": changes });
        let u1 =
            f.h.ok(&f.drafter, "update_draft", up(&c["revision"], json!({ "body_text": "Zweiter Entwurf." }))).await;
        let raw = f.draft(account, &json!({ "draft_id": c["draft_id"], "revision": u1["revision"] }));
        let text = text_of(&raw);
        assert!(text.starts_with("Zweiter Entwurf.\n\n-- \nDominik Lenhart"), "{text}");
        assert!(!text.contains("Erster"), "{text}");
        assert_eq!(text.matches("-- \n").count(), 1);
        assert!(text.contains("> Bitte <b>Unterlagen</b> nachreichen."), "{text}");
        let html = html_of(&raw);
        assert!(html.contains("Zweiter Entwurf.") && !html.contains("Erster"), "{html}");
        assert!(html.find("<b>Dominik Lenhart</b>").unwrap() < html.find("<blockquote").unwrap(), "{html}");
        assert_eq!(kinds(&raw), related(&["image/png"]));

        // A change that leaves body and signature alone keeps both parts byte for byte.
        let u2 = f.h.ok(&f.drafter, "update_draft", up(&u1["revision"], json!({ "subject": "Re: Antrag (2)" }))).await;
        let raw2 = f.draft(account, &json!({ "draft_id": c["draft_id"], "revision": u2["revision"] }));
        assert_eq!(text_of(&raw2), text);
        assert_eq!(html_of(&raw2), html);

        // Switch to gastgeber: two images, body and quote kept.
        let u3 = f.h.ok(&f.drafter, "update_draft", up(&u2["revision"], json!({ "signature": "gastgeber" }))).await;
        let raw = f.draft(account, &json!({ "draft_id": c["draft_id"], "revision": u3["revision"] }));
        assert_eq!(kinds(&raw), related(&["image/jpeg", "image/png"]));
        let text = text_of(&raw);
        assert!(text.starts_with("Zweiter Entwurf.\n\n-- \nHerzliche Grüße"), "{text}");
        assert!(text.contains("wrote:"), "{text}");

        // Drop it: plain text, quote kept.
        let u4 = f.h.ok(&f.drafter, "update_draft", up(&u3["revision"], json!({ "signature": false }))).await;
        let raw = f.draft(account, &json!({ "draft_id": c["draft_id"], "revision": u4["revision"] }));
        assert_eq!(kinds(&raw), [(0, "text/plain".to_string())]);
        let text = text_of(&raw);
        assert!(text.starts_with("Zweiter Entwurf.\n\n"), "{text}");
        assert!(!text.contains("-- \n") && text.contains("> Bitte"), "{text}");
        let d = f.h.ok(&f.drafter, "get_draft", json!({ "account": account, "draft_id": c["draft_id"] })).await;
        assert_eq!(d["composition"]["signature"], Value::Null);
        assert_eq!(d["composition"]["quote_or_forward_below"], true);

        // Back to the default, then the signature is deleted: a body change asks for a decision.
        let u5 = f.h.ok(&f.drafter, "update_draft", up(&u4["revision"], json!({ "signature": true }))).await;
        f.h.ok(&f.writer, "delete_signature", json!({ "account": account, "name": "behoerden" })).await;
        let (err, v) =
            f.h.call(&f.drafter, "update_draft", up(&u5["revision"], json!({ "body_text": "Dritter." }))).await;
        assert!(err);
        assert_eq!(v["error"]["details"]["field"], "changes.signature", "{v}");
        f.h.ok(
            &f.drafter,
            "update_draft",
            up(&u5["revision"], json!({ "body_text": "Dritter.", "signature": "gastgeber" })),
        )
        .await;
    }
}

#[tokio::test]
async fn a_draft_edited_elsewhere_is_not_reassembled() {
    let f = fx().await;
    f.two_signatures("box").await;
    let c = f.h.ok(&f.drafter, "create_draft", create("box")).await;
    // Dove's record no longer fits the text (as after an edit Dove could not see): the update is a conflict.
    let did = c["draft_id"].as_str().unwrap().to_string();
    f.h.app()
        .store
        .call(move |c| {
            Ok(c.execute(
                "UPDATE own_drafts SET composition = '{\"signature\":\"behoerden\",\"body\":3,\"sig\":40}' WHERE draft_id = ?1",
                [did],
            )?)
        })
        .await
        .unwrap();
    let (err, v) =
        f.h.call(
            &f.drafter,
            "update_draft",
            json!({ "account": "box", "draft_id": c["draft_id"], "expected_revision": c["revision"],
                    "changes": { "body_text": "Neu" } }),
        )
        .await;
    assert!(err);
    assert_eq!(v["error"]["code"], "draft_conflict", "{v}");
}

// ------------------------------------------------------------------ management

#[tokio::test]
async fn set_signature_validates_its_input() {
    let f = fx().await;
    let set = |args: Value| {
        let mut a = json!({ "account": "box", "name": "x" });
        a.as_object_mut().unwrap().extend(args.as_object().unwrap().clone());
        a
    };
    let logo = json!([{ "cid": "logo", "data_base64": b64(&png()) }]);
    for (args, field) in [
        (json!({ "html": "<img src=\"http://track.example/p.png\">" }), "signature"),
        (json!({ "html": "<img src=\"cid:logo\">" }), "signature"),
        (json!({ "html": "<b>x</b>", "images": logo }), "signature"),
        (
            json!({ "html": "<img src=\"cid:logo\">", "images": [{ "cid": "logo", "data_base64": b64(b"<svg onload=x>") }] }),
            "images[0]",
        ),
        (
            json!({ "html": "<img src=\"cid:logo\">", "images": [{ "cid": "logo", "data_base64": b64(&png()), "mime_type": "image/gif" }] }),
            "images[0]",
        ),
        (json!({ "html": "<script>x</script>" }), "signature"),
        (json!({ "text": "x", "for_address": "a@example.org" }), "for_address"),
        (json!({ "name": "Groß", "text": "x" }), "name"),
        (json!({}), "signature"),
    ] {
        let (err, v) = f.h.call(&f.writer, "set_signature", set(args.clone())).await;
        assert!(err, "{args}");
        assert_eq!(v["error"]["code"], "invalid_argument", "{args}: {v}");
        assert_eq!(v["error"]["details"]["field"], field, "{args}: {v}");
    }
    let too_big = vec![0x47u8; 600 * 1024];
    let (err, _) =
        f.h.call(
            &f.writer,
            "set_signature",
            set(json!({ "html": "<img src=\"cid:a\">", "images": [{ "cid": "a", "data_base64": b64(&too_big) }] })),
        )
        .await;
    assert!(err);
    let none: i64 =
        f.h.app().store.call(|c| Ok(c.query_row("SELECT count(*) FROM signatures", [], |r| r.get(0))?)).await.unwrap();
    assert_eq!(none, 0);

    // Text only, then HTML added later; text derived from the HTML only when not given.
    let r = f.h.ok(&f.writer, "set_signature", set(json!({ "text": "Nur Text" }))).await;
    assert_eq!(r["has_html"], false);
    f.h.ok(&f.writer, "set_signature", set(json!({ "html": "<p>Mit <b>HTML</b></p>" }))).await;
    let l = f.h.ok(&f.drafter, "list_signatures", json!({ "account": "box", "include_html": true })).await;
    assert_eq!(l["signatures"][0]["text"], "Mit HTML");
    assert_eq!(l["signatures"][0]["html"], "<p>Mit <b>HTML</b></p>");
    assert_eq!(l["signatures"][0]["default_for"], json!(["mailbox"]));
    let l = f.h.ok(&f.drafter, "list_signatures", json!({ "account": "box" })).await;
    assert!(l["signatures"][0].get("html").is_none());
}

#[tokio::test]
async fn defaults_follow_the_sender_and_make_default() {
    let f = fx().await;
    f.h.admin(AdminRequest::AccountsAliasAdd {
        account: "box".into(),
        address: "sales@example.org".into(),
        name: None,
        envelope: false,
    })
    .await
    .unwrap();
    f.two_signatures("box").await;
    let r =
        f.h.ok(
            &f.writer,
            "set_signature",
            json!({ "account": "box", "name": "gastgeber", "make_default": true, "for_address": "sales@example.org" }),
        )
        .await;
    assert_eq!(r["default"]["for_address"], "sales@example.org");
    let mut a = create("box");
    a["from_address"] = json!("sales@example.org");
    let raw = f.draft("box", &f.h.ok(&f.drafter, "create_draft", a).await);
    assert!(text_of(&raw).contains("Herzliche Grüße"));
    let raw = f.draft("box", &f.h.ok(&f.drafter, "create_draft", create("box")).await);
    assert!(text_of(&raw).contains("Keyset GmbH"));
    let l = f.h.ok(&f.drafter, "list_signatures", json!({ "account": "box" })).await;
    assert_eq!(l["signatures"][0]["name"], "behoerden");
    assert_eq!(l["signatures"][0]["default_for"], json!(["mailbox"]));
    assert_eq!(l["signatures"][1]["default_for"], json!(["sales@example.org"]));

    // Deleting the mailbox default leaves no signature, not another one.
    f.h.ok(&f.writer, "delete_signature", json!({ "account": "box", "name": "behoerden" })).await;
    let raw = f.draft("box", &f.h.ok(&f.drafter, "create_draft", create("box")).await);
    assert_eq!(kinds(&raw), [(0, "text/plain".to_string())]);
    assert_eq!(
        f.h.err(&f.writer, "delete_signature", json!({ "account": "box", "name": "behoerden" })).await,
        "invalid_argument"
    );
}

#[tokio::test]
async fn agent_changes_alert_the_owner_and_the_audit_holds_no_content() {
    let f = fx().await;
    f.two_signatures("box").await;
    f.h.ok(&f.writer, "set_signature", json!({ "account": "box", "name": "behoerden", "text": "Andere Zeile" })).await;
    let sent = f.h.app().notifier.sent.lock().unwrap().clone();
    let about: Vec<_> = sent.iter().filter(|m| m.contains("signature")).collect();
    // One alert per signature and day: behoerden twice changed, gastgeber once.
    assert_eq!(about.len(), 2, "{sent:?}");
    assert!(about[0].contains("'writer' changed signature 'behoerden' of mailbox 'box'"), "{about:?}");
    let pushes: i64 = f
        .h
        .app()
        .store
        .call(|c| Ok(c.query_row("SELECT count(*) FROM notifications WHERE key LIKE 'signature:%'", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(pushes, 2, "one dedup key per signature and day");
    f.h.ok(&f.drafter, "create_draft", create("box")).await;
    let hits: i64 =
        f.h.app()
            .store
            .call(|c| {
                Ok(c.query_row(
                    "SELECT count(*) FROM audit WHERE instr(object_ids || coalesce(query_hash, ''), 'Dominik') > 0 \
                 OR instr(object_ids, 'Andere') > 0 OR instr(object_ids, 'keyset.cloud') > 0",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
    assert_eq!(hits, 0);
    let named: i64 = f
        .h
        .app()
        .store
        .call(|c| {
            Ok(c.query_row(
                "SELECT count(*) FROM audit WHERE tool_or_action = 'set_signature' AND object_ids = '[\"signature:behoerden\"]'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(named, 2);
}

#[tokio::test]
async fn operator_verbs_manage_named_signatures() {
    let f = fx().await;
    let put = AdminRequest::AccountsSignaturePut {
        account: "box".into(),
        name: "behoerden".into(),
        html: Some(BEHOERDEN.into()),
        text: None,
        images: Some(vec![SignatureImage { cid: "keyset-logo".into(), mime_type: None, data_base64: b64(&png()) }]),
    };
    let r = f.h.admin(put).await.unwrap();
    assert_eq!(r["became_default"], true);
    f.h.admin(AdminRequest::AccountsSignaturePut {
        account: "box".into(),
        name: "kurz".into(),
        html: None,
        text: Some("D. L.".into()),
        images: None,
    })
    .await
    .unwrap();
    let l =
        f.h.admin(AdminRequest::AccountsSignaturesList { account: "box".into(), include_html: false }).await.unwrap();
    assert_eq!(l["signatures"].as_array().unwrap().len(), 2);
    assert_eq!(l["signatures"][0]["images"][0]["cid"], "keyset-logo");
    assert_eq!(l["signatures"][0]["updated_by"], "operator");

    // The plain-text verb edits the default's text and keeps its HTML.
    f.h.admin(AdminRequest::AccountsSignatureSet { account: "box".into(), alias: None, signature: Some("Neu".into()) })
        .await
        .unwrap();
    let l =
        f.h.admin(AdminRequest::AccountsSignaturesList { account: "box".into(), include_html: true }).await.unwrap();
    assert_eq!(l["signatures"][0]["text"], "Neu");
    assert!(l["signatures"][0]["html"].as_str().unwrap().contains("Dominik Lenhart"));

    f.h.admin(AdminRequest::AccountsSignatureDefault { account: "box".into(), alias: None, name: Some("kurz".into()) })
        .await
        .unwrap();
    let raw = f.draft("box", &f.h.ok(&f.drafter, "create_draft", create("box")).await);
    assert_eq!(text_of(&raw), "Guten Tag,\nanbei die Unterlagen.\n\n-- \nD. L.\n");
    f.h.admin(AdminRequest::AccountsSignatureDefault { account: "box".into(), alias: None, name: None }).await.unwrap();
    let raw = f.draft("box", &f.h.ok(&f.drafter, "create_draft", create("box")).await);
    assert_eq!(kinds(&raw), [(0, "text/plain".to_string())]);
    assert!(
        f.h.admin(AdminRequest::AccountsSignatureDelete { account: "box".into(), name: "nope".into() }).await.is_err()
    );
    f.h.admin(AdminRequest::AccountsSignatureDelete { account: "box".into(), name: "kurz".into() }).await.unwrap();
    // A whole signature with its images fits through the admin socket.
    let big = AdminRequest::AccountsSignaturePut {
        account: "box".into(),
        name: "gross".into(),
        html: Some("<img src=\"cid:a\">".into()),
        text: Some("x".into()),
        images: Some(vec![SignatureImage {
            cid: "a".into(),
            mime_type: None,
            data_base64: b64(&[b"\x89PNG\r\n\x1a\n".as_slice(), &vec![1u8; 500 * 1024]].concat()),
        }]),
    };
    assert!(serde_json::to_vec(&big).unwrap().len() > 64 * 1024);
    f.h.admin(big).await.unwrap();
}
