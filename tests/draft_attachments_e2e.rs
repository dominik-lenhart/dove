//! Attachments, forwards and reply quoting in drafts (owner request 2026-11-12), for Gmail (fake Google) and IMAP
//! (fake IMAP/SMTP): attachment bytes by reference never pass through the agent and arrive unchanged in the stored
//! draft; limits are errors, never silent drops; sources need `read` (identical `not_found` otherwise, before any
//! upstream call); update keeps or replaces attachments; sending submits the stored bytes; the audit log holds no
//! filenames or content.

mod support;

use dove::mime;
use serde_json::{Value, json};
use support::fake_google::MessageSpec;
use support::fake_imap::encode_utf7;
use support::harness::{FakeImapUser, Harness, g};

const INFO: &str = "info@acme.test";
const BILLING: &str = "billing@acme.test";
const OPS: &str = "ops@acme.test";
const OUTSIDE: &str = "outside@acme.test";
const IMAP: &str = "box@example.org";

fn key() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn pdf() -> Vec<u8> {
    // Binary with every byte value, CR and LF included.
    (0..=255u8).cycle().take(70_000).collect()
}

struct Setup {
    h: Harness,
    /// info: read,draft,send; billing: read; ops: in the project, not granted. `outside` is not in the project.
    /// (Grants enforce draft => read, so "no read" always means "no grant".)
    token: String,
    /// IMAP mailbox `box` (read,draft,send) in the same project.
    u: FakeImapUser,
}

async fn setup_with(customize: impl FnOnce(&mut dove::config::Config)) -> Setup {
    let h = Harness::start_with(|c| {
        c.allow_send = true;
        customize(c)
    })
    .await;
    h.mailbox("info", INFO);
    h.mailbox("billing", BILLING);
    h.mailbox("ops", OPS);
    h.mailbox("outside", OUTSIDE);
    let u = h.imap_mailbox("box", IMAP).await;
    h.project("p", &["info", "billing", "ops", "box"]).await;
    h.project("other", &["outside"]).await;
    let token = h
        .token("p", "agent", vec![g("info", "read,draft,send"), g("billing", "read"), g("box", "read,draft,send")])
        .await;
    Setup { h, token, u }
}

async fn setup() -> Setup {
    setup_with(|_| {}).await
}

/// A Gmail message with two attachments; returns (message id, attachment ids).
fn gmail_message(h: &Harness, mailbox: &str, subject: &str) -> (String, Vec<String>) {
    let id = h.google.add_message(
        mailbox,
        MessageSpec {
            from: "jane@example.org".into(),
            to: vec![mailbox.into()],
            cc: vec!["cc@example.org".into()],
            subject: subject.into(),
            text: Some("Hallo,\n\nanbei die Unterlagen.\n".into()),
            internal_date_ms: 1_700_000_000_000,
            message_id_header: Some(format!("<orig-{subject}@example.org>")),
            attachments: vec![
                ("Vertrag.pdf".into(), "application/pdf".into(), pdf()),
                ("notes.txt".into(), "text/plain".into(), b"a\nb\r\nc".to_vec()),
            ],
            ..Default::default()
        },
    );
    let raw = h.google.message_raw(mailbox, &id).unwrap();
    let ids = mime::parse(&raw, &mime::Limits::default()).unwrap().attachments.into_iter().map(|a| a.attachment_id);
    (id, ids.collect())
}

/// An IMAP message with one attachment in INBOX; returns (agent message id, attachment id).
async fn imap_message(h: &Harness, u: &FakeImapUser) -> (String, String) {
    let raw = b"From: Jane <jane@example.org>\r\nTo: box@example.org\r\nSubject: Scan\r\n\
Message-ID: <scan@example.org>\r\nDate: Tue, 14 Nov 2023 22:13:20 +0000\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nSiehe Anhang.\r\n\
--b\r\nContent-Type: image/png\r\nContent-Disposition: attachment; filename=\"scan.png\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\nAAECAwQFBgcICQoNCg==\r\n--b--\r\n";
    let uid = h.imap.add_message(&u.user, "INBOX", raw, &[]);
    let id = imap_id(h, u, "INBOX", uid).await;
    (id, "part-2".into())
}

async fn imap_id(h: &Harness, u: &FakeImapUser, folder: &str, uid: u32) -> String {
    let (a, n) = (u.account_id.clone(), encode_utf7(folder));
    let fid: i64 = h
        .app()
        .store
        .call(move |c| {
            Ok(c.query_row("SELECT folder_id FROM imap_folders WHERE account_id = ?1 AND name = ?2", [a, n], |r| {
                r.get(0)
            })?)
        })
        .await
        .unwrap();
    format!("f{fid}-{}-{uid}", h.imap.uidvalidity(&u.user, folder))
}

fn uid_of(id: &str) -> u32 {
    id.rsplit('-').next().unwrap().parse().unwrap()
}

/// Stored bytes of a Gmail draft (by Dove draft id).
fn gmail_draft(h: &Harness, mailbox: &str, draft_id: &Value) -> Vec<u8> {
    h.google.draft_raw(mailbox, draft_id.as_str().unwrap()).unwrap()
}

fn attachments_of(raw: &[u8]) -> Vec<mime::DraftAttachment> {
    mime::read_draft_fields(raw).expect("a Dove-shaped draft").attachments
}

fn names(list: &[mime::DraftAttachment]) -> Vec<String> {
    list.iter().map(|a| format!("{}|{}", a.filename, a.mime_type)).collect()
}

/// Full structured error of a failing call.
async fn error(h: &Harness, token: &str, tool: &str, args: Value) -> Value {
    let (err, v) = h.call(token, tool, args).await;
    assert!(err, "{tool} unexpectedly succeeded: {v}");
    v["error"].clone()
}

// ------------------------------------------------------------------ references

#[tokio::test]
async fn gmail_attach_by_reference_roundtrips_bytes() {
    let Setup { h, token, .. } = setup().await;
    let (mid, parts) = gmail_message(&h, INFO, "Vertrag");
    let (bmid, bparts) = gmail_message(&h, BILLING, "Rechnung");
    let search_ref = dove::tools::make_ref(&account_id(&h, "billing").await, &bmid);
    let c = h
        .ok(
            &token,
            "create_draft",
            json!({ "account": "info", "request_key": key(), "to": ["a@example.net"], "subject": "Unterlagen",
                    "body_text": "Anbei.", "attachments": [
                        { "account": "info", "message_id": mid, "attachment_id": parts[0] },
                        { "ref": search_ref, "attachment_id": bparts[1] },
                    ] }),
        )
        .await;
    let raw = gmail_draft(&h, INFO, &c["draft_id"]);
    let atts = attachments_of(&raw);
    assert_eq!(names(&atts), ["Vertrag.pdf|application/pdf", "notes.txt|text/plain"]);
    assert_eq!(atts[0].bytes, pdf());
    assert_eq!(atts[1].bytes, b"a\nb\r\nc");
    let f = mime::read_draft_fields(&raw).unwrap();
    assert_eq!((f.subject.as_str(), f.body_text.trim_end()), ("Unterlagen", "Anbei."));
    // The draft is still Dove's to edit.
    let d = h.ok(&token, "get_draft", json!({ "account": "info", "draft_id": c["draft_id"] })).await;
    assert_eq!(d["editable_by_dove"], true, "{d}");
    assert_eq!(d["message"]["attachments"].as_array().unwrap().len(), 2);
    h.google.assert_no_violations();
}

async fn account_id(h: &Harness, alias: &str) -> String {
    let a = alias.to_string();
    h.app()
        .store
        .call(move |c| Ok(c.query_row("SELECT id FROM accounts WHERE alias = ?1", [a], |r| r.get(0))?))
        .await
        .unwrap()
}

#[tokio::test]
async fn imap_attach_by_reference_update_preserves_and_replaces() {
    let Setup { h, token, u } = setup().await;
    let (mid, part) = imap_message(&h, &u).await;
    let (gmid, gparts) = gmail_message(&h, INFO, "Vertrag");
    let c = h
        .ok(
            &token,
            "create_draft",
            json!({ "account": "box", "request_key": key(), "to": ["a@example.net"], "subject": "Scan",
                    "body_text": "Hier der Scan.", "attachments": [
                        { "account": "box", "message_id": mid, "attachment_id": part },
                        { "account": "info", "message_id": gmid, "attachment_id": gparts[0] },
                    ] }),
        )
        .await;
    let rev = c["revision"].as_str().unwrap().to_string();
    let stored = h.imap.message_raw(&u.user, "Drafts", uid_of(&rev)).unwrap();
    let atts = attachments_of(&stored);
    assert_eq!(names(&atts), ["scan.png|image/png", "Vertrag.pdf|application/pdf"]);
    assert_eq!(atts[0].bytes, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 10]);
    assert_eq!(atts[1].bytes, pdf());
    // Reading the source never marked it seen.
    assert!(h.imap.flags(&u.user, "INBOX", uid_of(&mid)).unwrap().is_empty());

    // A body change passes the fresh check (hash of the stored multipart) and keeps both attachments.
    let up = h
        .ok(
            &token,
            "update_draft",
            json!({ "account": "box", "draft_id": c["draft_id"], "expected_revision": rev,
                    "changes": { "body_text": "Neuer Text." } }),
        )
        .await;
    let rev2 = up["revision"].as_str().unwrap().to_string();
    let stored2 = h.imap.message_raw(&u.user, "Drafts", uid_of(&rev2)).unwrap();
    let f = mime::read_draft_fields(&stored2).unwrap();
    assert_eq!(f.body_text.trim_end(), "Neuer Text.");
    assert_eq!(f.attachments, atts);
    assert_eq!(h.imap.uids(&u.user, "Drafts"), vec![uid_of(&rev2)]);

    // changes.attachments replaces the whole list ...
    let up = h
        .ok(
            &token,
            "update_draft",
            json!({ "account": "box", "draft_id": c["draft_id"], "expected_revision": rev2, "changes": {
                "attachments": [{ "filename": "neu.txt", "mime_type": "text/plain", "content_base64": "bmV1Cg==" }] } }),
        )
        .await;
    let rev3 = up["revision"].as_str().unwrap().to_string();
    let f = mime::read_draft_fields(&h.imap.message_raw(&u.user, "Drafts", uid_of(&rev3)).unwrap()).unwrap();
    assert_eq!(names(&f.attachments), ["neu.txt|text/plain"]);
    assert_eq!((f.attachments[0].bytes.as_slice(), f.body_text.trim_end()), (&b"neu\n"[..], "Neuer Text."));
    // ... and [] removes them: a plain text draft again.
    let up = h
        .ok(
            &token,
            "update_draft",
            json!({ "account": "box", "draft_id": c["draft_id"], "expected_revision": rev3, "changes": { "attachments": [] } }),
        )
        .await;
    let raw4 = h.imap.message_raw(&u.user, "Drafts", uid_of(up["revision"].as_str().unwrap())).unwrap();
    assert!(mime::parse(&raw4, &mime::Limits::default()).unwrap().is_simple_text);

    // A draft saved by a mail client is human-owned as before: draft_conflict, nothing deleted.
    let c = h
        .ok(
            &token,
            "create_draft",
            json!({ "account": "box", "request_key": key(), "to": ["a@example.net"], "body_text": "x",
                    "attachments": [{ "account": "box", "message_id": mid, "attachment_id": part }] }),
        )
        .await;
    let rev = c["revision"].as_str().unwrap();
    let human = String::from_utf8(h.imap.message_raw(&u.user, "Drafts", uid_of(rev)).unwrap()).unwrap();
    h.imap.expunge_external(&u.user, "Drafts", uid_of(rev));
    let new_uid = h.imap.add_message(&u.user, "Drafts", human.replace("x\r\n", "edited\r\n").as_bytes(), &["\\Draft"]);
    let e = h
        .err(
            &token,
            "update_draft",
            json!({ "account": "box", "draft_id": c["draft_id"], "expected_revision": rev, "changes": { "body_text": "y" } }),
        )
        .await;
    assert_eq!(e, "draft_conflict");
    assert!(h.imap.uids(&u.user, "Drafts").contains(&new_uid));
    h.imap.assert_only_allowlisted();
}

#[tokio::test]
async fn gmail_update_preserves_and_replaces_attachments() {
    let Setup { h, token, .. } = setup().await;
    let (mid, parts) = gmail_message(&h, INFO, "Vertrag");
    let c = h
        .ok(
            &token,
            "create_draft",
            json!({ "account": "info", "request_key": key(), "to": ["a@example.net"], "subject": "S", "body_text": "eins",
                    "attachments": [{ "account": "info", "message_id": mid, "attachment_id": parts[0] }] }),
        )
        .await;
    let did = c["draft_id"].clone();
    let up = h
        .ok(
            &token,
            "update_draft",
            json!({ "account": "info", "draft_id": did, "expected_revision": c["revision"],
                    "changes": { "subject": "S2", "to": ["b@example.net"] } }),
        )
        .await;
    let f = mime::read_draft_fields(&gmail_draft(&h, INFO, &did)).unwrap();
    assert_eq!((f.subject.as_str(), f.to[0].email.as_str(), f.body_text.trim_end()), ("S2", "b@example.net", "eins"));
    assert_eq!(names(&f.attachments), ["Vertrag.pdf|application/pdf"]);
    assert_eq!(f.attachments[0].bytes, pdf());
    let up = h
        .ok(
            &token,
            "update_draft",
            json!({ "account": "info", "draft_id": did, "expected_revision": up["revision"], "changes": {
                "attachments": [{ "account": "info", "message_id": mid, "attachment_id": parts[1] },
                                { "filename": "b.bin", "mime_type": "application/octet-stream", "content_base64": "AAE=" }] } }),
        )
        .await;
    let f = mime::read_draft_fields(&gmail_draft(&h, INFO, &did)).unwrap();
    assert_eq!(names(&f.attachments), ["notes.txt|text/plain", "b.bin|application/octet-stream"]);
    assert_eq!(f.attachments[1].bytes, [0, 1]);
    // Changed outside Dove: draft_conflict as before.
    let raw = gmail_draft(&h, INFO, &did);
    h.google.replace_draft_externally(INFO, did.as_str().unwrap(), &raw);
    let e = h
        .err(
            &token,
            "update_draft",
            json!({ "account": "info", "draft_id": did, "expected_revision": up["revision"], "changes": { "body_text": "x" } }),
        )
        .await;
    assert_eq!(e, "draft_conflict");
}

// ------------------------------------------------------------------ inline, validation, limits

#[tokio::test]
async fn inline_attachments_are_validated_and_sanitized() {
    let Setup { h, token, .. } = setup().await;
    let create = |atts: Value| {
        json!({ "account": "info", "request_key": key(), "to": ["a@example.net"], "subject": "S", "body_text": "b",
                "attachments": atts })
    };
    let c = h
        .ok(
            &token,
            "create_draft",
            create(json!([
                { "filename": "../../etc/Rechnung\r\nBcc: evil@example.net.pdf", "mime_type": "Application/PDF",
                  "content_base64": dove::util::b64std(&pdf()) },
                { "filename": "\u{202e}fdp.exe", "mime_type": "application/octet-stream", "content_base64": "AA==" },
            ])),
        )
        .await;
    let raw = gmail_draft(&h, INFO, &c["draft_id"]);
    let atts = attachments_of(&raw);
    assert_eq!(
        names(&atts),
        ["etcRechnungBcc: evil@example.net.pdf|application/pdf", "fdp.exe|application/octet-stream"]
    );
    assert_eq!(atts[0].bytes, pdf());
    let p = mime::parse(&raw, &mime::Limits::default()).unwrap();
    assert!(p.bcc.is_empty() && p.to.len() == 1, "{p:?}");
    assert_eq!(mime::header_values(&raw, "bcc"), Vec::<String>::new());

    for (atts, code) in [
        (
            json!([{ "filename": "a", "mime_type": "text/plain\r\nBcc: x@example.net", "content_base64": "AA==" }]),
            "invalid_argument",
        ),
        (json!([{ "filename": "a", "mime_type": "multipart/mixed", "content_base64": "AA==" }]), "invalid_argument"),
        (
            json!([{ "filename": "a", "mime_type": "text/plain; charset=x", "content_base64": "AA==" }]),
            "invalid_argument",
        ),
        (json!([{ "filename": "a", "mime_type": "text/plain", "content_base64": "not base64!" }]), "invalid_argument"),
        (json!([{ "mime_type": "text/plain", "content_base64": "AA==" }]), "invalid_argument"),
        (
            json!([{ "filename": "a", "mime_type": "text/plain", "content_base64": "AA==", "account": "info" }]),
            "invalid_argument",
        ),
        (json!([{ "account": "info", "message_id": "m1" }]), "invalid_argument"),
        (json!({ "filename": "a" }), "invalid_argument"),
    ] {
        assert_eq!(h.err(&token, "create_draft", create(atts.clone())).await, code, "{atts}");
    }
    assert_eq!(h.google.drafts(INFO).len(), 1);
}

#[tokio::test]
async fn limits_are_errors_never_silent_drops() {
    let Setup { h, token, u } = setup_with(|c| c.limits.draft_attachment_bytes = 100_000).await;
    let (mid, parts) = gmail_message(&h, INFO, "Vertrag"); // 70_000 + 6 bytes
    let inline = |n: usize| json!({ "filename": "x.bin", "mime_type": "application/octet-stream", "content_base64": dove::util::b64std(&vec![7u8; n]) });
    let create = |account: &str, atts: Value| json!({ "account": account, "request_key": key(), "to": ["a@example.net"], "body_text": "b", "attachments": atts });
    // Count: 11 is refused, 10 is fine.
    let e = error(&h, &token, "create_draft", create("info", Value::Array((0..11).map(|_| inline(1)).collect()))).await;
    assert_eq!(e["code"], "invalid_argument", "{e}");
    h.ok(&token, "create_draft", create("info", Value::Array((0..10).map(|_| inline(1)).collect()))).await;
    // Total decoded bytes: inline alone, and inline plus a reference.
    let e = error(&h, &token, "create_draft", create("info", json!([inline(100_001)]))).await;
    assert_eq!((e["code"].as_str(), e["details"]["limit_bytes"].as_u64()), (Some("too_large"), Some(100_000)), "{e}");
    let r = json!({ "account": "info", "message_id": mid, "attachment_id": parts[0] });
    let e = error(&h, &token, "create_draft", create("info", json!([inline(40_000), r]))).await;
    assert_eq!(e["code"], "too_large", "{e}");
    let e = error(&h, &token, "create_draft", create("box", json!([r, r]))).await;
    assert_eq!(e["code"], "too_large", "{e}");
    h.ok(&token, "create_draft", create("info", json!([inline(29_000), r]))).await;
    assert_eq!(h.google.drafts(INFO).len(), 2);
    assert!(h.imap.uids(&u.user, "Drafts").is_empty());
}

#[tokio::test]
async fn body_limit_is_large_only_for_authenticated_drafters() {
    let Setup { h, token, .. } = setup_with(|c| {
        c.limits.body_bytes = 64 * 1024;
        c.limits.draft_attachment_bytes = 512 * 1024;
    })
    .await;
    assert_eq!(h.app().cfg.limits.draft_body_bytes(), 512 * 1024 / 3 * 4 + 4 + 2 * 1024 * 1024);
    let reader = h.token("p", "reader", vec![g("info", "read")]).await;
    let big = |n: usize| {
        json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "create_draft", "arguments": {
            "account": "info", "request_key": key(), "to": ["a@example.net"], "body_text": "b",
            "attachments": [{ "filename": "x.bin", "mime_type": "application/octet-stream",
                              "content_base64": dove::util::b64std(&vec![1u8; n]) }] } } })
    };
    // 400 KiB of attachment: far above body_bytes, fine for a token with draft.
    let r = h.post_mcp(Some(&token), big(400 * 1024), &[]).await;
    assert_eq!(r.status(), 200);
    let v: Value = r.json().await.unwrap();
    assert!(v["result"]["isError"].as_bool() != Some(true), "{v}");
    // A read-only token keeps the small limit.
    assert_eq!(h.post_mcp(Some(&reader), big(100 * 1024), &[]).await.status(), 413);
    // No token, a wrong token: refused before the body is read.
    assert_eq!(h.post_mcp(None, big(400 * 1024), &[]).await.status(), 401);
    assert_eq!(h.post_mcp(Some("dove_wrong"), big(400 * 1024), &[]).await.status(), 401);
    // Unauthenticated routes keep body_bytes.
    let r = h
        .http
        .post(format!("{}/oauth/dove/register", h.base))
        .header("host", support::harness::HOST)
        .header("content-type", "application/json")
        .body(vec![b' '; 100 * 1024])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413);
    // Even a drafter cannot exceed draft_body_bytes.
    assert_eq!(h.post_mcp(Some(&token), big(5 * 1024 * 1024 / 2), &[]).await.status(), 413);
    assert_eq!(h.google.drafts(INFO).len(), 1);
}

#[tokio::test]
async fn default_limits_take_a_large_inline_attachment() {
    let Setup { h, token, .. } = setup().await;
    let bytes: Vec<u8> = (0..9 * 1024 * 1024).map(|i: u32| (i % 251) as u8).collect();
    let c = h
        .ok(
            &token,
            "create_draft",
            json!({ "account": "info", "request_key": key(), "to": ["a@example.net"], "body_text": "groß",
                    "attachments": [{ "filename": "big.bin", "mime_type": "application/octet-stream",
                                      "content_base64": dove::util::b64std(&bytes) }] }),
        )
        .await;
    assert_eq!(attachments_of(&gmail_draft(&h, INFO, &c["draft_id"]))[0].bytes, bytes);
}

// ------------------------------------------------------------------ authorization

#[tokio::test]
async fn sources_without_read_are_not_found_without_upstream_calls() {
    let Setup { h, token, u } = setup().await;
    let (ops_mid, ops_parts) = gmail_message(&h, OPS, "intern");
    let (out_mid, out_parts) = gmail_message(&h, OUTSIDE, "fremd");
    let ops_ref = dove::tools::make_ref(&account_id(&h, "ops").await, &ops_mid);
    let out_ref = dove::tools::make_ref(&account_id(&h, "outside").await, &out_mid);
    // Has ops and box, but not info: the sources below are not readable for it.
    let drafter = h.token("p", "drafter", vec![g("ops", "read,draft")]).await;
    let (imap_mid, imap_part) = imap_message(&h, &u).await;
    h.google.clear_requests();
    h.imap.clear_commands();

    let unknown = error(
        &h,
        &token,
        "create_draft",
        json!({ "account": "info", "request_key": key(), "body_text": "b",
                "attachments": [{ "account": "nope", "message_id": "m1", "attachment_id": "part-2" }] }),
    )
    .await;
    assert_eq!(unknown["code"], "not_found");
    let cases = vec![
        (
            &token,
            json!({ "attachments": [{ "account": "ops", "message_id": ops_mid, "attachment_id": ops_parts[0] }] }),
        ),
        (&token, json!({ "attachments": [{ "ref": ops_ref, "attachment_id": ops_parts[0] }] })),
        (
            &token,
            json!({ "attachments": [{ "account": "outside", "message_id": out_mid, "attachment_id": out_parts[0] }] }),
        ),
        (
            &token,
            json!({ "attachments": [{ "account": OUTSIDE, "message_id": out_mid, "attachment_id": out_parts[0] }] }),
        ),
        (&token, json!({ "attachments": [{ "ref": out_ref, "attachment_id": out_parts[0] }] })),
        (&token, json!({ "attachments": [{ "ref": "m_garbage", "attachment_id": "part-2" }] })),
        (&token, json!({ "forward_ref": ops_ref })),
        (&token, json!({ "forward_ref": out_ref })),
        (
            &drafter,
            json!({ "attachments": [{ "account": "box", "message_id": imap_mid, "attachment_id": imap_part }] }),
        ),
        (&drafter, json!({ "forward_ref": dove::tools::make_ref(&u.account_id, &imap_mid) })),
        (&drafter, json!({ "attachments": [{ "account": "info", "message_id": "m1", "attachment_id": "part-2" }] })),
    ];
    for (t, extra) in cases {
        let account = if *t == drafter { "ops" } else { "info" };
        let mut args = json!({ "account": account, "request_key": key(), "body_text": "b" });
        for (k, v) in extra.as_object().unwrap() {
            args[k] = v.clone();
        }
        assert_eq!(error(&h, t, "create_draft", args.clone()).await, unknown, "{args}");
    }
    // Nothing reached Google or the IMAP server (not even the send-as lookup).
    assert!(h.google.requests().is_empty(), "{:?}", h.google.requests().iter().map(|r| &r.path).collect::<Vec<_>>());
    assert!(h.imap.commands().is_empty(), "{:?}", h.imap.commands());
    // The same for update_draft's changes.attachments.
    let c = h.ok(&drafter, "create_draft", json!({ "account": "ops", "request_key": key(), "body_text": "b" })).await;
    h.google.clear_requests();
    let e = error(
        &h,
        &drafter,
        "update_draft",
        json!({ "account": "ops", "draft_id": c["draft_id"], "expected_revision": c["revision"], "changes": {
            "attachments": [{ "account": "box", "message_id": imap_mid, "attachment_id": imap_part }] } }),
    )
    .await;
    assert_eq!(e, unknown);
    // The update made no upstream call either.
    assert!(h.google.requests().is_empty(), "{:?}", h.google.requests().iter().map(|r| &r.path).collect::<Vec<_>>());
    assert!(h.imap.commands().is_empty(), "{:?}", h.imap.commands());
}

// ------------------------------------------------------------------ forward

#[tokio::test]
async fn forward_includes_header_block_text_and_attachments() {
    let Setup { h, token, u } = setup().await;
    let (mid, _) = gmail_message(&h, BILLING, "Rechnung 42");
    let fref = dove::tools::make_ref(&account_id(&h, "billing").await, &mid);
    // Cross-mailbox: read on billing, draft on info.
    let c = h
        .ok(
            &token,
            "create_draft",
            json!({ "account": "info", "request_key": key(), "to": ["buchhaltung@example.net"], "body_text": "Zur Info.",
                    "forward_ref": fref }),
        )
        .await;
    let f = mime::read_draft_fields(&gmail_draft(&h, INFO, &c["draft_id"])).unwrap();
    assert_eq!(f.subject, "Fwd: Rechnung 42");
    assert_eq!(
        f.body_text,
        "Zur Info.\n\n---------- Forwarded message ---------\nFrom: jane@example.org\n\
Date: Tue, 14 Nov 2023 22:13:20 +0000\nSubject: Rechnung 42\nTo: billing@acme.test\nCc: cc@example.org\n\n\
Hallo,\n\nanbei die Unterlagen.\n"
    );
    assert!(f.in_reply_to.is_none() && f.references.is_empty());
    assert_eq!(names(&f.attachments), ["Vertrag.pdf|application/pdf", "notes.txt|text/plain"]);
    assert_eq!(f.attachments[0].bytes, pdf());

    // include_attachments: false forwards the text only; a subject may be given.
    let c = h
        .ok(
            &token,
            "create_draft",
            json!({ "account": "info", "request_key": key(), "body_text": "", "subject": "Kurz",
                    "forward_ref": dove::tools::make_ref(&account_id(&h, "billing").await, &mid), "include_attachments": false }),
        )
        .await;
    let f = mime::read_draft_fields(&gmail_draft(&h, INFO, &c["draft_id"])).unwrap();
    assert_eq!(f.subject, "Kurz");
    assert!(f.attachments.is_empty() && f.body_text.starts_with("---------- Forwarded message"));

    // IMAP source into an IMAP draft, plus an extra inline file after the original's attachment.
    let (imid, _) = imap_message(&h, &u).await;
    let c = h
        .ok(
            &token,
            "create_draft",
            json!({ "account": "box", "request_key": key(), "body_text": "s.u.", "forward_message_id": imid,
                    "attachments": [{ "filename": "x.txt", "mime_type": "text/plain", "content_base64": "eA==" }] }),
        )
        .await;
    let stored = h.imap.message_raw(&u.user, "Drafts", uid_of(c["revision"].as_str().unwrap())).unwrap();
    let f = mime::read_draft_fields(&stored).unwrap();
    assert_eq!(f.subject, "Fwd: Scan");
    assert!(f.body_text.contains("From: Jane <jane@example.org>\n") && f.body_text.ends_with("Siehe Anhang.\n"));
    assert_eq!(names(&f.attachments), ["scan.png|image/png", "x.txt|text/plain"]);

    // Reply and forward together are refused; include_attachments without a forward too.
    let both = json!({ "account": "info", "request_key": key(), "body_text": "b", "forward_ref": fref, "reply_to_message_id": mid });
    assert_eq!(h.err(&token, "create_draft", both).await, "invalid_argument");
    let stray = json!({ "account": "info", "request_key": key(), "body_text": "b", "include_attachments": false });
    assert_eq!(h.err(&token, "create_draft", stray).await, "invalid_argument");
}

#[tokio::test]
async fn forward_over_the_limit_is_a_clear_error() {
    let Setup { h, token, .. } = setup_with(|c| c.limits.draft_attachment_bytes = 50_000).await;
    let (mid, _) = gmail_message(&h, INFO, "gross");
    let args = |inc: Option<bool>| {
        let mut a = json!({ "account": "info", "request_key": key(), "body_text": "b", "forward_message_id": mid });
        if let Some(i) = inc {
            a["include_attachments"] = json!(i);
        }
        a
    };
    let e = error(&h, &token, "create_draft", args(None)).await;
    assert_eq!(e["code"], "too_large", "{e}");
    assert!(e["message"].as_str().unwrap().contains("include_attachments: false"), "{e}");
    assert_eq!(e["details"]["limit_bytes"], 50_000);
    assert!(h.google.drafts(INFO).is_empty());
    h.ok(&token, "create_draft", args(Some(false))).await;
    // Too many attachments in the original: also an error, not a cut list.
    let many = h.google.add_message(
        INFO,
        MessageSpec {
            from: "a@example.org".into(),
            subject: "viele".into(),
            text: Some("t".into()),
            attachments: (0..11).map(|i| (format!("{i}.txt"), "text/plain".into(), b"x".to_vec())).collect(),
            ..Default::default()
        },
    );
    let mut a = args(None);
    a["forward_message_id"] = json!(many);
    let e = error(&h, &token, "create_draft", a).await;
    assert_eq!(e["code"], "invalid_argument", "{e}");
    assert_eq!(h.google.drafts(INFO).len(), 1);
}

// ------------------------------------------------------------------ reply quoting

#[tokio::test]
async fn reply_quotes_original_below_the_text() {
    let Setup { h, token, .. } = setup().await;
    let (mid, _) = gmail_message(&h, INFO, "Frage");
    let reply = |extra: Value| {
        let mut a = json!({ "account": "info", "request_key": key(), "to": ["jane@example.org"], "body_text": "Gerne.",
                            "reply_to_message_id": mid });
        for (k, v) in extra.as_object().unwrap() {
            a[k] = v.clone();
        }
        a
    };
    let c = h.ok(&token, "create_draft", reply(json!({}))).await;
    let f = mime::read_draft_fields(&gmail_draft(&h, INFO, &c["draft_id"])).unwrap();
    assert_eq!(
        f.body_text,
        "Gerne.\n\nOn Tue, 14 Nov 2023 22:13:20 +0000, jane@example.org wrote:\n> Hallo,\n>\n\
> anbei die Unterlagen.\n"
    );
    assert_eq!(f.subject, "Re: Frage");
    assert_eq!(f.in_reply_to.as_deref(), Some("<orig-Frage@example.org>"));
    assert_eq!(f.references, ["<orig-Frage@example.org>"]);
    // Quoting never carries the original's attachments.
    assert!(f.attachments.is_empty());

    let c = h.ok(&token, "create_draft", reply(json!({ "quote_original": false }))).await;
    assert_eq!(mime::read_draft_fields(&gmail_draft(&h, INFO, &c["draft_id"])).unwrap().body_text.trim_end(), "Gerne.");

    // quote_original only for replies.
    let e = h
        .err(
            &token,
            "create_draft",
            json!({ "account": "info", "request_key": key(), "body_text": "b", "quote_original": true }),
        )
        .await;
    assert_eq!(e, "invalid_argument");
}

#[tokio::test]
async fn reply_quote_is_bounded_and_stays_out_of_headers() {
    let Setup { h, token, u } = setup().await;
    let line = "Zeile mit etwas Text, die sich oft wiederholt.\r\n";
    let raw = format!(
        "From: =?utf-8?q?Eve=0D=0ABcc=3A_x=40evil=2Eexample?= <eve@example.org>\r\nTo: box@example.org\r\n\
Subject: =?utf-8?q?Hallo=0D=0ABcc=3A_y=40evil=2Eexample?=\r\nMessage-ID: <long@example.org>\r\n\
Date: Tue, 14 Nov 2023 22:13:20 +0000\r\n\r\n{}",
        line.repeat(10_000)
    );
    let uid = h.imap.add_message(&u.user, "INBOX", raw.as_bytes(), &[]);
    let mid = imap_id(&h, &u, "INBOX", uid).await;
    let c = h
        .ok(
            &token,
            "create_draft",
            json!({ "account": "box", "request_key": key(), "to": ["eve@example.org"], "body_text": "Antwort",
                    "reply_to_message_id": mid }),
        )
        .await;
    let stored = h.imap.message_raw(&u.user, "Drafts", uid_of(c["revision"].as_str().unwrap())).unwrap();
    let p = mime::parse(&stored, &mime::Limits::default()).unwrap();
    // Headers: exactly the one recipient, no Bcc, a one-line subject.
    assert!(p.bcc.is_empty() && p.cc.is_empty() && p.to.len() == 1, "{p:?}");
    assert!(mime::header_values(&stored, "bcc").is_empty());
    let subject = p.subject.clone().unwrap();
    assert!(subject.starts_with("Re: Hallo") && !subject.contains('\n') && !subject.contains('\r'), "{subject:?}");
    let body = mime::read_draft_fields(&stored).unwrap().body_text;
    assert!(
        body.starts_with(
            "Antwort\n\nOn Tue, 14 Nov 2023 22:13:20 +0000, Eve Bcc: x@evil.example <eve@example.org> wrote:\n"
        ),
        "{}",
        &body[..200]
    );
    let quoted = body.lines().filter(|l| l.starts_with("> ")).count();
    assert!(quoted > 1000 && body.len() < dove::tools::compose::QUOTE_MAX_BYTES + 10_000, "{}", body.len());
    assert!(body.trim_end().ends_with("> [...]"));
}

// ------------------------------------------------------------------ idempotency, send, audit

#[tokio::test]
async fn request_key_covers_attachment_content() {
    let Setup { h, token, .. } = setup().await;
    let k = key();
    let args = |b64: &str| {
        json!({ "account": "info", "request_key": k, "body_text": "b",
                "attachments": [{ "filename": "a.txt", "mime_type": "text/plain", "content_base64": b64 }] })
    };
    let first = h.ok(&token, "create_draft", args("YQ==")).await;
    assert_eq!(h.ok(&token, "create_draft", args("YQ==")).await["draft_id"], first["draft_id"]);
    assert_eq!(h.err(&token, "create_draft", args("Yg==")).await, "invalid_argument");
    assert_eq!(h.google.drafts(INFO).len(), 1);
}

#[tokio::test]
async fn sending_submits_the_stored_bytes() {
    let Setup { h, token, u } = setup().await;
    let (mid, parts) = gmail_message(&h, INFO, "Vertrag");
    let att = json!([{ "account": "info", "message_id": mid, "attachment_id": parts[0] }]);
    // Gmail: the sent message is the stored draft, byte for byte.
    let c = h
        .ok(
            &token,
            "create_draft",
            json!({ "account": "info", "request_key": key(), "to": ["a@example.net"], "bcc": ["h@example.net"],
                    "body_text": "b", "attachments": att }),
        )
        .await;
    let stored = gmail_draft(&h, INFO, &c["draft_id"]);
    h.ok(
        &token,
        "send_draft",
        json!({ "account": "info", "draft_id": c["draft_id"], "expected_revision": c["revision"] }),
    )
    .await;
    let sent = h.google.sent_messages(INFO);
    assert_eq!(sent.len(), 1);
    assert_eq!(h.google.message_raw(INFO, &sent[0]).unwrap(), stored);

    // IMAP: SMTP gets the stored bytes without Bcc; the Sent copy keeps them all.
    let c = h
        .ok(
            &token,
            "create_draft",
            json!({ "account": "box", "request_key": key(), "to": ["a@example.net"], "bcc": ["h@example.net"],
                    "body_text": "b", "attachments": att }),
        )
        .await;
    let rev = c["revision"].as_str().unwrap();
    let stored = h.imap.message_raw(&u.user, "Drafts", uid_of(rev)).unwrap();
    assert_eq!(attachments_of(&stored)[0].bytes, pdf());
    h.ok(&token, "send_draft", json!({ "account": "box", "draft_id": c["draft_id"], "expected_revision": rev })).await;
    let mails = h.imap.sent_mails();
    assert_eq!(mails.len(), 1);
    let mut expected = mime::without_header(&stored, "Bcc");
    if !expected.ends_with(b"\r\n") {
        expected.extend_from_slice(b"\r\n");
    }
    assert_eq!(mails[0].data, expected);
    assert_eq!(mails[0].rcpts, ["a@example.net", "h@example.net"]);
    let sent_uids = h.imap.uids(&u.user, "Sent");
    assert_eq!(h.imap.message_raw(&u.user, "Sent", sent_uids[0]).unwrap(), stored);
}

#[tokio::test]
async fn audit_records_hold_no_filenames_or_content() {
    let Setup { h, token, u } = setup().await;
    let (mid, parts) = gmail_message(&h, INFO, "Geheimprojekt");
    let (imid, ipart) = imap_message(&h, &u).await;
    let before = h.audit_count().await;
    let c = h
        .ok(
            &token,
            "create_draft",
            json!({ "account": "info", "request_key": key(), "to": ["secret-recipient@example.net"], "body_text": "b",
                    "forward_message_id": mid,
                    "attachments": [{ "filename": "Kündigung-Meier.pdf", "mime_type": "application/pdf", "content_base64": "JVBERg==" },
                                    { "account": "box", "message_id": imid, "attachment_id": ipart }] }),
        )
        .await;
    h.ok(
        &token,
        "update_draft",
        json!({ "account": "info", "draft_id": c["draft_id"], "expected_revision": c["revision"],
                "changes": { "attachments": [{ "account": "info", "message_id": mid, "attachment_id": parts[1] }] } }),
    )
    .await;
    // One record per call, failed calls included.
    let e = h
        .err(
            &token,
            "create_draft",
            json!({ "account": "info", "request_key": key(), "body_text": "b",
                    "attachments": [{ "filename": "Abmahnung.pdf", "mime_type": "bad type", "content_base64": "AA==" }] }),
        )
        .await;
    assert_eq!(e, "invalid_argument");
    assert_eq!(h.audit_count().await, before + 3);
    let rows: Vec<String> = h
        .app()
        .store
        .call(|c| {
            let mut st = c.prepare("SELECT * FROM audit")?;
            let n = st.column_count();
            let rows = st.query_map([], |r| {
                let cell = |i| match r.get::<_, rusqlite::types::Value>(i) {
                    Ok(rusqlite::types::Value::Text(t)) => t,
                    Ok(rusqlite::types::Value::Blob(b)) => String::from_utf8_lossy(&b).into_owned(),
                    Ok(v) => format!("{v:?}"),
                    Err(e) => format!("{e}"),
                };
                Ok((0..n).map(cell).collect::<Vec<_>>().join("|"))
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
        .await
        .unwrap();
    let all = rows.join("\n");
    for needle in [
        "Kündigung",
        "Meier",
        "Vertrag",
        "notes.txt",
        "scan.png",
        "Abmahnung",
        "Geheimprojekt",
        "secret-recipient",
        "jane@",
        "JVBERg",
    ] {
        assert!(!all.contains(needle), "audit contains {needle}: {all}");
    }
    // Ids and size classes are fine: the forwarded message id and the attachment count/class are recorded.
    assert!(all.contains(&mid) && all.contains("attachments:4") && all.contains("attachments<1MiB"), "{all}");
}
