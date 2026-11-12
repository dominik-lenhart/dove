//! Provider-neutral reads on IMAP mailboxes and `get_attachment` on both providers (design "Identifiers",
//! "Attachment reads"). IMAP runs against the fake server; nothing here may set `\Seen`.

mod support;

use base64::Engine;
use serde_json::{Value, json};
use support::fake_google::MessageSpec;
use support::harness::{FakeImapUser, Harness, g};

const PDF: &str = "application/pdf";

fn bytes(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(7).wrapping_add(i / 251)) as u8).collect()
}

/// A multipart message with a text body and the given attachments (filename header value, bytes).
fn mail(subject: &str, mid: &str, extra_headers: &str, atts: &[(&str, &[u8])]) -> Vec<u8> {
    let mut m = format!(
        "From: Ann <ann@example.org>\r\nTo: info@example.org\r\nSubject: {subject}\r\nMessage-ID: <{mid}>\r\n\
         {extra_headers}Date: Thu, 01 Jan 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\
         Please find the invoice attached.\r\n"
    );
    for (name, data) in atts {
        let b64 = base64::engine::general_purpose::STANDARD.encode(data);
        m.push_str(&format!(
            "--b1\r\nContent-Type: {PDF}; name=\"{name}\"\r\nContent-Disposition: attachment; filename=\"{name}\"\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n"
        ));
        for chunk in b64.as_bytes().chunks(76) {
            m.push_str(std::str::from_utf8(chunk).unwrap());
            m.push_str("\r\n");
        }
    }
    m.push_str("--b1--\r\n");
    m.into_bytes()
}

async fn folder_id(h: &Harness, account_id: &str, name: &str) -> i64 {
    let (a, n) = (account_id.to_string(), name.to_string());
    h.app()
        .store
        .call(move |c| {
            Ok(c.query_row("SELECT folder_id FROM imap_folders WHERE account_id = ?1 AND name = ?2", [a, n], |r| {
                r.get(0)
            })?)
        })
        .await
        .unwrap()
}

/// Agent-visible id of a fake message; `folder` is the UTF-8 name (the fake's API), the store keeps the wire name.
async fn imap_id(h: &Harness, u: &FakeImapUser, folder: &str, uid: u32) -> String {
    let f = folder_id(h, &u.account_id, &support::fake_imap::encode_utf7(folder)).await;
    format!("f{f}-{}-{uid}", h.imap.uidvalidity(&u.user, folder))
}

struct Setup {
    h: Harness,
    u: FakeImapUser,
    token: String,
}

async fn setup_with(customize: impl FnOnce(&mut dove::config::Config)) -> Setup {
    let h = Harness::start_with(customize).await;
    let u = h.imap_mailbox("info", "info@example.org").await;
    h.mailbox("gm", "gm@example.com");
    h.project("p", &["info", "gm"]).await;
    let token = h.token("p", "agent", vec![g("info", "read"), g("gm", "read")]).await;
    Setup { h, u, token }
}

async fn setup() -> Setup {
    setup_with(|_| {}).await
}

/// Full `tools/call` result (content items included).
async fn call_raw(h: &Harness, token: &str, tool: &str, args: Value) -> Value {
    h.rpc(token, "tools/call", json!({ "name": tool, "arguments": args })).await["result"].clone()
}

#[tokio::test]
async fn imap_get_message_shape() {
    let Setup { h, u, token } = setup().await;
    let uid = h.imap.add_message(&u.user, "INBOX", &mail("Rechnung 42", "a1@example.org", "", &[]), &[]);
    let id = imap_id(&h, &u, "INBOX", uid).await;
    let v = h.ok(&token, "get_message", json!({ "account": "info", "message_id": id })).await;
    let m = &v["message"];
    assert_eq!(m["message_id"], id.as_str());
    assert_eq!(m["subject"], "Rechnung 42");
    assert_eq!(m["is_unread"], true);
    assert_eq!(m["is_starred"], false);
    assert!(m["body_text"].as_str().unwrap().contains("invoice attached"));
    assert_eq!(m["labels"], json!(["INBOX", "UNREAD"]));
    assert!(m["thread_id"].as_str().unwrap().starts_with('t'));
    // INTERNALDATE (the fake's default), not the Date header.
    assert!(m["received_at"].as_str().unwrap().starts_with("2026-01-01T00:00:00"), "{}", m["received_at"]);
    // Reading never marks the message as read: the folder is opened read-only and bodies use BODY.PEEK.
    assert!(!h.imap.flags(&u.user, "INBOX", uid).unwrap().iter().any(|f| f == "\\Seen"));
    let verbs: Vec<String> = h.imap.commands().iter().map(|c| support::fake_imap::verb_of(c)).collect();
    assert!(verbs.iter().any(|v| v == "EXAMINE") && !verbs.iter().any(|v| v == "SELECT"), "{verbs:?}");
    h.imap.assert_only_allowlisted();

    // The ref from the shape resolves to the same message; flags map to labels.
    h.imap.set_flags(&u.user, "INBOX", uid, &["\\Seen", "\\Flagged"], &[]);
    let r = m["ref"].as_str().unwrap();
    let v = h.ok(&token, "get_message", json!({ "ref": r })).await;
    assert_eq!(v["message"]["labels"], json!(["INBOX", "STARRED"]));
    assert_eq!(v["message"]["is_unread"], false);

    // Malformed, unknown and stale ids are the same not_found.
    let unknown = h.call(&token, "get_message", json!({ "account": "info", "message_id": "f1-1-999" })).await.1;
    for bad in ["f99-1-1", "garbage", &format!("{id}9")] {
        let e = h.call(&token, "get_message", json!({ "account": "info", "message_id": bad })).await.1;
        assert_eq!(e, unknown, "{bad}");
    }
    // Gmail-only paths stop at the provider instead of touching the vault or Google (Task 4: the live Gmail source
    // refuses a named IMAP mailbox outright).
    let (_, v) =
        h.call(&token, "search_messages", json!({ "accounts": ["info"], "source": "gmail", "gmail_query": "x" })).await;
    assert_eq!(v["error"]["code"], "invalid_argument", "{v}");
    h.imap.set_uidvalidity(&u.user, "INBOX", 77);
    let e = h.call(&token, "get_message", json!({ "account": "info", "message_id": id })).await.1;
    assert_eq!(e, unknown);
    assert_eq!(e["error"]["code"], "not_found");
}

#[tokio::test]
async fn imap_list_labels_are_folders() {
    let Setup { h, u, token } = setup().await;
    // A folder created after connect shows up, with its UTF-8 name.
    h.imap.add_folder(&u.user, "Kundenübersicht", None);
    let v = h.ok(&token, "list_labels", json!({ "account": "info" })).await;
    let labels = v["labels"].as_array().unwrap();
    let folders: Vec<&str> =
        labels.iter().filter(|l| l["type"] == "folder").map(|l| l["name"].as_str().unwrap()).collect();
    for f in ["INBOX", "Drafts", "Sent", "Junk", "Trash", "Kundenübersicht"] {
        assert!(folders.contains(&f), "{f} in {folders:?}");
    }
    let drafts = labels.iter().find(|l| l["name"] == "Drafts").unwrap();
    assert_eq!(drafts["special_use"], "drafts");
    let system: Vec<&str> =
        labels.iter().filter(|l| l["type"] == "system").map(|l| l["id"].as_str().unwrap()).collect();
    assert!(system.contains(&"UNREAD") && system.contains(&"SPAM") && system.contains(&"TRASH"));
    // The new folder got a stable id: a message in it is readable with its folder label.
    let uid = h.imap.add_message(&u.user, "Kundenübersicht", &mail("Hallo", "k1@example.org", "", &[]), &["\\Seen"]);
    let id = imap_id(&h, &u, "Kundenübersicht", uid).await;
    let v = h.ok(&token, "get_message", json!({ "account": "info", "message_id": id })).await;
    assert_eq!(v["message"]["labels"], json!(["Kundenübersicht"]));
    // Junk and Trash map to the Gmail system labels the default search excludes.
    let uid = h.imap.add_message(&u.user, "Junk", &mail("Spam", "s1@example.org", "", &[]), &[]);
    let id = imap_id(&h, &u, "Junk", uid).await;
    let v = h.ok(&token, "get_message", json!({ "account": "info", "message_id": id })).await;
    assert_eq!(v["message"]["labels"], json!(["Junk", "UNREAD", "SPAM"]));
}

#[tokio::test]
async fn imap_get_thread_without_index_is_single_with_marker() {
    let Setup { h, u, token } = setup().await;
    let a = h.imap.add_message(&u.user, "INBOX", &mail("Frage", "root@example.org", "", &[]), &[]);
    let reply = mail(
        "Re: Frage",
        "reply@example.org",
        "In-Reply-To: <root@example.org>\r\nReferences: <root@example.org>\r\n",
        &[],
    );
    let b = h.imap.add_message(&u.user, "Sent", &reply, &["\\Seen"]);
    let (ida, idb) = (imap_id(&h, &u, "INBOX", a).await, imap_id(&h, &u, "Sent", b).await);
    let ma = h.ok(&token, "get_message", json!({ "account": "info", "message_id": ida })).await;
    let mb = h.ok(&token, "get_message", json!({ "account": "info", "message_id": idb })).await;
    // Derived thread ids: the reply shares the root's thread.
    assert_eq!(ma["message"]["thread_id"], mb["message"]["thread_id"]);
    assert_eq!(mb["message"]["labels"], json!(["Sent", "SENT"]));

    let v = h.ok(&token, "get_thread", json!({ "account": "info", "message_id": idb })).await;
    assert_eq!(v["thread_incomplete"], true);
    assert_eq!(v["thread_id"], ma["message"]["thread_id"]);
    assert_eq!(v["messages"].as_array().unwrap().len(), 1);
    assert_eq!(v["messages"][0]["message_id"], idb.as_str());
    let tid = v["thread_id"].as_str().unwrap();
    assert_eq!(h.err(&token, "get_thread", json!({ "account": "info", "thread_id": tid })).await, "invalid_argument");
    assert_eq!(
        h.err(&token, "get_thread", json!({ "account": "info", "thread_id": tid, "message_id": idb })).await,
        "invalid_argument"
    );
}

async fn gmail_message(h: &Harness, raw: Vec<u8>) -> String {
    h.google.add_message(
        "gm@example.com",
        MessageSpec { raw: Some(raw), internal_date_ms: 1_767_261_600_000, ..Default::default() },
    )
}

fn resource(result: &Value) -> (&str, Vec<u8>) {
    let items = result["content"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{result}");
    assert_eq!(items[0]["type"], "text");
    assert!(items[0]["text"].as_str().unwrap().contains("<untrusted"), "{}", items[0]["text"]);
    let r = &items[1]["resource"];
    assert_eq!(items[1]["type"], "resource");
    let blob = base64::engine::general_purpose::STANDARD.decode(r["blob"].as_str().unwrap()).unwrap();
    (r["uri"].as_str().unwrap(), blob)
}

#[tokio::test]
async fn get_attachment_imap_and_gmail_bytes_match() {
    let Setup { h, u, token } = setup().await;
    let data = bytes(300_000);
    let raw = mail("Rechnung", "att@example.org", "", &[("Rechnung März.pdf", &data)]);
    let uid = h.imap.add_message(&u.user, "INBOX", &raw, &[]);
    let iid = imap_id(&h, &u, "INBOX", uid).await;
    let gid = gmail_message(&h, raw).await;

    let mut seen = Vec::new();
    for (account, id) in [("info", iid.as_str()), ("gm", gid.as_str())] {
        let m = h.ok(&token, "get_message", json!({ "account": account, "message_id": id })).await;
        let att = &m["message"]["attachments"][0];
        assert_eq!(att["filename"], "Rechnung März.pdf");
        let part = att["attachment_id"].as_str().unwrap().to_string();
        let r =
            call_raw(&h, &token, "get_attachment", json!({ "ref": m["message"]["ref"], "attachment_id": part })).await;
        assert_eq!(r["isError"], false, "{r}");
        assert_eq!(
            r["structuredContent"],
            json!({ "filename": "Rechnung März.pdf", "mime_type": PDF, "size_bytes": data.len() })
        );
        let (uri, blob) = resource(&r);
        assert_eq!(uri, format!("dove://attachment/{}/{part}", m["message"]["ref"].as_str().unwrap()));
        assert!(blob == data, "{account}: bytes differ");
        seen.push(part);
    }
    assert_eq!(seen[0], seen[1], "attachment ids are provider-neutral");
    assert!(!h.imap.flags(&u.user, "INBOX", uid).unwrap().iter().any(|f| f == "\\Seen"));
    h.imap.assert_only_allowlisted();
}

#[tokio::test]
async fn get_attachment_too_large() {
    let Setup { h, u, token } = setup_with(|c| c.limits.attachment_bytes = 4096).await;
    let raw = mail("Gross", "big@example.org", "", &[("small.pdf", &bytes(100)), ("big.pdf", &bytes(5000))]);
    let uid = h.imap.add_message(&u.user, "INBOX", &raw, &[]);
    let id = imap_id(&h, &u, "INBOX", uid).await;
    let m = h.ok(&token, "get_message", json!({ "account": "info", "message_id": id })).await;
    let parts: Vec<String> = m["message"]["attachments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["attachment_id"].as_str().unwrap().to_string())
        .collect();
    let (err, v) = h
        .call(&token, "get_attachment", json!({ "account": "info", "message_id": id, "attachment_id": parts[1] }))
        .await;
    assert!(err);
    assert_eq!(v["error"]["code"], "too_large");
    assert_eq!(v["error"]["details"]["size_bytes"], 5000);
    // The small one in the same message is still returned.
    let v =
        h.ok(&token, "get_attachment", json!({ "account": "info", "message_id": id, "attachment_id": parts[0] })).await;
    assert_eq!(v["size_bytes"], 100);
}

#[tokio::test]
async fn get_attachment_unknown_part_not_found() {
    let Setup { h, u, token } = setup().await;
    let raw = mail("Rechnung", "p@example.org", "", &[("a.pdf", &bytes(10))]);
    let uid = h.imap.add_message(&u.user, "INBOX", &raw, &[]);
    let id = imap_id(&h, &u, "INBOX", uid).await;
    let gid = gmail_message(&h, raw).await;
    let unknown_msg = h
        .call(
            &token,
            "get_attachment",
            json!({ "account": "info", "message_id": "f1-1-4242", "attachment_id": "part-2" }),
        )
        .await;
    assert!(unknown_msg.0);
    assert_eq!(unknown_msg.1["error"]["code"], "not_found");
    // Unknown part, the text body part, a malformed id: all identical to an unknown message, on both providers.
    for (account, mid) in [("info", id.as_str()), ("gm", gid.as_str())] {
        for part in ["part-99", "part-1", "part-x", "../2", "part-02"] {
            let r = h
                .call(&token, "get_attachment", json!({ "account": account, "message_id": mid, "attachment_id": part }))
                .await;
            assert_eq!(r, unknown_msg, "{account} {part}");
        }
    }
}

#[tokio::test]
async fn attachment_filename_sanitised() {
    let Setup { h, u, token } = setup().await;
    let raw = mail(
        "Namen",
        "n@example.org",
        "",
        &[
            ("../../.ssh/authorized_keys", &bytes(5)),
            ("=?utf-8?q?rechnung=E2=80=AEfdp.exe?=", &bytes(6)),
            ("", &bytes(7)),
        ],
    );
    let uid = h.imap.add_message(&u.user, "INBOX", &raw, &[]);
    let id = imap_id(&h, &u, "INBOX", uid).await;
    let m = h.ok(&token, "get_message", json!({ "account": "info", "message_id": id })).await;
    let mut names = Vec::new();
    for a in m["message"]["attachments"].as_array().unwrap() {
        let v = h
            .ok(
                &token,
                "get_attachment",
                json!({ "account": "info", "message_id": id, "attachment_id": a["attachment_id"] }),
            )
            .await;
        names.push(v["filename"].as_str().unwrap().to_string());
    }
    assert_eq!(names, ["sshauthorized_keys", "rechnungfdp.exe", "attachment"]);
}

#[tokio::test]
async fn get_attachment_one_audit_record_without_filename() {
    let Setup { h, u, token } = setup().await;
    let raw = mail("Audit", "au@example.org", "", &[("CANARY-geheim-7781.pdf", &bytes(2048))]);
    let uid = h.imap.add_message(&u.user, "INBOX", &raw, &[]);
    let id = imap_id(&h, &u, "INBOX", uid).await;
    let m = h.ok(&token, "get_message", json!({ "account": "info", "message_id": id })).await;
    let part = m["message"]["attachments"][0]["attachment_id"].as_str().unwrap().to_string();
    let before = h.audit_count().await;
    h.ok(&token, "get_attachment", json!({ "account": "info", "message_id": id, "attachment_id": part })).await;
    assert_eq!(h.audit_count().await, before + 1);
    let rows: Vec<String> = h
        .app()
        .store
        .call(|c| {
            let mut s = c.prepare("SELECT * FROM audit ORDER BY rowid DESC LIMIT 1")?;
            let n = s.column_count();
            let r = s.query_map([], |r| {
                use rusqlite::types::ValueRef;
                Ok((0..n)
                    .map(|i| match r.get_ref(i).unwrap() {
                        ValueRef::Text(b) | ValueRef::Blob(b) => String::from_utf8_lossy(b).into_owned(),
                        ValueRef::Integer(x) => x.to_string(),
                        _ => String::new(),
                    })
                    .collect::<Vec<_>>()
                    .join("|"))
            })?;
            Ok(r.collect::<Result<_, _>>()?)
        })
        .await
        .unwrap();
    let row = &rows[0];
    assert!(row.contains("get_attachment") && row.contains("<1MiB") && row.contains(&part), "{row}");
    assert!(!row.contains("CANARY") && !row.contains(".pdf"), "{row}");
}
