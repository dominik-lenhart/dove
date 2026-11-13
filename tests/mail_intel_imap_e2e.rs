//! Mail intelligence on IMAP mailboxes: categories, calendar, attachment text, contacts and digest over the fake IMAP
//! server, through the deterministic sync entry point. The Gmail variants live in `mail_intel_e2e.rs`.

mod support;

use std::io::Write as _;

use dove::admin::AdminRequest;
use dove::index::imap_sync::sync_steps;
use serde_json::{Value, json};
use support::fake_imap::FakeImap;
use support::harness::{Harness, g};

const DOCX: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

fn since(days: i64) -> String {
    dove::util::rfc3339_ms(dove::util::now_unix_ms() - days * 86_400_000)
}

fn mail(from: &str, to: &str, subject: &str, extra: &str, body: &str) -> Vec<u8> {
    format!(
        "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nMessage-ID: <{}@x.test>\r\n{extra}Date: Thu, 12 Nov 2026 10:00:00 +0000\r\n\
         MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n",
        subject.replace(' ', "-")
    )
    .into_bytes()
}

fn zip_stored(entries: &[(&str, &[u8])]) -> Vec<u8> {
    zip_entries(entries.iter().map(|(n, d)| (*n, d.to_vec(), false)).collect())
}

fn zip_entries(entries: Vec<(&str, Vec<u8>, bool)>) -> Vec<u8> {
    let (mut out, mut cd) = (Vec::new(), Vec::new());
    for (name, data, deflate) in &entries {
        let (method, body): (u16, Vec<u8>) = if *deflate {
            let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(data).unwrap();
            (8, e.finish().unwrap())
        } else {
            (0, data.clone())
        };
        let off = out.len() as u32;
        out.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
        out.extend_from_slice(&[20, 0, 0, 0]);
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&body);
        cd.extend_from_slice(&0x0201_4B50u32.to_le_bytes());
        cd.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
        cd.extend_from_slice(&method.to_le_bytes());
        cd.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        cd.extend_from_slice(&(body.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&[0; 12]);
        cd.extend_from_slice(&off.to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
    }
    let cd_off = out.len() as u32;
    let n = entries.len() as u16;
    out.extend_from_slice(&cd);
    out.extend_from_slice(&0x0605_4B50u32.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}


fn with_docx(from: &str, subject: &str, text: &str) -> Vec<u8> {
    let xml = format!("<w:document><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>");
    let z = zip_stored(&[("[Content_Types].xml", b"<Types/>"), ("word/document.xml", xml.as_bytes())]);
    let b64 = dove::util::b64std(&z);
    let b64 = b64.as_bytes().chunks(76).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("\r\n");
    format!(
        "From: {from}\r\nTo: info@example.org\r\nSubject: {subject}\r\nMessage-ID: <{}@x.test>\r\nDate: Thu, 12 Nov 2026 10:00:00 +0000\r\n\
         MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n\
         --B\r\nContent-Type: {DOCX}; name=\"a.docx\"\r\nContent-Disposition: attachment; filename=\"a.docx\"\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--B--\r\n",
        subject.replace(' ', "-")
    )
    .into_bytes()
}

fn invite(subject: &str) -> Vec<u8> {
    format!(
        "From: Org <org@corp.example>\r\nTo: info@example.org\r\nSubject: {subject}\r\nMessage-ID: <{subject}@x.test>\r\n\
         Date: Thu, 12 Nov 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"A\"\r\n\r\n\
         --A\r\nContent-Type: text/plain\r\n\r\nInvited\r\n--A\r\nContent-Type: text/calendar; method=REQUEST\r\n\r\n\
         BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:u1\r\nSUMMARY:Standup\r\nDTSTART:20261120T090000Z\r\nDTEND:20261120T093000Z\r\n\
         ATTENDEE:mailto:a@x.test\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n--A--\r\n"
    )
    .into_bytes()
}

#[tokio::test]
async fn imap_mailboxes_get_categories_contacts_digest_and_attachment_text() {
    let mut h = Harness::start_with(|_| {}).await;
    h.imap = FakeImap::start().await;
    let u = h.imap_mailbox("info", "info@example.org").await;
    h.project("p", &["info"]).await;
    let token = h.token("p", "agent", vec![g("info", "read")]).await;
    let now = dove::util::now_unix_ms() / 1000;
    let add = |folder: &str, raw: &[u8], flags: &[&str]| h.imap.add_message_at(&u.user, folder, raw, flags, now - 3600);

    let news = add("INBOX", &mail("News <news@shop.example>", "info@example.org", "Deals", "List-Unsubscribe: <mailto:u@x>\r\n", "deals"), &["\\Seen"]);
    let pers = add("INBOX", &mail("Anna Berger <anna@example.com>", "info@example.org", "Lunch", "", "hi"), &[]);
    let note = add("INBOX", &mail("noreply@bank.example", "info@example.org", "Statement", "", "stmt"), &["\\Seen"]);
    let inv = add("INBOX", &invite("Standup"), &["\\Seen"]);
    let doc = add("INBOX", &with_docx("Anna Berger <anna@example.com>", "Contract", "quarterly zeppelin forecast"), &["\\Seen"]);
    add("Sent", &mail("info@example.org", "Carl <carl@example.org>", "Plan", "", "sent body"), &["\\Seen"]);
    add("Junk", &mail("spam@bad.example", "info@example.org", "Win", "", "junk"), &[]);

    h.admin(AdminRequest::IndexEnable { alias: "info".into() }).await.unwrap();
    let r = sync_steps(h.app(), &u.account_id, usize::MAX).await.unwrap();
    assert_eq!(r.error, None, "{r:?}");

    let id = |folder: &str, uid: u32| {
        let h = &h;
        let u = &u;
        let folder = folder.to_string();
        async move {
            let f: i64 = {
                let (a, n) = (u.account_id.clone(), support::fake_imap::encode_utf7(&folder));
                h.app()
                    .store
                    .call(move |c| Ok(c.query_row("SELECT folder_id FROM imap_folders WHERE account_id = ?1 AND name = ?2", [a, n], |r| r.get(0))?))
                    .await
                    .unwrap()
            };
            format!("f{f}-{}-{uid}", h.imap.uidvalidity(&u.user, &folder))
        }
    };
    let (news, pers, note, inv, doc) = (id("INBOX", news).await, id("INBOX", pers).await, id("INBOX", note).await, id("INBOX", inv).await, id("INBOX", doc).await);

    // Categories at ingest and the filter.
    let v = h.ok(&token, "search_messages", json!({"select": ["message_id", "category"], "limit": 50})).await;
    assert_eq!(v["coverage"], "complete", "{v}");
    let cat_of = |id: &str| v["rows"].as_array().unwrap().iter().find(|r| r[0] == id).map(|r| r[1].clone()).unwrap();
    assert_eq!(cat_of(&news), "newsletter");
    assert_eq!(cat_of(&pers), "personal");
    assert_eq!(cat_of(&note), "notification");
    assert_eq!(cat_of(&inv), "calendar");
    let v = h.ok(&token, "search_messages", json!({"where": {"field": "category", "op": "eq", "value": "newsletter"}, "select": ["message_id"]})).await;
    assert_eq!(v["rows"], json!([[news]]));

    // Calendar through get_message (the live IMAP fetch path).
    let m = h.ok(&token, "get_message", json!({"account": "info", "message_id": inv})).await;
    assert_eq!(m["message"]["calendar"]["summary"], "Standup");
    assert_eq!(m["message"]["calendar"]["start"], "2026-11-20T09:00:00Z");
    assert_eq!(m["message"]["calendar"]["attendees_count"], 1);
    assert_eq!(m["message"]["category"], "calendar");

    // Attachment text is indexed and as_text reads it.
    let v = h.ok(&token, "search_messages", json!({"where": {"field": "attachment_text", "op": "terms", "value": "zeppelin"}, "select": ["message_id"]})).await;
    assert_eq!(v["rows"], json!([[doc]]), "{v}");
    let m = h.ok(&token, "get_message", json!({"account": "info", "message_id": doc})).await;
    let part = m["message"]["attachments"][0]["attachment_id"].as_str().unwrap().to_string();
    let t = h.ok(&token, "get_attachment", json!({"account": "info", "message_id": doc, "attachment_id": part, "as_text": true})).await;
    assert_eq!(t["text"], "quarterly zeppelin forecast");

    // Contacts: sent to Carl, received from Anna; no-reply and junk excluded.
    let c = h.ok(&token, "search_contacts", json!({})).await;
    let list = c["contacts"].as_array().unwrap();
    let addrs: Vec<&str> = list.iter().map(|x| x["address"].as_str().unwrap()).collect();
    assert_eq!(addrs[0], "anna@example.com", "{addrs:?}");
    assert!(addrs.contains(&"carl@example.org") && addrs.contains(&"news@shop.example"), "{addrs:?}");
    assert!(!addrs.contains(&"noreply@bank.example") && !addrs.contains(&"spam@bad.example") && !addrs.contains(&"info@example.org"), "{addrs:?}");
    assert_eq!(list[0]["received"], 2);
    assert_eq!(list[0]["name"], "Anna Berger");
    let carl = list.iter().find(|x| x["address"] == "carl@example.org").unwrap();
    assert_eq!((carl["sent"].as_i64(), carl["received"].as_i64()), (Some(1), Some(0)));

    // Digest: INBOX threads (each IMAP message is its own thread unless References link them), junk and Sent absent.
    let d = h.ok(&token, "digest", json!({"since": since(10)})).await;
    let subjects: Vec<&str> = d["threads"].as_array().unwrap().iter().map(|t| t["subject"].as_str().unwrap()).collect();
    assert_eq!(subjects.len(), 5, "{subjects:?}");
    for s in ["Deals", "Lunch", "Statement", "Standup", "Contract"] {
        assert!(subjects.contains(&s), "{s} in {subjects:?}");
    }
    let sent = h.ok(&token, "digest", json!({"since": since(10), "folders": ["SENT"]})).await;
    assert_eq!(sent["threads"].as_array().unwrap().len(), 1);
    let lunch = d["threads"].as_array().unwrap().iter().find(|t| t["subject"] == "Lunch").unwrap();
    assert_eq!(lunch["unread"], true);
    // Paging with a cursor matches the unpaged order.
    let p1 = h.ok(&token, "digest", json!({"since": since(10), "limit": 2})).await;
    let p2 = h.ok(&token, "digest", json!({"cursor": p1["next_cursor"]})).await;
    let mut paged: Vec<Value> = p1["threads"].as_array().unwrap().clone();
    paged.extend(p2["threads"].as_array().unwrap().clone());
    let mut cur = p2["next_cursor"].clone();
    while let Some(c) = cur.as_str() {
        let p = h.ok(&token, "digest", json!({"cursor": c})).await;
        paged.extend(p["threads"].as_array().unwrap().clone());
        cur = p["next_cursor"].clone();
    }
    assert_eq!(paged, d["threads"].as_array().unwrap().clone());
    h.imap.assert_only_allowlisted();
}
