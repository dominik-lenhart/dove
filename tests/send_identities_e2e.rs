//! Sending identities (design 2026-11-13 section 5): IMAP send-as aliases, the SMTP envelope sender, and plain-text
//! signatures for both providers. Aliases and signatures are admin configuration; agents can only use them through
//! `from_address` and `signature`.

mod support;

use dove::admin::AdminRequest;
use dove::mime;
use serde_json::{Value, json};
use support::fake_google::MessageSpec;
use support::fake_imap::encode_utf7;
use support::harness::{FakeImapUser, Harness, g};

const GMAIL: &str = "info@acme.test";
const IMAP: &str = "box@example.org";
const ALIAS: &str = "sales@example.org";

fn key() -> String {
    uuid::Uuid::new_v4().to_string()
}

struct Setup {
    h: Harness,
    u: FakeImapUser,
    /// box: read,draft,send; info (Gmail): read,draft,send.
    token: String,
}

async fn setup() -> Setup {
    let h = Harness::start_with(|c| {
        c.allow_send = true;
        c.limits.client_sends_per_hour = 50;
    })
    .await;
    h.mailbox("info", GMAIL);
    let u = h.imap_mailbox("box", IMAP).await;
    h.project("p", &["info", "box"]).await;
    let token = h.token("p", "agent", vec![g("info", "read,draft,send"), g("box", "read,draft,send")]).await;
    Setup { h, u, token }
}

async fn add_alias(h: &Harness, address: &str, name: Option<&str>, envelope: bool) -> Result<Value, String> {
    h.admin(AdminRequest::AccountsAliasAdd {
        account: "box".into(),
        address: address.into(),
        name: name.map(Into::into),
        envelope,
    })
    .await
}

async fn set_signature(h: &Harness, account: &str, alias: Option<&str>, text: Option<&str>) -> Result<Value, String> {
    h.admin(AdminRequest::AccountsSignatureSet {
        account: account.into(),
        alias: alias.map(Into::into),
        signature: text.map(Into::into),
    })
    .await
}

fn uid_of(id: &str) -> u32 {
    id.rsplit('-').next().unwrap().parse().unwrap()
}

/// The stored draft of an IMAP create/update result.
fn imap_draft(h: &Harness, u: &FakeImapUser, revision: &Value) -> Vec<u8> {
    h.imap.message_raw(&u.user, "Drafts", uid_of(revision.as_str().unwrap())).expect("draft on the server")
}

fn gmail_draft(h: &Harness, draft_id: &Value) -> Vec<u8> {
    h.google.draft_raw(GMAIL, draft_id.as_str().unwrap()).expect("draft at Google")
}

fn body_of(raw: &[u8]) -> String {
    let p = mime::parse(raw, &mime::Limits::default()).unwrap();
    p.text_plain.unwrap_or_default().replace("\r\n", "\n")
}

fn from_of(raw: &[u8]) -> (String, Option<String>) {
    let p = mime::parse(raw, &mime::Limits::default()).unwrap();
    (p.from[0].email.clone(), p.from[0].name.clone())
}

fn create_args(account: &str, from: Option<&str>) -> Value {
    let mut a = json!({ "account": account, "request_key": key(), "to": ["ann@example.net"], "subject": "Angebot",
                        "body_text": "Hallo Ann" });
    if let Some(f) = from {
        a["from_address"] = json!(f);
    }
    a
}

async fn imap_inbox_id(h: &Harness, u: &FakeImapUser) -> String {
    let raw = b"From: Jane <jane@example.org>\r\nTo: box@example.org\r\nSubject: Frage\r\n\
Message-ID: <frage@example.org>\r\nDate: Tue, 14 Nov 2023 22:13:20 +0000\r\n\r\nWie sieht das Angebot aus?\r\n";
    let uid = h.imap.add_message(&u.user, "INBOX", raw, &[]);
    let (a, n) = (u.account_id.clone(), encode_utf7("INBOX"));
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
    format!("f{fid}-{}-{uid}", h.imap.uidvalidity(&u.user, "INBOX"))
}

// ------------------------------------------------------------------ aliases (admin)

#[tokio::test]
async fn alias_admin_verbs_validate_and_list() {
    let Setup { h, .. } = setup().await;
    // Gmail send-as addresses live in Gmail settings.
    let r = h
        .admin(AdminRequest::AccountsAliasAdd {
            account: "info".into(),
            address: "x@acme.test".into(),
            name: None,
            envelope: false,
        })
        .await;
    assert!(r.unwrap_err().contains("Gmail"));
    // Unknown mailbox, the mailbox's own address, malformed addresses, header injection, a name with a line break.
    let unknown = h
        .admin(AdminRequest::AccountsAliasAdd {
            account: "nope".into(),
            address: ALIAS.into(),
            name: None,
            envelope: false,
        })
        .await;
    assert!(unknown.is_err());
    assert!(add_alias(&h, IMAP, None, false).await.is_err());
    for bad in [
        "Sales <sales@example.org>",
        "sales@example.org\r\nBcc: x@evil.example",
        "sales@example.org, b@example.org",
        "not an address",
    ] {
        assert!(add_alias(&h, bad, None, false).await.is_err(), "{bad:?}");
    }
    assert!(add_alias(&h, ALIAS, Some("Acme\r\nBcc: x@evil.example"), false).await.is_err());
    assert!(add_alias(&h, ALIAS, Some("Acme <x>"), false).await.is_err());

    let ok = add_alias(&h, "Sales@Example.ORG", Some("Acme Sales"), true).await.unwrap();
    assert_eq!(ok["address"], ALIAS);
    assert!(add_alias(&h, ALIAS, None, false).await.is_err(), "no duplicates");
    let list = h.admin(AdminRequest::AccountsAliasList { account: "box".into() }).await.unwrap();
    assert_eq!(
        list["aliases"],
        json!([{ "address": ALIAS, "name": "Acme Sales", "envelope": true, "signature": false }])
    );

    // A signature on an alias needs the alias; removing the alias takes its signature along.
    assert!(set_signature(&h, "box", Some("other@example.org"), Some("x")).await.is_err());
    set_signature(&h, "box", Some(ALIAS), Some("Acme Sales")).await.unwrap();
    let list = h.admin(AdminRequest::AccountsAliasList { account: "box".into() }).await.unwrap();
    assert_eq!(list["aliases"][0]["signature"], true);
    h.admin(AdminRequest::AccountsAliasRemove { account: "box".into(), address: ALIAS.into() }).await.unwrap();
    assert!(h.admin(AdminRequest::AccountsAliasRemove { account: "box".into(), address: ALIAS.into() }).await.is_err());
    let left: i64 = h
        .app()
        .store
        .call(|c| Ok(c.query_row("SELECT COUNT(*) FROM account_signatures", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(left, 0);
}

#[tokio::test]
async fn alias_admin_actions_are_audited_without_addresses_or_text() {
    let Setup { h, .. } = setup().await;
    add_alias(&h, ALIAS, Some("Acme"), false).await.unwrap();
    set_signature(&h, "box", None, Some("Mit freundlichen Grüßen, Zebra-Signatur")).await.unwrap();
    let hits: i64 = h
        .app()
        .store
        .call(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM audit WHERE instr(object_ids || tool_or_action || coalesce(account_alias,'') \
                 || coalesce(project,'') || actor, 'example.org') > 0 OR instr(object_ids, 'Zebra') > 0",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(hits, 0);
    let actions: i64 = h
        .app()
        .store
        .call(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM audit WHERE tool_or_action IN ('accounts.alias_add', 'accounts.signature_set')",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(actions, 2);
}

// ------------------------------------------------------------------ from_address on IMAP

#[tokio::test]
async fn imap_from_address_must_be_the_mailbox_or_an_alias() {
    let Setup { h, u, token } = setup().await;
    add_alias(&h, ALIAS, Some("Acme Sales"), false).await.unwrap();
    let drafts = |h: &Harness| h.imap.uids(&u.user, "Drafts").len();

    // Unknown sender: invalid_argument, and nothing reached the server.
    for bad in ["boss@example.org", "box@example.org.evil.test", "Sales <sales@example.org.evil.test>"] {
        assert_eq!(h.err(&token, "create_draft", create_args("box", Some(bad))).await, "invalid_argument", "{bad}");
    }
    // Header injection through from_address never gets near a header.
    for inj in ["sales@example.org\r\nBcc: spy@evil.example", "Sales <sales@example.org>\nX-Evil: 1"] {
        assert_eq!(h.err(&token, "create_draft", create_args("box", Some(inj))).await, "invalid_argument");
    }
    assert_eq!(drafts(&h), 0);

    // The alias works (any case), takes the operator's display name unless the agent gives its own.
    let r = h.ok(&token, "create_draft", create_args("box", Some("Sales@Example.org"))).await;
    assert_eq!(from_of(&imap_draft(&h, &u, &r["revision"])), (ALIAS.into(), Some("Acme Sales".into())));
    let r = h.ok(&token, "create_draft", create_args("box", Some("Team <sales@example.org>"))).await;
    assert_eq!(from_of(&imap_draft(&h, &u, &r["revision"])), (ALIAS.into(), Some("Team".into())));
    // The mailbox address itself and the default still work.
    let r = h.ok(&token, "create_draft", create_args("box", Some(IMAP))).await;
    assert_eq!(from_of(&imap_draft(&h, &u, &r["revision"])).0, IMAP);
    let r = h.ok(&token, "create_draft", create_args("box", None)).await;
    assert_eq!(from_of(&imap_draft(&h, &u, &r["revision"])).0, IMAP);

    // Removed alias: unusable again.
    h.admin(AdminRequest::AccountsAliasRemove { account: "box".into(), address: ALIAS.into() }).await.unwrap();
    assert_eq!(h.err(&token, "create_draft", create_args("box", Some(ALIAS))).await, "invalid_argument");
}

#[tokio::test]
async fn gmail_from_address_keeps_its_send_as_behaviour() {
    let Setup { h, token, .. } = setup().await;
    h.google.add_send_as(GMAIL, "office@acme.test");
    // A Dove alias on a Gmail mailbox changes nothing: Gmail's own list decides.
    let r = h.ok(&token, "create_draft", create_args("info", Some("office@acme.test"))).await;
    assert_eq!(from_of(&gmail_draft(&h, &r["draft_id"])).0, "office@acme.test");
    assert_eq!(h.err(&token, "create_draft", create_args("info", Some(ALIAS))).await, "invalid_argument");
}

#[tokio::test]
async fn list_accounts_shows_from_addresses_to_drafters_only() {
    let Setup { h, token, .. } = setup().await;
    add_alias(&h, ALIAS, Some("Acme Sales"), false).await.unwrap();
    let readonly = h.token("p", "reader", vec![g("box", "read")]).await;
    let accounts = |v: &Value| v["accounts"].as_array().unwrap().clone();
    let box_of = |v: &Value| accounts(v).into_iter().find(|a| a["account"] == "box").unwrap();

    let v = h.ok(&token, "list_accounts", json!({})).await;
    assert_eq!(
        box_of(&v)["from_addresses"],
        json!([{ "address": IMAP, "name": null }, { "address": ALIAS, "name": "Acme Sales" }])
    );
    let info = accounts(&v).into_iter().find(|a| a["account"] == "info").unwrap();
    assert!(info.get("from_addresses").is_none(), "Gmail send-as comes from Gmail");
    // No draft right: no addresses (and no alias leak).
    let v = h.ok(&readonly, "list_accounts", json!({})).await;
    assert!(box_of(&v).get("from_addresses").is_none());
}

// ------------------------------------------------------------------ SMTP envelope

async fn send_as(h: &Harness, token: &str, from: Option<&str>) -> support::fake_imap::SentMail {
    let before = h.imap.sent_mails().len();
    let c = h.ok(token, "create_draft", create_args("box", from)).await;
    h.ok(
        token,
        "send_draft",
        json!({ "account": "box", "draft_id": c["draft_id"], "expected_revision": c["revision"] }),
    )
    .await;
    let mut sent = h.imap.sent_mails();
    assert_eq!(sent.len(), before + 1);
    sent.pop().unwrap()
}

#[tokio::test]
async fn envelope_sender_is_the_login_unless_the_alias_is_envelope_capable() {
    let Setup { h, token, .. } = setup().await;
    add_alias(&h, ALIAS, None, false).await.unwrap();
    add_alias(&h, "press@example.org", None, true).await.unwrap();

    let m = send_as(&h, &token, Some(ALIAS)).await;
    assert_eq!(m.from, IMAP, "plain alias: envelope stays the login address");
    assert!(String::from_utf8_lossy(&m.data).contains(&format!("<{ALIAS}>")), "the From header is the alias");

    let m = send_as(&h, &token, Some("press@example.org")).await;
    assert_eq!(m.from, "press@example.org", "envelope-capable alias");
    assert!(String::from_utf8_lossy(&m.data).contains("<press@example.org>"));

    let m = send_as(&h, &token, None).await;
    assert_eq!(m.from, IMAP);
}

#[tokio::test]
async fn a_removed_alias_cannot_send_an_existing_draft() {
    let Setup { h, token, .. } = setup().await;
    add_alias(&h, "press@example.org", None, true).await.unwrap();
    let c = h.ok(&token, "create_draft", create_args("box", Some("press@example.org"))).await;
    h.admin(AdminRequest::AccountsAliasRemove { account: "box".into(), address: "press@example.org".into() })
        .await
        .unwrap();
    let before = h.imap.smtp_connections();
    let args = json!({ "account": "box", "draft_id": c["draft_id"], "expected_revision": c["revision"] });
    assert_eq!(h.err(&token, "send_draft", args).await, "invalid_argument");
    assert_eq!(h.imap.smtp_connections(), before, "nothing was submitted");
    assert!(h.imap.sent_mails().is_empty());
}

// ------------------------------------------------------------------ signatures

const SIG: &str = "Dominik Lenhart\nCtrl App Studio";

fn count(hay: &str, needle: &str) -> usize {
    hay.matches(needle).count()
}

#[tokio::test]
async fn imap_signature_goes_after_the_body_and_before_the_quote_or_forward_block() {
    let Setup { h, u, token } = setup().await;
    set_signature(&h, "box", None, Some("Dominik Lenhart\r\nCtrl App Studio\r\n\r\n")).await.unwrap();

    // New draft: exactly `body \n\n-- \n signature`.
    let r = h.ok(&token, "create_draft", create_args("box", None)).await;
    assert_eq!(body_of(&imap_draft(&h, &u, &r["revision"])).trim_end(), format!("Hallo Ann\n\n-- \n{SIG}"));

    // Opt out.
    let mut a = create_args("box", None);
    a["signature"] = json!(false);
    let r = h.ok(&token, "create_draft", a).await;
    assert_eq!(body_of(&imap_draft(&h, &u, &r["revision"])).trim_end(), "Hallo Ann");

    // Reply: signature first, then the attribution and the quote.
    let orig = imap_inbox_id(&h, &u).await;
    let mut a = create_args("box", None);
    a["reply_to_message_id"] = json!(orig);
    let r = h.ok(&token, "create_draft", a).await;
    let body = body_of(&imap_draft(&h, &u, &r["revision"]));
    let (sig, quote) = (body.find("-- \n").unwrap(), body.find("wrote:").unwrap());
    assert!(body.starts_with("Hallo Ann\n\n-- \n"), "{body}");
    assert!(sig < quote, "{body}");
    assert!(body[sig..quote].contains(SIG), "{body}");
    assert!(body.contains("> Wie sieht das Angebot aus?"), "{body}");
    assert_eq!(count(&body, "-- \n"), 1);

    // Forward: signature before the forwarded block.
    let mut a = create_args("box", None);
    a["forward_message_id"] = json!(orig);
    a["body_text"] = json!("FYI");
    let r = h.ok(&token, "create_draft", a).await;
    let body = body_of(&imap_draft(&h, &u, &r["revision"]));
    assert!(body.starts_with(&format!("FYI\n\n-- \n{SIG}\n\n---------- Forwarded message")), "{body}");
}

#[tokio::test]
async fn gmail_signature_works_too() {
    let Setup { h, token, .. } = setup().await;
    set_signature(&h, "info", None, Some(SIG)).await.unwrap();
    let r = h.ok(&token, "create_draft", create_args("info", None)).await;
    assert_eq!(body_of(&gmail_draft(&h, &r["draft_id"])).trim_end(), format!("Hallo Ann\n\n-- \n{SIG}"));

    // A Gmail alias signature applies when the agent sends from that send-as address; the default is the mailbox's.
    h.google.add_send_as(GMAIL, "office@acme.test");
    set_signature(&h, "info", Some("office@acme.test"), Some("Office Team")).await.unwrap();
    let r = h.ok(&token, "create_draft", create_args("info", Some("office@acme.test"))).await;
    assert_eq!(body_of(&gmail_draft(&h, &r["draft_id"])).trim_end(), "Hallo Ann\n\n-- \nOffice Team");
    let r = h.ok(&token, "create_draft", create_args("info", None)).await;
    assert!(body_of(&gmail_draft(&h, &r["draft_id"])).contains(SIG));

    // A reply on Gmail: signature before the quote.
    let id = h.google.add_message(
        GMAIL,
        MessageSpec {
            from: "jane@example.org".into(),
            to: vec![GMAIL.into()],
            subject: "Frage".into(),
            text: Some("Wie geht es?\n".into()),
            internal_date_ms: 1_700_000_000_000,
            message_id_header: Some("<q@example.org>".into()),
            ..Default::default()
        },
    );
    let mut a = create_args("info", None);
    a["reply_to_message_id"] = json!(id);
    let r = h.ok(&token, "create_draft", a).await;
    let body = body_of(&gmail_draft(&h, &r["draft_id"]));
    assert!(body.find(SIG).unwrap() < body.find("wrote:").unwrap(), "{body}");
}

#[tokio::test]
async fn alias_signature_beats_the_mailbox_signature_and_falls_back_to_it() {
    let Setup { h, u, token } = setup().await;
    add_alias(&h, ALIAS, None, false).await.unwrap();
    add_alias(&h, "press@example.org", None, false).await.unwrap();
    set_signature(&h, "box", None, Some("Mailbox signature")).await.unwrap();
    set_signature(&h, "box", Some(ALIAS), Some("Sales signature")).await.unwrap();
    let sig_of = |raw: &[u8]| body_of(raw).split("-- \n").nth(1).unwrap_or_default().trim().to_string();

    let r = h.ok(&token, "create_draft", create_args("box", Some(ALIAS))).await;
    assert_eq!(sig_of(&imap_draft(&h, &u, &r["revision"])), "Sales signature");
    let r = h.ok(&token, "create_draft", create_args("box", Some("press@example.org"))).await;
    assert_eq!(sig_of(&imap_draft(&h, &u, &r["revision"])), "Mailbox signature");
    let r = h.ok(&token, "create_draft", create_args("box", None)).await;
    assert_eq!(sig_of(&imap_draft(&h, &u, &r["revision"])), "Mailbox signature");

    // Clearing the alias's signature falls back; clearing both leaves the body alone.
    set_signature(&h, "box", Some(ALIAS), None).await.unwrap();
    let r = h.ok(&token, "create_draft", create_args("box", Some(ALIAS))).await;
    assert_eq!(sig_of(&imap_draft(&h, &u, &r["revision"])), "Mailbox signature");
    set_signature(&h, "box", None, None).await.unwrap();
    let r = h.ok(&token, "create_draft", create_args("box", Some(ALIAS))).await;
    assert_eq!(body_of(&imap_draft(&h, &u, &r["revision"])).trim_end(), "Hallo Ann");
}

#[tokio::test]
async fn signature_limits() {
    let Setup { h, .. } = setup().await;
    assert!(set_signature(&h, "box", None, Some(&"x".repeat(dove::identity::MAX_SIGNATURE_BYTES + 1))).await.is_err());
    assert!(set_signature(&h, "box", None, Some("a\u{0}b")).await.is_err());
    assert!(set_signature(&h, "box", None, Some("  \n")).await.is_err());
    assert!(set_signature(&h, "nope", None, Some("x")).await.is_err());
    set_signature(&h, "box", None, Some(&"x".repeat(dove::identity::MAX_SIGNATURE_BYTES))).await.unwrap();
    let shown = h.admin(AdminRequest::AccountsSignatureShow { account: "box".into(), alias: None }).await.unwrap();
    assert_eq!(shown["signature"].as_str().unwrap().len(), dove::identity::MAX_SIGNATURE_BYTES);
}

#[tokio::test]
async fn update_draft_never_appends_the_signature_again() {
    let Setup { h, u, token } = setup().await;
    set_signature(&h, "box", None, Some(SIG)).await.unwrap();
    set_signature(&h, "info", None, Some(SIG)).await.unwrap();

    // IMAP: a change that does not touch the body keeps exactly one signature; a new body is stored as given.
    let c = h.ok(&token, "create_draft", create_args("box", None)).await;
    let u1 = h
        .ok(
            &token,
            "update_draft",
            json!({ "account": "box", "draft_id": c["draft_id"], "expected_revision": c["revision"],
                    "changes": { "subject": "Neu", "to": ["bob@example.net"] } }),
        )
        .await;
    let body = body_of(&imap_draft(&h, &u, &u1["revision"]));
    assert_eq!(count(&body, SIG), 1, "{body}");
    let u2 = h
        .ok(
            &token,
            "update_draft",
            json!({ "account": "box", "draft_id": c["draft_id"], "expected_revision": u1["revision"],
                    "changes": { "body_text": "Komplett neuer Text" } }),
        )
        .await;
    assert_eq!(body_of(&imap_draft(&h, &u, &u2["revision"])).trim_end(), "Komplett neuer Text");

    // Gmail: same.
    let c = h.ok(&token, "create_draft", create_args("info", None)).await;
    let u1 = h
        .ok(
            &token,
            "update_draft",
            json!({ "account": "info", "draft_id": c["draft_id"], "expected_revision": c["revision"],
                    "changes": { "subject": "Neu" } }),
        )
        .await;
    assert_eq!(count(&body_of(&gmail_draft(&h, &c["draft_id"])), SIG), 1);
    h.ok(
        &token,
        "update_draft",
        json!({ "account": "info", "draft_id": c["draft_id"], "expected_revision": u1["revision"],
                "changes": { "body_text": "Anders" } }),
    )
    .await;
    assert_eq!(body_of(&gmail_draft(&h, &c["draft_id"])).trim_end(), "Anders");
}

#[tokio::test]
async fn retrying_a_create_with_the_same_key_does_not_sign_twice() {
    let Setup { h, u, token } = setup().await;
    set_signature(&h, "box", None, Some(SIG)).await.unwrap();
    let a = create_args("box", None);
    let r1 = h.ok(&token, "create_draft", a.clone()).await;
    let r2 = h.ok(&token, "create_draft", a).await;
    assert_eq!(r1["draft_id"], r2["draft_id"]);
    assert_eq!(h.imap.uids(&u.user, "Drafts").len(), 1);
}

#[tokio::test]
async fn signature_text_stays_out_of_the_tool_audit() {
    let Setup { h, token, .. } = setup().await;
    set_signature(&h, "box", None, Some("Quokka-Signatur")).await.unwrap();
    h.ok(&token, "create_draft", create_args("box", None)).await;
    let hits: i64 = h
        .app()
        .store
        .call(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM audit WHERE instr(object_ids || coalesce(query_hash,''), 'Quokka') > 0",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(hits, 0);
}
