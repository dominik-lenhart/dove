//! Organize tools on IMAP (design 2026-11-13 sections 1 and 2): typed flag STOREs, `UID MOVE`, the COPY fallback
//! whose `\Deleted`/`UID EXPUNGE` only ever touch UIDs the server confirmed as copied (`CopiedUid`), Trash/Junk behind
//! `delete`, and `delete_draft` through the own-draft guard. The fake server's command log proves which UIDs were
//! flagged and expunged.

mod support;

use serde_json::{Value, json};
use support::fake_imap::{FakeImap, Fault, Opts, encode_utf7, verb_of};
use support::harness::{FakeImapUser, Harness, g};

const MB: &str = "info@example.org";

struct Setup {
    h: Harness,
    u: FakeImapUser,
    assistant: String,
    full: String,
}

async fn setup_with(opts: Opts) -> Setup {
    let mut h = Harness::start().await;
    h.imap = FakeImap::start_with(opts).await;
    let u = h.imap_mailbox("info", MB).await;
    h.project("p", &["info"]).await;
    let assistant = h.token("p", "assistant", vec![g("info", "assistant")]).await;
    let full = h.token("p", "full", vec![g("info", "full")]).await;
    Setup { h, u, assistant, full }
}

async fn setup() -> Setup {
    setup_with(Opts::default()).await
}

/// [`setup_with`] with an hourly organize budget of `per_hour` messages.
async fn budget_setup(opts: Opts, per_hour: u32) -> Setup {
    let mut h = Harness::start_with(|c| c.limits.client_organize_per_hour = per_hour).await;
    h.imap = FakeImap::start_with(opts).await;
    let u = h.imap_mailbox("info", MB).await;
    h.project("p", &["info"]).await;
    let assistant = h.token("p", "assistant", vec![g("info", "assistant")]).await;
    let full = h.token("p", "full", vec![g("info", "full")]).await;
    Setup { h, u, assistant, full }
}

/// Checks that exactly `n` units of the organize budget are left: `n + 1` unknown ids are refused as rate limited,
/// `n` fit (and, all being `not_found` before any write, are given back).
async fn assert_budget_left(s: &Setup, token: &str, n: usize) {
    let ids = |k: usize| (0..k).map(|i| format!("f999-1-{i}")).collect::<Vec<_>>();
    let star = |k: usize| json!({ "account": "info", "ids": ids(k), "add_flags": ["STARRED"] });
    assert_eq!(s.h.err(token, "update_messages", star(n + 1)).await, "rate_limited", "more than {n} left");
    s.h.ok(token, "update_messages", star(n)).await;
}

fn raw(subject: &str) -> Vec<u8> {
    format!(
        "From: Kunde <kunde@example.net>\r\nTo: {MB}\r\nSubject: {subject}\r\nMessage-ID: <{subject}@example.net>\r\n\
         Date: Thu, 01 Jan 2026 10:00:00 +0000\r\n\r\nHallo\r\n"
    )
    .into_bytes()
}

async fn folder_id(h: &Harness, account_id: &str, name: &str) -> i64 {
    let (a, n) = (account_id.to_string(), encode_utf7(name));
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

async fn imap_id(h: &Harness, u: &FakeImapUser, folder: &str, uid: u32) -> String {
    format!("f{}-{}-{uid}", folder_id(h, &u.account_id, folder).await, h.imap.uidvalidity(&u.user, folder))
}

/// Adds a folder on the server after connect and lets Dove learn it (list_labels refreshes the folder table).
async fn add_folder(s: &Setup, name: &str, special: Option<&str>) {
    s.h.imap.add_folder(&s.u.user, name, special);
    s.h.ok(&s.assistant, "list_labels", json!({ "account": "info" })).await;
}

fn expand(set: &str) -> Vec<u32> {
    set.split(',')
        .flat_map(|p| match p.split_once(':') {
            Some((a, b)) => (a.parse::<u32>().unwrap()..=b.parse::<u32>().unwrap()).collect::<Vec<_>>(),
            None => vec![p.parse().unwrap()],
        })
        .collect()
}

/// Walks the command log: every `\Deleted` STORE and every `UID EXPUNGE` names only UIDs that the preceding
/// `UID COPY` in the same selected folder copied, or (in Drafts) the given own-draft UIDs. Non-UID EXPUNGE/STORE
/// never appear. Returns the (verb, uids) pairs it checked.
fn assert_expunges_only_copied_or_own(h: &Harness, own_drafts: &[u32]) -> Vec<(String, Vec<u32>)> {
    let mut selected = String::new();
    let mut copied: Vec<u32> = Vec::new();
    let mut checked = Vec::new();
    for c in h.imap.commands() {
        let verb = verb_of(&c);
        let arg = |n: usize| c.split(' ').nth(n).unwrap_or_default().to_string();
        assert!(!matches!(verb.as_str(), "EXPUNGE" | "STORE" | "COPY" | "MOVE" | "CLOSE"), "{c}");
        match verb.as_str() {
            "SELECT" | "EXAMINE" => {
                selected = arg(1).trim_matches('"').to_string();
                copied.clear();
            }
            "UID COPY" => copied = expand(&arg(2)),
            _ => {}
        }
        let deleting = (verb == "UID STORE" && c.contains("\\Deleted")) || verb == "UID EXPUNGE";
        if deleting {
            let uids = expand(&arg(2));
            for u in &uids {
                let ok = copied.contains(u) || (selected == "Drafts" && own_drafts.contains(u));
                assert!(ok, "{c} in {selected} names UID {u} that was neither copied nor an own draft");
            }
            checked.push((verb, uids));
        }
    }
    checked
}

fn ok_ids(r: &Value) -> Vec<bool> {
    r["results"].as_array().unwrap().iter().map(|x| x["ok"].as_bool().unwrap()).collect()
}

#[tokio::test]
async fn flags_and_keywords_round_trip() {
    let s = setup().await;
    let (h, u) = (&s.h, &s.u);
    let a = h.imap.add_message(&u.user, "INBOX", &raw("a"), &[]);
    let b = h.imap.add_message(&u.user, "INBOX", &raw("b"), &["\\Seen"]);
    let sent = h.imap.add_message(&u.user, "Sent", &raw("c"), &["\\Seen"]);
    let (ia, ib, isent) =
        (imap_id(h, u, "INBOX", a).await, imap_id(h, u, "INBOX", b).await, imap_id(h, u, "Sent", sent).await);
    let stale = format!("f{}-1-{a}", folder_id(h, &u.account_id, "INBOX").await);
    h.imap.clear_commands();
    let r = h
        .ok(
            &s.assistant,
            "update_messages",
            json!({ "account": "info", "ids": [ia, ib, isent, stale, "f999-1-1", "garbage"],
                    "remove_flags": ["UNREAD"], "add_flags": ["STARRED"], "add_labels": ["Kunde", "$Follow"] }),
        )
        .await;
    assert_eq!(ok_ids(&r), vec![true, true, true, false, false, false], "{r}");
    for i in 3..6 {
        assert_eq!(r["results"][i]["error"]["code"], "not_found", "{r}");
    }
    let labels = r["results"][0]["labels"].to_string();
    assert!(labels.contains("STARRED") && labels.contains("Kunde") && !labels.contains("UNREAD"), "{labels}");
    let flags = h.imap.flags(&u.user, "INBOX", a).unwrap();
    for f in ["\\Seen", "\\Flagged", "Kunde", "$Follow"] {
        assert!(flags.contains(&f.to_string()), "{flags:?}");
    }
    assert!(h.imap.flags(&u.user, "Sent", sent).unwrap().contains(&"Kunde".to_string()));
    let m = h.ok(&s.assistant, "get_message", json!({ "account": "info", "message_id": ia })).await;
    assert_eq!((m["message"]["is_starred"].as_bool(), m["message"]["is_unread"].as_bool()), (Some(true), Some(false)));

    // And back.
    h.ok(
        &s.assistant,
        "update_messages",
        json!({ "account": "info", "ids": [ia], "add_flags": ["UNREAD"], "remove_flags": ["STARRED"], "remove_labels": ["Kunde"] }),
    )
    .await;
    let flags = h.imap.flags(&u.user, "INBOX", a).unwrap();
    assert_eq!(flags, vec!["$Follow".to_string()]);
    // Typed STOREs only: never \Deleted, never a non-UID STORE, nothing expunged.
    let stores: Vec<String> = h.imap.commands().into_iter().filter(|c| verb_of(c) == "UID STORE").collect();
    assert!(!stores.is_empty() && stores.iter().all(|c| !c.contains("\\Deleted")), "{stores:?}");
    assert!(assert_expunges_only_copied_or_own(h, &[]).is_empty());
    for bad in ["\\Deleted", "zwei Wörter", "a)"] {
        let args = json!({ "account": "info", "ids": [ia], "add_labels": [bad] });
        assert_eq!(h.err(&s.assistant, "update_messages", args).await, "invalid_argument", "{bad}");
    }
    h.imap.assert_only_allowlisted();
}

#[tokio::test]
async fn move_with_move_capability() {
    let s = setup().await;
    let (h, u) = (&s.h, &s.u);
    add_folder(&s, "Projekte", None).await;
    let a = h.imap.add_message(&u.user, "INBOX", &raw("a"), &[]);
    let b = h.imap.add_message(&u.user, "INBOX", &raw("b"), &["\\Seen"]);
    let keep = h.imap.add_message(&u.user, "INBOX", &raw("keep"), &[]);
    let (ia, ib) = (imap_id(h, u, "INBOX", a).await, imap_id(h, u, "INBOX", b).await);
    let gone = format!("f{}-{}-999", folder_id(h, &u.account_id, "INBOX").await, h.imap.uidvalidity(&u.user, "INBOX"));
    h.imap.clear_commands();
    let r = h
        .ok(&s.assistant, "move_messages", json!({ "account": "info", "ids": [ia, ib, gone], "to": "Projekte" }))
        .await;
    assert_eq!(ok_ids(&r), vec![true, true, false], "{r}");
    assert_eq!(r["results"][2]["error"]["code"], "not_found");
    assert_eq!(h.imap.uids(&u.user, "INBOX"), vec![keep]);
    assert_eq!(h.imap.uids(&u.user, "Projekte").len(), 2);
    // New ids resolve; old ids are not_found.
    let new_a = r["results"][0]["new_id"].as_str().unwrap().to_string();
    assert_eq!(new_a, imap_id(h, u, "Projekte", h.imap.uids(&u.user, "Projekte")[0]).await);
    let m = h.ok(&s.assistant, "get_message", json!({ "account": "info", "message_id": new_a })).await;
    assert_eq!(m["message"]["subject"], "a");
    assert_eq!(h.err(&s.assistant, "get_message", json!({ "account": "info", "message_id": ia })).await, "not_found");
    let cmds = h.imap.commands();
    assert!(cmds.iter().any(|c| verb_of(c) == "UID MOVE"), "{cmds:?}");
    assert!(!cmds.iter().any(|c| matches!(verb_of(c).as_str(), "UID COPY" | "UID EXPUNGE")), "{cmds:?}");
    assert!(!cmds.iter().any(|c| c.contains("\\Deleted")), "{cmds:?}");
    // Moving into the folder a message is already in changes nothing.
    let r = h.ok(&s.assistant, "move_messages", json!({ "account": "info", "ids": [new_a], "to": "Projekte" })).await;
    assert_eq!(r["results"][0]["new_id"], json!(new_a));
    // archive without an Archive folder is a clear argument error.
    assert_eq!(
        h.err(&s.assistant, "move_messages", json!({ "account": "info", "ids": [new_a], "to": "archive" })).await,
        "invalid_argument"
    );
    add_folder(&s, "Archiv", None).await;
    h.ok(&s.assistant, "move_messages", json!({ "account": "info", "ids": [new_a], "to": "archive" })).await;
    assert_eq!(h.imap.uids(&u.user, "Archiv").len(), 1);
    h.imap.assert_only_allowlisted();
}

/// Failed ids are given back only when nothing reached the server: a refused STORE or MOVE (`NO`) is refunded, a
/// STORE or MOVE whose reply was lost (`outcome_unknown`), a second STORE failing after the first went through, and a
/// failed read-back after a STORE are spent.
#[tokio::test]
async fn organize_budget_refunds_only_definitive_failures() {
    let s = budget_setup(Opts::default(), 10).await;
    let (h, u) = (&s.h, &s.u);
    add_folder(&s, "Projekte", None).await;
    let a = h.imap.add_message(&u.user, "INBOX", &raw("a"), &[]);
    let b = h.imap.add_message(&u.user, "INBOX", &raw("b"), &[]);
    let c = h.imap.add_message(&u.user, "Sent", &raw("c"), &["\\Seen"]);
    let (ia, ib, ic) =
        (imap_id(h, u, "INBOX", a).await, imap_id(h, u, "INBOX", b).await, imap_id(h, u, "Sent", c).await);
    let star = |ids: &[&String]| json!({ "account": "info", "ids": ids, "add_flags": ["STARRED"] });

    // The INBOX group's STORE is refused: both its ids are given back, Sent's change is spent. 10 - 1 = 9.
    h.imap.fail_next("UID STORE", Fault::No);
    let r = h.ok(&s.assistant, "update_messages", star(&[&ia, &ib, &ic])).await;
    assert_eq!(ok_ids(&r), vec![false, false, true], "{r}");
    assert!(!h.imap.flags(&u.user, "INBOX", a).unwrap().contains(&"\\Flagged".to_string()));
    // The reply to the STORE is lost after the server applied it: outcome_unknown, spent. 9 - 2 = 7.
    h.imap.fail_next("UID STORE", Fault::DropAfterApply);
    let r = h.ok(&s.assistant, "update_messages", star(&[&ia, &ib])).await;
    assert_eq!(ok_ids(&r), vec![false, false], "{r}");
    assert_eq!(r["results"][0]["error"]["code"], "outcome_unknown", "{r}");
    assert!(h.imap.flags(&u.user, "INBOX", a).unwrap().contains(&"\\Flagged".to_string()));
    // Two STOREs (+\Flagged, then -\Seen): the second is refused after the first went through. 7 - 1 = 6.
    h.imap.fail_next_containing("UID STORE", "-FLAGS", Fault::No);
    let r = h
        .ok(
            &s.assistant,
            "update_messages",
            json!({ "account": "info", "ids": [ic], "add_flags": ["UNREAD", "STARRED"] }),
        )
        .await;
    assert_eq!(r["results"][0]["error"]["code"], "outcome_unknown", "{r}");
    let mut flags = h.imap.flags(&u.user, "Sent", c).unwrap();
    flags.sort();
    assert_eq!(flags, vec!["\\Flagged".to_string(), "\\Seen".to_string()]);
    // A refused MOVE is given back; a MOVE whose reply is lost is spent. 6 - 1 = 5.
    h.imap.fail_next("UID MOVE", Fault::No);
    let r = h.ok(&s.assistant, "move_messages", json!({ "account": "info", "ids": [ia], "to": "Projekte" })).await;
    assert_eq!(ok_ids(&r), vec![false], "{r}");
    h.imap.fail_next("UID MOVE", Fault::DropAfterApply);
    let r = h.ok(&s.assistant, "move_messages", json!({ "account": "info", "ids": [ib], "to": "Projekte" })).await;
    assert_eq!(r["results"][0]["error"]["code"], "outcome_unknown", "{r}");
    // The STORE went through but reading the result back fails: spent, also for the id the server did not have
    // (its group's outcome is unknown). 5 - 2 = 3.
    let gone = format!("f{}-{}-999", folder_id(h, &u.account_id, "INBOX").await, h.imap.uidvalidity(&u.user, "INBOX"));
    h.imap.fail_next_containing("UID FETCH", &format!("UID FETCH {a} ("), Fault::Drop);
    let r = h
        .ok(&s.assistant, "update_messages", json!({ "account": "info", "ids": [ia, gone], "add_labels": ["Kunde"] }))
        .await;
    assert_eq!(r["results"][0]["error"]["code"], "outcome_unknown", "{r}");
    assert!(h.imap.flags(&u.user, "INBOX", a).unwrap().contains(&"Kunde".to_string()));
    assert_budget_left(&s, &s.assistant, 3).await;
    h.imap.assert_only_allowlisted();
}

/// Without MOVE, a copy whose original could not be flagged `\Deleted` is a failed id that still changed the mailbox
/// (a copy exists): it is not given back.
#[tokio::test]
async fn organize_budget_spends_copies_that_kept_their_original() {
    let s = budget_setup(Opts { move_cap: false, ..Opts::default() }, 4).await;
    let (h, u) = (&s.h, &s.u);
    add_folder(&s, "Archive", None).await;
    let a = h.imap.add_message(&u.user, "INBOX", &raw("a"), &[]);
    let ia = imap_id(h, u, "INBOX", a).await;
    h.imap.fail_next_containing("UID STORE", "\\Deleted", Fault::No);
    let r = h.ok(&s.assistant, "move_messages", json!({ "account": "info", "ids": [ia], "to": "archive" })).await;
    assert_eq!(r["results"][0]["error"]["code"], "upstream_error", "{r}");
    assert_eq!((h.imap.uids(&u.user, "INBOX"), h.imap.uids(&u.user, "Archive").len()), (vec![a], 1));
    assert_budget_left(&s, &s.assistant, 3).await;
}

#[tokio::test]
async fn move_without_move_expunges_only_confirmed_copies() {
    let s = setup_with(Opts { move_cap: false, ..Opts::default() }).await;
    let (h, u) = (&s.h, &s.u);
    add_folder(&s, "Archive", None).await;
    let a = h.imap.add_message(&u.user, "INBOX", &raw("a"), &[]);
    // Another client marked this one \Deleted without expunging: Dove's UID EXPUNGE must leave it alone.
    let other = h.imap.add_message(&u.user, "INBOX", &raw("other"), &["\\Deleted"]);
    let c = h.imap.add_message(&u.user, "INBOX", &raw("c"), &["\\Flagged"]);
    let ids = [imap_id(h, u, "INBOX", a).await, imap_id(h, u, "INBOX", c).await];
    let missing =
        format!("f{}-{}-77", folder_id(h, &u.account_id, "INBOX").await, h.imap.uidvalidity(&u.user, "INBOX"));
    h.imap.clear_commands();
    let r = h
        .ok(
            &s.assistant,
            "move_messages",
            json!({ "account": "info", "ids": [ids[0], ids[1], missing], "to": "archive" }),
        )
        .await;
    assert_eq!(ok_ids(&r), vec![true, true, false], "{r}");
    assert_eq!(h.imap.uids(&u.user, "INBOX"), vec![other]);
    let archived = h.imap.uids(&u.user, "Archive");
    assert_eq!(archived.len(), 2);
    // Flags travel with the copy; new ids point at the copies.
    assert!(h.imap.flags(&u.user, "Archive", archived[1]).unwrap().contains(&"\\Flagged".to_string()));
    assert_eq!(r["results"][1]["new_id"], json!(imap_id(h, u, "Archive", archived[1]).await));
    let checked = assert_expunges_only_copied_or_own(h, &[]);
    assert_eq!(
        checked,
        vec![("UID STORE".to_string(), vec![a, c]), ("UID EXPUNGE".to_string(), vec![a, c])],
        "{:?}",
        h.imap.commands()
    );
    assert!(!h.imap.commands().iter().any(|c| verb_of(c) == "UID MOVE"));
    h.imap.assert_only_allowlisted();
}

#[tokio::test]
async fn copy_without_copyuid_never_deletes() {
    let s = setup_with(Opts { move_cap: false, copyuid: false, ..Opts::default() }).await;
    let (h, u) = (&s.h, &s.u);
    add_folder(&s, "Archive", None).await;
    let a = h.imap.add_message(&u.user, "INBOX", &raw("a"), &[]);
    let ia = imap_id(h, u, "INBOX", a).await;
    h.imap.clear_commands();
    let r = h.ok(&s.assistant, "move_messages", json!({ "account": "info", "ids": [ia], "to": "archive" })).await;
    assert_eq!(ok_ids(&r), vec![false]);
    assert_eq!(r["results"][0]["error"]["code"], "upstream_error");
    // Unconfirmed copy: the original stays, nothing is flagged or expunged.
    assert_eq!(h.imap.uids(&u.user, "INBOX"), vec![a]);
    assert_eq!(h.imap.uids(&u.user, "Archive").len(), 1);
    assert!(assert_expunges_only_copied_or_own(h, &[]).is_empty(), "{:?}", h.imap.commands());
    h.imap.assert_only_allowlisted();
}

#[tokio::test]
async fn trash_and_junk_need_delete() {
    let s = setup().await;
    let (h, u) = (&s.h, &s.u);
    // A trash folder known only by name (no special-use flag) counts as Trash too, in other languages and any case.
    for name in ["Papierkorb", "Corbeille", "Indésirables", "КОРЗИНА", "Posta indesiderata", "Alte Spam-Regeln"]
    {
        add_folder(&s, name, None).await;
    }
    // Below Trash is Trash too.
    add_folder(&s, "Trash/alt", None).await;
    let a = h.imap.add_message(&u.user, "INBOX", &raw("a"), &[]);
    let ia = imap_id(h, u, "INBOX", a).await;
    h.imap.clear_commands();
    for to in [
        "trash",
        "spam",
        "Junk",
        "Trash",
        "Papierkorb",
        "Trash/alt",
        "corbeille",
        "Indésirables",
        "КОРЗИНА",
        "Posta indesiderata",
        "Alte Spam-Regeln",
    ] {
        let e = h.err(&s.assistant, "move_messages", json!({ "account": "info", "ids": [ia], "to": to })).await;
        assert_eq!(e, "forbidden", "{to}");
    }
    // Refused before any server write.
    assert!(!h.imap.commands().iter().any(|c| matches!(verb_of(c).as_str(), "UID MOVE" | "UID COPY" | "UID STORE")));
    let r = h.ok(&s.full, "move_messages", json!({ "account": "info", "ids": [ia], "to": "trash" })).await;
    let in_trash = r["results"][0]["new_id"].as_str().unwrap().to_string();
    assert_eq!(h.imap.uids(&u.user, "Trash").len(), 1);
    assert!(h.imap.uids(&u.user, "INBOX").is_empty());
    // Out of Trash is organize.
    let r = h.ok(&s.assistant, "move_messages", json!({ "account": "info", "ids": [in_trash], "to": "inbox" })).await;
    assert_eq!(ok_ids(&r), vec![true]);
    assert_eq!(h.imap.uids(&u.user, "INBOX").len(), 1);
    assert!(h.imap.uids(&u.user, "Trash").is_empty());
    // Out of Junk (or a junk folder known by name) needs delete: it promotes spam.
    let j = h.imap.add_message(&u.user, "Junk", &raw("j"), &[]);
    let ij = imap_id(h, u, "Junk", j).await;
    let k = h.imap.add_message(&u.user, "Indésirables", &raw("k"), &[]);
    let ik = imap_id(h, u, "Indésirables", k).await;
    let b = h.imap.add_message(&u.user, "INBOX", &raw("b"), &[]);
    let ib = imap_id(h, u, "INBOX", b).await;
    h.imap.clear_commands();
    for (ids, to) in [(vec![&ij], "inbox"), (vec![&ik], "INBOX"), (vec![&ib, &ij], "inbox")] {
        let e = h.err(&s.assistant, "move_messages", json!({ "account": "info", "ids": ids, "to": to })).await;
        assert_eq!(e, "forbidden", "{to}");
    }
    assert!(!h.imap.commands().iter().any(|c| matches!(verb_of(c).as_str(), "UID MOVE" | "UID COPY" | "UID STORE")));
    assert_eq!((h.imap.uids(&u.user, "Junk").len(), h.imap.uids(&u.user, "Indésirables").len()), (1, 1));
    let r = h.ok(&s.full, "move_messages", json!({ "account": "info", "ids": [ij, ik], "to": "inbox" })).await;
    assert_eq!(ok_ids(&r), vec![true, true]);
    assert!(h.imap.uids(&u.user, "Junk").is_empty() && h.imap.uids(&u.user, "Indésirables").is_empty());
    // A reader cannot organize at all.
    let reader = h.token("p", "reader", vec![g("info", "reader")]).await;
    assert_eq!(
        h.err(&reader, "move_messages", json!({ "account": "info", "ids": [ia], "to": "inbox" })).await,
        "forbidden"
    );
    h.imap.assert_only_allowlisted();
}

#[tokio::test]
async fn delete_draft_expunges_only_the_own_draft() {
    let s = setup().await;
    let (h, u) = (&s.h, &s.u);
    let human = h.imap.add_message(&u.user, "Drafts", &raw("human"), &["\\Draft"]);
    let create = || {
        json!({ "account": "info", "request_key": uuid::Uuid::new_v4().to_string(), "to": ["x@example.net"],
                "subject": "Angebot", "body_text": "Text" })
    };
    let d = h.ok(&s.assistant, "create_draft", create()).await;
    let rev = d["revision"].as_str().unwrap().to_string();
    let uid: u32 = rev.rsplit('-').next().unwrap().parse().unwrap();
    h.imap.clear_commands();
    h.ok(
        &s.assistant,
        "delete_draft",
        json!({ "account": "info", "draft_id": d["draft_id"], "expected_revision": rev }),
    )
    .await;
    assert_eq!(h.imap.uids(&u.user, "Drafts"), vec![human]);
    let checked = assert_expunges_only_copied_or_own(h, &[uid]);
    assert_eq!(checked, vec![("UID STORE".to_string(), vec![uid]), ("UID EXPUNGE".to_string(), vec![uid])]);
    assert_eq!(
        h.err(&s.assistant, "delete_draft", json!({ "account": "info", "draft_id": d["draft_id"] })).await,
        "not_found"
    );

    // Changed by a person: never deleted.
    let d = h.ok(&s.assistant, "create_draft", create()).await;
    let uid2: u32 = d["revision"].as_str().unwrap().rsplit('-').next().unwrap().parse().unwrap();
    h.imap.expunge_external(&u.user, "Drafts", uid2);
    h.imap.add_message(&u.user, "Drafts", &raw("rewritten"), &["\\Draft"]);
    h.imap.clear_commands();
    assert_eq!(
        h.err(&s.assistant, "delete_draft", json!({ "account": "info", "draft_id": d["draft_id"] })).await,
        "draft_conflict"
    );
    assert!(assert_expunges_only_copied_or_own(h, &[]).is_empty());
    // A human draft id is not a Dove draft id.
    let hid = imap_id(h, u, "Drafts", human).await;
    assert_eq!(h.err(&s.assistant, "delete_draft", json!({ "account": "info", "draft_id": hid })).await, "not_found");
    assert!(h.imap.uids(&u.user, "Drafts").contains(&human));
    h.imap.assert_only_allowlisted();
}

/// `CopiedUid` is the only way to flag a non-draft message `\Deleted`; only `ImapSession::move_uids` constructs one.
#[test]
fn only_move_uids_constructs_copied_uid() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk(&root.join("src"), &mut files);
    let mut uses = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        let n = text.matches("confirmed_by_copyuid(").count();
        if n > 0 {
            uses.push((f.strip_prefix(root).unwrap().to_string_lossy().into_owned(), n));
        }
    }
    // The definition and its single call, both in the session.
    assert_eq!(uses, vec![("src/imap/session.rs".to_string(), 2)]);
    let session = std::fs::read_to_string(root.join("src/imap/session.rs")).unwrap();
    let call = session.find("CopiedUid::confirmed_by_copyuid(").expect("the call");
    let move_fn = session.find("pub async fn move_uids(").expect("move_uids");
    let next_fn = session[move_fn + 1..].find("\n    pub async fn ").map(|i| i + move_fn + 1).unwrap_or(session.len());
    assert!(call > move_fn && call < next_fn, "the constructor is called outside move_uids");
    // Struct literals elsewhere would bypass it: only the constructor and the ops unit-test helper build one.
    assert_eq!(session.matches("Self { folder:").count(), 2);
}
