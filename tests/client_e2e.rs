//! Remote client commands through the real `dove` binary (spec 5.6, AC22 local part).
//!
//! Every command runs with a cleared environment, a temporary HOME and an unreachable D-Bus address, so the real
//! user configuration and keychain are never touched. The OS credential store is therefore unavailable here, which
//! is exactly the case where `dove login` must refuse instead of silently falling back to a file.

mod support;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use dove::admin::AdminRequest;
use serde_json::{Value, json};
use support::fake_google::{Fault, MessageSpec};
use support::harness::Harness;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

struct Client {
    home: tempfile::TempDir,
    server: String,
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Client {
    fn new(h: &Harness) -> Self {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join("project")).unwrap();
        Self { home, server: h.base.clone() }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.home.path().join(rel)
    }

    fn command(&self, args: &[&str]) -> tokio::process::Command {
        let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_dove"));
        c.env_clear()
            .env("HOME", self.home.path())
            .env("PATH", "/usr/bin:/bin")
            .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/dove-test-bus")
            .current_dir(self.path("project"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        c
    }

    async fn run_env(&self, args: &[&str], stdin: &str, env: &[(&str, &str)]) -> Out {
        let mut cmd = self.command(args);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().unwrap();
        let mut sin = child.stdin.take().unwrap();
        sin.write_all(stdin.as_bytes()).await.unwrap();
        drop(sin);
        let out = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output()).await.unwrap().unwrap();
        Out {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    async fn run(&self, args: &[&str], stdin: &str) -> Out {
        self.run_env(args, stdin, &[]).await
    }

    async fn ok(&self, args: &[&str], stdin: &str) -> Out {
        let o = self.run(args, stdin).await;
        assert_eq!(o.code, 0, "{args:?}\nstdout: {}\nstderr: {}", o.stdout, o.stderr);
        o
    }

    async fn login(&self, profile: &str, invitation: &str) -> Out {
        let file = self.path(&format!("{profile}.token"));
        self.ok(
            &["login", "--server", &self.server, "--profile", profile, "--secret-file", file.to_str().unwrap()],
            &format!("{invitation}\n"),
        )
        .await
    }
}

async fn setup() -> Harness {
    let h = Harness::start_loopback_public(|c| c.oauth.redeem_per_minute = 1000).await;
    h.mailbox("info", "info@acme.test");
    h.mailbox("billing", "billing@acme.test");
    h.project("acme", &["info", "billing"]).await;
    h
}

async fn invite(h: &Harness, name: &str, accounts: &[&str], caps: &str) -> String {
    let v = h
        .admin(AdminRequest::ClientsInvite {
            name: name.into(),
            project: "acme".into(),
            accounts: accounts.iter().map(|s| s.to_string()).collect(),
            capabilities: caps.into(),
            expires: None,
            allow_ip: vec![],
        })
        .await
        .unwrap();
    v["invitation"].as_str().unwrap().to_string()
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[tokio::test]
async fn login_requires_explicit_store_and_reads_invitation_from_stdin_only() {
    let h = setup().await;
    let c = Client::new(&h);
    let inv = invite(&h, "laptop", &["all"], "read").await;
    // No OS credential store available: refuse before redeeming, point at --secret-file, never fall back silently.
    let o = c.run(&["login", "--server", &c.server, "--profile", "acme"], &format!("{inv}\n")).await;
    assert_ne!(o.code, 0);
    assert!(o.stderr.contains("--secret-file"), "{}", o.stderr);
    assert!(!c.path(".config/dove/profiles.toml").exists());
    // The invitation cannot be passed in argv.
    let o = c.run(&["login", "--server", &c.server, "--profile", "acme", "--invitation", &inv], "").await;
    assert_ne!(o.code, 0);
    // The refused attempt did not consume the invitation.
    let o = c.login("acme", &inv).await;
    assert!(o.stdout.contains("billing <billing@acme.test>: read"), "{}", o.stdout);
    assert!(o.stdout.contains("info <info@acme.test>: read"));
    let token_file = c.path("acme.token");
    assert_eq!(mode(&token_file), 0o600);
    let token = std::fs::read_to_string(&token_file).unwrap().trim().to_string();
    assert!(token.starts_with("dove_"));
    let profiles = std::fs::read_to_string(c.path(".config/dove/profiles.toml")).unwrap();
    assert!(!profiles.contains(&token) && profiles.contains("file:"), "{profiles}");
    assert_eq!(mode(&c.path(".config/dove/profiles.toml")), 0o600);
    assert!(!o.stdout.contains(&inv) && !o.stderr.contains(&inv) && !o.stdout.contains(&token));
    // Reused invitation fails cleanly.
    let o = c
        .run(
            &["login", "--server", &c.server, "--profile", "two", "--secret-file", c.path("two").to_str().unwrap()],
            &format!("{inv}\n"),
        )
        .await;
    assert_ne!(o.code, 0);
    assert!(o.stderr.contains("invalid, expired or already used"), "{}", o.stderr);
    // A loose secret file is refused.
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let o = c.run(&["status", "--profile", "acme"], "").await;
    assert_ne!(o.code, 0);
    assert!(o.stderr.contains("chmod 600"), "{}", o.stderr);
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    // Status shows connectivity and rights.
    let o = c.ok(&["status", "--profile", "acme", "--json"], "").await;
    let v: Value = serde_json::from_str(&o.stdout).unwrap();
    assert_eq!(v["connected"], true);
    assert_eq!(v["mailboxes"].as_array().unwrap().len(), 2);
    // Headless: an operator-issued token via stdin.
    let t = h.token("acme", "ci", vec![support::harness::g("info", "read")]).await;
    let f = c.path("ci.token");
    let o = c
        .ok(
            &["login", "--server", &c.server, "--profile", "ci", "--token-stdin", "--secret-file", f.to_str().unwrap()],
            &format!("{t}\n"),
        )
        .await;
    assert!(o.stdout.contains("info <info@acme.test>: read"));
}

#[tokio::test]
async fn read_and_draft_commands_use_the_connection_rights_only() {
    let h = setup().await;
    let c = Client::new(&h);
    let id = h.google.add_message(
        "info@acme.test",
        MessageSpec {
            from: "Ann <ann@example.test>".into(),
            to: vec!["info@acme.test".into()],
            subject: "Invoice 42".into(),
            text: Some("Please pay.".into()),
            internal_date_ms: 1_700_000_000_000,
            ..Default::default()
        },
    );
    c.login("ro", &invite(&h, "reader", &["info"], "read").await).await;
    let o = c.ok(&["message", "get", "--profile", "ro", "--account", "info", "--id", &id], "").await;
    assert!(o.stdout.contains("Please pay."), "{}", o.stdout);
    let o = c.ok(&["message", "get", "--profile", "ro", "--account", "info", "--id", &id, "--json"], "").await;
    let v: Value = serde_json::from_str(&o.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["result"]["message"]["subject"], "Invoice 42");
    // Unknown mailbox and write attempts fail with stable codes and a non-zero exit.
    let o = c.run(&["message", "get", "--profile", "ro", "--account", "billing", "--id", &id], "").await;
    assert_ne!(o.code, 0);
    assert!(o.stderr.contains("not_found"), "{}", o.stderr);
    let o = c
        .run(
            &[
                "draft",
                "create",
                "--profile",
                "ro",
                "--account",
                "info",
                "--to",
                "a@b.test",
                "--subject",
                "s",
                "--body",
                "b",
            ],
            "",
        )
        .await;
    assert_ne!(o.code, 0);
    assert!(o.stderr.contains("forbidden"), "{}", o.stderr);
    // No transport or admin switches exist on remote commands.
    let o = c.run(&["search", "--profile", "ro", "--socket", "/tmp/x.sock"], "").await;
    assert_ne!(o.code, 0);
    assert!(o.stderr.contains("unexpected argument"), "{}", o.stderr);
    // Search reaches the server's search_messages tool (its result depends on the index implementation).
    let o = c
        .run(&["search", "--profile", "ro", "--from-domain", "example.test", "--select", "subject", "--json"], "")
        .await;
    let v: Value = serde_json::from_str(&o.stdout).unwrap_or(Value::Null);
    assert!(v.get("ok").is_some(), "stdout: {} stderr: {}", o.stdout, o.stderr);
    // Batch reads JSON from stdin and calls batch_read (may be unimplemented in this build).
    let o = c.run(&["batch", "--profile", "ro", "--json"], r#"{"items": []}"#).await;
    assert!(serde_json::from_str::<Value>(&o.stdout).is_ok_and(|v| v.get("ok").is_some()), "{} {}", o.stdout, o.stderr);

    // Draft round trip with a draft-enabled connection; the request key is printed for safe retries.
    c.login("rw", &invite(&h, "writer", &["info"], "read,draft").await).await;
    let key = uuid::Uuid::new_v4().to_string();
    let args = [
        "draft",
        "create",
        "--profile",
        "rw",
        "--account",
        "info",
        "--to",
        "bob@example.test",
        "--subject",
        "Hello",
        "--body",
        "First",
        "--request-key",
        &key,
        "--json",
    ];
    let o = c.ok(&args, "").await;
    assert!(o.stderr.contains(&key));
    let created: Value = serde_json::from_str(&o.stdout).unwrap();
    let draft_id = created["result"]["draft_id"].as_str().unwrap().to_string();
    // Retrying with the same key returns the same draft, never a second one.
    let again: Value = serde_json::from_str(&c.ok(&args, "").await.stdout).unwrap();
    assert_eq!(again["result"]["draft_id"], draft_id.as_str());
    assert_eq!(h.google.drafts("info@acme.test").len(), 1);
    let rev = created["result"]["revision"].as_str().unwrap();
    let o = c
        .ok(
            &[
                "draft",
                "update",
                "--profile",
                "rw",
                "--account",
                "info",
                "--id",
                &draft_id,
                "--revision",
                rev,
                "--body-file",
                "-",
                "--json",
            ],
            "Second version",
        )
        .await;
    assert_eq!(serde_json::from_str::<Value>(&o.stdout).unwrap()["ok"], true);
    let o = c.ok(&["draft", "get", "--profile", "rw", "--account", "info", "--id", &draft_id], "").await;
    assert!(o.stdout.contains("Second version"), "{}", o.stdout);
    // Sending is not granted: the tool is refused.
    let o = c
        .run(&["draft", "send", "--profile", "rw", "--account", "info", "--id", &draft_id, "--revision", "x"], "")
        .await;
    assert_ne!(o.code, 0);
}

#[tokio::test]
async fn mcp_install_preserves_entries_and_is_idempotent() {
    let h = setup().await;
    let c = Client::new(&h);
    c.login("acme", &invite(&h, "laptop", &["info"], "read").await).await;
    let token = std::fs::read_to_string(c.path("acme.token")).unwrap().trim().to_string();
    let exe = std::fs::canonicalize(env!("CARGO_BIN_EXE_dove")).unwrap();

    // Claude Code, user scope, with existing unrelated content.
    let claude = c.path(".claude.json");
    let original = "{\n  \"numStartups\": 7,\n  \"mcpServers\": {\n    \"other\": {\"command\": \"/bin/other\", \"args\": [\"x\"]}\n  },\n  \"projects\": {\"/p\": {\"allowedTools\": []}}\n}\n";
    std::fs::write(&claude, original).unwrap();
    std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o640)).unwrap();
    let o = c.ok(&["mcp", "install", "--profile", "acme", "--client", "claude-code"], "").await;
    assert!(o.stdout.contains("Added"), "{}", o.stdout);
    let after = std::fs::read_to_string(&claude).unwrap();
    let v: Value = serde_json::from_str(&after).unwrap();
    assert_eq!(v["numStartups"], 7);
    assert_eq!(v["projects"]["/p"]["allowedTools"], json!([]));
    assert_eq!(v["mcpServers"]["other"], json!({"command": "/bin/other", "args": ["x"]}), "unrelated entry kept");
    let keys: Vec<String> =
        serde_json::from_str::<indexmap::IndexMap<String, Value>>(&after).unwrap().keys().cloned().collect();
    assert_eq!(keys, ["numStartups", "mcpServers", "projects"], "key order kept");
    let entry = &v["mcpServers"]["dove-acme"];
    assert_eq!(entry["command"], exe.to_str().unwrap());
    assert_eq!(entry["args"], json!(["mcp", "stdio", "--profile", "acme"]));
    assert_eq!(mode(&claude), 0o640, "existing mode kept");
    assert!(!after.contains(&token));
    let o = c.ok(&["mcp", "install", "--profile", "acme", "--client", "claude-code"], "").await;
    assert!(o.stdout.contains("Already present"));
    assert_eq!(std::fs::read_to_string(&claude).unwrap(), after, "second install is a no-op");

    // Project scope writes .mcp.json in the current directory, without credentials.
    c.ok(&["mcp", "install", "--profile", "acme", "--client", "claude-code", "--scope", "project"], "").await;
    let project = std::fs::read_to_string(c.path("project/.mcp.json")).unwrap();
    assert!(!project.contains(&token) && !project.contains("dove_") && project.contains("--profile"), "{project}");

    // Codex keeps comments and other servers.
    let codex = c.path(".codex/config.toml");
    std::fs::create_dir_all(codex.parent().unwrap()).unwrap();
    std::fs::write(&codex, "# personal\nmodel = \"gpt-x\"\n\n[mcp_servers.other]\ncommand = \"/bin/other\"\n").unwrap();
    c.ok(&["mcp", "install", "--profile", "acme", "--client", "codex"], "").await;
    let text = std::fs::read_to_string(&codex).unwrap();
    assert!(text.starts_with("# personal\nmodel = \"gpt-x\"\n"), "{text}");
    assert!(text.contains("[mcp_servers.other]") && text.contains("[mcp_servers.dove-acme]"));
    let parsed: toml::Table = toml::from_str(&text).unwrap();
    assert_eq!(parsed["mcp_servers"]["dove-acme"]["args"].as_array().unwrap().len(), 4);
    c.ok(&["mcp", "install", "--profile", "acme", "--client", "codex"], "").await;
    assert_eq!(std::fs::read_to_string(&codex).unwrap(), text);

    // An invalid existing file is never overwritten.
    std::fs::write(&claude, "{ not json").unwrap();
    let o = c.run(&["mcp", "install", "--profile", "acme", "--client", "claude-code"], "").await;
    assert_ne!(o.code, 0);
    assert_eq!(std::fs::read_to_string(&claude).unwrap(), "{ not json");
    // Unknown profile: nothing written.
    let o = c.run(&["mcp", "install", "--profile", "nope", "--client", "codex", "--scope", "project"], "").await;
    assert_ne!(o.code, 0);
    assert!(!c.path("project/.codex/config.toml").exists());
}

struct Bridge {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    lines: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
}

impl Bridge {
    fn start(c: &Client, profile: &str) -> Self {
        let mut child = c.command(&["mcp", "stdio", "--profile", profile]).spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let lines = BufReader::new(child.stdout.take().unwrap()).lines();
        Self { child, stdin, lines }
    }

    async fn send(&mut self, v: &str) {
        self.stdin.write_all(v.as_bytes()).await.unwrap();
        self.stdin.write_all(b"\n").await.unwrap();
        self.stdin.flush().await.unwrap();
    }

    async fn recv(&mut self) -> Value {
        let line =
            tokio::time::timeout(Duration::from_secs(20), self.lines.next_line()).await.unwrap().unwrap().unwrap();
        serde_json::from_str(&line).unwrap()
    }
}

#[tokio::test]
async fn stdio_bridge_round_trip_cancellation_and_revocation() {
    let h = setup().await;
    let c = Client::new(&h);
    c.login("acme", &invite(&h, "bridge", &["info"], "read").await).await;
    let id = h.google.add_message(
        "info@acme.test",
        MessageSpec { from: "a@x.test".into(), subject: "S".into(), text: Some("T".into()), ..Default::default() },
    );
    let mut b = Bridge::start(&c, "acme");
    b.send(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#).await;
    let v = b.recv().await;
    assert_eq!((v["id"].clone(), v["result"]["protocolVersion"].clone()), (json!(1), json!("2025-06-18")));
    b.send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).await;
    b.send("this is not json").await;
    let v = b.recv().await;
    assert_eq!(v["error"]["code"], -32700);
    b.send(r#"{"jsonrpc":"2.0","id":"two","method":"tools/list"}"#).await;
    let v = b.recv().await;
    assert_eq!(v["id"], "two");
    assert!(v["result"]["tools"].as_array().unwrap().iter().any(|t| t["name"] == "get_message"));
    b.send(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_accounts","arguments":{}}}"#).await;
    let v = b.recv().await;
    assert_eq!(v["result"]["structuredContent"]["accounts"][0]["account"], "info");

    // Cancellation: a slow call is cancelled; its response never arrives, later requests still work.
    h.google.fail_next("GET", &format!("messages/{id}"), Fault::Delay(Duration::from_secs(3)));
    b.send(&format!(
        r#"{{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{{"name":"get_message","arguments":{{"account":"info","message_id":"{id}"}}}}}}"#
    ))
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    b.send(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":10}}"#).await;
    b.send(r#"{"jsonrpc":"2.0","id":11,"method":"ping"}"#).await;
    assert_eq!(b.recv().await["id"], 11);
    let late = tokio::time::timeout(Duration::from_secs(4), b.lines.next_line()).await;
    assert!(late.is_err() || matches!(late, Ok(Ok(None))), "cancelled request must not answer: {late:?}");

    // EOF ends the bridge cleanly.
    drop(b.stdin);
    let status = tokio::time::timeout(Duration::from_secs(10), b.child.wait()).await.unwrap().unwrap();
    assert!(status.success());

    // After revocation the bridge answers with a clear error instead of hanging.
    h.admin(AdminRequest::ClientsRevoke { name: "bridge".into() }).await.unwrap();
    let mut b = Bridge::start(&c, "acme");
    b.send(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#).await;
    let v = b.recv().await;
    assert_eq!(v["error"]["code"], -32001);
    drop(b.stdin);
    let _ = tokio::time::timeout(Duration::from_secs(10), b.child.wait()).await;
}

#[tokio::test]
async fn logout_revokes_remotely_and_removes_local_state() {
    let h = setup().await;
    let c = Client::new(&h);
    c.login("acme", &invite(&h, "gone", &["info"], "read").await).await;
    c.login("keep", &invite(&h, "kept", &["info"], "read").await).await;
    let keep_token = std::fs::read_to_string(c.path("keep.token")).unwrap().trim().to_string();
    // Non-interactive logout without --revoke keeps the server connection and says so.
    let o = c.ok(&["logout", "--profile", "keep"], "").await;
    assert!(o.stdout.contains("stays valid"));
    assert!(!c.path("keep.token").exists());
    let r =
        h.post_mcp(Some(&keep_token), json!({"jsonrpc":"2.0","id":1,"method":"ping"}), &[("host", &h.base[7..])]).await;
    assert_eq!(r.status(), 200);
    // --revoke ends the connection on the server.
    c.ok(&["logout", "--profile", "acme", "--revoke"], "").await;
    assert!(!c.path("acme.token").exists());
    let show = h.admin(AdminRequest::ClientsShow { name: "gone".into() }).await.unwrap();
    assert!(show["revoked_at"].is_string());
    let profiles = std::fs::read_to_string(c.path(".config/dove/profiles.toml")).unwrap();
    assert!(!profiles.contains("acme") && !profiles.contains("keep"));
}

#[tokio::test]
async fn doctor_and_connect_info_report_without_secrets() {
    let h = setup().await;
    let c = Client::new(&h);
    c.login("acme", &invite(&h, "doc", &["info"], "read,draft").await).await;
    let token = std::fs::read_to_string(c.path("acme.token")).unwrap().trim().to_string();
    let o = c.ok(&["doctor", "--profile", "acme"], "").await;
    for check in ["profile_file", "credential", "network", "discovery", "grants"] {
        assert!(o.stdout.contains(&format!("ok   {check}")), "{check}: {}", o.stdout);
    }
    assert!(o.stdout.contains("info <info@acme.test>: read,draft"));
    let o = c.ok(&["connect-info", "--profile", "acme"], "").await;
    assert!(o.stdout.contains(&format!("{}/mcp", c.server)));
    assert!(o.stdout.contains("info <info@acme.test>: read,draft"));
    // Missing credential is reported, not crashed on.
    std::fs::remove_file(c.path("acme.token")).unwrap();
    let o = c.run(&["doctor", "--profile", "acme"], "").await;
    assert_ne!(o.code, 0);
    assert!(o.stdout.contains("FAIL credential"), "{}", o.stdout);
    for out in [&o.stdout, &o.stderr] {
        assert!(!out.contains(&token));
    }
}

/// Remote commands never connect to the admin socket, even when the admin socket variable points at a live socket.
/// An admin command with the same environment does connect, proving the variable is honoured there.
#[tokio::test]
async fn remote_commands_have_no_path_to_the_admin_socket() {
    let h = setup().await;
    let c = Client::new(&h);
    c.login("acme", &invite(&h, "agent", &["info"], "read").await).await;
    let sock = c.path("admin.sock");
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let acc = accepted.clone();
    let server = tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            acc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            drop(s);
        }
    });
    let env = [("DOVE_ADMIN_SOCKET", sock.to_str().unwrap())];
    for args in [
        vec!["status", "--profile", "acme"],
        vec!["search", "--profile", "acme", "--text", "x"],
        vec!["doctor", "--profile", "acme"],
        vec!["connect-info", "--profile", "acme"],
        vec!["mcp", "install", "--profile", "acme", "--client", "codex"],
        vec!["message", "get", "--profile", "acme", "--account", "info", "--id", "x1"],
    ] {
        c.run_env(&args, "", &env).await;
    }
    assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 0, "a remote command touched the admin socket");
    c.run_env(&["clients", "list"], "", &env).await;
    assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1, "control: admin commands use the socket");
    server.abort();
}
