//! Local mode end to end (PLAN A58): `dove local init|start|status`, admin over the per-user socket, the loopback
//! origin's Host check, a graceful stop, and an MCP client (the real `dove` binary) against a local-mode server.
//!
//! Every command runs with a cleared environment and a temporary HOME / `DOVE_LOCAL_HOME`, so no real configuration,
//! keychain or service is touched. Admin commands name the socket from the local config explicitly, so a server-mode
//! `/run/dove/admin.sock` on the test host is never used.

// Unix only: file modes, SIGTERM and the Unix admin socket.
#![cfg(unix)]

mod support;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use dove::admin::AdminRequest;
use serde_json::{Value, json};
use support::harness::Harness;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

struct Env {
    home: tempfile::TempDir,
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Env {
    fn new() -> Self {
        Self { home: tempfile::tempdir().unwrap() }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.home.path().join(rel)
    }

    fn command(&self, args: &[&str]) -> tokio::process::Command {
        let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_dove"));
        c.env_clear()
            .env("HOME", self.home.path())
            .env("DOVE_LOCAL_HOME", self.path("local"))
            .env("PATH", "/usr/bin:/bin")
            .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/dove-test-bus")
            .env("DOVE_NO_UPDATE_CHECK", "1")
            .current_dir(self.home.path())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        c
    }

    async fn run(&self, args: &[&str], stdin: &str) -> Out {
        let mut child = self.command(args).spawn().unwrap();
        child.stdin.take().unwrap().write_all(stdin.as_bytes()).await.unwrap();
        let o = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output()).await.unwrap().unwrap();
        Out {
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }

    async fn ok(&self, args: &[&str], stdin: &str) -> Out {
        let o = self.run(args, stdin).await;
        assert_eq!(o.code, 0, "{args:?}\nstdout: {}\nstderr: {}", o.stdout, o.stderr);
        o
    }
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// GET `path` on the loopback listener with an explicit Host header.
async fn get(port: u16, path: &str, host: &str) -> (u16, String) {
    let r =
        reqwest::Client::new().get(format!("http://127.0.0.1:{port}{path}")).header("host", host).send().await.unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

#[tokio::test]
async fn local_init_start_admin_and_stop() {
    let e = Env::new();
    let port = free_port();
    let port_s = port.to_string();
    let o = e.ok(&["local", "init", "--port", &port_s], "").await;
    assert!(o.stdout.contains("dove local install"), "{}", o.stdout);
    let local = e.path("local");
    let data = local.join("data");
    assert_eq!(mode(&data), 0o700);
    assert_eq!(mode(&data.join("secrets")), 0o700);
    for k in ["kek", "pepper", "index_key"] {
        assert_eq!(mode(&data.join("secrets").join(k)), 0o600, "{k}");
    }
    let cfg_file = local.join("dove.toml");
    assert_eq!(mode(&cfg_file), 0o600);
    let cfg = dove::config::Config::load(&cfg_file).unwrap();
    assert!(cfg.is_local());
    assert_eq!(cfg.public_url, format!("http://127.0.0.1:{port}"));
    let sock = cfg.admin.socket_path.clone();
    assert_eq!(sock, data.join("admin.sock"));
    let sock_s = sock.to_str().unwrap().to_string();

    // A second init changes nothing.
    let kek = std::fs::read(data.join("secrets").join("kek")).unwrap();
    let o = e.run(&["local", "init", "--port", &port_s], "").await;
    assert_ne!(o.code, 0);
    assert!(o.stderr.contains("already exists"), "{}", o.stderr);
    assert_eq!(std::fs::read(data.join("secrets").join("kek")).unwrap(), kek);

    let o = e.ok(&["local", "status"], "").await;
    assert!(o.stdout.contains("service:    not answering"), "{}", o.stdout);

    // Foreground start, logging to a file.
    let log = e.path("dove.log");
    let mut server = e.command(&["local", "start", "--log-file", log.to_str().unwrap()]).spawn().unwrap();
    let mut up = false;
    for _ in 0..80 {
        let o = e.run(&["local", "status"], "").await;
        if o.stdout.contains("service:    running") {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(up, "the local service did not come up; log: {}", std::fs::read_to_string(&log).unwrap_or_default());
    assert_eq!(mode(&log), 0o600);
    // The admin socket's directory is the private data directory.
    assert_eq!(mode(sock.parent().unwrap()), 0o700);

    // A second start refuses and leaves the running instance's admin socket alone (L1).
    let o = e.run(&["local", "start"], "").await;
    assert_ne!(o.code, 0);
    assert!(o.stderr.contains("already running"), "{}", o.stderr);
    let o = e.ok(&["local", "status"], "").await;
    assert!(o.stdout.contains("service:    running"), "{}", o.stdout);

    // Admin over the per-user socket, as the user who ran init.
    e.ok(&["projects", "create", "assistant", "--socket", &sock_s], "").await;
    let o = e.ok(&["projects", "list", "--json", "--socket", &sock_s], "").await;
    assert!(o.stdout.contains("assistant"), "{}", o.stdout);
    let o = e.ok(&["doctor", "--json", "--socket", &sock_s], "").await;
    let checks: Value = serde_json::from_str(&o.stdout).unwrap();
    let row = |name: &str| checks.as_array().unwrap().iter().find(|c| c["check"] == name).cloned();
    assert_eq!(row("mode").unwrap()["detail"], "local");
    assert_eq!(row("service_user").unwrap()["ok"], true, "{checks}");
    assert_eq!(row("proxy_secret").unwrap()["ok"], true, "{checks}");
    assert_eq!(row("config").unwrap()["ok"], true, "{checks}");
    assert!(row("tailscale").is_none(), "no Tailscale check in local mode: {checks}");
    // Without --socket the CLI finds the local config's socket (unless a server-mode socket is visible here).
    if !Path::new(dove::config::DEFAULT_ADMIN_SOCKET).exists() {
        let o = e.ok(&["projects", "list", "--json"], "").await;
        assert!(o.stdout.contains("assistant"), "{}", o.stdout);
        // Which instance answered is always named on stderr (L3).
        assert!(o.stderr.contains(&format!("answered by your local instance ({sock_s})")), "{}", o.stderr);
    }

    // Plain HTTP on the loopback origin, and only with that exact Host.
    let origin = format!("127.0.0.1:{port}");
    let (status, body) = get(port, "/.well-known/oauth-protected-resource", &origin).await;
    assert_eq!(status, 200, "{body}");
    let meta: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(meta["resource"], format!("http://127.0.0.1:{port}/mcp"));
    for host in [format!("localhost:{port}"), format!("evil.example:{port}"), "127.0.0.1".to_string()] {
        let (status, _) = get(port, "/.well-known/oauth-protected-resource", &host).await;
        assert_eq!(status, 421, "Host {host}");
    }
    let r = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/mcp"))
        .header("host", &origin)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);

    // SIGTERM stops it gracefully.
    let pid = server.id().unwrap().to_string();
    assert!(std::process::Command::new("kill").args(["-TERM", &pid]).status().unwrap().success());
    let status = tokio::time::timeout(Duration::from_secs(20), server.wait()).await.unwrap().unwrap();
    assert!(status.success(), "{status:?}");
    let o = e.ok(&["local", "status"], "").await;
    assert!(o.stdout.contains("service:    not answering"), "{}", o.stdout);
    assert!(std::fs::metadata(&log).unwrap().len() > 0);

    // `dove local stop` stops it over the admin channel, without a signal (P4: the Windows task cannot be relied on).
    let mut server = e.command(&["local", "start", "--log-file", log.to_str().unwrap()]).spawn().unwrap();
    let mut up = false;
    for _ in 0..80 {
        if e.run(&["local", "status"], "").await.stdout.contains("service:    running") {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(up, "the local service did not come up again");
    let o = e.ok(&["local", "stop"], "").await;
    assert!(o.stdout.contains("Dove stopped."), "{}", o.stdout);
    let status = tokio::time::timeout(Duration::from_secs(20), server.wait()).await.unwrap().unwrap();
    assert!(status.success(), "{status:?}");
    let o = e.ok(&["local", "stop"], "").await;
    assert!(o.stdout.contains("Dove was not running."), "{}", o.stdout);
}

/// A local-mode server (plain HTTP on 127.0.0.1) with an IMAP mailbox, used by the real client: login with an
/// invitation, the MCP stdio bridge, and `dove mcp install --client claude-desktop`.
#[tokio::test]
async fn mcp_client_against_local_mode() {
    let h = Harness::start_local(|c| c.secrets.proxy_secret_file = None).await;
    assert!(h.app().cfg.is_local());
    h.imap_mailbox("personal", "me@home.test").await;
    h.project("assistant", &["personal"]).await;
    let v = h
        .admin(AdminRequest::ClientsInvite {
            name: "desktop".into(),
            project: "assistant".into(),
            accounts: vec!["personal".into()],
            capabilities: "read".into(),
            expires: None,
            allow_ip: vec![],
        })
        .await
        .unwrap();
    let invitation = v["invitation"].as_str().unwrap().to_string();

    let e = Env::new();
    let secret = e.path("desktop.token");
    e.ok(
        &["login", "--server", &h.base, "--profile", "desktop", "--secret-file", secret.to_str().unwrap()],
        &format!("{invitation}\n"),
    )
    .await;

    let mut child = e.command(&["mcp", "stdio", "--profile", "desktop"]).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut recv = async || -> Value {
        let line = tokio::time::timeout(Duration::from_secs(20), lines.next_line()).await.unwrap().unwrap().unwrap();
        serde_json::from_str(&line).unwrap()
    };
    let initialize = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#;
    stdin.write_all(format!("{initialize}\n").as_bytes()).await.unwrap();
    assert_eq!(recv().await["id"], 1);
    for msg in [
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_accounts","arguments":{}}}"#,
    ] {
        stdin.write_all(format!("{msg}\n").as_bytes()).await.unwrap();
    }
    let v = recv().await;
    assert_eq!(v["id"], 2);
    assert_eq!(v["result"]["structuredContent"]["accounts"][0]["account"], "personal", "{v}");
    drop(stdin);
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait()).await.unwrap().unwrap();
    assert!(status.success());

    // Claude Desktop's config (Linux: the XDG config directory).
    let o = e.ok(&["mcp", "install", "--client", "claude-desktop", "--profile", "desktop"], "").await;
    assert!(o.stdout.contains("Restart Claude Desktop"), "{}", o.stdout);
    let file = e.path(".config/Claude/claude_desktop_config.json");
    let cfg: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let entry = &cfg["mcpServers"]["dove-desktop"];
    assert_eq!(entry["args"], json!(["mcp", "stdio", "--profile", "desktop"]), "{cfg}");
    assert!(entry.get("type").is_none(), "{cfg}");
    assert_eq!(mode(&file), 0o600);
    let o = e
        .run(&["mcp", "install", "--client", "claude-desktop", "--profile", "desktop", "--scope", "project"], "")
        .await;
    assert_ne!(o.code, 0);
}

/// P1: when another user holds the local port (here `nobody`, which needs passwordless `sudo -n -u nobody` like AC19),
/// `dove login` refuses before it connects, so the invitation never reaches that listener. Linux only (the owner
/// check reads /proc/net/tcp; macOS does not check, see docs/deployment.md).
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs passwordless sudo -n -u nobody"]
async fn login_never_sends_to_a_loopback_port_of_another_user() {
    let e = Env::new();
    let port = free_port();
    // Records everything the first connection sends, then prints it.
    let script = format!(
        "import socket,sys\ns=socket.socket()\ns.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n\
         s.bind(('127.0.0.1',{port}))\ns.listen(4)\ns.settimeout(20)\nprint('ready',flush=True)\nc,_=s.accept()\nc.settimeout(3)\n\
         data=b''\ntry:\n  while True:\n    d=c.recv(65536)\n    if not d: break\n    data+=d\nexcept Exception: pass\n\
         sys.stdout.write('received:'+data.decode('latin1'))\n"
    );
    let mut squatter = tokio::process::Command::new("sudo")
        .args(["-n", "-u", "nobody", "python3", "-c", &script])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut out = BufReader::new(squatter.stdout.take().unwrap());
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(10), out.read_line(&mut line)).await.unwrap().unwrap();
    assert_eq!(line.trim(), "ready");

    let server = format!("http://127.0.0.1:{port}");
    let file = e.path("p.secret");
    let args = ["login", "--server", &server, "--profile", "p", "--secret-file", file.to_str().unwrap()];
    let o = e.run(&args, "dovei_secretinvitation\n").await;
    assert_ne!(o.code, 0, "{}", o.stdout);
    assert!(o.stderr.contains("belongs to another user"), "{}", o.stderr);

    // Our own empty connection ends the squatter; the first connection it saw must be this one, not the CLI's.
    drop(std::net::TcpStream::connect(("127.0.0.1", port)).unwrap());
    let mut rest = String::new();
    tokio::time::timeout(Duration::from_secs(10), tokio::io::AsyncReadExt::read_to_string(&mut out, &mut rest))
        .await
        .unwrap()
        .unwrap();
    assert!(rest.starts_with("received:"), "{rest}");
    assert!(!rest.contains("dovei_"), "the invitation reached another user's listener: {rest}");
    let _ = squatter.wait().await;
}
