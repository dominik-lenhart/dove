//! End-to-end harness: fake Google + Dove HTTP server on loopback + small MCP client.

use std::sync::Arc;

use dove::admin::ops::{Actor, GrantSpec};
use dove::admin::{AdminRequest, server};
use dove::app::App;
use dove::config::Config;
use dove::gmail::gateway::Upstream;
use dove::testing::TestEnv;
use serde_json::{Value, json};

use super::fake_google::FakeGoogle;
use super::fake_imap::FakeImap;

pub const CLIENT_ID: &str = "000000000000-example.apps.googleusercontent.com";
pub const CLIENT_SECRET: &str = "test-client-secret";
pub const HOST: &str = "dove.example.com";

pub struct Harness {
    pub env: TestEnv,
    pub google: FakeGoogle,
    /// Fake IMAP/SMTP server (plaintext, loopback); IMAP mailboxes connect to it.
    pub imap: FakeImap,
    pub base: String,
    pub http: reqwest::Client,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// An IMAP mailbox connected through the real `AccountsConnectImap` path.
#[allow(dead_code)]
pub struct FakeImapUser {
    pub alias: String,
    pub email: String,
    /// IMAP/SMTP login on the fake server (the email address).
    pub user: String,
    pub password: String,
    pub account_id: String,
}

/// A password with characters that need an IMAP literal or quoting (space, quote, backslash, braces, umlaut).
pub const IMAP_PASSWORD: &str = "p\"a ss\\w{0}rd-ä";

pub fn g(account: &str, actions: &str) -> GrantSpec {
    GrantSpec { account: account.into(), actions: actions.into() }
}

impl Harness {
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    pub async fn start_with(customize: impl FnOnce(&mut Config)) -> Self {
        let google = FakeGoogle::start(CLIENT_ID, CLIENT_SECRET).await;
        let env = TestEnv::with_upstream(Upstream::single_origin(&google.base_url), |c| {
            c.limits.tool_call_timeout_secs = 8;
            c.limits.upstream_request_timeout_secs = 3;
            c.limits.client_requests_per_minute = 10_000;
            c.limits.client_burst = 10_000;
            customize(c)
        });
        let (base, server) = serve(env.app.clone()).await;
        let imap = FakeImap::start().await;
        Self { env, google, imap, base, http: reqwest::Client::new(), server }
    }

    /// Like [`Harness::start_with`], but the public URL is `https://127.0.0.1:<port>` of the listener itself, so a
    /// remote client can reach the server over plain loopback HTTP with a matching Host header (no TLS in tests).
    /// `base` is then `http://127.0.0.1:<port>`.
    pub async fn start_loopback_public(customize: impl FnOnce(&mut Config)) -> Self {
        let google = FakeGoogle::start(CLIENT_ID, CLIENT_SECRET).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let env = TestEnv::with_upstream(Upstream::single_origin(&google.base_url), |c| {
            c.public_url = format!("https://{addr}");
            c.limits.tool_call_timeout_secs = 8;
            c.limits.upstream_request_timeout_secs = 3;
            c.limits.client_requests_per_minute = 10_000;
            c.limits.client_burst = 10_000;
            customize(c)
        });
        let app = env.app.clone();
        let server = tokio::spawn(async move {
            let _ = dove::http::serve(app, listener, std::future::pending()).await;
        });
        let imap = FakeImap::start().await;
        Self { env, google, imap, base: format!("http://{addr}"), http: reqwest::Client::new(), server }
    }

    /// A local-mode server (PLAN A58): `public_url` is `http://<listen>` of the loopback listener itself.
    #[allow(dead_code)]
    pub async fn start_local(customize: impl FnOnce(&mut Config)) -> Self {
        Self::start_loopback_public(|c| {
            c.mode = dove::config::Mode::Local;
            c.public_url = c.public_url.replace("https://", "http://");
            c.listen = c.public_url.trim_start_matches("http://").parse().unwrap();
            customize(c)
        })
        .await
    }

    pub fn app(&self) -> &Arc<App> {
        &self.env.app
    }

    /// Restarts the HTTP server on a new App over the same data directory.
    pub async fn restart(&mut self) {
        self.restart_with(|_| {}).await;
    }

    /// Restarts with a changed configuration (same data directory and secrets).
    #[allow(dead_code)]
    pub async fn restart_with(&mut self, customize: impl FnOnce(&mut Config)) {
        self.server.abort();
        let mut cfg = self.env.app.cfg.clone();
        customize(&mut cfg);
        let app = dove::app::App::from_config_with(
            cfg,
            Upstream::single_origin(&self.google.base_url),
            dove::imap::ImapConnector::plaintext_for_tests(),
        )
        .unwrap();
        app.store.call(|c| dove::tools::drafts::recover_after_restart(c).map(|_| ())).await.unwrap();
        self.env.app = app;
        let (base, server) = serve(self.env.app.clone()).await;
        self.base = base;
        self.server = server;
    }

    /// Connects a mailbox as a completed OAuth flow would: fake mailbox, refresh token, encrypted grant.
    pub fn mailbox(&self, alias: &str, email: &str) -> String {
        self.google.add_mailbox(email, &format!("sub-{alias}"));
        let rt = self.google.issue_refresh_token(email);
        self.env.add_account(alias, email, &rt)
    }

    /// Endpoints of the fake IMAP and SMTP servers.
    #[allow(dead_code)]
    pub fn imap_endpoints(&self) -> (dove::imap::ServerEndpoint, dove::imap::ServerEndpoint) {
        use dove::imap::{ServerEndpoint, TlsMode};
        let ep = |a: std::net::SocketAddr| ServerEndpoint {
            host: a.ip().to_string(),
            port: a.port(),
            tls: TlsMode::Implicit,
        };
        (ep(self.imap.imap_addr), ep(self.imap.smtp_addr))
    }

    /// The `AccountsConnectImap` request for a user of the fake server.
    #[allow(dead_code)]
    pub fn connect_imap_request(&self, alias: &str, email: &str, password: &str) -> AdminRequest {
        let (imap, smtp) = self.imap_endpoints();
        AdminRequest::AccountsConnectImap {
            alias: alias.into(),
            email: email.into(),
            username: None,
            smtp_username: None,
            password: dove::admin::Password(zeroize::Zeroizing::new(password.into())),
            imap: Some(imap),
            smtp: Some(smtp),
            drafts_folder: None,
            preset: None,
        }
    }

    /// Creates a user with INBOX, Drafts, Sent, Junk and Trash (special-use flags) on the fake server and connects
    /// it as an IMAP mailbox through the real admin verb.
    #[allow(dead_code)]
    pub async fn imap_mailbox(&self, alias: &str, email: &str) -> FakeImapUser {
        self.imap.add_user(email, IMAP_PASSWORD);
        for (name, special) in [("Drafts", "\\Drafts"), ("Sent", "\\Sent"), ("Junk", "\\Junk"), ("Trash", "\\Trash")] {
            self.imap.add_folder(email, name, Some(special));
        }
        self.admin(self.connect_imap_request(alias, email, IMAP_PASSWORD)).await.expect("connect-imap");
        let a = alias.to_string();
        let account_id = self
            .app()
            .store
            .call(move |c| Ok(c.query_row("SELECT id FROM accounts WHERE alias = ?1", [a], |r| r.get(0))?))
            .await
            .unwrap();
        FakeImapUser {
            alias: alias.into(),
            email: email.into(),
            user: email.into(),
            password: IMAP_PASSWORD.into(),
            account_id,
        }
    }

    pub async fn admin(&self, req: AdminRequest) -> Result<Value, String> {
        let actor = Actor { name: "uid:test".into(), request_id: dove::util::new_id() };
        let r = server::dispatch(&self.env.app, &actor, req).await;
        if r.ok { Ok(r.result.unwrap_or(Value::Null)) } else { Err(r.error.unwrap_or_default()) }
    }

    pub async fn project(&self, name: &str, accounts: &[&str]) {
        self.admin(AdminRequest::ProjectsCreate { name: name.into() }).await.unwrap();
        for a in accounts {
            self.admin(AdminRequest::ProjectsAddAccount { project: name.into(), account: (*a).into() }).await.unwrap();
        }
    }

    pub async fn token(&self, project: &str, name: &str, grants: Vec<GrantSpec>) -> String {
        let v = self
            .admin(AdminRequest::ClientsCreate {
                name: name.into(),
                project: project.into(),
                grants,
                expires: None,
                allow_ip: vec![],
            })
            .await
            .unwrap();
        v["token"].as_str().unwrap().to_string()
    }

    pub async fn post_mcp(&self, token: Option<&str>, body: Value, headers: &[(&str, &str)]) -> reqwest::Response {
        // Caller headers replace the defaults (reqwest's `.header` would append a second value).
        let mut map = reqwest::header::HeaderMap::new();
        for (k, v) in
            [("host", HOST), ("accept", "application/json, text/event-stream"), ("mcp-protocol-version", "2025-06-18")]
                .into_iter()
                .chain(headers.iter().copied())
        {
            map.insert(reqwest::header::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        let mut req = self.http.post(format!("{}/mcp", self.base)).headers(map).json(&body);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        req.send().await.unwrap()
    }

    pub async fn rpc(&self, token: &str, method: &str, params: Value) -> Value {
        let r = self
            .post_mcp(Some(token), json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }), &[])
            .await;
        assert_eq!(r.status(), 200, "rpc {method}");
        r.json().await.unwrap()
    }

    /// Calls a tool; returns (is_error, structuredContent).
    pub async fn call(&self, token: &str, tool: &str, args: Value) -> (bool, Value) {
        let v = self.rpc(token, "tools/call", json!({ "name": tool, "arguments": args })).await;
        let r = &v["result"];
        (r["isError"].as_bool().unwrap_or(false), r["structuredContent"].clone())
    }

    pub async fn ok(&self, token: &str, tool: &str, args: Value) -> Value {
        let (err, v) = self.call(token, tool, args).await;
        assert!(!err, "{tool} failed: {v}");
        v
    }

    pub async fn err(&self, token: &str, tool: &str, args: Value) -> String {
        let (err, v) = self.call(token, tool, args).await;
        assert!(err, "{tool} unexpectedly succeeded: {v}");
        v["error"]["code"].as_str().unwrap().to_string()
    }

    pub async fn tool_names(&self, token: &str) -> Vec<String> {
        let v = self.rpc(token, "tools/list", json!({})).await;
        v["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect()
    }

    pub async fn audit_count(&self) -> i64 {
        self.app().store.call(|c| Ok(c.query_row("SELECT COUNT(*) FROM audit", [], |r| r.get(0))?)).await.unwrap()
    }
}

async fn serve(app: Arc<App>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        let _ = dove::http::serve(app, listener, std::future::pending()).await;
    });
    (base, handle)
}
