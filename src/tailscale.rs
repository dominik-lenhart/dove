//! `dove tailscale setup` and the `dove doctor` check for it (design 2026-11-13 section 6).
//!
//! Dove can be published on a tailnet instead of behind Caddy or nginx: `tailscale serve` terminates TLS with the
//! node's MagicDNS certificate and forwards to Dove's loopback listener. Setup does three things, all idempotent:
//! it reads this node's name from `tailscale status --json`, mounts exactly [`PUBLIC_PATHS`] on one HTTPS port of
//! that name (nothing else: no `/healthz`, nothing admin), and writes the resulting `public_url` into the config
//! file with the existing comments and layout kept. `--funnel` additionally makes the port reachable from the
//! internet and is never implied.
//!
//! Rules:
//! - This module never changes a Tailscale setting it did not create: other ports and other hosts' handlers are
//!   untouched, a foreign handler on the chosen port is an error (pick another `--port`), and `tailscale serve reset`
//!   is never run.
//! - Funnel that is already on for the port is reported, never changed behind the operator's back.
//! - Nothing here runs unless the operator started it: the service itself never calls `tailscale`.
//! - [`PUBLIC_PATHS`] is the one list; tests compare it with `deploy/Caddyfile`, `deploy/nginx/dove.conf` and the
//!   routes the HTTP layer registers, so a new route cannot be added to one and forgotten in the others.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use serde_json::{Value, json};

use crate::config::Config;

/// The routes a reverse proxy in front of Dove may forward (spec 5.6). `/healthz` is deliberately absent.
pub const PUBLIC_PATHS: &[&str] = &[
    "/mcp",
    "/oauth/google/callback",
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    "/.well-known/oauth-authorization-server",
    "/oauth/dove/authorize",
    "/oauth/dove/token",
    "/oauth/dove/register",
    "/oauth/dove/revoke",
    "/connect/redeem",
];

/// Ports Tailscale Funnel accepts.
const FUNNEL_PORTS: [u16; 3] = [443, 8443, 10000];

const TS_TIMEOUT: Duration = Duration::from_secs(20);

// ------------------------------------------------------------------ running tailscale

#[derive(Debug)]
pub enum TsError {
    NotInstalled,
    /// The CLI refused: this user is not allowed to change or read the configuration.
    Denied(String),
    Failed(String),
}

impl std::fmt::Display for TsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TsError::NotInstalled => f.write_str("the `tailscale` command was not found in PATH"),
            TsError::Denied(m) => write!(f, "tailscale refused: {m}"),
            TsError::Failed(m) => write!(f, "tailscale failed: {m}"),
        }
    }
}

impl std::error::Error for TsError {}

/// The `tailscale` command line client.
#[derive(Clone)]
pub struct Tailscale {
    program: OsString,
    envs: Vec<(String, String)>,
}

impl Tailscale {
    /// `tailscale` from PATH.
    pub fn from_path() -> Self {
        Self { program: "tailscale".into(), envs: Vec::new() }
    }

    /// A specific executable (tests).
    pub fn at(program: impl Into<OsString>) -> Self {
        Self { program: program.into(), envs: Vec::new() }
    }

    /// An environment variable for the executable (tests point a fake at its state directory).
    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.envs.push((key.into(), value.into()));
        self
    }

    /// Runs one command and returns its stdout.
    pub async fn run<S: AsRef<str>>(&self, args: &[S]) -> Result<String, TsError> {
        let mut cmd = tokio::process::Command::new(&self.program);
        cmd.args(args.iter().map(AsRef::as_ref)).stdin(std::process::Stdio::null()).kill_on_drop(true);
        cmd.envs(self.envs.iter().map(|(k, v)| (k, v)));
        let out = match tokio::time::timeout(TS_TIMEOUT, cmd.output()).await {
            Err(_) => return Err(TsError::Failed("timed out".into())),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => return Err(TsError::NotInstalled),
            Ok(Err(e)) => return Err(TsError::Failed(e.to_string())),
            Ok(Ok(o)) => o,
        };
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        if out.status.success() {
            return Ok(stdout);
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        let msg = format!("{} {}", stderr.trim(), stdout.trim()).trim().to_string();
        let lower = msg.to_lowercase();
        if ["access denied", "permission denied", "sudo", "operator", "not permitted"].iter().any(|k| lower.contains(k))
        {
            return Err(TsError::Denied(first_line(&msg)));
        }
        Err(TsError::Failed(first_line(&msg)))
    }

    async fn json(&self, args: &[&str]) -> Result<Value, TsError> {
        let text = self.run(args).await?;
        serde_json::from_str(&text)
            .map_err(|_| TsError::Failed(format!("`tailscale {}` did not print JSON", args.join(" "))))
    }
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or_default().chars().take(300).collect()
}

// ------------------------------------------------------------------ node and serve state

/// This node as `tailscale status --json` describes it.
#[derive(Debug, PartialEq, Eq)]
pub struct Node {
    /// MagicDNS name without the trailing dot.
    pub dns_name: String,
    pub funnel_allowed: bool,
    pub https_enabled: bool,
}

pub fn parse_status(v: &Value) -> anyhow::Result<Node> {
    let state = v["BackendState"].as_str().unwrap_or("unknown");
    if state != "Running" {
        bail!("Tailscale is not connected on this host (state: {state}); run `tailscale up` first");
    }
    let dns_name = v["Self"]["DNSName"].as_str().unwrap_or_default().trim_end_matches('.').to_lowercase();
    if dns_name.is_empty() {
        bail!("this node has no MagicDNS name; enable MagicDNS for your tailnet in the Tailscale admin console");
    }
    let https_enabled = v["CertDomains"].as_array().is_some_and(|a| !a.is_empty());
    let funnel_allowed = v["Self"]["CapMap"].get("funnel").is_some()
        || v["Self"]["Capabilities"].as_array().is_some_and(|a| a.iter().any(|c| c == "funnel"));
    Ok(Node { dns_name, funnel_allowed, https_enabled })
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Handler {
    Proxy(String),
    /// Files, text, redirects: anything that is not a plain proxy.
    Other,
}

/// What `tailscale serve status --json` says about one `host:port`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Current {
    pub handlers: BTreeMap<String, Handler>,
    pub funnel: bool,
}

pub fn read_current(serve: &Value, host: &str, port: u16) -> Current {
    let key = format!("{host}:{port}");
    let mut cur = Current { funnel: serve["AllowFunnel"][&key].as_bool().unwrap_or(false), ..Default::default() };
    if let Some(h) = serve["Web"][&key]["Handlers"].as_object() {
        for (path, v) in h {
            let handler = match v["Proxy"].as_str() {
                Some(p) => Handler::Proxy(p.to_string()),
                None => Handler::Other,
            };
            cur.handlers.insert(path.clone(), handler);
        }
    }
    cur
}

// ------------------------------------------------------------------ planning

#[derive(Debug, Clone)]
pub struct Desired {
    pub host: String,
    pub port: u16,
    /// Dove's loopback origin, `http://127.0.0.1:8787`.
    pub upstream: String,
    pub funnel: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// `tailscale` arguments, in the order to run them.
    pub steps: Vec<Vec<String>>,
    pub added: Vec<String>,
    pub changed: Vec<String>,
    pub removed: Vec<String>,
    /// Funnel is on although it was not asked for: reported, not changed.
    pub funnel_left_on: bool,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

impl Desired {
    pub fn target(&self, path: &str) -> String {
        format!("{}{path}", self.upstream.trim_end_matches('/'))
    }

    fn is_dove_target(&self, proxy: &str) -> bool {
        proxy == self.upstream.trim_end_matches('/')
            || proxy.starts_with(&format!("{}/", self.upstream.trim_end_matches('/')))
    }
}

/// The commands that bring `cur` to exactly [`PUBLIC_PATHS`] on `d.host:d.port`. Fails when the port already serves
/// something that is not Dove's, so nothing foreign is ever removed.
pub fn plan(d: &Desired, cur: &Current) -> anyhow::Result<Plan> {
    let https = format!("--https={}", d.port);
    let mut p = Plan::default();
    let foreign: Vec<&String> = cur
        .handlers
        .iter()
        .filter(|(path, h)| {
            !PUBLIC_PATHS.contains(&path.as_str()) && !matches!(h, Handler::Proxy(t) if d.is_dove_target(t))
        })
        .map(|(path, _)| path)
        .collect();
    if !foreign.is_empty() {
        bail!(
            "port {} of {} already serves something else ({}); choose another port with --port",
            d.port,
            d.host,
            foreign.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        );
    }
    for path in PUBLIC_PATHS {
        let want = Handler::Proxy(d.target(path));
        match cur.handlers.get(*path) {
            Some(h) if *h == want => {}
            other => {
                if other.is_some() {
                    p.changed.push((*path).to_string());
                } else {
                    p.added.push((*path).to_string());
                }
                p.steps.push(vec![
                    "serve".into(),
                    "--bg".into(),
                    "--yes".into(),
                    https.clone(),
                    "--set-path".into(),
                    (*path).into(),
                    d.target(path),
                ]);
            }
        }
    }
    // Mounts of an older Dove release that are no longer public.
    for path in cur.handlers.keys().filter(|p| !PUBLIC_PATHS.contains(&p.as_str())) {
        p.removed.push(path.clone());
        p.steps.push(vec!["serve".into(), https.clone(), "--set-path".into(), path.clone(), "off".into()]);
    }
    if d.funnel && !cur.funnel {
        p.steps.push(vec![
            "funnel".into(),
            "--bg".into(),
            "--yes".into(),
            https.clone(),
            "--set-path".into(),
            "/mcp".into(),
            d.target("/mcp"),
        ]);
    }
    p.funnel_left_on = cur.funnel && !d.funnel;
    Ok(p)
}

/// `https://host` or `https://host:port`.
pub fn public_url(host: &str, port: u16) -> String {
    if port == 443 { format!("https://{host}") } else { format!("https://{host}:{port}") }
}

fn display(args: &[String]) -> String {
    let quote = |a: &str| {
        if a.chars().all(|c| c.is_ascii_alphanumeric() || "-_./:=@".contains(c)) {
            a.to_string()
        } else {
            format!("'{a}'")
        }
    };
    format!("tailscale {}", args.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" "))
}

// ------------------------------------------------------------------ config file

/// `text` with `public_url` set to `url`, every comment and the layout kept. `None` when it already is.
pub fn set_public_url(text: &str, url: &str) -> anyhow::Result<Option<String>> {
    use toml_edit::{DocumentMut, Value, value};
    let mut doc: DocumentMut =
        text.parse().map_err(|e| anyhow!("the config file is not valid TOML ({e}); not modified"))?;
    match doc.get_mut("public_url") {
        Some(item) => {
            let Some(v) = item.as_value_mut().filter(|v| v.is_str()) else {
                bail!("`public_url` in the config file is not a string; not modified");
            };
            if v.as_str() == Some(url) {
                return Ok(None);
            }
            let decor = v.decor().clone();
            *v = Value::from(url);
            *v.decor_mut() = decor;
        }
        None => {
            // Top-level keys must come before the first table.
            doc.insert("public_url", value(url));
        }
    }
    let out = doc.to_string();
    let back: toml::Value = toml::from_str(&out).context("internal: generated invalid TOML")?;
    if back.get("public_url").and_then(|v| v.as_str()) != Some(url) {
        bail!("internal: could not set public_url; not modified");
    }
    Ok(Some(out))
}

/// Writes `text` over `path` atomically (temp file in the same directory, same mode and owner, then rename).
fn write_config(path: &Path, text: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let meta = std::fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    let tmp = temp_path(path);
    let denied = |e: std::io::Error| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            anyhow!(
                "cannot write {}: permission denied. Run the command with sudo, or set the line by hand and restart Dove",
                path.display()
            )
        } else {
            anyhow!("cannot write {}: {e}", path.display())
        }
    };
    // Never wider than the original while the file is half written.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(meta.permissions().mode() & 0o770)
        .open(&tmp)
        .map_err(denied)?;
    let res = (|| -> std::io::Result<()> {
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        // Keep the owner when root edits a file owned by someone else (a no-op error for other users).
        let _ = std::os::unix::fs::chown(&tmp, Some(meta.uid()), Some(meta.gid()));
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(meta.permissions().mode() & 0o7777))?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(denied(e));
    }
    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    path.with_file_name(format!(".{name}.dove-{}.tmp", std::process::id()))
}

// ------------------------------------------------------------------ setup

pub struct SetupOpts {
    pub config: PathBuf,
    pub port: u16,
    pub funnel: bool,
    pub dry_run: bool,
}

fn guidance_for_denied(out: &mut dyn Write, opts: &SetupOpts, why: &str) -> std::io::Result<()> {
    writeln!(out, "\nTailscale did not allow this user to do that ({why}).")?;
    writeln!(out, "Either run the same command with sudo:")?;
    writeln!(
        out,
        "  sudo dove tailscale setup --config {} --port {}{}",
        opts.config.display(),
        opts.port,
        if opts.funnel { " --funnel" } else { "" }
    )?;
    writeln!(out, "or let your user manage Tailscale once, then run it again:")?;
    writeln!(out, "  sudo tailscale set --operator=$USER")
}

fn tailscale_failure(out: &mut dyn Write, opts: &SetupOpts, e: TsError) -> anyhow::Error {
    if let TsError::Denied(why) = &e {
        let _ = guidance_for_denied(out, opts, why);
    }
    anyhow!("{e}")
}

/// `dove tailscale setup`. Prints what it does; with `dry_run` it only reads state and prints the commands.
pub async fn setup(opts: &SetupOpts, ts: &Tailscale, out: &mut dyn Write) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(&opts.config).with_context(|| {
        format!(
            "cannot read {} (pass --config, or run with sudo if it is only readable by root)",
            opts.config.display()
        )
    })?;
    let cfg: Config = toml::from_str(&text).context("invalid config file")?;
    if !cfg.listen.ip().is_loopback() {
        bail!("listen must be a loopback address");
    }
    let status = ts.json(&["status", "--json"]).await.map_err(|e| tailscale_failure(out, opts, e))?;
    let node = parse_status(&status)?;
    if !node.https_enabled {
        bail!(
            "HTTPS certificates are not enabled for this tailnet; turn on HTTPS in the Tailscale admin console (DNS page)"
        );
    }
    if opts.funnel {
        if !FUNNEL_PORTS.contains(&opts.port) {
            bail!("Funnel only works on ports 443, 8443 and 10000, not {}", opts.port);
        }
        if !node.funnel_allowed {
            bail!("Funnel is not enabled for this node; allow it in the tailnet policy (the `funnel` node attribute)");
        }
    }
    let desired = Desired {
        host: node.dns_name.clone(),
        port: opts.port,
        upstream: format!("http://{}", cfg.listen),
        funnel: opts.funnel,
    };
    let serve = ts.json(&["serve", "status", "--json"]).await.map_err(|e| tailscale_failure(out, opts, e))?;
    let current = read_current(&serve, &desired.host, desired.port);
    let plan = plan(&desired, &current)?;
    let url = public_url(&desired.host, desired.port);
    let new_text = set_public_url(&text, &url)?;

    writeln!(out, "Node:       {}", desired.host)?;
    writeln!(out, "Public URL: {url}")?;
    writeln!(
        out,
        "Reachable:  {}",
        if opts.funnel { "from the internet (Funnel)" } else { "only from devices on your tailnet" }
    )?;
    if opts.funnel {
        writeln!(out)?;
        writeln!(out, "WARNING: --funnel makes Dove reachable from the entire internet, not just your tailnet.")?;
        writeln!(out, "Only the public paths below are forwarded, and every MCP call still needs a connection token,")?;
        writeln!(out, "but anyone can now reach the sign-in and OAuth endpoints. Tailscale ACLs no longer apply.")?;
    }
    if plan.funnel_left_on {
        writeln!(out)?;
        writeln!(
            out,
            "NOTE: Funnel is already ON for port {}: Dove is reachable from the internet. Setup does not change that.\n\
             To make it tailnet-only: tailscale funnel --https={} off",
            desired.port, desired.port
        )?;
    }
    writeln!(out)?;
    if plan.is_empty() {
        writeln!(
            out,
            "Tailscale serve already matches: {} paths on port {}. Nothing to change.",
            PUBLIC_PATHS.len(),
            desired.port
        )?;
    } else {
        writeln!(out, "{}", if opts.dry_run { "Commands (dry run, nothing is changed):" } else { "Running:" })?;
        for s in &plan.steps {
            writeln!(out, "  {}", display(s))?;
        }
    }
    match &new_text {
        Some(_) => writeln!(out, "Config:     set public_url = \"{url}\" in {}", opts.config.display())?,
        None => writeln!(out, "Config:     public_url is already {url}")?,
    }
    if opts.dry_run {
        return Ok(());
    }

    // Fail before changing Tailscale if the config cannot be written afterwards.
    if new_text.is_some() {
        let probe = temp_path(&opts.config);
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&probe) {
            Ok(_) => {
                let _ = std::fs::remove_file(&probe);
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                writeln!(out, "\nCannot write {}: permission denied. Run with sudo:", opts.config.display())?;
                writeln!(
                    out,
                    "  sudo dove tailscale setup --config {} --port {}{}",
                    opts.config.display(),
                    opts.port,
                    if opts.funnel { " --funnel" } else { "" }
                )?;
                bail!("config file not writable");
            }
            Err(e) => bail!("cannot write next to {}: {e}", opts.config.display()),
        }
    }
    for s in &plan.steps {
        ts.run(s).await.map_err(|e| tailscale_failure(out, opts, e))?;
    }
    if let Some(t) = new_text {
        write_config(&opts.config, &t)?;
    }
    writeln!(out)?;
    writeln!(out, "Done. Restart Dove so it uses the new public_url:  sudo systemctl restart dove")?;
    writeln!(out, "Then check it with:  dove doctor")?;
    writeln!(out)?;
    writeln!(out, "Notes:")?;
    writeln!(
        out,
        "- Tailscale Serve cannot add the X-Dove-Proxy-Auth header, so Dove sees every request as coming from"
    )?;
    writeln!(
        out,
        "  127.0.0.1: per-client --allow-ip lists cannot match tailnet addresses (use Tailscale ACLs instead),"
    )?;
    writeln!(out, "  and rate limits are shared by all clients.")?;
    writeln!(
        out,
        "- Gmail: add {url}/oauth/google/callback as an authorized redirect URI of your Google OAuth client."
    )?;
    Ok(())
}

// ------------------------------------------------------------------ doctor

/// The `tailscale_serve` doctor row, or `None` when this Dove is not published through Tailscale (its public URL is
/// not a `.ts.net` name). Runs in the CLI, as the operator, because the service user normally may not ask Tailscale.
pub async fn doctor_check(public_url: &str, listen: &str, ts: &Tailscale) -> Option<Value> {
    let url = url::Url::parse(public_url).ok()?;
    let host = url.host_str()?.to_lowercase();
    if !host.ends_with(".ts.net") {
        return None;
    }
    let port = url.port().unwrap_or(443);
    let row = |ok: bool, detail: String| Some(json!({ "check": "tailscale_serve", "ok": ok, "detail": detail }));
    let status = match ts.json(&["status", "--json"]).await {
        Ok(v) => v,
        Err(e) => return row(false, format!("public_url is a Tailscale name but this host cannot ask Tailscale: {e}")),
    };
    let node = match parse_status(&status) {
        Ok(n) => n,
        Err(e) => return row(false, e.to_string()),
    };
    if node.dns_name != host {
        return row(
            false,
            format!("public_url host {host} is not this node's name ({}); run `dove tailscale setup`", node.dns_name),
        );
    }
    let serve = match ts.json(&["serve", "status", "--json"]).await {
        Ok(v) => v,
        Err(e) => return row(false, format!("cannot read the serve configuration: {e}")),
    };
    let cur = read_current(&serve, &host, port);
    // Funnel is the operator's choice: compare as if it stays as it is.
    let d = Desired { host, port, upstream: format!("http://{listen}"), funnel: cur.funnel };
    let p = match plan(&d, &cur) {
        Ok(p) => p,
        Err(e) => return row(false, e.to_string()),
    };
    let funnel = if cur.funnel { "; Funnel is ON (reachable from the internet)" } else { "" };
    if p.is_empty() {
        return row(true, format!("{} paths served on port {port}{funnel}", PUBLIC_PATHS.len()));
    }
    let mut parts = Vec::new();
    for (label, list) in [("missing", &p.added), ("different target", &p.changed), ("no longer public", &p.removed)] {
        if !list.is_empty() {
            parts.push(format!("{label}: {}", list.join(", ")));
        }
    }
    row(false, format!("serve configuration differs ({}); run `dove tailscale setup`{funnel}", parts.join("; ")))
}

/// Adds the Tailscale row to the service's doctor output when it applies.
pub async fn add_doctor_check(checks: &mut Value, ts: &Tailscale) {
    let Some(list) = checks.as_array_mut() else { return };
    let Some(row) = list.iter().find(|c| c["check"] == "public_url") else { return };
    let (Some(url), Some(listen)) = (row["detail"].as_str(), row["listen"].as_str()) else { return };
    if let Some(r) = doctor_check(url, listen, ts).await {
        list.push(r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desired(funnel: bool) -> Desired {
        Desired { host: "dove.tail1234.ts.net".into(), port: 443, upstream: "http://127.0.0.1:8787".into(), funnel }
    }

    fn serve_json(paths: &[(&str, &str)], funnel: bool) -> Value {
        let handlers: serde_json::Map<String, Value> =
            paths.iter().map(|(p, t)| ((*p).to_string(), json!({ "Proxy": t }))).collect();
        json!({ "TCP": { "443": { "HTTPS": true } },
                "Web": { "dove.tail1234.ts.net:443": { "Handlers": handlers } },
                "AllowFunnel": { "dove.tail1234.ts.net:443": funnel } })
    }

    fn all_mounted() -> Vec<(String, String)> {
        PUBLIC_PATHS.iter().map(|p| ((*p).to_string(), format!("http://127.0.0.1:8787{p}"))).collect()
    }

    fn current(extra: &[(&str, &str)], drop: &[&str], funnel: bool) -> Current {
        let mut v: Vec<(String, String)> =
            all_mounted().into_iter().filter(|(p, _)| !drop.contains(&p.as_str())).collect();
        v.extend(extra.iter().map(|(p, t)| ((*p).to_string(), (*t).to_string())));
        let refs: Vec<(&str, &str)> = v.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        read_current(&serve_json(&refs, funnel), "dove.tail1234.ts.net", 443)
    }

    #[test]
    fn fresh_node_gets_every_public_path_and_nothing_else() {
        let p = plan(&desired(false), &Current::default()).unwrap();
        assert_eq!(p.steps.len(), PUBLIC_PATHS.len());
        assert!(p.steps.iter().all(|s| s[0] == "serve" && s.contains(&"--https=443".to_string())));
        let mounted: Vec<&str> = p.steps.iter().map(|s| s[5].as_str()).collect();
        assert_eq!(mounted, PUBLIC_PATHS);
        assert!(!mounted.iter().any(|m| m.contains("healthz")));
        // Each mount forwards to the same path on Dove's loopback origin.
        assert!(p.steps.iter().all(|s| s[6] == format!("http://127.0.0.1:8787{}", s[5])));
        assert!(!p.steps.iter().any(|s| s[0] == "funnel"));
    }

    #[test]
    fn plan_is_idempotent_and_repairs_only_what_differs() {
        assert!(plan(&desired(false), &current(&[], &[], false)).unwrap().is_empty());
        let p = plan(&desired(false), &current(&[], &["/connect/redeem"], false)).unwrap();
        assert_eq!((p.added.as_slice(), p.steps.len()), (&["/connect/redeem".to_string()][..], 1));
        // A mount that points at the wrong place is replaced, not duplicated.
        let p = plan(&desired(false), &current(&[("/mcp", "http://127.0.0.1:9999/mcp")], &["/mcp"], false)).unwrap();
        assert_eq!(p.changed, ["/mcp"]);
        assert_eq!(p.steps.len(), 1);
    }

    #[test]
    fn stale_dove_mounts_go_but_foreign_ones_stop_the_setup() {
        // A path an older Dove published (it proxies to Dove's origin) is removed.
        let p = plan(&desired(false), &current(&[("/healthz", "http://127.0.0.1:8787/healthz")], &[], false)).unwrap();
        assert_eq!(p.removed, ["/healthz"]);
        assert_eq!(p.steps, vec![vec!["serve", "--https=443", "--set-path", "/healthz", "off"]]);
        // Someone else's handler on this port is never touched.
        let e = plan(&desired(false), &current(&[("/grafana", "http://127.0.0.1:3000")], &[], false)).unwrap_err();
        assert!(e.to_string().contains("/grafana") && e.to_string().contains("--port"), "{e}");
        let other = read_current(
            &json!({ "Web": { "dove.tail1234.ts.net:443": { "Handlers": { "/": { "Path": "/srv/www" } } } } }),
            "dove.tail1234.ts.net",
            443,
        );
        assert!(plan(&desired(false), &other).is_err());
    }

    #[test]
    fn handlers_of_other_ports_are_not_ours() {
        let serve = json!({ "Web": { "dove.tail1234.ts.net:8443": { "Handlers": { "/": { "Proxy": "http://127.0.0.1:1" } } } } });
        assert!(read_current(&serve, "dove.tail1234.ts.net", 443).handlers.is_empty());
        assert!(plan(&desired(false), &read_current(&serve, "dove.tail1234.ts.net", 443)).is_ok());
    }

    #[test]
    fn funnel_is_added_only_on_request_and_never_removed_silently() {
        let on = plan(&desired(true), &current(&[], &[], false)).unwrap();
        assert_eq!(on.steps.len(), 1);
        assert_eq!(&on.steps[0][..2], ["funnel", "--bg"]);
        // Already on and requested: nothing to do. Already on, not requested: reported, not changed.
        assert!(plan(&desired(true), &current(&[], &[], true)).unwrap().is_empty());
        let left = plan(&desired(false), &current(&[], &[], true)).unwrap();
        assert!(left.is_empty() && left.funnel_left_on);
    }

    #[test]
    fn status_parsing() {
        let ok = json!({ "BackendState": "Running", "Self": { "DNSName": "Dove.Tail1234.ts.net.", "CapMap": { "funnel": null } },
                         "CertDomains": ["dove.tail1234.ts.net"] });
        assert_eq!(
            parse_status(&ok).unwrap(),
            Node { dns_name: "dove.tail1234.ts.net".into(), funnel_allowed: true, https_enabled: true }
        );
        let no_funnel = json!({ "BackendState": "Running", "Self": { "DNSName": "a.ts.net." }, "CertDomains": [] });
        let n = parse_status(&no_funnel).unwrap();
        assert!(!n.funnel_allowed && !n.https_enabled);
        assert!(parse_status(&json!({ "BackendState": "Stopped", "Self": { "DNSName": "a.ts.net." } })).is_err());
        assert!(parse_status(&json!({ "BackendState": "Running", "Self": {} })).is_err());
    }

    #[test]
    fn urls_and_command_display() {
        assert_eq!(public_url("d.ts.net", 443), "https://d.ts.net");
        assert_eq!(public_url("d.ts.net", 8443), "https://d.ts.net:8443");
        let s: Vec<String> =
            ["serve", "--set-path", "/.well-known/x", "http://127.0.0.1:8787/x y"].map(String::from).to_vec();
        assert_eq!(display(&s), "tailscale serve --set-path /.well-known/x 'http://127.0.0.1:8787/x y'");
    }

    #[test]
    fn public_url_edit_keeps_comments_and_layout() {
        let text = "# Dove\nlisten = \"127.0.0.1:8787\"\npublic_url = \"https://dove.example.com\" # the proxy host\n\n[secrets]\n# keys\nkek_file = \"/x\"\n";
        let out = set_public_url(text, "https://dove.tail1234.ts.net").unwrap().unwrap();
        assert_eq!(out, text.replace("https://dove.example.com", "https://dove.tail1234.ts.net"));
        assert!(set_public_url(&out, "https://dove.tail1234.ts.net").unwrap().is_none(), "idempotent");
        // Missing key: added at the top level, before the first table.
        let out = set_public_url("[secrets]\nkek_file = \"/x\"\n", "https://d.ts.net").unwrap().unwrap();
        let v: toml::Value = toml::from_str(&out).unwrap();
        assert_eq!(v["public_url"].as_str(), Some("https://d.ts.net"));
        assert_eq!(v["secrets"]["kek_file"].as_str(), Some("/x"));
        assert!(set_public_url("public_url = 5\n", "https://d.ts.net").is_err());
        assert!(set_public_url("public_url = ", "https://d.ts.net").is_err());
    }

    /// Every list of public routes is the same list: the constant, the Caddyfile, the nginx map and the routes the
    /// HTTP layer registers (minus `/healthz`, which is loopback only).
    #[test]
    fn allowlists_do_not_drift() {
        use std::collections::BTreeSet;
        let want: BTreeSet<String> = PUBLIC_PATHS.iter().map(|s| (*s).to_string()).collect();
        assert_eq!(want.len(), PUBLIC_PATHS.len(), "no duplicates");

        let caddy = include_str!("../deploy/Caddyfile");
        let caddy_paths: BTreeSet<String> = caddy
            .lines()
            .map(str::trim)
            .filter_map(|l| l.strip_prefix("path "))
            .flat_map(|l| l.split_whitespace().map(str::to_string).collect::<Vec<_>>())
            .collect();
        assert_eq!(caddy_paths, want, "deploy/Caddyfile");

        let nginx = include_str!("../deploy/nginx/dove.conf");
        let nginx_paths: BTreeSet<String> = nginx
            .lines()
            .map(str::trim)
            .filter_map(|l| l.strip_prefix("\"~^"))
            .filter_map(|l| l.split_once(' ').map(|(_, rest)| rest))
            .filter_map(|rest| rest.split_once('$').map(|(p, _)| p.replace("\\.", ".")))
            .collect();
        assert_eq!(nginx_paths, want, "deploy/nginx/dove.conf");

        let mut routes = BTreeSet::new();
        for src in [include_str!("http.rs"), include_str!("mcp.rs"), include_str!("oauth.rs")] {
            for part in src.split(".route(").skip(1) {
                let arg = part.split(',').next().unwrap_or_default().trim();
                let path = match arg {
                    "AUTHORIZE_PATH" => crate::oauth::AUTHORIZE_PATH.to_string(),
                    lit if lit.starts_with('"') => lit.trim_matches('"').to_string(),
                    other => panic!("route registered with an expression this test does not understand: {other}"),
                };
                routes.insert(path);
            }
        }
        routes.remove("/healthz");
        assert_eq!(routes, want, "routes registered in src/http.rs, src/mcp.rs and src/oauth.rs");
    }
}
