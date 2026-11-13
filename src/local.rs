//! Local mode (PLAN A58): Dove on the desktop user's own computer, for MCP hosts on the same machine.
//!
//! `dove local init` writes a per-user config, generates the keys (DPAPI-protected on Windows, 0600 files elsewhere)
//! and creates the private data directory. `dove local start` runs the service in the foreground; `install` and
//! `uninstall` register it to start at login (launchd agent, `systemd --user` unit, Task Scheduler logon task, none of
//! them needing administrator rights). The service itself is the same as in server mode, with plain HTTP on the
//! loopback origin only.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use clap::Subcommand;

use crate::config::Config;
use crate::platform::paths::{LocalPaths, local_paths};
use crate::secrets;

pub const DEFAULT_PORT: u16 = 8787;
/// launchd label and systemd user unit name.
pub const SERVICE_LABEL: &str = "io.github.dominik-lenhart.dove";
pub const SYSTEMD_UNIT: &str = "dove.service";
/// Rotated at start once larger than this (launchd and Task Scheduler keep no journal).
const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Subcommand)]
pub enum LocalCmd {
    /// Create the per-user config, keys and data directory for local mode.
    Init {
        /// Loopback port Dove listens on (http://127.0.0.1:<port>).
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
    },
    /// Run Dove in the foreground with the local config (Ctrl+C stops it).
    Start {
        /// Config file (default: the per-user local config).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Append the service log to this file instead of stderr.
        #[arg(long)]
        log_file: Option<PathBuf>,
    },
    /// Start Dove now and at every login (launchd agent, systemd user unit or Task Scheduler logon task).
    Install,
    /// Stop the running service gracefully. A login item starts it again at the next login.
    Stop,
    /// Stop Dove and remove the login item. Config, keys and data stay.
    Uninstall,
    /// Show paths, the login item and whether the service answers.
    Status,
}

pub async fn run(cmd: LocalCmd) -> anyhow::Result<()> {
    let paths = local_paths()?;
    match cmd {
        LocalCmd::Init { port } => {
            init(&paths, port)?;
            print!("{}", next_steps(&paths, port));
            Ok(())
        }
        LocalCmd::Start { config, log_file } => {
            let config = config.unwrap_or_else(|| paths.config_file.clone());
            let cfg = Config::load(&config)?;
            if !cfg.is_local() {
                bail!(
                    "{} is not a local-mode config (mode = \"local\"); use `dove serve` for server mode",
                    config.display()
                );
            }
            match log_file {
                Some(p) => crate::serve::run_with_log(&config, Some(open_log(&p)?)).await,
                None => crate::serve::run(&config).await,
            }
        }
        LocalCmd::Install => install(&paths).await,
        LocalCmd::Stop => {
            if stop_service(&paths).await? {
                println!("Dove stopped.");
            } else {
                println!("Dove was not running.");
            }
            Ok(())
        }
        LocalCmd::Uninstall => uninstall(&paths).await,
        LocalCmd::Status => status(&paths).await,
    }
}

/// The local-mode config file text. Paths are written as TOML basic strings (Windows backslashes escaped).
pub fn config_text(paths: &LocalPaths, port: u16, operator_uid: Option<u32>) -> String {
    let q = |p: &Path| toml::Value::String(p.to_string_lossy().into_owned()).to_string();
    let s = paths.secrets_dir();
    let uid = operator_uid.map(|u| format!("operator_uid = {u}\n")).unwrap_or_default();
    format!(
        r#"# Dove in local mode (written by `dove local init`). Dove runs as you, for MCP hosts on this computer only.
# See docs/deployment.md#local-mode for what this protects and what it does not.
mode = "local"
public_url = "http://127.0.0.1:{port}"
listen = "127.0.0.1:{port}"
data_dir = {data}
allowed_origins = []
allow_send = false

[admin]
socket_path = {socket}
{uid}
[secrets]
kek_file = {kek}
pepper_file = {pepper}
index_key_file = {index_key}

# Gmail through your own Google Cloud OAuth client (optional; IMAP mailboxes need nothing). Register the redirect URI
# http://127.0.0.1:{port}/oauth/google/callback and save the client secret in a file only you can read.
# [google]
# client_id = "000000000000-example.apps.googleusercontent.com"
# client_secret_file = {google}
"#,
        data = q(&paths.data_dir),
        socket = q(&paths.admin_socket()),
        kek = q(&s.join("kek")),
        pepper = q(&s.join("pepper")),
        index_key = q(&s.join("index_key")),
        google = q(&s.join("google_client_secret")),
    )
}

fn current_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        Some(nix::unistd::getuid().as_raw())
    }
    #[cfg(windows)]
    {
        None
    }
}

/// Creates the data directory, keys and config. Refuses to touch an existing config or key (a lost key loses the
/// mailboxes' stored credentials and the index), so nothing is written unless everything is new.
pub fn init(paths: &LocalPaths, port: u16) -> anyhow::Result<()> {
    if port == 0 {
        bail!("--port must not be 0");
    }
    check_socket_path(&paths.admin_socket())?;
    let secrets_dir = paths.secrets_dir();
    let keys = ["kek", "pepper", "index_key"].map(|n| secrets_dir.join(n));
    for p in std::iter::once(&paths.config_file).chain(&keys) {
        if p.exists() {
            bail!(
                "{} already exists: Dove is already set up here (`dove local status`). Nothing was changed.",
                p.display()
            );
        }
    }
    crate::platform::ensure_private_dir(&paths.data_dir)?;
    // A data directory something else created first may pass the check with an inherited access list (Windows);
    // make it explicitly private before any key goes in (L4).
    crate::platform::restrict_dir(&paths.data_dir)?;
    crate::platform::ensure_private_dir(&secrets_dir)?;
    // Everything this run creates is removed again when a later step fails: nothing is encrypted under these keys
    // yet, and a leftover key would make every retry refuse with "already exists" (L5).
    let mut created: Vec<PathBuf> = Vec::new();
    let result = (|| -> anyhow::Result<()> {
        for k in &keys {
            let line = zeroize::Zeroizing::new(secrets::generate_key_line(1));
            crate::platform::write_private_new(k, &secrets::encode_secret_file(line.as_bytes())?)?;
            created.push(k.clone());
        }
        if let Some(dir) = paths.config_file.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        }
        let text = config_text(paths, port, current_uid());
        crate::platform::write_private_new(&paths.config_file, text.as_bytes())?;
        created.push(paths.config_file.clone());
        let cfg = Config::load(&paths.config_file)?;
        cfg.validate().context("the new local config does not validate")?;
        Ok(())
    })();
    if result.is_err() {
        for p in &created {
            let _ = std::fs::remove_file(p);
        }
    }
    result
}

/// Longest Unix socket path that binds everywhere (`sun_path` is 104 bytes on macOS, 108 on Linux, NUL included).
pub const MAX_SOCKET_PATH: usize = 103;

/// Refuses a data directory whose admin socket path is too long to bind, before anything is written: the service
/// would otherwise fail at every start.
fn check_socket_path(socket: &Path) -> anyhow::Result<()> {
    if cfg!(unix) && socket.as_os_str().len() > MAX_SOCKET_PATH {
        bail!(
            "the admin socket path {} is longer than {MAX_SOCKET_PATH} bytes, which Unix sockets do not allow; set \
             DOVE_LOCAL_HOME to a shorter directory. Nothing was changed.",
            socket.display()
        );
    }
    Ok(())
}

pub fn next_steps(paths: &LocalPaths, port: u16) -> String {
    format!(
        "Dove local mode is set up.\n  config: {}\n  data:   {}\n\nNext steps:\n  \
         1. dove local install            start Dove now and at every login (or `dove local start` in a terminal)\n  \
         2. dove accounts connect-imap personal --email you@example.com\n  \
         3. dove projects create assistant && dove projects add-account assistant personal\n  \
         4. dove clients invite desktop --project assistant --accounts personal --capabilities assistant\n  \
         5. dove login --server http://127.0.0.1:{port} --profile desktop      (paste the invitation)\n  \
         6. dove mcp install --client claude-desktop --profile desktop       (or claude-code, codex)\n",
        paths.config_file.display(),
        paths.data_dir.display(),
    )
}

/// Opens the service log for appending (private to the user), rotating it once it grew past [`MAX_LOG_BYTES`].
fn open_log(path: &Path) -> anyhow::Result<std::fs::File> {
    if std::fs::metadata(path).is_ok_and(|m| m.len() > MAX_LOG_BYTES) {
        let _ = std::fs::rename(path, path.with_extension("log.1"));
    }
    let f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("cannot open log file {}", path.display()))?;
    crate::platform::restrict_file(path)?;
    Ok(f)
}

/// The binary the login item runs. Symlinks are kept on purpose: a package manager's link (Homebrew's
/// `bin/dove` into a versioned Cellar directory) stays valid across upgrades, its target does not.
fn exe() -> anyhow::Result<PathBuf> {
    std::env::current_exe().context("cannot find the path of the running dove binary")
}

fn run_tool(program: &str, args: &[&str]) -> anyhow::Result<String> {
    let out = Command::new(program).args(args).output().with_context(|| format!("cannot run {program}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let out_text = String::from_utf8_lossy(&out.stdout);
        bail!("{program} {} failed: {}", args.join(" "), format!("{err} {out_text}").trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn require_config(paths: &LocalPaths) -> anyhow::Result<Config> {
    if !paths.config_file.exists() {
        bail!("no local config at {}; run `dove local init` first", paths.config_file.display());
    }
    let cfg = Config::load(&paths.config_file)?;
    cfg.validate()?;
    if !cfg.is_local() {
        bail!("{} is not a local-mode config", paths.config_file.display());
    }
    Ok(cfg)
}

// ------------------------------------------------------------------ Linux: systemd user unit

/// `$XDG_CONFIG_HOME/systemd/user/dove.service` (default `~/.config/systemd/user`).
pub fn systemd_unit_path() -> anyhow::Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).filter(|p| p.is_absolute()) {
        Some(d) => d,
        None => crate::client::profile::home_dir()?.join(".config"),
    };
    Ok(base.join("systemd").join("user").join(SYSTEMD_UNIT))
}

/// The user unit. systemd quotes arguments with double quotes; paths are escaped for that.
/// The user unit. Paths are double-quoted with `\\`, `"`, `%` (specifiers) and `$` (variables) escaped; a control
/// character (a newline would start a new directive) is refused (L7).
pub fn systemd_unit(exe: &Path, config: &Path) -> anyhow::Result<String> {
    let q = |p: &Path| -> anyhow::Result<String> {
        let s = p.to_string_lossy();
        if s.chars().any(char::is_control) {
            bail!("{} contains a control character; move it to a plain path", p.display());
        }
        Ok(format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('%', "%%").replace('$', "$$")))
    };
    Ok(format!(
        "# Written by `dove local install`. Remove with `dove local uninstall`.\n[Unit]\nDescription=Dove mail MCP server \
         (local mode)\nAfter=network-online.target\n\n[Service]\nExecStart={} local start --config {}\nRestart=on-failure\n\
         RestartSec=5\n\n[Install]\nWantedBy=default.target\n",
        q(exe)?,
        q(config)?
    ))
}

// ------------------------------------------------------------------ macOS: launchd agent

pub fn launchd_plist_path() -> anyhow::Result<PathBuf> {
    Ok(crate::client::profile::home_dir()?.join("Library").join("LaunchAgents").join(format!("{SERVICE_LABEL}.plist")))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

pub fn launchd_plist(exe: &Path, config: &Path, log: &Path) -> String {
    let e = |p: &Path| xml_escape(&p.to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{SERVICE_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string><string>local</string><string>start</string>
    <string>--config</string><string>{config}</string>
    <string>--log-file</string><string>{log}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
"#,
        exe = e(exe),
        config = e(config),
        log = e(log),
    )
}

// ------------------------------------------------------------------ Windows: Task Scheduler logon task

/// The task name: one task per Windows user (tasks live in a folder all users share).
pub fn windows_task_name() -> String {
    match std::env::var("USERNAME") {
        Ok(u) if !u.is_empty() && u.chars().all(|c| c.is_ascii_alphanumeric() || "-_. ".contains(c)) => {
            format!("Dove ({u})")
        }
        _ => "Dove".to_string(),
    }
}

/// Task Scheduler XML: at this user's logon, as this user, without elevation, no time limit. `conhost --headless`
/// keeps a console window from opening at every login.
/// Task Scheduler expands `%VAR%` in arguments and has no escape for it, and `"` would end a quoted argument: paths
/// with either are refused (L7; `"` cannot occur in Windows paths anyway).
pub fn windows_task_xml(
    user_sid: &str,
    conhost: &Path,
    exe: &Path,
    config: &Path,
    log: &Path,
) -> anyhow::Result<String> {
    for p in [conhost, exe, config, log] {
        let s = p.to_string_lossy();
        if s.contains(['%', '"']) || s.chars().any(char::is_control) {
            bail!(
                "{} contains %, \" or a control character, which a logon task cannot pass safely; move it",
                p.display()
            );
        }
    }
    let e = |s: &str| xml_escape(s);
    let args = format!(
        "--headless \"{}\" local start --config \"{}\" --log-file \"{}\"",
        exe.display(),
        config.display(),
        log.display()
    );
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Dove mail MCP server (local mode). Remove with: dove local uninstall</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{sid}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{sid}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec><Command>{conhost}</Command><Arguments>{args}</Arguments></Exec></Actions>
</Task>
"#,
        sid = e(user_sid),
        conhost = e(&conhost.to_string_lossy()),
        args = e(&args),
    ))
}

#[cfg(windows)]
fn conhost_path() -> PathBuf {
    let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    root.join("System32").join("conhost.exe")
}

// ------------------------------------------------------------------ install / uninstall / status

async fn install(paths: &LocalPaths) -> anyhow::Result<()> {
    let _cfg = require_config(paths)?;
    let exe = exe()?;
    // A running instance (an older login item or a foreground `dove local start`) holds the port and the admin
    // channel; the new one could not start next to it.
    stop_service(paths).await?;
    #[cfg(target_os = "linux")]
    {
        let unit = systemd_unit_path()?;
        if let Some(dir) = unit.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        }
        crate::client::profile::atomic_write(&unit, systemd_unit(&exe, &paths.config_file)?.as_bytes(), 0o644)?;
        run_tool("systemctl", &["--user", "daemon-reload"])?;
        run_tool("systemctl", &["--user", "enable", SYSTEMD_UNIT])?;
        run_tool("systemctl", &["--user", "restart", SYSTEMD_UNIT])?;
        println!("Installed {} and started it. Logs: journalctl --user -u dove", unit.display());
        println!(
            "systemd stops user services at logout unless lingering is on: `loginctl enable-linger` keeps Dove running."
        );
    }
    #[cfg(target_os = "macos")]
    {
        let plist = launchd_plist_path()?;
        if let Some(dir) = plist.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        }
        let text = launchd_plist(&exe, &paths.config_file, &paths.log_file());
        crate::client::profile::atomic_write(&plist, text.as_bytes(), 0o644)?;
        let domain = format!("gui/{}", nix::unistd::getuid().as_raw());
        // A loaded older version must go first; not being loaded is fine.
        let _ = run_tool("launchctl", &["bootout", &format!("{domain}/{SERVICE_LABEL}")]);
        run_tool("launchctl", &["bootstrap", &domain, &plist.to_string_lossy()])?;
        println!("Installed {} and started it. Log: {}", plist.display(), paths.log_file().display());
    }
    #[cfg(windows)]
    {
        let sid = crate::platform::windows::current_user_sid()?.to_string_sid()?;
        let xml = windows_task_xml(&sid, &conhost_path(), &exe, &paths.config_file, &paths.log_file())?;
        // schtasks reads task XML as UTF-16 with a byte order mark.
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
        let file = paths.data_dir.join(format!("task-{}.xml", crate::util::new_id()));
        crate::platform::write_private_new(&file, &bytes)?;
        let name = windows_task_name();
        let created = run_tool("schtasks", &["/Create", "/TN", &name, "/XML", &file.to_string_lossy(), "/F"]);
        let _ = std::fs::remove_file(&file);
        created?;
        let _ = run_tool("schtasks", &["/End", "/TN", &name]);
        run_tool("schtasks", &["/Run", "/TN", &name])?;
        println!("Installed the logon task \"{name}\" and started it. Log: {}", paths.log_file().display());
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = exe;
        bail!("no login item support on this platform; run `dove local start` from your own startup mechanism");
    }
    wait_until_up(paths).await;
    Ok(())
}

/// Waits a few seconds for the service to answer on the admin channel and says whether it did.
async fn wait_until_up(paths: &LocalPaths) {
    let socket = admin_socket(paths);
    for _ in 0..20 {
        if service_version(&socket).await.is_some() {
            println!("Dove answers on its admin channel.");
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    println!("Dove did not answer within 5 seconds; check `dove local status` and the log.");
}

fn admin_socket(paths: &LocalPaths) -> PathBuf {
    Config::load(&paths.config_file).map(|c| c.admin.socket_path).unwrap_or_else(|_| paths.admin_socket())
}

/// Asks the running service to stop over its admin channel and waits until it no longer answers. Returns whether one
/// was running. This is the reliable stop on every platform: on Windows `schtasks /End` ends the task's `conhost`
/// process, which does not always take the `dove.exe` it started along (P4); the task commands remain a fallback.
pub async fn stop_service(paths: &LocalPaths) -> anyhow::Result<bool> {
    let socket = admin_socket(paths);
    if service_version(&socket).await.is_none() {
        return Ok(false);
    }
    let req = crate::admin::AdminRequest::Shutdown;
    let v = tokio::time::timeout(std::time::Duration::from_secs(5), crate::admin::client::send(&socket, &req))
        .await
        .context("the service did not answer the stop request")??;
    if v["stopping"] != true {
        bail!("the service did not accept the stop request: {v}");
    }
    // In-flight requests get up to 10 seconds (spec 8.2).
    for _ in 0..60 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if service_version(&socket).await.is_none() {
            return Ok(true);
        }
    }
    bail!("Dove still answers on {} after 15 seconds; stop it by hand", socket.display())
}

async fn service_version(socket: &Path) -> Option<String> {
    let req = crate::admin::AdminRequest::Version;
    let v = tokio::time::timeout(std::time::Duration::from_secs(2), crate::admin::client::send(socket, &req))
        .await
        .ok()?
        .ok()?;
    v["version"].as_str().map(str::to_string)
}

async fn uninstall(paths: &LocalPaths) -> anyhow::Result<()> {
    // Stop over the admin channel first; the service manager's stop below is the fallback.
    if let Err(e) = stop_service(paths).await {
        eprintln!("warning: {e:#}");
    }
    #[cfg(target_os = "linux")]
    {
        let unit = systemd_unit_path()?;
        let _ = run_tool("systemctl", &["--user", "disable", "--now", SYSTEMD_UNIT]);
        match std::fs::remove_file(&unit) {
            Ok(()) => println!("Stopped Dove and removed {}.", unit.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!("No login item was installed."),
            Err(e) => return Err(e).with_context(|| format!("cannot remove {}", unit.display())),
        }
        let _ = run_tool("systemctl", &["--user", "daemon-reload"]);
    }
    #[cfg(target_os = "macos")]
    {
        let plist = launchd_plist_path()?;
        let domain = format!("gui/{}", nix::unistd::getuid().as_raw());
        let _ = run_tool("launchctl", &["bootout", &format!("{domain}/{SERVICE_LABEL}")]);
        match std::fs::remove_file(&plist) {
            Ok(()) => println!("Stopped Dove and removed {}.", plist.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!("No login item was installed."),
            Err(e) => return Err(e).with_context(|| format!("cannot remove {}", plist.display())),
        }
    }
    #[cfg(windows)]
    {
        let name = windows_task_name();
        let _ = run_tool("schtasks", &["/End", "/TN", &name]);
        match run_tool("schtasks", &["/Delete", "/TN", &name, "/F"]) {
            Ok(_) => println!("Stopped Dove and removed the logon task \"{name}\"."),
            Err(_) => println!("No logon task \"{name}\" was installed."),
        }
    }
    println!("Config, keys and data are kept in {} and {}.", paths.config_file.display(), paths.data_dir.display());
    Ok(())
}

fn login_item_installed() -> anyhow::Result<Option<String>> {
    #[cfg(target_os = "linux")]
    {
        let p = systemd_unit_path()?;
        return Ok(p.exists().then(|| format!("systemd user unit {}", p.display())));
    }
    #[cfg(target_os = "macos")]
    {
        let p = launchd_plist_path()?;
        return Ok(p.exists().then(|| format!("launchd agent {}", p.display())));
    }
    #[cfg(windows)]
    {
        let name = windows_task_name();
        return Ok(run_tool("schtasks", &["/Query", "/TN", &name]).ok().map(|_| format!("logon task \"{name}\"")));
    }
    #[allow(unreachable_code)]
    Ok(None)
}

async fn status(paths: &LocalPaths) -> anyhow::Result<()> {
    println!(
        "config:     {}{}",
        paths.config_file.display(),
        if paths.config_file.exists() { "" } else { " (missing: run `dove local init`)" }
    );
    println!("data:       {}", paths.data_dir.display());
    let cfg = match Config::load(&paths.config_file) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };
    println!("url:        {}/mcp", cfg.public_base());
    println!("admin:      {}", cfg.admin.socket_path.display());
    match login_item_installed() {
        Ok(Some(item)) => println!("login item: {item}"),
        Ok(None) => println!("login item: none (`dove local install` adds one)"),
        Err(e) => println!("login item: unknown ({e})"),
    }
    match service_version(&cfg.admin.socket_path).await {
        Some(v) => println!("service:    running, version {v}"),
        None => println!("service:    not answering"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(root: &Path) -> LocalPaths {
        LocalPaths { config_file: root.join("cfg").join("dove.toml"), data_dir: root.join("data") }
    }

    #[test]
    fn init_writes_a_valid_local_config_and_private_keys() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        init(&p, 48787).unwrap();
        let cfg = Config::load(&p.config_file).unwrap();
        cfg.validate().unwrap();
        assert!(cfg.is_local());
        assert_eq!(cfg.public_url, "http://127.0.0.1:48787");
        assert_eq!(cfg.listen.to_string(), "127.0.0.1:48787");
        assert_eq!(cfg.data_dir, p.data_dir);
        assert_eq!(cfg.admin.socket_path, p.admin_socket());
        #[cfg(unix)]
        assert_eq!(cfg.admin.operator_uid, nix::unistd::getuid().as_raw());
        crate::platform::dir_is_private(&p.data_dir).unwrap();
        crate::platform::dir_is_private(&p.secrets_dir()).unwrap();
        for k in ["kek", "pepper", "index_key"] {
            let f = p.secrets_dir().join(k);
            secrets::check_secret_file_mode(&f).unwrap();
            secrets::KeyRing::load(&f).unwrap();
            // Windows keeps the keys DPAPI-protected on disk.
            assert_eq!(std::fs::read(&f).unwrap().starts_with(secrets::DPAPI_MAGIC.as_bytes()), cfg!(windows));
        }
        // The service starts from it.
        let app = crate::app::App::from_config(cfg).unwrap();
        assert!(app.cfg.is_local());
    }

    /// A second init never replaces keys: losing the kek would lose every stored mailbox credential.
    #[test]
    fn init_refuses_to_overwrite() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        init(&p, 48787).unwrap();
        let kek = std::fs::read(p.secrets_dir().join("kek")).unwrap();
        let err = init(&p, 48788).unwrap_err().to_string();
        assert!(err.contains("already exists"), "{err}");
        assert_eq!(std::fs::read(p.secrets_dir().join("kek")).unwrap(), kek);
        // Keys without a config (a half-deleted setup) are not replaced either.
        std::fs::remove_file(&p.config_file).unwrap();
        let err = init(&p, 48788).unwrap_err().to_string();
        assert!(err.contains("kek already exists"), "{err}");
        assert_eq!(std::fs::read(p.secrets_dir().join("kek")).unwrap(), kek);
        assert!(!p.config_file.exists());
    }

    /// A socket path the service could never bind is refused before anything is written.
    #[cfg(unix)]
    #[test]
    fn init_refuses_a_socket_path_too_long_to_bind() {
        let d = tempfile::tempdir().unwrap();
        let long = d.path().join("x".repeat(MAX_SOCKET_PATH));
        let p = paths(&long);
        let err = init(&p, 48787).unwrap_err().to_string();
        assert!(err.contains("DOVE_LOCAL_HOME"), "{err}");
        assert!(!long.exists(), "nothing is created");
        // Exactly at the limit it still works, and the service can bind there.
        let base = d.path().to_string_lossy().len();
        let fit = d.path().join("y".repeat(MAX_SOCKET_PATH - base - "/".len() - "/data/admin.sock".len()));
        let p = paths(&fit);
        assert_eq!(p.admin_socket().as_os_str().len(), MAX_SOCKET_PATH);
        init(&p, 48787).unwrap();
        std::os::unix::net::UnixListener::bind(p.admin_socket()).unwrap();
    }

    /// A failed init leaves nothing behind that blocks the next try (L5): here the config directory cannot be created
    /// after all three keys were written.
    #[test]
    fn a_failed_init_can_be_retried() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        std::fs::write(d.path().join("cfg"), "a file where the config directory should be").unwrap();
        init(&p, 48787).unwrap_err();
        for k in ["kek", "pepper", "index_key"] {
            assert!(!p.secrets_dir().join(k).exists(), "{k} left behind");
        }
        let leftovers: Vec<_> = std::fs::read_dir(p.secrets_dir()).unwrap().collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        std::fs::remove_file(d.path().join("cfg")).unwrap();
        init(&p, 48787).unwrap();
    }

    /// `write_private_new` never replaces an existing file and leaves no temporary file behind.
    #[test]
    fn private_files_are_created_once_and_atomically() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("kek");
        crate::platform::write_private_new(&f, b"one").unwrap();
        assert!(crate::platform::write_private_new(&f, b"two").is_err());
        assert_eq!(std::fs::read(&f).unwrap(), b"one");
        secrets::check_secret_file_mode(&f).unwrap();
        let names: Vec<String> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["kek"]);
    }

    #[test]
    fn config_text_escapes_windows_paths() {
        let p = LocalPaths {
            config_file: PathBuf::from(r"C:\Users\a b\AppData\Roaming\Dove\dove.toml"),
            data_dir: PathBuf::from(r#"C:\Users\a b\AppData\Local\Dove"q"#),
        };
        let text = config_text(&p, 8787, None);
        let v: toml::Value = toml::from_str(&text).unwrap();
        assert_eq!(v["data_dir"].as_str().unwrap(), r#"C:\Users\a b\AppData\Local\Dove"q"#);
        assert!(v["admin"].get("operator_uid").is_none());
        assert_eq!(v["mode"].as_str(), Some("local"));
    }

    #[test]
    fn login_items_quote_their_paths() {
        let exe = Path::new("/opt/my apps/dove");
        let cfg = Path::new("/home/a/.config/dove/dove.toml");
        let unit = systemd_unit(exe, cfg).unwrap();
        assert!(
            unit.contains("ExecStart=\"/opt/my apps/dove\" local start --config \"/home/a/.config/dove/dove.toml\"")
        );
        // systemd expands `$VAR` and `%x` and ends a directive at a newline (L7).
        let unit = systemd_unit(Path::new("/home/a/$HOME/100%/dove"), cfg).unwrap();
        assert!(unit.contains("ExecStart=\"/home/a/$$HOME/100%%/dove\" local"), "{unit}");
        let err = systemd_unit(Path::new("/tmp/x\nExecStartPre=/bin/evil/dove"), cfg).unwrap_err().to_string();
        assert!(err.contains("control character"), "{err}");
        let plist = launchd_plist(Path::new("/Users/a&b/dove"), cfg, Path::new("/tmp/dove.log"));
        assert!(plist.contains("<string>/Users/a&amp;b/dove</string>"));
        let task = |exe: &str| {
            windows_task_xml(
                "S-1-5-21-1-2-3-1001",
                Path::new(r"C:\Windows\System32\conhost.exe"),
                Path::new(exe),
                Path::new(r"C:\Users\a\AppData\Roaming\Dove\dove.toml"),
                Path::new(r"C:\Users\a\AppData\Local\Dove\dove.log"),
            )
        };
        let xml = task(r"C:\Users\a\AppData\Local\Programs\Dove\dove.exe").unwrap();
        assert!(xml.contains("<UserId>S-1-5-21-1-2-3-1001</UserId>"));
        assert!(xml.contains("<LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel>"));
        assert!(xml.contains(r"--headless &quot;C:\Users\a\AppData\Local\Programs\Dove\dove.exe&quot; local start"));
        // Task Scheduler expands %VAR% in arguments and has no escape for it (L7).
        let err = task(r"C:\Users\%USERNAME%\dove.exe").unwrap_err().to_string();
        assert!(err.contains("contains %"), "{err}");
    }
}
