//! `dove mcp install`: adds a stdio entry for `dove mcp stdio --profile <p>` to a host's MCP configuration.
//!
//! Supported (spec 5.6): Claude Code (`~/.claude.json` user scope, `./.mcp.json` project scope, key `mcpServers`),
//! Codex (`~/.codex/config.toml` or `$CODEX_HOME/config.toml` user scope, `./.codex/config.toml` project scope,
//! table `mcp_servers`) and Claude Desktop (`claude_desktop_config.json`, user scope only, key `mcpServers`; PLAN A58). Existing files are parsed first and left untouched when invalid. Unrelated entries are kept
//! byte for byte where the format allows it (raw JSON values, `toml_edit` documents). Writes are atomic and
//! idempotent. The entry holds only the absolute `dove` path and the profile name, never a credential.
//! Compatibility with current host versions is unverified (docs/PLAN.md).

use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use indexmap::IndexMap;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum HostClient {
    ClaudeCode,
    Codex,
    ClaudeDesktop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Scope {
    User,
    Project,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Installed,
    Updated,
    Unchanged,
}

pub struct Entry {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
}

impl Entry {
    pub fn for_profile(profile: &str, name: Option<&str>, command: &Path) -> Self {
        Self {
            name: name.map(str::to_string).unwrap_or_else(|| format!("dove-{profile}")),
            command: command.to_string_lossy().into_owned(),
            args: vec!["mcp".into(), "stdio".into(), "--profile".into(), profile.into()],
        }
    }
}

pub fn config_path(client: HostClient, scope: Scope, home: &Path, cwd: &Path) -> anyhow::Result<PathBuf> {
    Ok(match (client, scope) {
        (HostClient::ClaudeCode, Scope::User) => match std::env::var_os("CLAUDE_CONFIG_DIR") {
            Some(d) if !d.is_empty() => PathBuf::from(d).join(".claude.json"),
            _ => home.join(".claude.json"),
        },
        (HostClient::ClaudeCode, Scope::Project) => cwd.join(".mcp.json"),
        (HostClient::Codex, Scope::User) => match std::env::var_os("CODEX_HOME") {
            Some(d) if !d.is_empty() => PathBuf::from(d).join("config.toml"),
            _ => home.join(".codex").join("config.toml"),
        },
        (HostClient::Codex, Scope::Project) => cwd.join(".codex").join("config.toml"),
        (HostClient::ClaudeDesktop, Scope::User) => claude_desktop_path(home, |k| std::env::var_os(k))?,
        (HostClient::ClaudeDesktop, Scope::Project) => bail!("Claude Desktop has no project scope; use --scope user"),
    })
}

/// Claude Desktop's config file: `%APPDATA%\Claude\claude_desktop_config.json` on Windows (or the Microsoft Store
/// package's redirected copy when only that one exists), `~/Library/Application Support/Claude/...` on macOS, and the
/// XDG config directory elsewhere (community Linux builds).
pub fn claude_desktop_path(home: &Path, var: impl Fn(&str) -> Option<std::ffi::OsString>) -> anyhow::Result<PathBuf> {
    const FILE: &str = "claude_desktop_config.json";
    let abs = |k: &str| var(k).map(PathBuf::from).filter(|p| p.is_absolute());
    if cfg!(windows) {
        let regular = abs("APPDATA").ok_or_else(|| anyhow!("%APPDATA% is not set"))?.join("Claude");
        if !regular.join(FILE).exists()
            && let Some(local) = abs("LOCALAPPDATA")
            && let Ok(entries) = std::fs::read_dir(local.join("Packages"))
        {
            // The Store build keeps AppData in its package (Packages\Claude_<publisher id>\LocalCache\Roaming).
            let packaged: Vec<PathBuf> = entries
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with("Claude_"))
                .map(|e| e.path().join("LocalCache").join("Roaming").join("Claude"))
                .filter(|d| d.join(FILE).exists())
                .collect();
            if let [only] = packaged.as_slice() {
                return Ok(only.join(FILE));
            }
        }
        return Ok(regular.join(FILE));
    }
    if cfg!(target_os = "macos") {
        return Ok(home.join("Library").join("Application Support").join("Claude").join(FILE));
    }
    Ok(abs("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config")).join("Claude").join(FILE))
}

/// Installs or updates the entry in `path`. `new_file_mode` applies only when the file does not exist yet.
pub fn install(client: HostClient, path: &Path, entry: &Entry, new_file_mode: u32) -> anyhow::Result<Outcome> {
    let existing = match std::fs::read_to_string(path) {
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let merged = match client {
        HostClient::ClaudeCode => merge_json(existing.as_deref(), entry, true)?,
        HostClient::ClaudeDesktop => merge_json(existing.as_deref(), entry, false)?,
        HostClient::Codex => merge_toml(existing.as_deref(), entry)?,
    };
    let Some((text, outcome)) = merged else {
        return Ok(Outcome::Unchanged);
    };
    let mode = match std::fs::metadata(path) {
        #[cfg(unix)]
        Ok(m) => {
            use std::os::unix::fs::PermissionsExt;
            m.permissions().mode() & 0o777
        }
        #[cfg(not(unix))]
        Ok(_) => new_file_mode,
        Err(_) => new_file_mode,
    };
    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
    {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    super::profile::atomic_write(path, text.as_bytes(), mode)?;
    Ok(outcome)
}

/// The JSON server entry. Claude Desktop's schema has no `type` key (every entry is stdio there).
fn entry_json(e: &Entry, with_type: bool) -> Value {
    if with_type {
        serde_json::json!({ "type": "stdio", "command": e.command, "args": e.args, "env": {} })
    } else {
        serde_json::json!({ "command": e.command, "args": e.args, "env": {} })
    }
}

/// Returns the new file text, or `None` when the entry is already present and identical.
/// A JSON value that keeps object key order, so rewriting a host's config does not reorder unrelated settings.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
enum OrderedJson {
    Null(()),
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<OrderedJson>),
    Object(IndexMap<String, OrderedJson>),
}

/// Returns the new file text, or `None` when the entry is already present and identical. The output uses two-space
/// indentation (the format Claude Code itself writes); key order and all unrelated values are kept.
fn merge_json(existing: Option<&str>, e: &Entry, with_type: bool) -> anyhow::Result<Option<(String, Outcome)>> {
    let mut top: IndexMap<String, OrderedJson> = match existing.map(str::trim) {
        None | Some("") => IndexMap::new(),
        Some(t) => serde_json::from_str(t)
            .map_err(|err| anyhow!("existing file is not a JSON object ({err}); not modified"))?,
    };
    let wanted: OrderedJson = serde_json::from_value(entry_json(e, with_type))?;
    let servers = top.entry("mcpServers".to_string()).or_insert_with(|| OrderedJson::Object(IndexMap::new()));
    let OrderedJson::Object(servers) = servers else {
        bail!("`mcpServers` is not a JSON object; not modified");
    };
    let outcome = match servers.get(&e.name) {
        Some(cur) if serde_json::to_value(cur)? == serde_json::to_value(&wanted)? => return Ok(None),
        Some(_) => Outcome::Updated,
        None => Outcome::Installed,
    };
    servers.insert(e.name.clone(), wanted);
    let mut text = serde_json::to_string_pretty(&top)?;
    text.push('\n');
    // Never write something we could not read back, and never lose a value.
    let reread: Value = serde_json::from_str(&text).context("internal: generated invalid JSON")?;
    if let Some(orig) = existing.filter(|t| !t.trim().is_empty()) {
        let mut orig: Value = serde_json::from_str(orig)?;
        if let Some(m) = orig.get_mut("mcpServers").and_then(Value::as_object_mut) {
            m.remove(&e.name);
        }
        let mut check = reread.clone();
        if let Some(m) = check.get_mut("mcpServers").and_then(Value::as_object_mut) {
            m.remove(&e.name);
        }
        if orig.get("mcpServers").is_none() {
            check.as_object_mut().map(|o| o.remove("mcpServers"));
        }
        if orig != check {
            bail!("internal: rewriting the file would change unrelated settings; not modified");
        }
    }
    Ok(Some((text, outcome)))
}

fn merge_toml(existing: Option<&str>, e: &Entry) -> anyhow::Result<Option<(String, Outcome)>> {
    use toml_edit::{Array, DocumentMut, Item, Table, value};
    let mut doc: DocumentMut = existing
        .unwrap_or("")
        .parse()
        .map_err(|err| anyhow!("existing file is not valid TOML ({err}); not modified"))?;
    if !doc.contains_key("mcp_servers") {
        let mut t = Table::new();
        t.set_implicit(true);
        doc.insert("mcp_servers", Item::Table(t));
    }
    let servers =
        doc["mcp_servers"].as_table_mut().ok_or_else(|| anyhow!("`mcp_servers` is not a table; not modified"))?;
    let current = servers.get(&e.name).and_then(Item::as_table);
    let same = current.is_some_and(|t| {
        t.get("command").and_then(|c| c.as_str()) == Some(e.command.as_str())
            && t.get("args").and_then(|a| a.as_array()).is_some_and(|a| {
                a.iter().map(|v| v.as_str()).collect::<Vec<_>>()
                    == e.args.iter().map(|s| Some(s.as_str())).collect::<Vec<_>>()
            })
    });
    if same {
        return Ok(None);
    }
    let outcome = if current.is_some() { Outcome::Updated } else { Outcome::Installed };
    if servers.get(&e.name).is_some_and(|i| !i.is_table()) {
        bail!("`mcp_servers.{}` is not a table; not modified", e.name);
    }
    let table = servers.entry(&e.name).or_insert(Item::Table(Table::new())).as_table_mut().expect("table");
    table.insert("command", value(e.command.clone()));
    let mut args = Array::new();
    for a in &e.args {
        args.push(a.as_str());
    }
    table.insert("args", value(args));
    let text = doc.to_string();
    text.parse::<DocumentMut>().context("internal: generated invalid TOML")?;
    Ok(Some((text, outcome)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry::for_profile("acme", None, Path::new("/usr/local/bin/dove"))
    }

    #[test]
    fn json_merge_preserves_and_is_idempotent() {
        let existing = r#"{"numStartups": 3, "mcpServers": {"other": {"command": "x",   "args": []}}, "zeta": [1,2]}"#;
        let (text, o) = merge_json(Some(existing), &entry(), true).unwrap().unwrap();
        assert_eq!(o, Outcome::Installed);
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["numStartups"], 3);
        assert_eq!(v["zeta"], serde_json::json!([1, 2]));
        assert_eq!(v["mcpServers"]["dove-acme"]["args"], serde_json::json!(["mcp", "stdio", "--profile", "acme"]));
        assert_eq!(v["mcpServers"]["other"], serde_json::json!({"command": "x", "args": []}));
        let other = text.find("\"other\"").unwrap();
        assert!(other < text.find("\"dove-acme\"").unwrap(), "existing servers keep their place: {text}");
        let keys: Vec<&str> =
            text.lines().filter_map(|l| l.strip_prefix("  \"")).map(|l| l.split('"').next().unwrap()).collect();
        assert_eq!(keys, ["numStartups", "mcpServers", "zeta"], "top-level order kept");
        assert!(merge_json(Some(&text), &entry(), true).unwrap().is_none(), "second run is a no-op");
        assert!(merge_json(Some("[1]"), &entry(), true).is_err());
        assert!(merge_json(Some("{broken"), &entry(), true).is_err());
    }

    #[test]
    fn toml_merge_preserves_comments_and_is_idempotent() {
        let existing = "# my settings\nmodel = \"o3\" # keep\n\n[mcp_servers.other]\ncommand = \"x\"\n";
        let (text, o) = merge_toml(Some(existing), &entry()).unwrap().unwrap();
        assert_eq!(o, Outcome::Installed);
        assert!(text.starts_with("# my settings\nmodel = \"o3\" # keep\n"), "{text}");
        assert!(text.contains("[mcp_servers.other]\ncommand = \"x\""));
        assert!(text.contains("[mcp_servers.dove-acme]"));
        assert!(merge_toml(Some(&text), &entry()).unwrap().is_none());
        let moved = Entry::for_profile("acme", None, Path::new("/opt/dove"));
        assert_eq!(merge_toml(Some(&text), &moved).unwrap().unwrap().1, Outcome::Updated);
        assert!(merge_toml(Some("not = [valid"), &entry()).is_err());
    }

    /// Claude Desktop: same `mcpServers` map, entries without `type`, other settings kept.
    #[test]
    fn claude_desktop_entry_has_no_type_and_keeps_settings() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("Claude").join("claude_desktop_config.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"globalShortcut": "Ctrl+Space", "mcpServers": {"fs": {"command": "npx", "args": ["x"]}}}"#,
        )
        .unwrap();
        assert_eq!(install(HostClient::ClaudeDesktop, &path, &entry(), 0o600).unwrap(), Outcome::Installed);
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["globalShortcut"], "Ctrl+Space");
        assert_eq!(v["mcpServers"]["fs"], serde_json::json!({"command": "npx", "args": ["x"]}));
        assert_eq!(
            v["mcpServers"]["dove-acme"],
            serde_json::json!({"command": "/usr/local/bin/dove", "args": ["mcp", "stdio", "--profile", "acme"], "env": {}})
        );
        assert_eq!(install(HostClient::ClaudeDesktop, &path, &entry(), 0o600).unwrap(), Outcome::Unchanged);
        assert!(config_path(HostClient::ClaudeDesktop, Scope::Project, d.path(), d.path()).is_err());
    }

    #[test]
    fn claude_desktop_location() {
        let env = |pairs: Vec<(&'static str, std::path::PathBuf)>| {
            move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone().into_os_string())
        };
        let d = tempfile::tempdir().unwrap();
        let home = d.path().join("home");
        // Every location comes from the injected variables, never from the test runner's environment.
        let xdg = || env(vec![("XDG_CONFIG_HOME", d.path().join("xdg"))]);
        if cfg!(target_os = "macos") {
            let p = claude_desktop_path(&home, xdg()).unwrap();
            assert_eq!(p, home.join("Library/Application Support/Claude/claude_desktop_config.json"));
        } else if cfg!(windows) {
            assert!(claude_desktop_path(&home, env(vec![])).is_err(), "needs %APPDATA%");
            let roaming = d.path().join("Roaming");
            let local = d.path().join("Local");
            let vars = || env(vec![("APPDATA", roaming.clone()), ("LOCALAPPDATA", local.clone())]);
            assert_eq!(
                claude_desktop_path(&home, vars()).unwrap(),
                roaming.join("Claude").join("claude_desktop_config.json")
            );
            // The Store build's redirected file is used when it is the only one.
            let pkg = local.join("Packages").join("Claude_abc123").join("LocalCache").join("Roaming").join("Claude");
            std::fs::create_dir_all(&pkg).unwrap();
            std::fs::write(pkg.join("claude_desktop_config.json"), "{}").unwrap();
            assert_eq!(claude_desktop_path(&home, vars()).unwrap(), pkg.join("claude_desktop_config.json"));
        } else {
            let p = claude_desktop_path(&home, xdg()).unwrap();
            assert_eq!(p, d.path().join("xdg").join("Claude").join("claude_desktop_config.json"));
        }
    }
}
