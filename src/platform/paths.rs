//! Per-user locations for local mode (PLAN A58).
//!
//! | | config file | data (state, index, secrets, admin socket) |
//! |---|---|---|
//! | Linux | `$XDG_CONFIG_HOME/dove/dove.toml` (`~/.config/dove`) | `$XDG_DATA_HOME/dove` (`~/.local/share/dove`) |
//! | macOS | `~/Library/Application Support/Dove/dove.toml` | `~/Library/Application Support/Dove/data` |
//! | Windows | `%APPDATA%\Dove\dove.toml` | `%LOCALAPPDATA%\Dove` |
//!
//! The config file is called `dove.toml`, not `config.toml`: the remote client keeps its profiles in the same
//! directory on Linux and Windows. `DOVE_LOCAL_HOME` replaces all of them with one directory (`<dir>/dove.toml`,
//! `<dir>/data`), for tests and portable setups.

use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Context, anyhow};

pub const CONFIG_FILE: &str = "dove.toml";

/// Where local mode keeps its files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPaths {
    pub config_file: PathBuf,
    pub data_dir: PathBuf,
}

impl LocalPaths {
    /// The secrets directory (kek, pepper, index key), inside the private data directory.
    pub fn secrets_dir(&self) -> PathBuf {
        self.data_dir.join("secrets")
    }

    /// Log file of the autostart service (launchd and Task Scheduler have no journal).
    pub fn log_file(&self) -> PathBuf {
        self.data_dir.join("dove.log")
    }

    /// The admin endpoint: a Unix socket in the data directory, or the per-user named pipe on Windows.
    pub fn admin_socket(&self) -> PathBuf {
        #[cfg(unix)]
        {
            self.data_dir.join("admin.sock")
        }
        #[cfg(windows)]
        {
            PathBuf::from(default_admin_pipe())
        }
    }
}

/// Local-mode paths from the environment (`var` reads one variable; real code passes `std::env::var_os`).
pub fn local_paths_from(var: impl Fn(&str) -> Option<OsString>) -> anyhow::Result<LocalPaths> {
    let abs = |k: &str| var(k).map(PathBuf::from).filter(|p| p.is_absolute());
    if let Some(d) = abs("DOVE_LOCAL_HOME") {
        return Ok(LocalPaths { config_file: d.join(CONFIG_FILE), data_dir: d.join("data") });
    }
    if cfg!(windows) {
        let roaming = abs("APPDATA").ok_or_else(|| anyhow!("%APPDATA% is not set"))?;
        let local = abs("LOCALAPPDATA").ok_or_else(|| anyhow!("%LOCALAPPDATA% is not set"))?;
        return Ok(LocalPaths { config_file: roaming.join("Dove").join(CONFIG_FILE), data_dir: local.join("Dove") });
    }
    let home = abs("HOME").context("HOME is not set")?;
    if cfg!(target_os = "macos") {
        let base = home.join("Library").join("Application Support").join("Dove");
        return Ok(LocalPaths { config_file: base.join(CONFIG_FILE), data_dir: base.join("data") });
    }
    let config = abs("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
    let data = abs("XDG_DATA_HOME").unwrap_or_else(|| home.join(".local").join("share"));
    Ok(LocalPaths { config_file: config.join("dove").join(CONFIG_FILE), data_dir: data.join("dove") })
}

pub fn local_paths() -> anyhow::Result<LocalPaths> {
    local_paths_from(|k| std::env::var_os(k))
}

/// `\\.\pipe\dove-admin-<user SID>`: one admin pipe per Windows user.
#[cfg(windows)]
pub fn default_admin_pipe() -> String {
    let sid = super::windows::current_user_sid().and_then(|s| s.to_string_sid()).unwrap_or_else(|_| "unknown".into());
    format!(r"\\.\pipe\dove-admin-{sid}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let pairs: Vec<(String, String)> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| OsString::from(v))
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_follows_xdg() {
        let p = local_paths_from(env(&[("HOME", "/home/a")])).unwrap();
        assert_eq!(p.config_file, PathBuf::from("/home/a/.config/dove/dove.toml"));
        assert_eq!(p.data_dir, PathBuf::from("/home/a/.local/share/dove"));
        assert_eq!(p.admin_socket(), PathBuf::from("/home/a/.local/share/dove/admin.sock"));
        let p =
            local_paths_from(env(&[("HOME", "/home/a"), ("XDG_CONFIG_HOME", "/c"), ("XDG_DATA_HOME", "rel")])).unwrap();
        assert_eq!(p.config_file, PathBuf::from("/c/dove/dove.toml"));
        assert_eq!(p.data_dir, PathBuf::from("/home/a/.local/share/dove"), "relative XDG paths are ignored");
    }

    #[cfg(windows)]
    #[test]
    fn windows_uses_roaming_config_and_local_data() {
        let p = local_paths_from(env(&[
            (r"APPDATA", r"C:\U\a\AppData\Roaming"),
            ("LOCALAPPDATA", r"C:\U\a\AppData\Local"),
        ]))
        .unwrap();
        assert_eq!(p.config_file, PathBuf::from(r"C:\U\a\AppData\Roaming\Dove\dove.toml"));
        assert_eq!(p.data_dir, PathBuf::from(r"C:\U\a\AppData\Local\Dove"));
        assert!(p.admin_socket().to_string_lossy().starts_with(r"\\.\pipe\dove-admin-S-1-"));
    }

    #[test]
    fn override_puts_everything_in_one_directory() {
        let root = std::env::temp_dir().join("dove-local");
        let p = local_paths_from(env(&[("DOVE_LOCAL_HOME", root.to_str().unwrap()), ("HOME", "/h")])).unwrap();
        assert_eq!(p.config_file, root.join("dove.toml"));
        assert_eq!(p.data_dir, root.join("data"));
        assert_eq!(p.secrets_dir(), root.join("data").join("secrets"));
    }
}
