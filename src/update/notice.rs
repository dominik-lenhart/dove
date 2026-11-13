//! The "new version available" line on stderr after CLI commands.
//!
//! At most one release lookup per day: its outcome, a failure included, is cached in a small JSON file in the user's
//! cache directory, so a dead network costs at most [`NOTICE_BUDGET`] once a day. A missing, corrupt or unwritable
//! cache is tolerated silently. The caller decides when the notice applies ([`enabled`] plus the command) and prints
//! the line; nothing here writes to stdout or changes a command's outcome.

use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use semver::Version;
use serde::{Deserialize, Serialize};

use super::{Source, parse_tag, tag};

/// Minimum time between two release lookups.
pub const CHECK_INTERVAL_SECS: i64 = 24 * 60 * 60;
/// The longest a command may wait for the notice. The lookup itself gets a little less, so that its outcome is cached
/// before the command stops waiting.
pub const NOTICE_BUDGET: Duration = Duration::from_secs(2);
const LOOKUP_TIMEOUT: Duration = Duration::from_millis(1800);
const CACHE_FILE: &str = "update-check.json";
const MAX_CACHE_BYTES: u64 = 4096;

/// Cached outcome of the last lookup. `latest` is a release tag; a failed lookup keeps the previous one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEntry {
    pub checked_at: i64,
    pub latest: Option<String>,
}

/// Whether the notice may run at all: only for a terminal on stderr, not in CI, and not when opted out with
/// `DOVE_NO_UPDATE_CHECK` (any value except empty or `0`).
pub fn enabled(var: impl Fn(&str) -> Option<OsString>, stderr_is_terminal: bool) -> bool {
    stderr_is_terminal && var("CI").is_none() && !var("DOVE_NO_UPDATE_CHECK").is_some_and(|v| !v.is_empty() && v != "0")
}

/// The cache directory: `~/Library/Caches/dove` on macOS, else `$XDG_CACHE_HOME/dove` or `~/.cache/dove`.
pub fn cache_dir(var: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let home = var("HOME").map(PathBuf::from).filter(|p| p.is_absolute());
    if cfg!(target_os = "macos") {
        return home.map(|h| h.join("Library").join("Caches").join("dove"));
    }
    if let Some(d) = var("XDG_CACHE_HOME").map(PathBuf::from).filter(|d| d.is_absolute()) {
        return Some(d.join("dove"));
    }
    home.map(|h| h.join(".cache").join("dove"))
}

/// The cache file in [`cache_dir`].
pub fn cache_file(var: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    cache_dir(var).map(|d| d.join(CACHE_FILE))
}

/// Reads the cache; anything unreadable counts as no cache.
pub fn read_cache(path: &Path) -> Option<CacheEntry> {
    let mut text = String::new();
    std::fs::File::open(path).ok()?.take(MAX_CACHE_BYTES).read_to_string(&mut text).ok()?;
    serde_json::from_str(&text).ok()
}

/// Writes the cache (directory 0700, file 0600). Errors are ignored: the notice must never fail a command.
pub fn write_cache(path: &Path, entry: &CacheEntry) {
    use std::os::unix::fs::DirBuilderExt;
    let Some(dir) = path.parent() else { return };
    if std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).is_err() {
        return;
    }
    if let Ok(data) = serde_json::to_vec(entry) {
        let _ = crate::client::profile::atomic_write(path, &data, 0o600);
    }
}

/// A cache entry younger than [`CHECK_INTERVAL_SECS`]. An entry from the future (clock moved back) is stale.
pub fn is_fresh(entry: &CacheEntry, now: i64) -> bool {
    now >= entry.checked_at && now - entry.checked_at < CHECK_INTERVAL_SECS
}

/// The latest known release: from a fresh cache without any request, else from one lookup whose outcome is cached.
pub async fn latest_known(cache: Option<&Path>, src: &Source, http: &reqwest::Client, now: i64) -> Option<Version> {
    let cached = cache.and_then(read_cache);
    if let Some(c) = &cached
        && is_fresh(c, now)
    {
        return c.latest.as_deref().and_then(|t| parse_tag(t).ok());
    }
    let found = super::latest_release(src, http).await.ok();
    let entry =
        CacheEntry { checked_at: now, latest: found.as_ref().map(tag).or_else(|| cached.and_then(|c| c.latest)) };
    if let Some(p) = cache {
        write_cache(p, &entry);
    }
    entry.latest.as_deref().and_then(|t| parse_tag(t).ok())
}

/// The notice for a newer release.
pub fn notice_text(latest: &Version, installed: &Version) -> String {
    format!("A new Dove version is available: {} (installed {}). Run: dove upgrade", tag(latest), tag(installed))
}

/// The notice, when `latest` is newer than the installed version.
pub fn notice_line(latest: Option<&Version>, installed: &Version) -> Option<String> {
    latest.filter(|l| *l > installed).map(|l| notice_text(l, installed))
}

/// The production check for this binary (GitHub, user cache). The caller bounds it with [`NOTICE_BUDGET`].
pub async fn check() -> Option<String> {
    let src = Source::github();
    let http = super::http_client(LOOKUP_TIMEOUT).ok()?;
    let cache = cache_file(|k| std::env::var_os(k));
    let latest = latest_known(cache.as_deref(), &src, &http, crate::util::now_unix()).await;
    notice_line(latest.as_ref(), &src.current)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let pairs: Vec<(String, String)> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| OsString::from(v))
    }

    #[test]
    fn suppressed_without_terminal_in_ci_and_on_opt_out() {
        assert!(enabled(env(&[]), true));
        assert!(!enabled(env(&[]), false), "stderr is not a terminal");
        assert!(!enabled(env(&[("CI", "true")]), true));
        assert!(!enabled(env(&[("CI", "")]), true), "CI set, even empty");
        assert!(!enabled(env(&[("DOVE_NO_UPDATE_CHECK", "1")]), true));
        assert!(!enabled(env(&[("DOVE_NO_UPDATE_CHECK", "yes")]), true));
        assert!(enabled(env(&[("DOVE_NO_UPDATE_CHECK", "0")]), true));
        assert!(enabled(env(&[("DOVE_NO_UPDATE_CHECK", "")]), true));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn cache_location() {
        assert_eq!(
            cache_file(env(&[("HOME", "/home/u"), ("XDG_CACHE_HOME", "/xdg")])),
            Some(PathBuf::from("/xdg/dove/update-check.json"))
        );
        assert_eq!(
            cache_file(env(&[("HOME", "/home/u"), ("XDG_CACHE_HOME", "relative")])),
            Some(PathBuf::from("/home/u/.cache/dove/update-check.json"))
        );
        assert_eq!(cache_file(env(&[])), None);
    }

    #[test]
    fn freshness() {
        let e = CacheEntry { checked_at: 1_000_000, latest: None };
        assert!(is_fresh(&e, 1_000_000));
        assert!(is_fresh(&e, 1_000_000 + CHECK_INTERVAL_SECS - 1));
        assert!(!is_fresh(&e, 1_000_000 + CHECK_INTERVAL_SECS));
        assert!(!is_fresh(&e, 999_999), "an entry from the future is stale");
    }

    #[test]
    fn line_only_for_newer_releases() {
        let cur = Version::new(0, 2, 0);
        assert_eq!(notice_line(None, &cur), None);
        assert_eq!(notice_line(Some(&Version::new(0, 2, 0)), &cur), None);
        assert_eq!(notice_line(Some(&Version::new(0, 1, 9)), &cur), None);
        assert_eq!(
            notice_line(Some(&Version::new(0, 3, 0)), &cur).unwrap(),
            "A new Dove version is available: v0.3.0 (installed v0.2.0). Run: dove upgrade"
        );
    }

    #[test]
    fn cache_files_are_private_and_corruption_is_tolerated() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("cache").join("dove").join(CACHE_FILE);
        let e = CacheEntry { checked_at: 5, latest: Some("v1.0.0".into()) };
        write_cache(&path, &e);
        assert_eq!(read_cache(&path), Some(e));
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(read_cache(&path), None);
        // An unwritable location is ignored without panicking.
        write_cache(Path::new("/proc/dove-no-such-dir/x.json"), &CacheEntry { checked_at: 1, latest: None });
    }
}
