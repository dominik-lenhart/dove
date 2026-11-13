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

/// Real and effective user id of a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ids {
    pub uid: u32,
    pub euid: u32,
}

impl Ids {
    /// On Windows an elevated (administrator) token counts as root: `euid` 0.
    pub fn current() -> Self {
        #[cfg(unix)]
        {
            Self { uid: nix::unistd::getuid().as_raw(), euid: nix::unistd::geteuid().as_raw() }
        }
        #[cfg(windows)]
        {
            let euid = if crate::platform::windows::is_elevated() { 0 } else { 1 };
            Self { uid: euid, euid }
        }
    }
}

/// Whether the notice may run at all: only for a terminal on stderr, not in CI, not when opted out with
/// `DOVE_NO_UPDATE_CHECK` (any value except empty or `0`), and never with privileges (root, setuid, or under sudo):
/// a privileged process must not read or write a cache in a directory another user controls (`sudo -E` or macOS
/// sudo keep `HOME`).
pub fn enabled(var: impl Fn(&str) -> Option<OsString>, stderr_is_terminal: bool, ids: Ids) -> bool {
    stderr_is_terminal
        && ids.euid != 0
        && ids.euid == ids.uid
        && var("SUDO_UID").is_none()
        && var("CI").is_none()
        && !var("DOVE_NO_UPDATE_CHECK").is_some_and(|v| !v.is_empty() && v != "0")
}

/// The cache directory: `~/Library/Caches/dove` on macOS, `%LOCALAPPDATA%\DoveCache` on Windows, else
/// `$XDG_CACHE_HOME/dove` or `~/.cache/dove`. Never inside local mode's data directory (`%LOCALAPPDATA%\Dove`): the
/// notice would create that directory first, with an inherited instead of a private access list (L4).
pub fn cache_dir(var: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    if cfg!(windows) {
        let local = var("LOCALAPPDATA").map(PathBuf::from).filter(|p| p.is_absolute());
        return local.map(|d| d.join("DoveCache"));
    }
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

/// Opens `path` for reading without following a symlink (Unix `O_NOFOLLOW`) or reparse point (Windows: the link
/// itself is opened and then refused).
fn open_nofollow(path: &Path) -> Option<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut opts, nix::libc::O_NOFOLLOW);
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::custom_flags(
        &mut opts,
        windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
    );
    let f = opts.open(path).ok()?;
    #[cfg(windows)]
    if is_reparse_point(&f.metadata().ok()?) {
        return None;
    }
    Some(f)
}

#[cfg(windows)]
fn is_reparse_point(m: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    m.file_attributes() & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Reads the cache; anything unreadable counts as no cache. A symlink at `path` is not followed.
pub fn read_cache(path: &Path) -> Option<CacheEntry> {
    let mut text = String::new();
    let f = open_nofollow(path)?;
    f.take(MAX_CACHE_BYTES).read_to_string(&mut text).ok()?;
    serde_json::from_str(&text).ok()
}

/// Writes the cache (directory 0700, file 0600). Errors are ignored: the notice must never fail a command.
///
/// Symlinks are never followed: the cache directory must be a real directory owned by the effective user, the data
/// goes to a new file with a random name (`O_EXCL | O_NOFOLLOW`), and the rename replaces whatever sits at `path`
/// (a symlink included) instead of writing through it. On Windows the same holds for reparse points (symlinks,
/// junctions), and the directory must be private to the current user.
pub fn write_cache(path: &Path, entry: &CacheEntry) {
    use std::io::Write;
    let Some(dir) = path.parent() else { return };
    if !cache_dir_ok(dir) {
        return;
    }
    let Ok(data) = serde_json::to_vec(entry) else { return };
    let tmp = dir.join(format!(".update-check.{}.tmp", crate::util::new_id()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut opts, nix::libc::O_NOFOLLOW);
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::custom_flags(
        &mut opts,
        windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
    );
    let Ok(mut f) = opts.open(&tmp) else {
        return;
    };
    let written = f.write_all(&data).and_then(|()| f.sync_all());
    drop(f);
    if written.and_then(|()| std::fs::rename(&tmp, path)).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Creates the cache directory if needed and checks it is a real directory (not a symlink or reparse point) of the
/// current user.
fn cache_dir_ok(dir: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        if std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).is_err() {
            return false;
        }
        let euid = nix::unistd::geteuid().as_raw();
        matches!(std::fs::symlink_metadata(dir), Ok(m) if m.file_type().is_dir() && m.uid() == euid)
    }
    #[cfg(windows)]
    {
        if !dir.exists() && crate::platform::create_private_dir_all(dir).is_err() {
            return false;
        }
        matches!(std::fs::symlink_metadata(dir), Ok(m) if m.file_type().is_dir() && !is_reparse_point(&m))
            && crate::platform::windows::check_private(dir).is_ok()
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

    /// The notice never creates (or writes into) local mode's data directory or config directory (L4).
    #[test]
    fn cache_stays_outside_the_local_mode_directories() {
        let root = std::env::temp_dir().join("dove-l4");
        let vars: Vec<(&str, PathBuf)> =
            vec![("HOME", root.join("home")), ("APPDATA", root.join("Roaming")), ("LOCALAPPDATA", root.join("Local"))];
        let var = |k: &str| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone().into_os_string());
        let cache = cache_dir(var).unwrap();
        let local = crate::platform::paths::local_paths_from(var).unwrap();
        assert!(!cache.starts_with(&local.data_dir), "{} is inside {}", cache.display(), local.data_dir.display());
        assert!(!local.data_dir.starts_with(&cache));
        assert!(!cache.starts_with(local.config_file.parent().unwrap()));
    }

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let pairs: Vec<(String, String)> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| OsString::from(v))
    }

    #[test]
    fn suppressed_without_terminal_in_ci_and_on_opt_out() {
        let user = Ids { uid: 1000, euid: 1000 };
        assert!(enabled(env(&[]), true, user));
        assert!(!enabled(env(&[]), false, user), "stderr is not a terminal");
        assert!(!enabled(env(&[("CI", "true")]), true, user));
        assert!(!enabled(env(&[("CI", "")]), true, user), "CI set, even empty");
        assert!(!enabled(env(&[("DOVE_NO_UPDATE_CHECK", "1")]), true, user));
        assert!(!enabled(env(&[("DOVE_NO_UPDATE_CHECK", "yes")]), true, user));
        assert!(enabled(env(&[("DOVE_NO_UPDATE_CHECK", "0")]), true, user));
        assert!(enabled(env(&[("DOVE_NO_UPDATE_CHECK", "")]), true, user));
    }

    #[test]
    fn never_with_privileges() {
        assert!(!enabled(env(&[]), true, Ids { uid: 0, euid: 0 }), "root");
        assert!(!enabled(env(&[]), true, Ids { uid: 1000, euid: 0 }), "setuid root");
        assert!(!enabled(env(&[]), true, Ids { uid: 0, euid: 1000 }), "euid differs from uid");
        assert!(!enabled(env(&[("SUDO_UID", "1000")]), true, Ids { uid: 1001, euid: 1001 }), "sudo -u someone");
    }

    #[cfg(unix)]
    #[test]
    fn cache_writes_do_not_follow_symlinks() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        // The cache directory is a symlink to somewhere else: nothing is written there.
        let elsewhere = d.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::create_dir(d.path().join("cache")).unwrap();
        symlink(&elsewhere, d.path().join("cache").join("dove")).unwrap();
        let entry = CacheEntry { checked_at: 7, latest: Some("v1.0.0".into()) };
        write_cache(&d.path().join("cache").join("dove").join(CACHE_FILE), &entry);
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0, "wrote through a symlinked directory");

        // The cache file is a symlink to a victim file: the victim keeps its content, the link is replaced.
        let dir = d.path().join("real");
        std::fs::create_dir(&dir).unwrap();
        let victim = d.path().join("victim");
        // A valid cache entry, so reading through the link would be visible.
        let precious = br#"{"checked_at":1,"latest":"v9.9.9"}"#;
        std::fs::write(&victim, precious).unwrap();
        let path = dir.join(CACHE_FILE);
        symlink(&victim, &path).unwrap();
        assert_eq!(read_cache(&path), None, "a symlinked cache file is not read");
        write_cache(&path, &entry);
        assert_eq!(std::fs::read(&victim).unwrap(), precious);
        assert!(!std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
        assert_eq!(read_cache(&path), Some(entry));
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "no temporary file left");
    }

    /// Windows twin of `cache_writes_do_not_follow_symlinks`. Creating symlinks needs a privilege (developer mode or
    /// an elevated token); without it the test has nothing to check and returns.
    #[cfg(windows)]
    #[test]
    fn cache_writes_do_not_follow_reparse_points() {
        use std::os::windows::fs::symlink_file;
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("real");
        crate::platform::create_private_dir_all(&dir).unwrap();
        let victim = d.path().join("victim");
        let precious = br#"{"checked_at":1,"latest":"v9.9.9"}"#;
        std::fs::write(&victim, precious).unwrap();
        let path = dir.join(CACHE_FILE);
        if let Err(e) = symlink_file(&victim, &path) {
            // CI runners can create symlinks (administrator); there a skip would hide a regression.
            assert!(std::env::var_os("CI").is_none(), "cannot create a symlink on CI: {e}");
            eprintln!("skipped: cannot create a symlink here ({e})");
            return;
        }
        assert_eq!(read_cache(&path), None, "a symlinked cache file is not read");
        let entry = CacheEntry { checked_at: 7, latest: Some("v1.0.0".into()) };
        write_cache(&path, &entry);
        assert_eq!(std::fs::read(&victim).unwrap(), precious);
        assert!(!std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
        assert_eq!(read_cache(&path), Some(entry));
    }

    /// A junction (a directory reparse point, which any user may create) as the cache directory is never written
    /// through, so this half of the check runs on every Windows machine.
    #[cfg(windows)]
    #[test]
    fn cache_writes_do_not_follow_a_junction() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        let dir = d.path().join("cache");
        let ok = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&dir)
            .arg(&target)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(ok.success(), "mklink /J failed");
        let entry = CacheEntry { checked_at: 7, latest: Some("v1.0.0".into()) };
        write_cache(&dir.join(CACHE_FILE), &entry);
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0, "written through the junction");
        assert_eq!(read_cache(&dir.join(CACHE_FILE)), None);
    }

    #[cfg(windows)]
    #[test]
    fn windows_cache_location() {
        assert_eq!(
            cache_file(env(&[("LOCALAPPDATA", r"C:\U\a\AppData\Local"), ("HOME", "/h")])),
            Some(PathBuf::from(r"C:\U\a\AppData\Local\DoveCache\update-check.json"))
        );
        assert_eq!(cache_file(env(&[("HOME", r"C:\U\a")])), None);
    }

    #[cfg(not(any(target_os = "macos", windows)))]
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

    #[cfg(unix)]
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
