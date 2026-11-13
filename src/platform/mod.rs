//! Platform differences in one place: private directories and files, the strict-permission check, and per-user
//! paths for local mode. Unix uses modes (0700/0600, nothing for group or others); Windows uses DACLs (owner = the
//! current user, nothing for other accounts; PLAN A58).

pub mod paths;
#[cfg(windows)]
pub mod windows;

use std::path::Path;

use anyhow::{Context, bail};

/// Creates `dir` (and missing parents) private to the current user, or checks that an existing `dir` is private.
pub fn ensure_private_dir(dir: &Path) -> anyhow::Result<()> {
    if !dir.exists() {
        create_private_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    if let Err(why) = dir_is_private(dir) {
        bail!("data directory {} is not private: {why}", dir.display());
    }
    Ok(())
}

/// Creates `dir` and missing parents; the last component is created private (0700 / user-only DACL). Parents are
/// created with the platform defaults.
pub fn create_private_dir_all(dir: &Path) -> std::io::Result<()> {
    if let Some(parent) = dir.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new().mode(0o700).create(dir)?;
        // Explicit chmod: the creation mode is subject to the umask.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(windows)]
    {
        windows::create_private_dir(dir)
    }
}

/// `Ok(())` when `dir` grants nothing to other users, else the reason (doctor, startup).
pub fn dir_is_private(dir: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir).map_err(|e| e.to_string())?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 { Err(format!("it has mode {mode:o}; it must be 0700")) } else { Ok(()) }
    }
    #[cfg(windows)]
    {
        windows::check_private(dir)
    }
}

/// Restricts an existing file to the current user (0600 / user-only DACL).
pub fn restrict_file(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(windows)]
    {
        windows::restrict(path, false)
    }
}

/// Restricts an existing directory to the current user (0700 / user-only DACL inherited by new children).
pub fn restrict_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(windows)]
    {
        windows::restrict(path, true)
    }
}

/// Writes a new file readable only by the current user; fails if `path` exists. The data goes to a private temporary
/// file first, which is then hard-linked to `path` (atomic, never replaces anything), so a failed or interrupted write
/// never leaves a partial file at `path` (L5).
pub fn write_private_new(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = dir.join(format!(".{name}.tmp-{}", crate::util::new_id()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    let mut f = opts.open(&tmp).with_context(|| format!("cannot create {}", tmp.display()))?;
    let written = (|| -> anyhow::Result<()> {
        #[cfg(windows)]
        windows::restrict(&tmp, false).with_context(|| format!("cannot restrict {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        std::fs::hard_link(&tmp, path).with_context(|| format!("cannot create {}", path.display()))
    })();
    let _ = std::fs::remove_file(&tmp);
    written
}

/// The current OS user, as shown in audit actors and doctor output (`uid:1000`, `sid:S-1-5-21-...`).
pub fn current_user_label() -> String {
    #[cfg(unix)]
    {
        format!("uid:{}", nix::unistd::getuid().as_raw())
    }
    #[cfg(windows)]
    {
        match windows::current_user_sid().and_then(|s| s.to_string_sid()) {
            Ok(s) => format!("sid:{s}"),
            Err(_) => "sid:unknown".into(),
        }
    }
}
