//! Replacing the running `dove.exe` (PLAN A58). Windows refuses to overwrite or delete an executable while a process
//! runs it, but allows renaming it. So the old file is renamed aside (`.dove.exe.old-<id>` in the same directory),
//! the new one is moved to the original name, and the old one is deleted right away when nothing runs it any more,
//! or else on a later start ([`cleanup_old_binaries`]).

use std::path::{Path, PathBuf};

fn aside_prefix(exe: &Path) -> String {
    format!(".{}.old-", exe.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "dove.exe".into()))
}

/// Moves `new` to `exe`, renaming a present `exe` aside first. On failure the original `exe` is put back.
pub fn swap_in(new: &Path, exe: &Path) -> std::io::Result<()> {
    let dir = exe.parent().unwrap_or(Path::new("."));
    let aside: PathBuf = dir.join(format!("{}{}", aside_prefix(exe), crate::util::new_id()));
    let moved_aside = match std::fs::rename(exe, &aside) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e),
    };
    if let Err(e) = std::fs::rename(new, exe) {
        if moved_aside {
            let _ = std::fs::rename(&aside, exe);
        }
        return Err(e);
    }
    if moved_aside {
        // Fails while a process (this one, or the service) still runs the old binary; a later start retries.
        let _ = std::fs::remove_file(&aside);
    }
    Ok(())
}

/// Deletes binaries left aside by earlier upgrades next to `exe`. Files still in use stay for the next start.
/// Returns how many were deleted.
pub fn cleanup_old_binaries(exe: &Path) -> usize {
    let Some(dir) = exe.parent() else { return 0 };
    let prefix = aside_prefix(exe);
    let Ok(entries) = std::fs::read_dir(dir) else { return 0 };
    entries
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter(|e| std::fs::remove_file(e.path()).is_ok())
        .count()
}

/// [`cleanup_old_binaries`] for the running executable; errors are ignored (it must never fail a command).
pub fn cleanup_after_upgrade() {
    if let Ok(exe) = std::env::current_exe() {
        cleanup_old_binaries(&exe);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".old-"))
            .collect()
    }

    /// A running executable is replaced: it is renamed aside (its deletion fails while it runs) and cleaned up on a
    /// later start. `ping.exe` copied to `dove.exe` stands in for the running service.
    #[test]
    fn a_running_exe_is_replaced_and_cleaned_up_later() {
        let d = tempfile::tempdir().unwrap();
        let exe = d.path().join("dove.exe");
        let system = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        std::fs::copy(system.join("System32").join("PING.EXE"), &exe).unwrap();
        let mut child = std::process::Command::new(&exe)
            .args(["-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        // Overwriting in place is what Windows refuses.
        assert!(std::fs::write(&exe, b"new").is_err(), "the running exe could be overwritten in place");
        super::super::replace_binary(&exe, b"new binary").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new binary");
        assert_eq!(leftovers(d.path()).len(), 1, "the old binary is still in use and stays aside");
        assert_eq!(cleanup_old_binaries(&exe), 0, "in use: not deleted yet");
        child.kill().unwrap();
        child.wait().unwrap();
        // The process may hold the image a moment after it exits.
        let mut removed = 0;
        for _ in 0..50 {
            removed += cleanup_old_binaries(&exe);
            if leftovers(d.path()).is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert_eq!(removed, 1);
        assert!(leftovers(d.path()).is_empty());
        assert_eq!(std::fs::read(&exe).unwrap(), b"new binary");
    }

    #[test]
    fn a_failed_swap_restores_the_old_binary() {
        let d = tempfile::tempdir().unwrap();
        let exe = d.path().join("dove.exe");
        std::fs::write(&exe, b"old").unwrap();
        let err = swap_in(&d.path().join("missing-new"), &exe).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(std::fs::read(&exe).unwrap(), b"old");
        assert!(leftovers(d.path()).is_empty());
    }
}
