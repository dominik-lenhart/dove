//! Encrypted index database (spec 7.9 "Storage and lifecycle", 8.1a).
//!
//! The index is a rebuildable SQLCipher database with FTS5. At open we verify that SQLCipher is linked, the key is
//! correct, FTS5 is available and temporary storage stays in memory. A plaintext file is refused, never migrated.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, bail};
use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::config::IndexConfig;
use crate::util;

const PLAINTEXT_HEADER: &[u8; 16] = b"SQLite format 3\0";

/// Sets the process-wide SQLite heap hard limit (spec 8.1a). Allocations beyond it fail with SQLITE_NOMEM, which
/// callers map to `budget_exceeded`.
pub fn set_heap_limit(mib: i64) -> i64 {
    unsafe { rusqlite::ffi::sqlite3_hard_heap_limit64(mib.saturating_mul(1024 * 1024)) }
}

fn is_plaintext_sqlite(path: &Path) -> anyhow::Result<bool> {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let mut hdr = [0u8; 16];
    match f.read_exact(&mut hdr) {
        Ok(()) => Ok(&hdr == PLAINTEXT_HEADER),
        Err(_) => Ok(false),
    }
}

/// Opens one index connection with the raw 256-bit key and runs the startup self-checks.
pub fn open(path: &Path, key: &[u8; 32], cfg: &IndexConfig) -> anyhow::Result<Connection> {
    if let Some(dir) = path.parent() {
        crate::store::ensure_private_dir(dir)?;
    }
    if is_plaintext_sqlite(path)? {
        bail!(
            "index file {} is an unencrypted SQLite database; refusing to use it (delete it and rebuild)",
            path.display()
        );
    }
    let conn = Connection::open(path).with_context(|| format!("cannot open index {}", path.display()))?;
    let key_pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", util::hex(key)));
    conn.execute_batch(&key_pragma).context("cannot set index key")?;
    let cipher: Option<String> = conn.query_row("PRAGMA cipher_version", [], |r| r.get(0)).ok();
    if cipher.as_deref().unwrap_or("").is_empty() {
        bail!("SQLCipher is not available in this build; refusing plaintext index");
    }
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
        .context("index key is wrong or the index file is corrupt")?;
    conn.execute_batch(&format!(
        "PRAGMA temp_store = MEMORY; PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; \
         PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA secure_delete = ON; \
         PRAGMA cache_size = -{};",
        cfg.page_cache_kib.max(256)
    ))?;
    let temp_store: i64 = conn.query_row("PRAGMA temp_store", [], |r| r.get(0))?;
    if temp_store != 2 {
        bail!("index temp_store is not MEMORY");
    }
    let fts5: bool = conn.query_row("SELECT sqlite_compileoption_used('ENABLE_FTS5')", [], |r| r.get(0))?;
    if !fts5 {
        bail!("FTS5 is not compiled into this SQLite build");
    }
    for suffix in ["", "-wal", "-shm"] {
        let p = std::path::PathBuf::from(format!("{}{suffix}", path.display()));
        if p.exists() {
            crate::platform::restrict_file(&p)?;
        }
    }
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_with_fts5_and_memory_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("idx/index.db");
        let key = util::random_bytes::<32>();
        let cfg = IndexConfig::default();
        let canary = "zebracanary4711";
        {
            let c = open(&path, &key, &cfg).unwrap();
            c.execute_batch("CREATE VIRTUAL TABLE t USING fts5(body, tokenize='unicode61')").unwrap();
            c.execute("INSERT INTO t(body) VALUES (?1)", [canary]).unwrap();
            let n: i64 = c.query_row("SELECT count(*) FROM t WHERE t MATCH ?1", [canary], |r| r.get(0)).unwrap();
            assert_eq!(n, 1);
        }
        // Neither the main file nor any WAL/SHM leftovers contain the canary or a plaintext header.
        for entry in std::fs::read_dir(path.parent().unwrap()).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(!bytes.windows(canary.len()).any(|w| w == canary.as_bytes()));
            assert!(!bytes.starts_with(PLAINTEXT_HEADER));
        }
        // Wrong key fails closed.
        assert!(open(&path, &util::random_bytes::<32>(), &cfg).is_err());
        assert!(open(&path, &key, &cfg).is_ok());
    }

    #[test]
    fn refuses_plaintext_file() {
        let dir = tempfile::tempdir().unwrap();
        crate::platform::restrict_dir(dir.path()).unwrap();
        let path = dir.path().join("index.db");
        Connection::open(&path).unwrap().execute_batch("CREATE TABLE x(a)").unwrap();
        let err = open(&path, &[1; 32], &IndexConfig::default()).unwrap_err();
        assert!(err.to_string().contains("unencrypted"), "{err}");
    }
}
