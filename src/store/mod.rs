//! Durable state store (spec 7.2): SQLite in WAL mode, single writer, versioned migrations.
//!
//! All access goes through [`Store::call`], which runs the closure on a blocking thread. Closures must not await,
//! so a transaction can never span network I/O.

pub mod schema;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use rusqlite::{Connection, OptionalExtension, params};

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
    path: Option<PathBuf>,
}

impl Store {
    /// Opens (creating if needed) the store, enforces file permissions and runs pending migrations.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(dir) = path.parent() {
            ensure_private_dir(dir)?;
        }
        let conn = Connection::open(path).with_context(|| format!("cannot open state store {}", path.display()))?;
        for suffix in ["", "-wal", "-shm"] {
            let p = PathBuf::from(format!("{}{suffix}", path.display()));
            if p.exists() {
                crate::platform::restrict_file(&p)?;
            }
        }
        Self::init(conn, Some(path.to_path_buf()))
    }

    pub fn open_in_memory() -> anyhow::Result<Self> {
        Self::init(Connection::open_in_memory()?, None)
    }

    fn init(mut conn: Connection, path: Option<PathBuf>) -> anyhow::Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; \
             PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON; PRAGMA temp_store=MEMORY;",
        )?;
        migrate(&mut conn)?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)), path })
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Runs `f` with exclusive access on a blocking thread.
    pub async fn call<F, T>(&self, f: F) -> anyhow::Result<T>
    where
        F: FnOnce(&mut Connection) -> anyhow::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().map_err(|_| anyhow::anyhow!("state store lock poisoned"))?;
            f(&mut guard)
        })
        .await
        .context("state store task failed")?
    }

    /// Synchronous access for startup code and tests that are not on the async runtime.
    pub fn call_blocking<F, T>(&self, f: F) -> anyhow::Result<T>
    where
        F: FnOnce(&mut Connection) -> anyhow::Result<T>,
    {
        let mut guard = self.conn.lock().map_err(|_| anyhow::anyhow!("state store lock poisoned"))?;
        f(&mut guard)
    }
}

/// Creates `dir` with mode 0700 or fails if it exists with group/other access.
pub fn ensure_private_dir(dir: &Path) -> anyhow::Result<()> {
    crate::platform::ensure_private_dir(dir)
}

/// Applies migrations in order, each inside its own transaction. A failure rolls back and stops startup (spec 10).
fn migrate(conn: &mut Connection) -> anyhow::Result<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")?;
    let current: i64 = conn
        .query_row("SELECT value FROM meta WHERE key = 'schema_version'", [], |r| r.get::<_, String>(0))
        .optional()?
        .map(|v| v.parse().unwrap_or(-1))
        .unwrap_or(0);
    if current < 0 || current as usize > schema::MIGRATIONS.len() {
        bail!("state store schema version {current} is newer than this binary supports");
    }
    for (i, sql) in schema::MIGRATIONS.iter().enumerate().skip(current as usize) {
        let version = i + 1;
        let tx = conn.transaction()?;
        tx.execute_batch(sql).with_context(|| format!("migration {version} failed"))?;
        tx.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', ?1) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![version.to_string()],
        )?;
        tx.commit()?;
    }
    Ok(())
}

pub fn get_meta(conn: &Connection, key: &str) -> anyhow::Result<Option<String>> {
    Ok(conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).optional()?)
}

pub fn set_meta(conn: &Connection, key: &str, value: &str) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_apply_once_and_are_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data/state.db");
        let s = Store::open(&path).unwrap();
        let v = s.call_blocking(|c| get_meta(c, "schema_version")).unwrap();
        assert_eq!(v.as_deref(), Some(schema::MIGRATIONS.len().to_string().as_str()));
        drop(s);
        Store::open(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("data")).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
        crate::platform::dir_is_private(&dir.path().join("data")).unwrap();
    }

    /// The Gmail-over-IMAP migration keeps every folder row and id and only widens the `special` check.
    #[test]
    fn gmail_imap_migration_keeps_folders() {
        let mut c = Connection::open_in_memory().unwrap();
        c.execute_batch("PRAGMA foreign_keys = ON").unwrap();
        let n = schema::MIGRATIONS.len();
        for sql in &schema::MIGRATIONS[..n - 1] {
            c.execute_batch(sql).unwrap();
        }
        c.execute_batch(
            "INSERT INTO accounts(id, alias, email, status, provider) VALUES ('a', 'x', 'x@example.org', 'active', 'imap');
             INSERT INTO imap_folders VALUES ('a', 1, 'INBOX', NULL), ('a', 7, 'Entw&APw-rfe', 'drafts');",
        )
        .unwrap();
        assert!(c.execute("INSERT INTO imap_folders VALUES ('a', 8, 'All', 'all')", []).is_err());
        let tx = c.transaction().unwrap();
        tx.execute_batch(schema::MIGRATIONS[n - 1]).unwrap();
        tx.commit().unwrap();
        c.execute("INSERT INTO imap_folders VALUES ('a', 8, '[Gmail]/All Mail', 'all')", []).unwrap();
        assert!(c.execute("INSERT INTO imap_folders VALUES ('a', 9, 'X', 'bogus')", []).is_err());
        assert!(c.execute("INSERT INTO imap_folders VALUES ('a', 10, 'INBOX', NULL)", []).is_err(), "unique name");
        let rows: Vec<(i64, String, Option<String>)> = c
            .prepare("SELECT folder_id, name, special FROM imap_folders ORDER BY folder_id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![
                (1, "INBOX".into(), None),
                (7, "Entw&APw-rfe".into(), Some("drafts".into())),
                (8, "[Gmail]/All Mail".into(), Some("all".into()))
            ]
        );
        // Removing the account still takes its folders with it.
        c.execute("DELETE FROM accounts WHERE id = 'a'", []).unwrap();
        assert_eq!(c.query_row("SELECT count(*) FROM imap_folders", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
    }

    #[test]
    fn refuses_newer_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        crate::platform::restrict_dir(dir.path()).unwrap();
        let s = Store::open(&path).unwrap();
        s.call_blocking(|c| set_meta(c, "schema_version", "999")).unwrap();
        drop(s);
        assert!(Store::open(&path).is_err());
    }
}
