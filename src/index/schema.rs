//! Versioned schema of the encrypted index database (spec 7.9 "Data"). The index is rebuildable, but migrations
//! are still append-only so an upgrade never silently drops a large index. Version is `PRAGMA user_version`.
//!
//! Layout: every derived row belongs to a generation (`gen`), and a generation belongs to one account. Queries
//! only ever read the generation a mailbox currently serves, so a rebuild can fill a fresh generation while the
//! old one stays readable, and the old one is deleted after cutover. Each generation has its own FTS table
//! (`fts_g<id>`, V3), so text matching only touches the generations a query may read.

use anyhow::bail;
use rusqlite::{Connection, Transaction};

/// One schema step: plain SQL, or code for steps that depend on existing rows (per-generation tables).
pub enum Migration {
    Sql(&'static str),
    Code(fn(&Transaction<'_>) -> anyhow::Result<()>),
}

pub const MIGRATIONS: &[Migration] = &[Migration::Sql(V1), Migration::Sql(V2), Migration::Code(v3)];

/// Name of a generation's FTS table. Derived only from the integer generation id, never from input.
pub fn fts_table(gen_id: i64) -> String {
    format!("fts_g{gen_id}")
}

/// Creates the (empty) FTS table of a generation. Generation ids are never reused (`gen_seq`), so a table of that
/// name cannot exist; it is dropped first anyway so stale postings can never be served under a new generation.
pub fn create_fts(tx: &Connection, gen_id: i64) -> anyhow::Result<()> {
    let t = fts_table(gen_id);
    // One text source: subject + sanitized body, written in the same transaction as the metadata row
    // (rowid = messages.id). Contentless: postings only, never a second copy of the body.
    tx.execute_batch(&format!(
        "DROP TABLE IF EXISTS {t}; \
         CREATE VIRTUAL TABLE {t} USING fts5(subject, body, content='', contentless_delete=1, tokenize='unicode61');"
    ))?;
    Ok(())
}

const V1: &str = r#"
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;
INSERT INTO meta(key, value) VALUES ('fence_seq', '0');

-- One row per index-enabled account. `fence` changes on enable, rebuild and purge; a sync job carries the fence it
-- started with and every write transaction re-checks it, so a stale job can never write after a purge.
CREATE TABLE sync_state (
    account_id      TEXT PRIMARY KEY,
    fence           INTEGER NOT NULL,
    stage           TEXT NOT NULL CHECK (stage IN ('backfill', 'ready', 'rebuilding')),
    active_gen      INTEGER,
    building_gen    INTEGER,
    -- Gmail history id up to which the active generation is complete. Opaque; never incremented locally.
    checkpoint      TEXT,
    last_success_at INTEGER,
    last_error      TEXT,
    last_error_at   INTEGER,
    backoff_secs    INTEGER NOT NULL DEFAULT 0,
    next_run_at     INTEGER NOT NULL DEFAULT 0,
    -- Bumped by every committed derived write; cursors compare it to report changed_since_first_page.
    data_seq        INTEGER NOT NULL DEFAULT 0,
    enabled_at      INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE generations (
    id               INTEGER PRIMARY KEY,
    account_id       TEXT NOT NULL,
    state            TEXT NOT NULL CHECK (state IN ('building', 'active', 'retired')),
    -- Captured before enumeration starts; reconciliation replays history from here before publishing.
    start_history_id TEXT,
    page_token       TEXT,
    enum_done        INTEGER NOT NULL DEFAULT 0,
    listed           INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL,
    completed_at     INTEGER
);
CREATE INDEX generations_account ON generations(account_id);

-- Enumerated messages not yet indexed, and retry records for transient failures.
CREATE TABLE pending (
    gen             INTEGER NOT NULL,
    gmail_id        TEXT NOT NULL,
    seq             INTEGER NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    PRIMARY KEY (gen, gmail_id)
) WITHOUT ROWID;
CREATE INDEX pending_due ON pending(gen, next_attempt_at, seq);

CREATE TABLE messages (
    id               INTEGER PRIMARY KEY,
    gen              INTEGER NOT NULL,
    account_id       TEXT NOT NULL,
    gmail_id         TEXT NOT NULL,
    thread_id        TEXT NOT NULL,
    -- Gmail internalDate in unix milliseconds (the wire format keeps millisecond precision).
    received_at      INTEGER NOT NULL,
    size_bytes       INTEGER NOT NULL,
    subject          TEXT,
    subject_missing  INTEGER NOT NULL,
    subject_key      TEXT NOT NULL,
    from_list        TEXT NOT NULL,
    to_list          TEXT NOT NULL,
    cc_list          TEXT NOT NULL,
    bcc_list         TEXT NOT NULL,
    labels           TEXT NOT NULL,
    snippet          TEXT,
    is_unread        INTEGER NOT NULL,
    is_starred       INTEGER NOT NULL,
    is_draft         INTEGER NOT NULL,
    spam_trash       INTEGER NOT NULL,
    -- NULL when MIME metadata could not be extracted (unknown, not false).
    has_attachment   INTEGER,
    attachment_names TEXT NOT NULL,
    attachment_mimes TEXT NOT NULL,
    body_complete    INTEGER NOT NULL,
    meta_complete    INTEGER NOT NULL,
    UNIQUE (gen, gmail_id)
);
-- Tiebreaker columns DESC: a backwards walk yields received_at DESC, (account_id, gmail_id) ASC, the default order.
CREATE INDEX messages_date ON messages(gen, spam_trash, received_at, account_id DESC, gmail_id DESC);
CREATE INDEX messages_size ON messages(gen, spam_trash, size_bytes);
CREATE INDEX messages_subject ON messages(gen, spam_trash, subject_missing, subject_key);
CREATE INDEX messages_thread ON messages(thread_id, gen);
CREATE INDEX messages_gmail_id ON messages(gmail_id, gen);
CREATE INDEX messages_body_incomplete ON messages(gen) WHERE body_complete = 0;
CREATE INDEX messages_meta_incomplete ON messages(gen) WHERE meta_complete = 0;

-- Normalized visible addresses. role: 1 from, 2 to, 3 cc, 4 bcc.
CREATE TABLE addrs (
    msg    INTEGER NOT NULL,
    gen    INTEGER NOT NULL,
    role   INTEGER NOT NULL,
    addr   TEXT NOT NULL,
    domain TEXT NOT NULL
);
CREATE INDEX addrs_addr ON addrs(addr, gen, role, msg);
CREATE INDEX addrs_domain ON addrs(domain, gen, role, msg);
CREATE INDEX addrs_msg ON addrs(msg);

CREATE TABLE labels (
    label TEXT NOT NULL,
    gen   INTEGER NOT NULL,
    msg   INTEGER NOT NULL,
    PRIMARY KEY (label, gen, msg)
) WITHOUT ROWID;
CREATE INDEX labels_msg ON labels(msg);

CREATE TABLE atts (
    msg      INTEGER NOT NULL,
    gen      INTEGER NOT NULL,
    name_lc  TEXT,
    -- Reversed lowercase name: a literal suffix becomes an indexable prefix range.
    name_rev TEXT,
    mime_lc  TEXT NOT NULL
);
CREATE INDEX atts_name ON atts(name_lc, gen, msg);
CREATE INDEX atts_name_rev ON atts(name_rev, gen, msg);
CREATE INDEX atts_mime ON atts(mime_lc, gen, msg);
CREATE INDEX atts_msg ON atts(msg);

-- Replaced by one FTS table per generation in V3.
CREATE VIRTUAL TABLE fts USING fts5(subject, body, content='', contentless_delete=1, tokenize='unicode61');
"#;

/// Query planner support. Newest-first top-N across several mailboxes walks `messages_recent` in order and stops
/// after `limit + 1` eligible rows instead of sorting every row of every mailbox.
///
/// Fixed `sqlite_stat1` rows describe a representative large index (250k messages over 10 mailboxes) so plans do not
/// depend on how full the index happens to be: selective lookups (addresses, attachment names, ids) drive the join,
/// mailbox-wide predicates do not. Dove never runs ANALYZE afterwards, so these numbers stay authoritative.
const V2: &str = r#"
CREATE INDEX messages_recent ON messages(spam_trash, received_at, account_id DESC, gmail_id DESC);
ANALYZE meta;
DELETE FROM sqlite_stat1;
INSERT INTO sqlite_stat1(tbl, idx, stat) VALUES
    ('messages', 'messages_date', '250000 25000 12500 2 1 1'),
    ('messages', 'messages_recent', '250000 125000 2 1 1'),
    ('messages', 'messages_size', '250000 25000 12500 3'),
    ('messages', 'messages_subject', '250000 25000 12500 12500 4'),
    ('messages', 'messages_thread', '250000 3 3'),
    ('messages', 'messages_gmail_id', '250000 1 1'),
    ('messages', 'messages_body_incomplete', '2500 250'),
    ('messages', 'messages_meta_incomplete', '250 25'),
    ('messages', 'sqlite_autoindex_messages_1', '250000 25000 1'),
    ('addrs', 'addrs_addr', '1000000 40 30 20 1'),
    ('addrs', 'addrs_domain', '1000000 400 300 200 1'),
    ('addrs', 'addrs_msg', '1000000 4'),
    ('labels', 'sqlite_autoindex_labels_1', '750000 25000 2500 1'),
    ('labels', 'labels_msg', '750000 3'),
    ('atts', 'atts_name', '100000 2 2 1'),
    ('atts', 'atts_name_rev', '100000 2 2 1'),
    ('atts', 'atts_mime', '100000 5000 500 1'),
    ('atts', 'atts_msg', '100000 2');
"#;

/// One FTS table per generation (spec 7.9 "derive eligible mailboxes first"): a text query only ever evaluates
/// MATCH on the tables of the generations it may read, so its work no longer depends on other accounts' postings,
/// and dropping a generation drops its postings with it.
///
/// The old shared table is contentless, so its postings cannot be moved. Every account therefore rebuilds into a
/// fresh generation: an active generation keeps serving metadata while the account is `rebuilding` (coverage is
/// partial meanwhile, and its new, empty FTS table matches nothing); a half-built generation is abandoned and
/// collected later in bounded chunks. Generation ids come from `gen_seq` from now on and are never reused.
fn v3(tx: &Transaction<'_>) -> anyhow::Result<()> {
    tx.execute(
        "INSERT INTO meta(key, value) VALUES ('gen_seq', (SELECT CAST(IFNULL(max(id), 0) AS TEXT) FROM generations))",
        [],
    )?;
    let gens: Vec<i64> = {
        let mut st = tx.prepare("SELECT id FROM generations")?;
        st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?
    };
    for g in gens {
        create_fts(tx, g)?;
    }
    let accounts: Vec<String> = {
        let mut st = tx.prepare("SELECT account_id FROM sync_state")?;
        st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?
    };
    for aid in accounts {
        let fence = super::next_fence(tx)?;
        let g = super::new_generation(tx, &aid)?;
        tx.execute(
            "UPDATE sync_state SET fence = ?1, building_gen = ?2, \
             stage = CASE WHEN active_gen IS NULL THEN 'backfill' ELSE 'rebuilding' END, \
             next_run_at = 0, data_seq = data_seq + 1 WHERE account_id = ?3",
            rusqlite::params![fence, g, aid],
        )?;
    }
    tx.execute_batch("DROP TABLE fts;")?;
    Ok(())
}

/// Applies pending index migrations in one transaction each.
pub fn migrate(conn: &mut Connection) -> anyhow::Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let target = MIGRATIONS.len() as i64;
    if version > target {
        bail!("index schema version {version} is newer than this binary ({target}); delete the index and rebuild");
    }
    for (i, step) in MIGRATIONS.iter().enumerate().skip(version as usize) {
        let tx = conn.transaction()?;
        match step {
            Migration::Sql(sql) => tx.execute_batch(sql)?,
            Migration::Code(f) => f(&tx)?,
        }
        tx.execute_batch(&format!("PRAGMA user_version = {}", i + 1))?;
        tx.commit()?;
    }
    // Load the planner statistics into this connection (later connections read them at open).
    conn.execute_batch("ANALYZE sqlite_schema;")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// V3 moves an existing index (shared `fts` table) to per-generation tables without serving stale postings:
    /// every account rebuilds into a new generation, an active generation keeps serving metadata meanwhile, and a
    /// half-built generation is left unreferenced for garbage collection.
    #[test]
    fn v3_marks_existing_generations_for_rebuild() {
        let mut c = Connection::open_in_memory().unwrap();
        for m in &MIGRATIONS[..2] {
            let Migration::Sql(sql) = m else { panic!("V1/V2 are SQL") };
            c.execute_batch(sql).unwrap();
        }
        c.execute_batch(
            "PRAGMA user_version = 2;
             UPDATE meta SET value = '2' WHERE key = 'fence_seq';
             INSERT INTO generations(id, account_id, state, created_at) VALUES (5, 'a', 'active', 0), (6, 'a', 'building', 0),
                (7, 'b', 'building', 0);
             INSERT INTO sync_state(account_id, fence, stage, active_gen, building_gen, checkpoint, enabled_at)
                VALUES ('a', 1, 'rebuilding', 5, 6, '100', 0), ('b', 2, 'backfill', NULL, 7, NULL, 0);
             INSERT INTO fts(rowid, subject, body) VALUES (1, 's', 'oldposting');",
        )
        .unwrap();
        migrate(&mut c).unwrap();
        let q = |sql: &str| {
            use rusqlite::OptionalExtension;
            c.query_row(sql, [], |r| r.get::<_, String>(0)).optional().unwrap()
        };
        assert_eq!(q("SELECT name FROM sqlite_schema WHERE name = 'fts'"), None, "shared table dropped");
        for g in [5, 6, 7] {
            assert!(q(&format!("SELECT name FROM sqlite_schema WHERE name = '{}'", fts_table(g))).is_some());
        }
        let st = |a: &str| {
            c.query_row(
                "SELECT stage, active_gen, building_gen, fence FROM sync_state WHERE account_id = ?1",
                [a],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?)),
            )
            .unwrap()
        };
        let (stage, active, building, fence) = st("a");
        assert_eq!((stage.as_str(), active), ("rebuilding", Some(5)));
        assert!(building > 7 && fence > 2, "new generation and fence: {building} {fence}");
        let (stage, active, building_b, _) = st("b");
        assert_eq!((stage.as_str(), active), ("backfill", None));
        assert!(building_b > 7 && building_b != building);
        assert!(q(&format!("SELECT name FROM sqlite_schema WHERE name = '{}'", fts_table(building_b))).is_some());
        // The new generations' tables are empty; the old posting is gone with the shared table.
        let hits: i64 = c
            .query_row(&format!("SELECT count(*) FROM {t} WHERE {t} MATCH 'oldposting'", t = fts_table(5)), [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(hits, 0);
        // Generation ids keep increasing from gen_seq.
        let tx = c.transaction().unwrap();
        let next = crate::index::new_generation(&tx, "a").unwrap();
        assert!(next > building.max(building_b));
    }
}
