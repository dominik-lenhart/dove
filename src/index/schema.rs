//! Versioned schema of the encrypted index database (spec 7.9 "Data"). The index is rebuildable, but migrations
//! are still append-only so an upgrade never silently drops a large index. Version is `PRAGMA user_version`.
//!
//! Layout: every derived row belongs to a generation (`gen`), and a generation belongs to one account. Queries
//! only ever read the generation a mailbox currently serves, so a rebuild can fill a fresh generation while the
//! old one stays readable, and the old one is deleted after cutover.

use anyhow::bail;
use rusqlite::Connection;

pub const MIGRATIONS: &[&str] = &[V1];

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
CREATE INDEX messages_date ON messages(gen, spam_trash, received_at, account_id, gmail_id);
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

-- One text source: subject + sanitized body, written in the same transaction as the metadata row (rowid = id).
-- Contentless: the index stores postings only, never a second copy of the body.
CREATE VIRTUAL TABLE fts USING fts5(subject, body, content='', contentless_delete=1, tokenize='unicode61');
"#;

/// Applies pending index migrations in one transaction each.
pub fn migrate(conn: &mut Connection) -> anyhow::Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let target = MIGRATIONS.len() as i64;
    if version > target {
        bail!("index schema version {version} is newer than this binary ({target}); delete the index and rebuild");
    }
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(version as usize) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.execute_batch(&format!("PRAGMA user_version = {}", i + 1))?;
        tx.commit()?;
    }
    Ok(())
}
