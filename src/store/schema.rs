//! Versioned schema migrations for the durable state store. Never edit a released migration; append a new one.

pub const MIGRATIONS: &[&str] = &[V1, V2, V3, V_SEND_IDENTITIES, V_WATCHES, V_GMAIL_IMAP];

const V1: &str = r#"
CREATE TABLE accounts (
    id               TEXT PRIMARY KEY,
    alias            TEXT NOT NULL UNIQUE,
    email            TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name     TEXT,
    status           TEXT NOT NULL CHECK (status IN ('active', 'reauth_required', 'disabled')),
    granted_scopes   TEXT NOT NULL DEFAULT '',
    google_sub       TEXT,
    connected_at     INTEGER,
    last_used_at     INTEGER,
    last_error_code  TEXT,
    last_error_at    INTEGER,
    -- Incremented on every committed (re)connect. A refresh for an older generation cannot change state.
    grant_generation INTEGER NOT NULL DEFAULT 1,
    reauth_notified  INTEGER NOT NULL DEFAULT 0,
    index_enabled    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE grants (
    account_id               TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    dek_wrapped              BLOB NOT NULL,
    kek_version              INTEGER NOT NULL,
    refresh_token_ciphertext BLOB NOT NULL,
    nonce                    BLOB NOT NULL,
    created_at               INTEGER NOT NULL,
    rotated_at               INTEGER
);

CREATE TABLE projects (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

CREATE TABLE project_accounts (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    added_at   INTEGER NOT NULL,
    PRIMARY KEY (project_id, account_id)
);

-- One row per connection: a CLI-issued token, an invitation-redeemed login or a downstream OAuth connection.
CREATE TABLE clients (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL UNIQUE,
    project_id     TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind           TEXT NOT NULL CHECK (kind IN ('token', 'oauth')),
    token_hash     BLOB UNIQUE,
    allowed_cidrs  TEXT NOT NULL DEFAULT '[]',
    expires_at     INTEGER,
    revoked_at     INTEGER,
    created_at     INTEGER NOT NULL,
    created_via    TEXT NOT NULL,
    -- Bumped on rotate, revoke and grant change; cursors carry it and become invalid when it moves.
    auth_epoch     INTEGER NOT NULL DEFAULT 1,
    last_used_at   INTEGER,
    last_ip        TEXT
);

CREATE TABLE client_mailboxes (
    client_id  TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    actions    TEXT NOT NULL,
    PRIMARY KEY (client_id, account_id)
);

CREATE TABLE pending_connects (
    state_hash               BLOB PRIMARY KEY,
    account_alias            TEXT NOT NULL,
    expected_email           TEXT NOT NULL,
    pkce_verifier_ciphertext BLOB NOT NULL,
    mode                     TEXT NOT NULL CHECK (mode IN ('connect', 'reconnect')),
    account_id               TEXT,
    created_at               INTEGER NOT NULL,
    expires_at               INTEGER NOT NULL,
    used_at                  INTEGER,
    outcome                  TEXT
);

CREATE TABLE own_drafts (
    account_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    draft_id        TEXT NOT NULL,
    message_id      TEXT NOT NULL,
    thread_id       TEXT NOT NULL,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('active', 'update_unknown', 'sending', 'sent', 'send_unknown')),
    sent_message_id TEXT,
    PRIMARY KEY (account_id, draft_id)
);
CREATE INDEX own_drafts_project ON own_drafts(project_id, account_id);

CREATE TABLE create_operations (
    client_id   TEXT NOT NULL,
    account_id  TEXT NOT NULL,
    request_key TEXT NOT NULL,
    input_hash  BLOB NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('in_flight', 'succeeded', 'failed', 'unknown')),
    result_ids  TEXT,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (client_id, account_id, request_key)
);

CREATE TABLE audit (
    seq            INTEGER PRIMARY KEY,
    ts             INTEGER NOT NULL,
    prev_hash      BLOB NOT NULL,
    hash           BLOB NOT NULL,
    request_id     TEXT NOT NULL,
    actor          TEXT NOT NULL,
    project        TEXT,
    tool_or_action TEXT NOT NULL,
    account_alias  TEXT,
    object_ids     TEXT NOT NULL DEFAULT '[]',
    result_code    TEXT NOT NULL,
    duration_ms    INTEGER NOT NULL,
    result_count   INTEGER,
    source_ip      TEXT,
    query_len      INTEGER,
    query_hash     TEXT
);
CREATE INDEX audit_ts ON audit(ts);

CREATE TABLE invitations (
    id               TEXT PRIMARY KEY,
    secret_hash      BLOB NOT NULL UNIQUE,
    project_id       TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    connection_name  TEXT NOT NULL,
    grants           TEXT NOT NULL,
    expires_in_secs  INTEGER,
    allowed_cidrs    TEXT NOT NULL DEFAULT '[]',
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    used_at          INTEGER,
    issued_client_id TEXT
);

CREATE TABLE oauth_apps (
    client_id     TEXT PRIMARY KEY,
    client_name   TEXT,
    redirect_uris TEXT NOT NULL,
    registered_via TEXT NOT NULL CHECK (registered_via IN ('dynamic', 'preregistered')),
    created_at    INTEGER NOT NULL
);

CREATE TABLE oauth_codes (
    code_hash      BLOB PRIMARY KEY,
    app_client_id  TEXT NOT NULL,
    connection_id  TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    resource       TEXT NOT NULL,
    expires_at     INTEGER NOT NULL,
    used_at        INTEGER
);

CREATE TABLE oauth_tokens (
    token_hash    BLOB PRIMARY KEY,
    kind          TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
    family_id     TEXT NOT NULL,
    connection_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    app_client_id TEXT NOT NULL,
    resource      TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    used_at       INTEGER,
    revoked_at    INTEGER
);
CREATE INDEX oauth_tokens_family ON oauth_tokens(family_id);

CREATE TABLE notifications (
    key          TEXT PRIMARY KEY,
    last_sent_at INTEGER NOT NULL
);
"#;

/// V2: the source bucket of a dynamic registration (`oauth::ip_bucket`), for the per-source cap on unused
/// registrations. NULL for rows registered before V2 and for pre-registered applications.
const V2: &str = r#"
ALTER TABLE oauth_apps ADD COLUMN registered_from TEXT;
"#;

/// V3: IMAP/SMTP accounts (design 2026-11-12). `imap_settings` holds the server endpoints and options as JSON (no
/// secrets); the password is sealed in `grants` with its own AAD kind. `imap_folders` maps small per-account folder
/// ids (part of agent-visible message ids) to the server's wire name (modified UTF-7). `own_drafts.content_hash` is
/// the SHA-256 of the server's bytes of an IMAP draft.
const V3: &str = r#"
ALTER TABLE accounts ADD COLUMN provider TEXT NOT NULL DEFAULT 'gmail' CHECK (provider IN ('gmail', 'imap'));
ALTER TABLE accounts ADD COLUMN imap_settings TEXT;

CREATE TABLE imap_folders (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    folder_id  INTEGER NOT NULL,
    name       TEXT NOT NULL,
    special    TEXT CHECK (special IN ('drafts', 'sent', 'junk', 'trash')),
    PRIMARY KEY (account_id, folder_id),
    UNIQUE (account_id, name)
);

ALTER TABLE own_drafts ADD COLUMN content_hash BLOB;
"#;

/// Sending identities (design 2026-11-13 section 5): send-as aliases of IMAP mailboxes (`envelope` marks an alias the
/// SMTP server accepts as envelope sender) and plain-text signatures. A signature row with `address = ''` is the
/// mailbox's default; any other address is a per-alias signature (for Gmail the address is a Gmail send-as address,
/// which Dove learns from the API, so it is not required to exist in `account_aliases`).
const V_SEND_IDENTITIES: &str = r#"
CREATE TABLE account_aliases (
    account_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    address      TEXT NOT NULL,
    display_name TEXT,
    envelope     INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL,
    PRIMARY KEY (account_id, address)
);

CREATE TABLE account_signatures (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    address    TEXT NOT NULL,
    body       TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (account_id, address)
);
"#;

/// Watches, their events and the operator's webhook sinks (design 0.2 section 3, `src/watch/`).
///
/// - `sinks.secret` is the HMAC signing secret sealed by the vault (`seal_aux`, kind `sink_secret`, scope = sink id).
/// - `watches.filter` holds the agent's match arguments (`from` address or domain, `where` query) sealed the same way
///   (kind `watch_filter`, scope = watch id), so the state store keeps no addresses or query text in the clear.
/// - `watches.baseline_ms`: thread kinds count only messages newer than the thread's newest one at creation.
/// - `watch_events.seq` is AUTOINCREMENT: pruned positions are never reused, so an old cursor never skips events.
/// - Events and deliveries carry ids and timestamps only, never subjects, senders or bodies.
const V_WATCHES: &str = r#"
CREATE TABLE sinks (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    url        TEXT NOT NULL,
    secret     BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE watches (
    id            TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    account_id    TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL CHECK (kind IN ('thread_reply', 'from', 'query', 'no_reply_by')),
    thread_id     TEXT,
    -- thread_reply / no_reply_by: newest received_at (ms) in the thread when the watch was created; only later
    -- messages count.
    baseline_ms   INTEGER,
    filter        BLOB,
    deadline      INTEGER,
    sink_id       TEXT REFERENCES sinks(id) ON DELETE SET NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    state         TEXT NOT NULL CHECK (state IN ('active', 'ended')),
    ended_at      INTEGER,
    end_reason    TEXT,
    fired         INTEGER NOT NULL DEFAULT 0,
    last_fired_at INTEGER
);
CREATE INDEX watches_account ON watches(account_id, state);
CREATE INDEX watches_client ON watches(client_id, state);

CREATE TABLE watch_events (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    watch_id    TEXT NOT NULL REFERENCES watches(id) ON DELETE CASCADE,
    client_id   TEXT NOT NULL,
    account_id  TEXT NOT NULL,
    kind        TEXT NOT NULL,
    message_id  TEXT,
    thread_id   TEXT,
    received_at INTEGER,
    created_at  INTEGER NOT NULL,
    UNIQUE (watch_id, message_id)
);
CREATE INDEX watch_events_client ON watch_events(client_id, seq);
CREATE INDEX watch_events_created ON watch_events(created_at);

CREATE TABLE sink_deliveries (
    event_seq       INTEGER NOT NULL REFERENCES watch_events(seq) ON DELETE CASCADE,
    sink_id         TEXT NOT NULL REFERENCES sinks(id) ON DELETE CASCADE,
    state           TEXT NOT NULL CHECK (state IN ('pending', 'delivered', 'failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    last_status     INTEGER,
    updated_at      INTEGER NOT NULL,
    PRIMARY KEY (event_seq, sink_id)
) WITHOUT ROWID;
CREATE INDEX sink_deliveries_due ON sink_deliveries(state, next_attempt_at);
CREATE INDEX sink_deliveries_sink ON sink_deliveries(sink_id);
"#;

/// Gmail over IMAP (PLAN A52): `imap_folders.special` also takes `all` (Gmail's All Mail, `\All`). SQLite cannot change
/// a CHECK constraint, so the table is rebuilt with the same rows and ids (nothing references it).
const V_GMAIL_IMAP: &str = r#"
CREATE TABLE imap_folders_v6 (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    folder_id  INTEGER NOT NULL,
    name       TEXT NOT NULL,
    special    TEXT CHECK (special IN ('drafts', 'sent', 'junk', 'trash', 'all')),
    PRIMARY KEY (account_id, folder_id),
    UNIQUE (account_id, name)
);
INSERT INTO imap_folders_v6(account_id, folder_id, name, special)
    SELECT account_id, folder_id, name, special FROM imap_folders;
DROP TABLE imap_folders;
ALTER TABLE imap_folders_v6 RENAME TO imap_folders;
"#;
