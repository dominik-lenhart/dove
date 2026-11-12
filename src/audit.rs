//! Append-only, hash-chained audit log (spec 6.7).
//!
//! Records hold no content: no subjects, bodies, addresses or query text. Queries appear only as length plus a keyed
//! fingerprint. Each record stores the hash of the previous one; `verify` recomputes the chain. Pruning records the
//! retained boundary in `meta` and is itself audited.

use rusqlite::{Connection, params};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::store::{get_meta, set_meta};
use crate::util;

#[derive(Debug, Clone, Default, Serialize)]
pub struct AuditRecord {
    pub request_id: String,
    pub actor: String,
    pub project: Option<String>,
    pub tool_or_action: String,
    pub account_alias: Option<String>,
    pub object_ids: Vec<String>,
    pub result_code: String,
    pub duration_ms: i64,
    pub result_count: Option<i64>,
    pub source_ip: Option<String>,
    pub query_len: Option<i64>,
    pub query_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StoredRecord {
    pub seq: i64,
    pub ts: i64,
    #[serde(flatten)]
    pub record: AuditRecord,
}

fn record_hash(prev: &[u8], seq: i64, ts: i64, r: &AuditRecord) -> Vec<u8> {
    // Canonical encoding: fixed field order via serde_json of a tuple.
    let canonical = serde_json::to_vec(&(
        seq,
        ts,
        &r.request_id,
        &r.actor,
        &r.project,
        &r.tool_or_action,
        &r.account_alias,
        &r.object_ids,
        &r.result_code,
        r.duration_ms,
        r.result_count,
        &r.source_ip,
        r.query_len,
        &r.query_hash,
    ))
    .expect("serializable");
    let mut h = Sha256::new();
    h.update(prev);
    h.update(&canonical);
    h.finalize().to_vec()
}

fn last_hash(conn: &Connection) -> anyhow::Result<Vec<u8>> {
    let last: Option<Vec<u8>> =
        conn.query_row("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1", [], |r| r.get(0)).ok();
    match last {
        Some(h) => Ok(h),
        None => Ok(boundary(conn)?.1),
    }
}

/// (first retained seq - 1, hash of the record before it). Zero hash before any pruning.
fn boundary(conn: &Connection) -> anyhow::Result<(i64, Vec<u8>)> {
    let seq = get_meta(conn, "audit_boundary_seq")?.and_then(|s| s.parse().ok()).unwrap_or(0);
    let hash = get_meta(conn, "audit_boundary_hash")?.and_then(|h| util::b64url_decode(&h)).unwrap_or(vec![0; 32]);
    Ok((seq, hash))
}

/// Appends one record. Call inside the same transaction as the state change it describes when there is one.
pub fn append(conn: &Connection, r: &AuditRecord) -> anyhow::Result<i64> {
    append_at(conn, r, util::now_unix())
}

fn append_at(conn: &Connection, r: &AuditRecord, ts: i64) -> anyhow::Result<i64> {
    let prev = last_hash(conn)?;
    let max_seq: i64 = conn.query_row("SELECT COALESCE(MAX(seq), 0) FROM audit", [], |row| row.get(0))?;
    let seq = max_seq.max(boundary(conn)?.0) + 1;
    let hash = record_hash(&prev, seq, ts, r);
    conn.execute(
        "INSERT INTO audit(seq, ts, prev_hash, hash, request_id, actor, project, tool_or_action, account_alias, \
         object_ids, result_code, duration_ms, result_count, source_ip, query_len, query_hash) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            seq,
            ts,
            prev,
            hash,
            r.request_id,
            r.actor,
            r.project,
            r.tool_or_action,
            r.account_alias,
            serde_json::to_string(&r.object_ids)?,
            r.result_code,
            r.duration_ms,
            r.result_count,
            r.source_ip,
            r.query_len,
            r.query_hash,
        ],
    )?;
    Ok(seq)
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<(StoredRecord, Vec<u8>, Vec<u8>)> {
    let object_ids: String = row.get(9)?;
    Ok((
        StoredRecord {
            seq: row.get(0)?,
            ts: row.get(1)?,
            record: AuditRecord {
                request_id: row.get(4)?,
                actor: row.get(5)?,
                project: row.get(6)?,
                tool_or_action: row.get(7)?,
                account_alias: row.get(8)?,
                object_ids: serde_json::from_str(&object_ids).unwrap_or_default(),
                result_code: row.get(10)?,
                duration_ms: row.get(11)?,
                result_count: row.get(12)?,
                source_ip: row.get(13)?,
                query_len: row.get(14)?,
                query_hash: row.get(15)?,
            },
        },
        row.get(2)?,
        row.get(3)?,
    ))
}

const SELECT: &str = "SELECT seq, ts, prev_hash, hash, request_id, actor, project, tool_or_action, account_alias, \
                      object_ids, result_code, duration_ms, result_count, source_ip, query_len, query_hash FROM audit";

#[derive(Debug, Serialize)]
pub struct VerifyReport {
    pub ok: bool,
    pub records: i64,
    pub first_bad_seq: Option<i64>,
    pub retained_from_seq: i64,
}

/// Recomputes the chain from the retained boundary.
pub fn verify(conn: &Connection) -> anyhow::Result<VerifyReport> {
    let (bseq, mut prev) = boundary(conn)?;
    let mut stmt = conn.prepare(&format!("{SELECT} ORDER BY seq"))?;
    let mut rows = stmt.query([])?;
    let mut n = 0;
    let mut expected_seq = bseq + 1;
    while let Some(row) = rows.next()? {
        let (rec, prev_hash, hash) = row_to_record(row)?;
        n += 1;
        let recomputed = record_hash(&prev, rec.seq, rec.ts, &rec.record);
        if rec.seq != expected_seq || prev_hash != prev || hash != recomputed {
            return Ok(VerifyReport {
                ok: false,
                records: n,
                first_bad_seq: Some(rec.seq),
                retained_from_seq: bseq + 1,
            });
        }
        prev = hash;
        expected_seq += 1;
    }
    Ok(VerifyReport { ok: true, records: n, first_bad_seq: None, retained_from_seq: bseq + 1 })
}

pub fn tail(conn: &Connection, limit: i64) -> anyhow::Result<Vec<StoredRecord>> {
    let mut stmt = conn.prepare(&format!("{SELECT} ORDER BY seq DESC LIMIT ?1"))?;
    let mut out: Vec<StoredRecord> =
        stmt.query_map([limit], |r| row_to_record(r).map(|x| x.0))?.collect::<Result<_, _>>()?;
    out.reverse();
    Ok(out)
}

#[derive(Debug, Default, Clone, Serialize, serde::Deserialize)]
pub struct SearchFilter {
    pub actor: Option<String>,
    pub tool: Option<String>,
    pub account: Option<String>,
    pub result_code: Option<String>,
    pub since: Option<i64>,
    pub limit: Option<i64>,
}

pub fn search(conn: &Connection, f: &SearchFilter) -> anyhow::Result<Vec<StoredRecord>> {
    let mut stmt = conn.prepare(&format!(
        "{SELECT} WHERE (?1 IS NULL OR actor = ?1) AND (?2 IS NULL OR tool_or_action = ?2) \
         AND (?3 IS NULL OR account_alias = ?3) AND (?4 IS NULL OR result_code = ?4) AND (?5 IS NULL OR ts >= ?5) \
         ORDER BY seq DESC LIMIT ?6"
    ))?;
    let rows = stmt.query_map(
        params![f.actor, f.tool, f.account, f.result_code, f.since, f.limit.unwrap_or(100).clamp(1, 10_000)],
        |r| row_to_record(r).map(|x| x.0),
    )?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Deletes records older than `retention_days`, records the new boundary and audits the pruning.
pub fn prune(conn: &mut Connection, retention_days: u32, request_id: &str) -> anyhow::Result<i64> {
    let cutoff = util::now_unix() - i64::from(retention_days) * 86_400;
    let tx = conn.transaction()?;
    let last: Option<(i64, Vec<u8>)> = tx
        .query_row("SELECT seq, hash FROM audit WHERE ts < ?1 ORDER BY seq DESC LIMIT 1", [cutoff], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .ok();
    let mut deleted = 0;
    if let Some((seq, hash)) = last {
        deleted = tx.execute("DELETE FROM audit WHERE seq <= ?1", [seq])? as i64;
        set_meta(&tx, "audit_boundary_seq", &seq.to_string())?;
        set_meta(&tx, "audit_boundary_hash", &util::b64url(&hash))?;
    }
    append(
        &tx,
        &AuditRecord {
            request_id: request_id.to_string(),
            actor: "system".into(),
            tool_or_action: "audit.prune".into(),
            result_code: "ok".into(),
            result_count: Some(deleted),
            ..Default::default()
        },
    )?;
    tx.commit()?;
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    fn rec(action: &str) -> AuditRecord {
        AuditRecord {
            request_id: util::new_id(),
            actor: "operator".into(),
            tool_or_action: action.into(),
            result_code: "ok".into(),
            ..Default::default()
        }
    }

    #[test]
    fn chain_verifies_and_detects_edits() {
        let s = Store::open_in_memory().unwrap();
        s.call_blocking(|c| {
            for i in 0..5 {
                append(c, &rec(&format!("a{i}")))?;
            }
            assert!(verify(c)?.ok);
            // AC16: an edited record is detected.
            c.execute("UPDATE audit SET result_code = 'forbidden' WHERE seq = 3", [])?;
            let r = verify(c)?;
            assert!(!r.ok);
            assert_eq!(r.first_bad_seq, Some(3));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn deletion_in_the_middle_is_detected() {
        let s = Store::open_in_memory().unwrap();
        s.call_blocking(|c| {
            for i in 0..4 {
                append(c, &rec(&format!("a{i}")))?;
            }
            c.execute("DELETE FROM audit WHERE seq = 2", [])?;
            assert_eq!(verify(c)?.first_bad_seq, Some(3));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn prune_keeps_chain_valid_and_logs_itself() {
        let s = Store::open_in_memory().unwrap();
        s.call_blocking(|c| {
            let old = util::now_unix() - 200 * 86_400;
            for i in 0..3 {
                append_at(c, &rec(&format!("old{i}")), old)?;
            }
            append(c, &rec("recent"))?;
            assert_eq!(prune(c, 180, "req")?, 3);
            let v = verify(c)?;
            assert!(v.ok, "{v:?}");
            assert_eq!(v.retained_from_seq, 4);
            let t = tail(c, 10)?;
            assert_eq!(t.len(), 2);
            assert_eq!(t[1].record.tool_or_action, "audit.prune");
            // Tampering after pruning is still detected.
            c.execute("UPDATE audit SET actor = 'x' WHERE seq = 4", [])?;
            assert!(!verify(c)?.ok);
            Ok(())
        })
        .unwrap();
    }
}
