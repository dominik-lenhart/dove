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
    /// Only records whose result is not `ok` (failed or refused).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<bool>,
    /// Only records naming this id in `object_ids` (exact element).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// Only records older than this sequence number (paging).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<i64>,
    /// Leaves out watch polls ([`POLL_TOOL`]) unless `tool` names them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hide_polls: Option<bool>,
}

/// The tool agents call in a loop to read watch events; it would bury every other record.
pub const POLL_TOOL: &str = "list_watch_events";

pub fn search(conn: &Connection, f: &SearchFilter) -> anyhow::Result<Vec<StoredRecord>> {
    let mut stmt = conn.prepare(&format!(
        "{SELECT} WHERE (?1 IS NULL OR actor = ?1) AND (?2 IS NULL OR tool_or_action = ?2) \
         AND (?3 IS NULL OR account_alias = ?3) AND (?4 IS NULL OR result_code = ?4) AND (?5 IS NULL OR ts >= ?5) \
         AND (?7 = 0 OR result_code <> 'ok') AND (?8 IS NULL OR seq < ?8) \
         AND (?9 IS NULL OR EXISTS (SELECT 1 FROM json_each(object_ids) WHERE value = ?9)) \
         AND (?10 = 0 OR ?2 IS NOT NULL OR tool_or_action <> ?11) \
         ORDER BY seq DESC LIMIT ?6"
    ))?;
    let rows = stmt.query_map(
        params![
            f.actor,
            f.tool,
            f.account,
            f.result_code,
            f.since,
            f.limit.unwrap_or(100).clamp(1, 10_000),
            f.failed.unwrap_or(false),
            f.before,
            f.object,
            f.hide_polls.unwrap_or(false),
            POLL_TOOL
        ],
        |r| row_to_record(r).map(|x| x.0),
    )?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Agent activity for the overview (design 2026-11-17 "dashboard"). Agent calls are records whose action is a tool
/// name; admin and system records drop out.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Stats {
    /// One entry per UTC day of the last [`STATS_DAYS`], oldest first, watch polls left out.
    pub days: Vec<DayStats>,
    /// Connections active in the last 7 days, most calls first.
    pub clients: Vec<ClientStats>,
    /// Values seen in the log, most frequent first, for search suggestions.
    pub values: Values,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct DayStats {
    pub date: String,
    pub ok: i64,
    pub failed: i64,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct ClientStats {
    pub actor: String,
    /// Calls without watch polls.
    pub calls: i64,
    pub failed: i64,
    /// Successful calls of tools that are not read-only.
    pub writes: i64,
    pub polls: i64,
    pub last_ts: i64,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Values {
    pub actors: Vec<String>,
    pub actions: Vec<String>,
    pub accounts: Vec<String>,
    pub results: Vec<String>,
}

pub const STATS_DAYS: i64 = 14;
const VALUES_MAX: i64 = 100;

/// `tools` are the agent tools as `(name, read_only)`.
pub fn stats(conn: &Connection, now: i64, tools: &[(&str, bool)]) -> anyhow::Result<Stats> {
    let names = serde_json::to_string(&tools.iter().map(|t| t.0).collect::<Vec<_>>())?;
    let writes = serde_json::to_string(&tools.iter().filter(|t| !t.1).map(|t| t.0).collect::<Vec<_>>())?;
    let today = now.div_euclid(86_400);
    let first = today - (STATS_DAYS - 1);
    let mut days: Vec<DayStats> = (first..=today)
        .map(|d| DayStats {
            date: util::rfc3339(d * 86_400).get(..10).unwrap_or_default().to_string(),
            ok: 0,
            failed: 0,
        })
        .collect();
    let mut st = conn.prepare(
        "SELECT ts / 86400, sum(result_code = 'ok'), sum(result_code <> 'ok') FROM audit \
         WHERE ts >= ?1 AND tool_or_action IN (SELECT value FROM json_each(?2)) AND tool_or_action <> ?3 \
         GROUP BY ts / 86400",
    )?;
    let rows = st.query_map(params![first * 86_400, names, POLL_TOOL], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))
    })?;
    for row in rows {
        let (d, ok, failed) = row?;
        if let Some(slot) = days.get_mut((d - first) as usize) {
            slot.ok = ok;
            slot.failed = failed;
        }
    }
    let mut st = conn.prepare(
        "SELECT actor, sum(tool_or_action <> ?3), sum(tool_or_action <> ?3 AND result_code <> 'ok'), \
                sum(result_code = 'ok' AND tool_or_action IN (SELECT value FROM json_each(?4))), \
                sum(tool_or_action = ?3), max(ts) \
         FROM audit WHERE ts >= ?1 AND tool_or_action IN (SELECT value FROM json_each(?2)) \
         GROUP BY actor ORDER BY 2 DESC, 5 DESC, actor LIMIT 20",
    )?;
    let clients = st
        .query_map(params![now - 7 * 86_400, names, POLL_TOOL, writes], |r| {
            Ok(ClientStats {
                actor: r.get(0)?,
                calls: r.get(1)?,
                failed: r.get(2)?,
                writes: r.get(3)?,
                polls: r.get(4)?,
                last_ts: r.get(5)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    let distinct = |col: &str| -> anyhow::Result<Vec<String>> {
        let mut st = conn.prepare(&format!(
            "SELECT {col} FROM audit WHERE {col} IS NOT NULL GROUP BY {col} ORDER BY count(*) DESC, {col} LIMIT ?1"
        ))?;
        Ok(st.query_map([VALUES_MAX], |r| r.get(0))?.collect::<Result<_, _>>()?)
    };
    let values = Values {
        actors: distinct("actor")?,
        actions: distinct("tool_or_action")?,
        accounts: distinct("account_alias")?,
        results: distinct("result_code")?,
    };
    Ok(Stats { days, clients, values })
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

    fn call(actor: &str, tool: &str, result: &str, ids: &[&str]) -> AuditRecord {
        AuditRecord {
            request_id: util::new_id(),
            actor: actor.into(),
            project: Some("p".into()),
            tool_or_action: tool.into(),
            account_alias: Some("info".into()),
            object_ids: ids.iter().map(|s| s.to_string()).collect(),
            result_code: result.into(),
            ..Default::default()
        }
    }

    const TOOLS: &[(&str, bool)] = &[("search_messages", true), ("create_draft", false), (POLL_TOOL, true)];

    /// Days are UTC buckets, oldest first, with gaps as zeros; polls and admin records stay out of the chart; the
    /// connection rows count polls apart and writes only when they succeeded.
    #[test]
    fn stats_count_agent_calls_per_day_and_connection() {
        let s = Store::open_in_memory().unwrap();
        let now = 1_794_800_000; // 2026-11-17T…Z
        let day = 86_400;
        s.call_blocking(move |c| {
            append_at(c, &call("bot", "search_messages", "ok", &[]), now - 13 * day)?;
            append_at(c, &call("bot", "search_messages", "ok", &[]), now - 14 * day)?; // outside the window
            for _ in 0..3 {
                append_at(c, &call("bot", "search_messages", "ok", &[]), now)?;
            }
            append_at(c, &call("bot", "create_draft", "ok", &[]), now)?;
            append_at(c, &call("bot", "create_draft", "invalid_argument", &[]), now)?;
            append_at(c, &call("poller", POLL_TOOL, "ok", &[]), now)?;
            append_at(c, &call("poller", POLL_TOOL, "error", &[]), now)?;
            append_at(c, &call("uid:1000", "accounts.list", "ok", &[]), now)?;
            append_at(c, &call("old", "search_messages", "ok", &[]), now - 8 * day)?;

            let st = stats(c, now, TOOLS)?;
            assert_eq!(st.days.len(), 14);
            assert_eq!(st.days[13].date, util::rfc3339(now)[..10]);
            assert_eq!((st.days[13].ok, st.days[13].failed), (4, 1), "polls and admin records are not charted");
            assert_eq!((st.days[0].ok, st.days[0].failed), (1, 0), "13 days ago is the first bar");
            assert_eq!(st.days[5].ok + st.days[5].failed, 1, "8 days ago");
            assert!(st.days[6..13].iter().all(|d| d.ok + d.failed == 0), "gaps are zeros");

            let by = |a: &str| st.clients.iter().find(|x| x.actor == a).cloned();
            let bot = by("bot").unwrap();
            assert_eq!((bot.calls, bot.failed, bot.writes, bot.polls, bot.last_ts), (5, 1, 1, 0, now));
            let poller = by("poller").unwrap();
            assert_eq!((poller.calls, poller.failed, poller.polls), (0, 0, 2), "poll errors are not call failures");
            assert!(by("uid:1000").is_none(), "admin records are not agents");
            assert!(by("old").is_none(), "older than 7 days");
            assert_eq!(st.clients[0].actor, "bot", "most calls first");

            assert_eq!(st.values.actors[0], "bot", "most frequent first");
            assert!(st.values.actions.contains(&"accounts.list".to_string()), "suggestions cover admin actions");
            assert_eq!(st.values.accounts, vec!["info"]);
            assert!(st.values.results.contains(&"invalid_argument".to_string()));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn search_filters_failed_object_polls_and_pages() {
        let s = Store::open_in_memory().unwrap();
        s.call_blocking(|c| {
            append(c, &call("bot", "search_messages", "ok", &["m1"]))?;
            append(c, &call("bot", "get_message", "not_found", &["m12"]))?;
            append(c, &call("bot", POLL_TOOL, "ok", &[]))?;
            append(c, &call("bot", "create_draft", "ok", &["m12", "d1"]))?;
            let tools = |f: &SearchFilter| -> anyhow::Result<Vec<String>> {
                Ok(search(c, f)?.into_iter().map(|r| r.record.tool_or_action).collect())
            };
            let all = SearchFilter::default();
            assert_eq!(tools(&all)?, ["create_draft", POLL_TOOL, "get_message", "search_messages"]);
            let failed = SearchFilter { failed: Some(true), ..Default::default() };
            assert_eq!(tools(&failed)?, ["get_message"]);
            let obj = SearchFilter { object: Some("m12".into()), ..Default::default() };
            assert_eq!(tools(&obj)?, ["create_draft", "get_message"], "exact element, not a substring of m1");
            let obj = SearchFilter { object: Some("m1".into()), ..Default::default() };
            assert_eq!(tools(&obj)?, ["search_messages"]);
            let quiet = SearchFilter { hide_polls: Some(true), ..Default::default() };
            assert_eq!(tools(&quiet)?, ["create_draft", "get_message", "search_messages"]);
            let named = SearchFilter { hide_polls: Some(true), tool: Some(POLL_TOOL.into()), ..Default::default() };
            assert_eq!(tools(&named)?, [POLL_TOOL], "naming the poll tool shows it");
            let page = SearchFilter { limit: Some(2), ..Default::default() };
            let first = search(c, &page)?;
            let next = SearchFilter { before: Some(first[1].seq), ..page };
            assert_eq!(tools(&next)?, ["get_message", "search_messages"], "the page after the first two");
            Ok(())
        })
        .unwrap();
    }

    /// A filter from an older client (no new fields) parses, and an unset new field is not sent to an older service.
    #[test]
    fn search_filter_stays_wire_compatible() {
        let old: SearchFilter = serde_json::from_str(
            r#"{"actor":"bot","tool":null,"account":null,"result_code":null,"since":null,"limit":5}"#,
        )
        .unwrap();
        assert_eq!((old.actor.as_deref(), old.failed, old.before), (Some("bot"), None, None));
        let v = serde_json::to_value(SearchFilter::default()).unwrap();
        for k in ["failed", "object", "before", "hide_polls"] {
            assert!(v.get(k).is_none(), "{k}");
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
