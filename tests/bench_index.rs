//! Reproducible benchmark for spec 8.1 (PLAN item "Benchmarks"). Everything here is `#[ignore]`; run it in release:
//!
//! ```sh
//! DOVE_BENCH_ACCOUNTS=25 cargo test --release --test bench_index -- --ignored --nocapture bench_index
//! cargo test --release --test bench_index -- --ignored --nocapture bench_sync_through_fake_google
//! ```
//!
//! `bench_index` generates a deterministic synthetic corpus (default 250k messages) and indexes it through the real
//! parse and index-write path (`doc_from_raw_answer` with the `format=raw` answer shape, then `ingest::upsert` in
//! transactions of 16, the sync engine's batch size, on the real writer connection). It does not go through a fake
//! Google server because that would hold the whole corpus in this process, distort RSS and make the run take hours;
//! `bench_sync_through_fake_google` runs the full sync engine against the fake server on a smaller corpus to report the
//! throughput of the whole path, so the difference (HTTP, gateway, scheduling) is visible. Queries then run against
//! the real MCP layer, once through `mcp::call_tool` (service time, spec 8.1 "at the service") and once over HTTP
//! (end to end). Environment: `DOVE_BENCH_MESSAGES` (250000), `DOVE_BENCH_ACCOUNTS` (25), `DOVE_BENCH_LIVE` (messages
//! ingested while queries run, 20000), `DOVE_BENCH_E2E` (messages of the fake-Google run, 10000), `DOVE_BENCH_OUT`
//! (write the report to this path), `DOVE_BENCH_MAX_REPS` (cap on warm repetitions per query), `DOVE_BENCH_CONC_ROUNDS` (20), `DOVE_BENCH_FAST=1` (tuning run: 5 repetitions, no concurrent/live phase), `DOVE_BENCH_EXPLAIN=1` (print EXPLAIN QUERY PLAN of every search).

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use dove::admin::AdminRequest;
use dove::index::sync::{load_state, sync_account};
use dove::index::{ingest, sync};
use futures::StreamExt;
use mail_builder::MessageBuilder;
use mail_builder::headers::raw::Raw;
use serde_json::{Value, json};
use support::fake_google::MessageSpec;
use support::harness::{Harness, g};

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

// ------------------------------------------------------------------------------------------------------ process

fn proc_status_kib(key: &str) -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines()
        .find_map(|l| l.strip_prefix(key))
        .and_then(|r| r.trim_start_matches(':').split_whitespace().next()?.parse().ok())
        .unwrap_or(0)
}

/// Restarts the peak-RSS counter (`VmHWM`) so each phase reports its own peak.
fn reset_peak_rss() {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
}

fn rss_mib() -> f64 {
    proc_status_kib("VmRSS") as f64 / 1024.0
}

fn peak_rss_mib() -> f64 {
    proc_status_kib("VmHWM") as f64 / 1024.0
}

/// User + system CPU seconds of this process.
fn cpu_secs() -> f64 {
    let s = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let rest = s.rsplit_once(')').map(|(_, r)| r).unwrap_or("");
    let f: Vec<&str> = rest.split_whitespace().collect();
    let tick = |i: usize| f.get(i).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
    (tick(11) + tick(12)) / 100.0
}

// ------------------------------------------------------------------------------------------------------ corpus

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn f(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi - lo + 1)
    }
    fn chance(&mut self, p: f64) -> bool {
        self.f() < p
    }
}

struct Zipf {
    cum: Vec<f64>,
}

impl Zipf {
    fn new(n: usize, s: f64) -> Self {
        let mut t = 0.0;
        Self {
            cum: (1..=n)
                .map(|k| {
                    t += 1.0 / (k as f64).powf(s);
                    t
                })
                .collect(),
        }
    }
    fn sample(&self, r: &mut Rng) -> usize {
        let x = r.f() * self.cum[self.cum.len() - 1];
        self.cum.partition_point(|c| *c < x).min(self.cum.len() - 1)
    }
}

const FIRST: [&str; 40] = [
    "Anna", "Ben", "Clara", "David", "Eva", "Felix", "Greta", "Hannah", "Ivan", "Julia", "Karl", "Lena", "Max", "Nina",
    "Oskar", "Paula", "Quentin", "Rosa", "Stefan", "Tina", "Uwe", "Vera", "Walter", "Xenia", "Yusuf", "Zoe", "Joanna",
    "Marianne", "Hans", "Petra", "Lukas", "Mia", "Noah", "Emma", "Tom", "Sara", "Jonas", "Lisa", "Paul", "Marie",
];
const LAST: [&str; 50] = [
    "Meier",
    "Schmidt",
    "Fischer",
    "Weber",
    "Wagner",
    "Becker",
    "Hoffmann",
    "Koch",
    "Richter",
    "Klein",
    "Wolf",
    "Neumann",
    "Schwarz",
    "Zimmermann",
    "Braun",
    "Krueger",
    "Hofmann",
    "Hartmann",
    "Lange",
    "Schmitt",
    "Werner",
    "Krause",
    "Lehmann",
    "Schmid",
    "Schulze",
    "Maier",
    "Koehler",
    "Herrmann",
    "Koenig",
    "Walter",
    "Mayer",
    "Huber",
    "Kaiser",
    "Fuchs",
    "Peters",
    "Lang",
    "Scholz",
    "Moeller",
    "Weiss",
    "Jung",
    "Hahn",
    "Schubert",
    "Vogel",
    "Friedrich",
    "Keller",
    "Guenther",
    "Frank",
    "Berger",
    "Winkler",
    "Roth",
];

/// Frequent and rare terms the queries look for (share of messages that contain them).
const TERMS: [(&str, f64); 5] =
    [("project", 0.25), ("meeting", 0.12), ("invoice", 0.04), ("budget", 0.02), ("quarterly", 0.004)];
/// Appears whenever the generator's step counter (one step per thread and per message, about 1.4 per message) is a
/// multiple of 12,500: in about 27 of 250k messages.
const RARE_TERM: &str = "zebrafish";
/// In the text of about 10 % of the CSV attachments.
const ATT_TERM: &str = "ledgerline";
const NEWSLETTER_DOMAINS: usize = 60;
const SENDERS: usize = 5000;
const USER_LABELS: usize = 120;

struct GenMsg {
    id: String,
    thread_id: String,
    labels: Vec<String>,
    date_ms: i64,
    snippet: String,
    raw: Vec<u8>,
}

struct Corpus {
    rng: Rng,
    vocab: Vec<String>,
    words: Zipf,
    senders: Zipf,
    labels: Zipf,
    png_noise: Vec<u8>,
    now: i64,
    seq: u64,
    /// Account email per index.
    accounts: Vec<String>,
}

fn sender(i: usize) -> (String, String) {
    let (f, l) = (FIRST[i % 40], LAST[(i / 40) % 50]);
    (format!("{f} {l}"), format!("{}.{}.{i}@dom{}.example", f.to_lowercase(), l.to_lowercase(), i % 400))
}

impl Corpus {
    fn new(seed: u64, accounts: Vec<String>) -> Self {
        let cons = b"bcdfghjklmnprstvwz";
        let vow = b"aeiou";
        let syl = |k: usize| format!("{}{}", cons[(k / 5) % 18] as char, vow[k % 5] as char);
        let vocab: Vec<String> = (0..30_000)
            .map(|i| {
                let mut w = format!("{}{}", syl(i % 90), syl((i / 90) % 90));
                if i >= 8100 {
                    w.push_str(&syl((i / 8100) % 90 + i % 7));
                }
                w
            })
            .collect();
        let mut rng = Rng(seed);
        let png_noise: Vec<u8> = (0..65_536).map(|_| rng.next() as u8).collect();
        Self {
            rng,
            words: Zipf::new(vocab.len(), 1.05),
            vocab,
            senders: Zipf::new(SENDERS, 1.1),
            labels: Zipf::new(USER_LABELS, 1.0),
            png_noise,
            now: dove::util::now_unix(),
            seq: 0,
            accounts,
        }
    }

    fn text(&mut self, words: usize, extra: &[&str]) -> String {
        let mut out = String::with_capacity(words * 7);
        let mut in_sentence = 0;
        let mut sentence_len = self.rng.range(8, 20);
        let insert: Vec<usize> = extra.iter().map(|_| self.rng.below(words.max(1))).collect();
        for i in 0..words {
            for (k, at) in insert.iter().enumerate() {
                if *at == i {
                    out.push_str(extra[k]);
                    out.push(' ');
                }
            }
            let w = &self.vocab[self.words.sample(&mut self.rng)];
            if in_sentence == 0 {
                let mut c = w.chars();
                if let Some(f) = c.next() {
                    out.extend(f.to_uppercase());
                    out.push_str(c.as_str());
                }
            } else {
                out.push_str(w);
            }
            in_sentence += 1;
            if in_sentence == sentence_len {
                out.push_str(if self.rng.chance(0.2) { ".\n" } else { ". " });
                in_sentence = 0;
                sentence_len = self.rng.range(8, 20);
            } else {
                out.push(' ');
            }
        }
        out
    }

    fn body_words(&mut self) -> usize {
        let u = self.rng.f();
        if u < 0.60 {
            self.rng.range(20, 200)
        } else if u < 0.90 {
            self.rng.range(200, 1200)
        } else if u < 0.99 {
            self.rng.range(1200, 6000)
        } else {
            self.rng.range(6000, 30_000)
        }
    }

    fn user_labels(&mut self, labels: &mut Vec<String>) {
        let u = self.rng.f();
        let n = if u < 0.55 {
            0
        } else if u < 0.85 {
            1
        } else if u < 0.95 {
            2
        } else {
            3
        };
        for _ in 0..n {
            let l = format!("Label_{}", self.labels.sample(&mut self.rng) + 10);
            if !labels.contains(&l) {
                labels.push(l);
            }
        }
    }

    fn thread_size(&mut self) -> usize {
        let u = self.rng.f();
        if u < 0.50 {
            1
        } else if u < 0.80 {
            self.rng.range(2, 3)
        } else if u < 0.97 {
            self.rng.range(4, 10)
        } else {
            self.rng.range(11, 40)
        }
    }

    /// One thread (or a single newsletter/notification) of mail in one mailbox, oldest message first.
    fn group(&mut self, account: usize) -> Vec<GenMsg> {
        let own = self.accounts[account].clone();
        let kind = self.rng.f();
        let (class, size) = if kind < 0.15 {
            (1, 1)
        } else if kind < 0.25 {
            (2, self.rng.range(1, 2))
        } else {
            (0, self.thread_size())
        };
        let contact = self.senders.sample(&mut self.rng);
        let (cname, caddr) = match class {
            1 => {
                let n = self.rng.below(NEWSLETTER_DOMAINS);
                (format!("News {n}"), format!("newsletter-{n}@mail{n}.example"))
            }
            2 => {
                let n = self.rng.below(30);
                (format!("Service {n}"), format!("no-reply@svc{n}.example"))
            }
            _ => sender(contact),
        };
        let age = 5.0 * 365.0 * 86_400.0 * self.rng.f().powf(1.3);
        let mut t = self.now - age as i64;
        let subject = {
            let n = self.rng.range(3, 8);
            let s = self.text(n, &[]);
            s.trim().trim_end_matches('.').to_string()
        };
        self.seq += 1;
        let thread_id = format!("{:016x}", self.rng.next());
        let mut out = Vec::with_capacity(size);
        let mut prev_mid: Option<String> = None;
        let mut from_self = class == 0 && self.rng.chance(0.1);
        for k in 0..size {
            self.seq += 1;
            let id = format!("{:016x}", self.rng.next());
            let mid = format!("{id}@bench.example");
            let words = self.body_words();
            let mut extra: Vec<&str> = TERMS.iter().filter(|(_, p)| self.rng.chance(*p)).map(|(t, _)| *t).collect();
            if self.seq.is_multiple_of(12_500) {
                extra.push(RARE_TERM);
            }
            let body = self.text(words, &extra);
            let (fname, faddr, toaddr) = if from_self {
                (own.clone(), own.clone(), caddr.clone())
            } else {
                (cname.clone(), caddr.clone(), own.clone())
            };
            let mut b = MessageBuilder::new()
                .from((fname, faddr))
                .to(toaddr)
                .subject(if k == 0 { subject.clone() } else { format!("Re: {subject}") })
                .date(t)
                .message_id(mid.clone());
            if let Some(p) = &prev_mid {
                b = b.in_reply_to(p.clone()).references(p.clone());
            }
            if self.rng.chance(0.15) {
                let c = self.senders.sample(&mut self.rng);
                b = b.cc(sender(c).1);
            }
            if class == 1 {
                b = b.header(
                    "List-Unsubscribe",
                    Raw::new(format!("<mailto:unsub@{}>", caddr.split('@').nth(1).unwrap())),
                );
            }
            // Mostly plain text, a fifth multipart with HTML, a tenth HTML only (newsletters mostly).
            let h = self.rng.f();
            let html = |t: &str| format!("<html><body><p>{}</p></body></html>", t.replace('\n', "<br>"));
            b = if class == 1 && h < 0.7 || h < 0.10 {
                b.html_body(html(&body))
            } else if h < 0.30 {
                b.text_body(body.clone()).html_body(html(&body))
            } else {
                b.text_body(body.clone())
            };
            if self.rng.chance(0.12) {
                let u = self.rng.f();
                if u < 0.35 {
                    let n = self.rng.range(300, 3000);
                    let t = self.text(n, &[]);
                    b = b.attachment("text/plain", format!("notes-{}.txt", self.seq), t.into_bytes());
                } else if u < 0.55 {
                    let rows = self.rng.range(30, 400);
                    let mut csv = String::from("id,account,amount,memo\n");
                    for r in 0..rows {
                        let w = self.vocab[self.words.sample(&mut self.rng)].clone();
                        csv.push_str(&format!("{r},{},{:.2},{w}\n", self.rng.below(900), self.rng.f() * 1000.0));
                    }
                    if self.rng.chance(0.10) {
                        csv.push_str(&format!("0,0,0.00,{ATT_TERM}\n"));
                    }
                    b = b.attachment("text/csv", format!("export-{}.csv", self.seq), csv.into_bytes());
                } else {
                    let n = self.rng.range(2_000, 60_000);
                    let off = self.rng.below(self.png_noise.len() - n.min(self.png_noise.len() - 1));
                    let data = self.png_noise[off..(off + n).min(self.png_noise.len())].to_vec();
                    b = b.attachment("image/png", format!("scan-{}.png", self.seq), data);
                }
            }
            let raw = b.write_to_vec().unwrap();
            let mut labels: Vec<String> = Vec::new();
            if from_self {
                labels.push("SENT".into());
            } else {
                let u = self.rng.f();
                if u < 0.01 {
                    labels.push("SPAM".into());
                } else if u < 0.02 {
                    labels.push("TRASH".into());
                } else if u < 0.90 {
                    labels.push("INBOX".into());
                    if self.rng.chance(if class == 1 { 0.6 } else { 0.25 }) {
                        labels.push("UNREAD".into());
                    }
                }
                labels.push(
                    match class {
                        1 => "CATEGORY_PROMOTIONS",
                        2 => "CATEGORY_UPDATES",
                        _ => "CATEGORY_PERSONAL",
                    }
                    .into(),
                );
                if self.rng.chance(0.02) {
                    labels.push("STARRED".into());
                }
                if self.rng.chance(0.10) {
                    labels.push("IMPORTANT".into());
                }
            }
            self.user_labels(&mut labels);
            let snippet: String = body.chars().filter(|c| *c != '\n').take(100).collect();
            out.push(GenMsg { id, thread_id: thread_id.clone(), labels, date_ms: t * 1000, snippet, raw });
            prev_mid = Some(mid);
            t = (t + 60 + (self.rng.f() * 3.0 * 86_400.0 * self.rng.f()) as i64).min(self.now);
            from_self = class == 0 && !from_self;
        }
        out
    }
}

/// The body of a Gmail `format=raw` answer, as the sync engine receives it.
fn raw_answer(m: &GenMsg) -> Vec<u8> {
    let v = json!({"id": m.id, "threadId": m.thread_id, "labelIds": m.labels, "internalDate": m.date_ms.to_string(),
        "sizeEstimate": m.raw.len(), "snippet": m.snippet, "raw": dove::util::b64url(&m.raw)});
    serde_json::to_vec(&v).unwrap()
}

// ------------------------------------------------------------------------------------------------------ ingest

#[derive(Default, Clone, Copy)]
struct IngestStats {
    messages: usize,
    raw_bytes: u64,
    parse: Duration,
    commit: Duration,
    generate: Duration,
}

struct Target {
    account_id: String,
    gen_id: i64,
}

/// Parses (two body jobs at a time, as `body_jobs` allows) and commits one batch of 16 in a single transaction.
async fn ingest_batch(app: &Arc<dove::app::App>, t: &Target, batch: Vec<GenMsg>, st: &mut IngestStats) {
    let cfg = &app.index.cfg;
    let (max_bytes, max_chars) = (cfg.max_message_bytes, cfg.max_body_chars);
    let att = Arc::new(cfg.attachment_cfg());
    st.raw_bytes += batch.iter().map(|m| m.raw.len() as u64).sum::<u64>();
    let bodies: Vec<Vec<u8>> = batch.iter().map(raw_answer).collect();
    drop(batch);
    let p0 = Instant::now();
    let docs: Vec<_> = futures::stream::iter(bodies)
        .map(|body| {
            let att = att.clone();
            tokio::task::spawn_blocking(move || sync::doc_from_raw_answer(body, max_bytes, max_chars, &att))
        })
        .buffered(cfg.body_jobs.clamp(1, 8))
        .map(|r| r.unwrap().expect("parsed"))
        .collect()
        .await;
    st.parse += p0.elapsed();
    let c0 = Instant::now();
    let (aid, gen_id) = (t.account_id.clone(), t.gen_id);
    let n = docs.len();
    app.index
        .write(move |c| {
            let tx = c.transaction()?;
            for d in &docs {
                ingest::upsert(&tx, gen_id, &aid, d)?;
            }
            tx.execute("UPDATE sync_state SET data_seq = data_seq + 1 WHERE account_id = ?1", [&aid])?;
            tx.commit()?;
            Ok(())
        })
        .await
        .unwrap();
    st.commit += c0.elapsed();
    st.messages += n;
}

/// Generates and ingests `count` messages into one mailbox.
async fn ingest_account(
    app: &Arc<dove::app::App>,
    corpus: &mut Corpus,
    account: usize,
    t: &Target,
    count: usize,
    st: &mut IngestStats,
) {
    let mut done = 0;
    let mut pending: Vec<GenMsg> = Vec::new();
    while done < count {
        let g0 = Instant::now();
        while pending.len() < 16 && done + pending.len() < count {
            let take = count - done - pending.len();
            let mut grp = corpus.group(account);
            grp.truncate(take);
            pending.extend(grp);
        }
        let rest = if pending.len() > 16 { pending.split_off(16) } else { Vec::new() };
        let batch = std::mem::replace(&mut pending, rest);
        st.generate += g0.elapsed();
        done += batch.len();
        ingest_batch(app, t, batch, st).await;
    }
}

fn account_sizes(total: usize, n: usize) -> Vec<usize> {
    let w: Vec<f64> = (1..=n).map(|k| 1.0 / (k as f64).powf(0.8)).collect();
    let sum: f64 = w.iter().sum();
    let mut sizes: Vec<usize> = w.iter().map(|x| (total as f64 * x / sum) as usize).collect();
    let rest = total - sizes.iter().sum::<usize>();
    sizes[0] += rest;
    sizes
}

// ------------------------------------------------------------------------------------------------------ stats

fn pct(v: &mut [f64], p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[(((v.len() as f64) * p).ceil() as usize).clamp(1, v.len()) - 1]
}

fn dir_size(p: &std::path::Path) -> Vec<(String, u64)> {
    let mut out = vec![];
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            if let Ok(m) = e.metadata()
                && m.is_file()
            {
                out.push((e.file_name().to_string_lossy().into_owned(), m.len()));
            }
        }
    }
    out.sort();
    out
}

// ------------------------------------------------------------------------------------------------------ queries

struct Q {
    group: &'static str,
    name: &'static str,
    tool: &'static str,
    args: Value,
    /// Warm repetitions.
    reps: usize,
}

fn pred(field: &str, op: &str, value: Value) -> Value {
    json!({"field": field, "op": op, "value": value})
}

fn queries(now: i64) -> Vec<Q> {
    let rfc = |secs: i64| dove::util::rfc3339(secs);
    let days = |d: i64| rfc(now - d * 86_400);
    let (top_sender, mid_sender, rare_sender) = (sender(0).1, sender(300).1, sender(4_500).1);
    let sel = json!(["ref", "received_at", "from", "subject", "snippet"]);
    let q = |group, name, tool, args, reps| Q { group, name, tool, args, reps };
    let search = |w: Value| json!({"where": w, "select": sel, "limit": 20});
    vec![
        // Structured, no FTS (target p95 <= 100 ms)
        q(
            "structured",
            "unread inbox, newest 20",
            "search_messages",
            search(json!({"all": [pred("label", "eq", json!("INBOX")), pred("is_unread", "eq", json!(true))]})),
            100,
        ),
        q(
            "structured",
            "from the most frequent sender",
            "search_messages",
            search(pred("from", "eq", json!(top_sender))),
            100,
        ),
        q(
            "structured",
            "from a mid-frequency sender",
            "search_messages",
            search(pred("from", "eq", json!(mid_sender))),
            100,
        ),
        q("structured", "from a rare sender", "search_messages", search(pred("from", "eq", json!(rare_sender))), 100),
        q(
            "structured",
            "from_domain of a newsletter sender",
            "search_messages",
            search(pred("from_domain", "eq", json!("mail3.example"))),
            100,
        ),
        q(
            "structured",
            "label Label_10 (frequent user label)",
            "search_messages",
            search(pred("label", "eq", json!("Label_10"))),
            100,
        ),
        q(
            "structured",
            "label Label_100 (rare user label)",
            "search_messages",
            search(pred("label", "eq", json!("Label_100"))),
            100,
        ),
        q(
            "structured",
            "label Label_12 and last 30 days",
            "search_messages",
            search(
                json!({"all": [pred("label", "eq", json!("Label_12")), pred("received_at", "gte", json!(days(30)))]}),
            ),
            100,
        ),
        q(
            "structured",
            "has attachment, last year",
            "search_messages",
            search(
                json!({"all": [pred("has_attachment", "eq", json!(true)), pred("received_at", "gte", json!(days(365)))]}),
            ),
            100,
        ),
        q("structured", "starred", "search_messages", search(pred("label", "eq", json!("STARRED"))), 100),
        q("structured", "sent by self", "search_messages", search(pred("from_self", "eq", json!(true))), 100),
        q(
            "structured",
            "newsletters (category)",
            "search_messages",
            search(pred("category", "eq", json!("newsletter"))),
            100,
        ),
        q(
            "structured",
            "count: unread inbox",
            "search_messages",
            json!({"where": {"all": [pred("label", "eq", json!("INBOX")), pred("is_unread", "eq", json!(true))]}, "count_only": true, "coverage_policy": "require_complete", "max_lag_seconds": 86400}),
            30,
        ),
        // FTS + filters + date order (target p95 <= 250 ms)
        q(
            "fts",
            "text: project (about 25 % of mail)",
            "search_messages",
            search(pred("text", "terms", json!("project"))),
            50,
        ),
        q("fts", "text: meeting (about 12 %)", "search_messages", search(pred("text", "terms", json!("meeting"))), 50),
        q("fts", "text: invoice (about 4 %)", "search_messages", search(pred("text", "terms", json!("invoice"))), 50),
        q(
            "fts",
            "text: quarterly (about 0.4 %)",
            "search_messages",
            search(pred("text", "terms", json!("quarterly"))),
            50,
        ),
        q(
            "fts",
            "text: zebrafish (about 27 messages)",
            "search_messages",
            search(pred("text", "terms", json!("zebrafish"))),
            50,
        ),
        q(
            "fts",
            "text: project AND meeting",
            "search_messages",
            search(pred("text", "terms", json!("project meeting"))),
            50,
        ),
        q(
            "fts",
            "text: project, INBOX, last 90 days",
            "search_messages",
            search(
                json!({"all": [pred("text", "terms", json!("project")), pred("label", "eq", json!("INBOX")), pred("received_at", "gte", json!(days(90)))]}),
            ),
            50,
        ),
        q(
            "fts",
            "text: invoice, from a frequent sender",
            "search_messages",
            search(json!({"all": [pred("text", "terms", json!("invoice")), pred("from", "eq", json!(top_sender))]})),
            50,
        ),
        q(
            "fts",
            "subject: baba (most frequent word)",
            "search_messages",
            search(pred("subject", "terms", json!("baba"))),
            50,
        ),
        q(
            "fts",
            "attachment_text: ledgerline",
            "search_messages",
            search(pred("attachment_text", "terms", json!("ledgerline"))),
            50,
        ),
        q("fts", "text: prefix proj*", "search_messages", search(pred("text", "prefix", json!("proj"))), 20),
        // Thread view
        q(
            "thread",
            "group_by thread, newest 20",
            "search_messages",
            json!({"group_by": "thread", "limit": 20, "select": ["thread_id", "subject", "from", "received_at", "message_count"]}),
            50,
        ),
        q(
            "thread",
            "group_by thread, INBOX",
            "search_messages",
            json!({"group_by": "thread", "limit": 20, "where": pred("label", "eq", json!("INBOX")), "select": ["thread_id", "subject", "from", "message_count", "awaiting_reply"]}),
            50,
        ),
        q(
            "thread",
            "group_by thread, awaiting_reply",
            "search_messages",
            json!({"group_by": "thread", "awaiting_reply": true, "limit": 20, "where": pred("label", "eq", json!("INBOX")), "select": ["thread_id", "subject", "last_inbound_at", "awaiting_reply"]}),
            30,
        ),
        q(
            "thread",
            "group_by thread, text: project",
            "search_messages",
            json!({"group_by": "thread", "limit": 20, "where": pred("text", "terms", json!("project")), "select": ["thread_id", "subject", "matched_count"]}),
            30,
        ),
        // Digest and contacts
        q("digest", "digest last 7 days, INBOX", "digest", json!({"since": days(7), "limit": 20}), 50),
        q(
            "digest",
            "digest last 30 days, newsletters",
            "digest",
            json!({"since": days(30), "category": "newsletter", "limit": 20}),
            30,
        ),
        q("digest", "digest last 365 days", "digest", json!({"since": days(365), "limit": 20}), 20),
        q("contacts", "search_contacts: ann", "search_contacts", json!({"query": "ann"}), 30),
        q("contacts", "search_contacts: schmidt", "search_contacts", json!({"query": "schmidt"}), 30),
        q("contacts", "search_contacts: no query (top)", "search_contacts", json!({}), 20),
        // Response bytes: subject only vs default vs detail
        q("bytes", "select: subject only", "search_messages", json!({"select": ["subject"], "limit": 20}), 30),
        q("bytes", "select: default", "search_messages", json!({"limit": 20}), 30),
        q(
            "bytes",
            "select: detail",
            "search_messages",
            json!({"select": ["ref", "account", "message_id", "thread_id", "received_at", "from", "to", "cc", "subject", "labels", "snippet", "has_attachment", "is_unread"], "limit": 20}),
            30,
        ),
    ]
}

struct Service {
    app: Arc<dove::app::App>,
    ctx: dove::policy::ClientCtx,
}

impl Service {
    /// One tool call through `mcp::call_tool` (authorization, deadline, audit record). Returns the error code if any.
    async fn call(&self, tool: &str, args: &Value) -> (f64, Option<String>) {
        let t0 = Instant::now();
        let v = dove::mcp::call_tool(&self.app, &self.ctx, "2025-06-18", tool, args.clone()).await;
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        let code = v["isError"].as_bool().unwrap_or(false).then(|| {
            if std::env::var("DOVE_BENCH_EXPLAIN").is_ok() {
                println!("ERROR {tool}: {}", v["structuredContent"].to_string().chars().take(900).collect::<String>());
            }
            let e = &v["structuredContent"]["error"];
            let msg: String = e["message"].as_str().unwrap_or("").chars().take(70).collect();
            format!("{}: {msg}", e["code"].as_str().unwrap_or("error"))
        });
        (ms, code)
    }
}

struct QueryResult {
    group: &'static str,
    name: &'static str,
    first_ms: f64,
    p50: f64,
    p95: f64,
    http_p50: f64,
    http_p95: f64,
    bytes: usize,
    rows: i64,
    coverage: String,
    error: Option<String>,
}

async fn http_call(h: &Harness, token: &str, tool: &str, args: &Value) -> (f64, usize, Value) {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}});
    let t0 = Instant::now();
    let r = h.post_mcp(Some(token), body, &[]).await;
    let bytes = r.bytes().await.unwrap();
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    (ms, bytes.len(), v["result"]["structuredContent"].clone())
}

fn row_count(v: &Value) -> i64 {
    v["count"]
        .as_i64()
        .or_else(|| v["rows"].as_array().map(|a| a.len() as i64))
        .or_else(|| v["threads"].as_array().map(|a| a.len() as i64))
        .or_else(|| v["contacts"].as_array().map(|a| a.len() as i64))
        .unwrap_or(-1)
}

async fn run_queries(h: &Harness, svc: &Service, token: &str, qs: &[Q], first_calls: &[f64]) -> Vec<QueryResult> {
    let mut out = vec![];
    for (i, q) in qs.iter().enumerate() {
        // Warm up, then measure at the service and over HTTP.
        for _ in 0..3 {
            svc.call(q.tool, &q.args).await;
        }
        let mut svc_ms = vec![];
        let mut error = None;
        for _ in 0..q.reps {
            let (ms, code) = svc.call(q.tool, &q.args).await;
            error = error.or(code);
            svc_ms.push(ms);
        }
        let mut http_ms = vec![];
        let mut bytes = 0;
        let mut sc = Value::Null;
        for _ in 0..q.reps.min(30) {
            let (ms, b, v) = http_call(h, token, q.tool, &q.args).await;
            http_ms.push(ms);
            bytes = b;
            sc = v;
        }
        out.push(QueryResult {
            group: q.group,
            name: q.name,
            first_ms: first_calls.get(i).copied().unwrap_or(f64::NAN),
            p50: pct(&mut svc_ms.clone(), 0.5),
            p95: pct(&mut svc_ms, 0.95),
            http_p50: pct(&mut http_ms.clone(), 0.5),
            http_p95: pct(&mut http_ms, 0.95),
            bytes,
            rows: row_count(&sc),
            coverage: sc["coverage"].as_str().unwrap_or("-").to_string(),
            error,
        });
    }
    out
}

async fn make_service(h: &Harness, token_name: &str) -> Service {
    let app = h.app().clone();
    let name = token_name.to_string();
    let (client_id, project_id, project_name, auth_epoch): (String, String, String, i64) = app
        .store
        .call(move |c| {
            Ok(c.query_row(
                "SELECT c.id, c.project_id, p.name, c.auth_epoch FROM clients c JOIN projects p ON p.id = c.project_id \
                 WHERE c.name = ?1",
                [name],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?)
        })
        .await
        .unwrap();
    let cid = client_id.clone();
    let mailboxes = app.store.call(move |c| dove::policy::load_mailboxes(c, &cid)).await.unwrap();
    let ctx = dove::policy::ClientCtx {
        client_id,
        client_name: token_name.into(),
        project_id,
        project_name,
        auth_epoch,
        source_ip: None,
        mailboxes,
        allow_send: false,
        redact_secrets: false,
    };
    Service { app, ctx }
}

fn table(res: &[QueryResult], target: impl Fn(&QueryResult) -> Option<f64>) -> String {
    let mut s = String::from(
        "| query | rows | cov | first (ms) | p50 (ms) | p95 (ms) | HTTP p50 | HTTP p95 | bytes | target p95 |\n\
         |---|--:|---|--:|--:|--:|--:|--:|--:|--:|\n",
    );
    for r in res {
        let t = target(r).map(|t| format!("{t:.0}")).unwrap_or_else(|| "-".into());
        let name = match &r.error {
            Some(e) => format!("{} ({e})", r.name),
            None => r.name.to_string(),
        };
        s.push_str(&format!(
            "| {name} | {} | {} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} | {} | {t} |\n",
            r.rows, r.coverage, r.first_ms, r.p50, r.p95, r.http_p50, r.http_p95, r.bytes
        ));
    }
    s
}

fn target_ms(r: &QueryResult) -> Option<f64> {
    match r.group {
        "structured" => Some(100.0),
        "fts" => Some(250.0),
        _ => None,
    }
}

// ------------------------------------------------------------------------------------------------------ the runs

async fn setup_accounts(h: &Harness, n: usize) -> (Vec<String>, Vec<String>, String) {
    let mut emails = vec![];
    let mut aliases = vec![];
    for i in 0..n {
        let alias = format!("a{i:02}");
        let email = format!("acct{i}@bench{i}.example");
        h.mailbox(&alias, &email);
        aliases.push(alias);
        emails.push(email);
    }
    let refs: Vec<&str> = aliases.iter().map(String::as_str).collect();
    h.project("bench", &refs).await;
    let grants = aliases.iter().map(|a| g(a, "read")).collect();
    let token = h.token("bench", "bench-agent", grants).await;
    (aliases, emails, token)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark: minutes of runtime and GBs of disk, see the module docs"]
async fn bench_index() {
    let total = env_usize("DOVE_BENCH_MESSAGES", 250_000);
    let n_acc = env_usize("DOVE_BENCH_ACCOUNTS", 25);
    let live = if std::env::var("DOVE_BENCH_FAST").is_ok() { 0 } else { env_usize("DOVE_BENCH_LIVE", 20_000) };
    let h = Harness::start().await;
    let (aliases, emails, token) = setup_accounts(&h, n_acc).await;
    let app = h.app().clone();
    let rss_idle = rss_mib();
    // DOVE_BENCH_FAST=1: few repetitions, no concurrent or live phase (for tuning runs); DOVE_BENCH_EXPLAIN=1 prints
    // EXPLAIN QUERY PLAN of every search query.
    let fast = std::env::var("DOVE_BENCH_FAST").is_ok();
    let explain = std::env::var("DOVE_BENCH_EXPLAIN").is_ok();

    // One seed message per mailbox through the real sync engine publishes a generation; the corpus goes into it.
    let mut seed = Corpus::new(7, emails.clone());
    let mut targets = vec![];
    for (i, (alias, email)) in aliases.iter().zip(&emails).enumerate() {
        let m = seed.group(i).remove(0);
        h.google.add_message(
            email,
            MessageSpec { raw: Some(m.raw), labels: m.labels, internal_date_ms: m.date_ms, ..Default::default() },
        );
        h.admin(AdminRequest::IndexEnable { alias: alias.clone() }).await.unwrap();
        let account_id: String = {
            let a = alias.clone();
            app.store
                .call(move |c| Ok(c.query_row("SELECT id FROM accounts WHERE alias = ?1", [a], |r| r.get(0))?))
                .await
                .unwrap()
        };
        let r = sync_account(&app, &account_id).await.unwrap();
        assert_eq!(r.indexed, 1, "{r:?}");
        let aid = account_id.clone();
        let st = app.index.write(move |c| load_state(c, &aid)).await.unwrap().unwrap();
        targets.push(Target { account_id, gen_id: st.active_gen.expect("published generation") });
    }

    // ---- ingest
    let mut corpus = Corpus::new(42, emails.clone());
    let sizes = account_sizes(total, n_acc);
    let mut st = IngestStats::default();
    reset_peak_rss();
    let (cpu0, wall0) = (cpu_secs(), Instant::now());
    for (i, n) in sizes.iter().enumerate() {
        ingest_account(&app, &mut corpus, i, &targets[i], *n, &mut st).await;
        if i % 5 == 4 || i + 1 == n_acc {
            eprintln!("ingested {} / {total} (rss {:.0} MiB)", st.messages, rss_mib());
        }
    }
    let wall = wall0.elapsed();
    let cpu_total = cpu_secs() - cpu0;
    let peak_ingest = peak_rss_mib();
    let rss_after_ingest = rss_mib();
    let busy = (st.parse + st.commit).as_secs_f64();
    let data_dir = h.env.dir.path().join("data");
    let files_before = dir_size(&data_dir);
    app.index.write(|c| Ok(c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?)).await.unwrap();
    let files = dir_size(&data_dir);
    let index_bytes: u64 = files.iter().filter(|(n, _)| n.starts_with("index")).map(|(_, s)| *s).sum();
    let wal_bytes: u64 =
        files_before.iter().filter(|(n, _)| n.starts_with("index") && n.ends_with("-wal")).map(|(_, s)| *s).sum();

    // ---- queries: cold (new App over the same data, empty page caches; the OS cache stays warm), warm, concurrent
    let mut h = h;
    h.restart().await;
    reset_peak_rss();
    let svc = make_service(&h, "bench-agent").await;
    let gmail_calls = |h: &Harness| h.google.requests().iter().filter(|r| r.path.contains("/gmail/")).count();
    let gmail_before = gmail_calls(&h);
    let mut qs = queries(dove::util::now_unix());
    let max_reps = if fast { 5 } else { env_usize("DOVE_BENCH_MAX_REPS", usize::MAX) };
    qs.iter_mut().for_each(|q| q.reps = q.reps.min(max_reps));
    let conc_rounds = env_usize("DOVE_BENCH_CONC_ROUNDS", 20);
    if explain {
        let tg: Vec<dove::index::query::Target> = targets
            .iter()
            .zip(&aliases)
            .map(|(t, a)| dove::index::query::Target {
                account_id: t.account_id.clone(),
                alias: a.clone(),
                gen_id: t.gen_id,
                att_fts: true,
            })
            .collect();
        let selves: std::collections::HashMap<String, Vec<String>> =
            targets.iter().zip(&emails).map(|(t, e)| (t.account_id.clone(), vec![e.clone()])).collect();
        for q in qs.iter().filter(|q| q.tool == "search_messages") {
            let Ok(req) = dove::tools::search::parse_index_req(&q.args) else { continue };
            let (tg, selves) = (tg.clone(), selves.clone());
            let plan = app
                .index
                .read(Instant::now() + Duration::from_secs(30), move |c| {
                    let known = std::collections::HashMap::new();
                    dove::index::query::explain(
                        c,
                        &req,
                        &dove::index::query::Scope { targets: &tg, known: &known, selves: &selves },
                    )
                })
                .await;
            println!("PLAN {}:\n  {}", q.name, plan.map(|p| p.join("\n  ")).unwrap_or_else(|e| format!("{e:?}")));
        }
    }
    let mut first = vec![];
    for q in &qs {
        first.push(svc.call(q.tool, &q.args).await.0);
    }
    let rss_after_cold = rss_mib();
    let res = run_queries(&h, &svc, &token, &qs, &first).await;
    let peak_query = peak_rss_mib();
    assert_eq!(gmail_calls(&h), gmail_before, "indexed searches must make zero Gmail calls");

    if fast {
        println!("\n===== bench_index (fast) =====\n{}", table(&res, target_ms));
        return;
    }
    // Concurrent foreground reads: 4 clients looping over a mix of the typical queries.
    reset_peak_rss();
    let mix: Vec<usize> =
        [0usize, 1, 13, 14, 15, 18, 26, 28, 30, 33].iter().copied().filter(|i| *i < qs.len()).collect();
    let conc_n = 4;
    let t0 = Instant::now();
    let mut tasks = vec![];
    for w in 0..conc_n {
        let svc = Service { app: svc.app.clone(), ctx: svc.ctx.clone() };
        let list: Vec<(String, Value)> = mix.iter().map(|i| (qs[*i].tool.to_string(), qs[*i].args.clone())).collect();
        tasks.push(tokio::spawn(async move {
            let mut ms = vec![];
            for round in 0..conc_rounds {
                for k in 0..list.len() {
                    let (tool, args) = &list[(k + w + round) % list.len()];
                    ms.push((svc.call(tool, args).await.0, (k + w + round) % list.len()));
                }
            }
            ms
        }));
    }
    let mut conc: Vec<(f64, usize)> = vec![];
    for t in tasks {
        conc.extend(t.await.unwrap());
    }
    let conc_wall = t0.elapsed();
    let peak_conc = peak_rss_mib();
    let mut conc_structured: Vec<f64> =
        conc.iter().filter(|(_, i)| qs[mix[*i]].group == "structured").map(|(m, _)| *m).collect();
    let mut conc_fts: Vec<f64> = conc.iter().filter(|(_, i)| qs[mix[*i]].group == "fts").map(|(m, _)| *m).collect();
    let mut conc_all: Vec<f64> = conc.iter().map(|(m, _)| *m).collect();

    // Queries while the writer is ingesting more mail (steady backfill of one more mailbox's worth).
    let mut live_ms: Vec<(f64, bool)> = vec![];
    let mut live_stats = IngestStats::default();
    if live > 0 {
        reset_peak_rss();
        let app2 = svc.app.clone();
        let tgt = Target { account_id: targets[0].account_id.clone(), gen_id: targets[0].gen_id };
        let mut c2 = Corpus::new(4242, emails.clone());
        let writer = tokio::spawn(async move {
            let mut s = IngestStats::default();
            ingest_account(&app2, &mut c2, 0, &tgt, live, &mut s).await;
            s
        });
        let probe: Vec<usize> = vec![0, 1, 13, 15, 26];
        let mut k = 0;
        while !writer.is_finished() {
            let i = probe[k % probe.len()];
            let (ms, _) = svc.call(qs[i].tool, &qs[i].args).await;
            live_ms.push((ms, qs[i].group == "structured"));
            k += 1;
        }
        live_stats = writer.await.unwrap();
    }
    let peak_live = peak_rss_mib();

    // ---- report
    let mut md = String::new();
    md.push_str(&format!(
        "Corpus: {total} messages in {n_acc} mailboxes (largest {}, smallest {}), generated {:.0} s, ingest wall {:.0} s\n\n",
        sizes[0],
        sizes[n_acc - 1],
        st.generate.as_secs_f64(),
        wall.as_secs_f64()
    ));
    md.push_str(&format!(
        "Ingest (real parse path + index writes, batches of 16): {:.0} msg/s over parse+commit ({:.0} s: parse {:.0} s, commit {:.0} s), {:.0} MiB raw mail ({:.1} KiB average), process CPU {:.0} s over {:.0} s wall ({:.1} cores)\n\n",
        st.messages as f64 / busy,
        busy,
        st.parse.as_secs_f64(),
        st.commit.as_secs_f64(),
        st.raw_bytes as f64 / 1048576.0,
        st.raw_bytes as f64 / st.messages as f64 / 1024.0,
        cpu_total,
        wall.as_secs_f64(),
        cpu_total / wall.as_secs_f64()
    ));
    md.push_str(&format!(
        "Disk: index {:.0} MiB after checkpoint ({:.0} MiB per 1000 messages), WAL before checkpoint {:.0} MiB; files: {}\n\n",
        index_bytes as f64 / 1048576.0,
        index_bytes as f64 / 1048576.0 / (st.messages as f64 / 1000.0),
        wal_bytes as f64 / 1048576.0,
        files.iter().map(|(n, s)| format!("{n} {:.0} MiB", *s as f64 / 1048576.0)).collect::<Vec<_>>().join(", ")
    ));
    md.push_str(&format!(
        "RSS (whole test process, includes fake Google, HTTP client and server): idle {rss_idle:.0} MiB; peak during ingest {peak_ingest:.0} MiB (after {rss_after_ingest:.0}); after restart + first calls {rss_after_cold:.0}; peak during warm queries {peak_query:.0}; peak during {conc_n} concurrent clients {peak_conc:.0}; peak during queries + live ingest {peak_live:.0}\n\n"
    ));
    md.push_str("Gmail calls made by all queries below (service and HTTP): 0 (asserted)\n\n");
    md.push_str(&table(&res, target_ms));
    md.push_str(&format!(
        "\nConcurrent: {conc_n} clients, {} calls in {:.1} s ({:.0} calls/s). Structured p50 {:.1} / p95 {:.1} ms (target 100); FTS p50 {:.1} / p95 {:.1} ms (target 250); all p95 {:.1} ms\n",
        conc.len(),
        conc_wall.as_secs_f64(),
        conc.len() as f64 / conc_wall.as_secs_f64(),
        pct(&mut conc_structured.clone(), 0.5),
        pct(&mut conc_structured, 0.95),
        pct(&mut conc_fts.clone(), 0.5),
        pct(&mut conc_fts, 0.95),
        pct(&mut conc_all, 0.95)
    ));
    let mut ls: Vec<f64> = live_ms.iter().filter(|(_, s)| *s).map(|(m, _)| *m).collect();
    let mut lf: Vec<f64> = live_ms.iter().filter(|(_, s)| !*s).map(|(m, _)| *m).collect();
    md.push_str(&format!(
        "\nDuring ingest of {live} more messages ({:.0} msg/s while queried): {} queries, structured p50 {:.1} / p95 {:.1} ms, FTS/thread p50 {:.1} / p95 {:.1} ms\n",
        live_stats.messages as f64 / (live_stats.parse + live_stats.commit).as_secs_f64().max(0.001),
        live_ms.len(),
        pct(&mut ls.clone(), 0.5),
        pct(&mut ls, 0.95),
        pct(&mut lf.clone(), 0.5),
        pct(&mut lf, 0.95)
    ));
    println!("\n===== bench_index =====\n{md}");
    if let Ok(path) = std::env::var("DOVE_BENCH_OUT") {
        std::fs::write(&path, &md).unwrap();
    }
}

/// The whole sync engine against the fake Google server: list, fetch, parse, commit, publish. Smaller than the main
/// run because the fake holds the corpus in this process.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark, see the module docs"]
async fn bench_sync_through_fake_google() {
    let total = env_usize("DOVE_BENCH_E2E", 10_000);
    let n_acc = 5;
    let h = Harness::start().await;
    let (aliases, emails, _token) = setup_accounts(&h, n_acc).await;
    let app = h.app().clone();
    let mut corpus = Corpus::new(99, emails.clone());
    let sizes = account_sizes(total, n_acc);
    let mut raw_bytes = 0u64;
    for (i, n) in sizes.iter().enumerate() {
        let mut done = 0;
        while done < *n {
            for m in corpus.group(i).into_iter().take(n - done) {
                raw_bytes += m.raw.len() as u64;
                h.google.add_message(
                    &emails[i],
                    MessageSpec {
                        raw: Some(m.raw),
                        labels: m.labels,
                        thread_id: Some(m.thread_id),
                        internal_date_ms: m.date_ms,
                        ..Default::default()
                    },
                );
                done += 1;
            }
        }
    }
    for alias in &aliases {
        h.admin(AdminRequest::IndexEnable { alias: alias.clone() }).await.unwrap();
    }
    let ids: Vec<String> = app
        .store
        .call(|c| {
            let mut s = c.prepare("SELECT id FROM accounts ORDER BY alias")?;
            Ok(s.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?)
        })
        .await
        .unwrap();
    reset_peak_rss();
    let (cpu0, t0) = (cpu_secs(), Instant::now());
    let mut indexed = 0;
    for id in &ids {
        let r = sync_account(&app, id).await.unwrap();
        assert_eq!(r.error, None, "{r:?}");
        indexed += r.indexed;
    }
    let wall = t0.elapsed().as_secs_f64();
    let reqs = h.google.requests();
    let count = |p: &str| reqs.iter().filter(|r| r.path.contains(p)).count();
    let lists = reqs.iter().filter(|r| r.path.ends_with("/messages")).count();
    let gets = count("/messages/");
    let md = format!(
        "Sync engine against the fake Google server: {indexed} messages in {n_acc} mailboxes, {:.1} MiB raw, {wall:.1} s = {:.0} msg/s, \
         process CPU {:.0} s ({:.1} cores), peak RSS (test process incl. the fake's copy of the corpus) {:.0} MiB; \
         {lists} messages.list and {gets} messages.get calls (Gmail quota units: {} at 5 each)\n",
        raw_bytes as f64 / 1048576.0,
        indexed as f64 / wall,
        cpu_secs() - cpu0,
        (cpu_secs() - cpu0) / wall,
        peak_rss_mib(),
        (lists + gets) * 5
    );
    assert_eq!(indexed, total);
    println!("\n===== bench_sync_through_fake_google =====\n{md}");
    if let Ok(path) = std::env::var("DOVE_BENCH_OUT") {
        std::fs::write(&path, &md).unwrap();
    }
}
