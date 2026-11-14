# Benchmarks (spec 8.1)

Reproducible measurements of ingest, disk, memory and query latency on a synthetic 250k-message corpus. The code is
`tests/bench_index.rs`; every test in it is `#[ignore]`, so a normal `cargo test` does not run it. Results below were
measured on 2026-11-14, release profile, `main` at 754b21e plus the benchmark commit. Host: AMD EPYC-Genoa, 12 cores,
23 GB RAM, Linux 7.0, rustc 1.100.0, **shared with the production service and other agent sessions** (jobs ran through
`heavy`, niced, with up to two other heavy jobs on the host), so absolute numbers carry noise; compare ratios and
orders of magnitude, not single milliseconds.

## How to run

```sh
# 250k messages in 25 mailboxes: about 10 min ingest plus 20 to 30 min of queries, 1.1 GB of disk in a temp dir
CARGO_BUILD_JOBS=3 heavy cargo test --release --test bench_index -- --ignored --nocapture bench_index

# the whole sync engine against the fake Google server (10k messages, under a minute)
CARGO_BUILD_JOBS=3 heavy cargo test --release --test bench_index -- --ignored --nocapture bench_sync_through_fake_google
```

Environment: `DOVE_BENCH_MESSAGES` (250000), `DOVE_BENCH_ACCOUNTS` (25; the spec asks for 1, 5 and 25),
`DOVE_BENCH_LIVE` (messages ingested while queries run, 20000), `DOVE_BENCH_MAX_REPS` (cap on warm repetitions per
query), `DOVE_BENCH_CONC_ROUNDS` (20), `DOVE_BENCH_E2E` (messages of the fake-Google run, 10000), `DOVE_BENCH_OUT`
(also write the report to this file), `DOVE_BENCH_FAST=1` (tuning run: 5 repetitions, no concurrent or live phase) and
`DOVE_BENCH_EXPLAIN=1` (print `EXPLAIN QUERY PLAN` of every search query and the body of failed calls). The corpus is
deterministic (seeded generator, no new dependencies); only the dates move with the clock.

## What is measured, and why this way

* **Ingest** goes through the real parse and write path, not through a fake Google server: each message is wrapped
  as a Gmail `format=raw` answer (JSON with base64url MIME) and parsed by `index::sync::doc_from_raw_answer` with two
  parse jobs in flight (`body_jobs`), then written with `index::ingest::upsert` in one transaction per 16 messages
  (the sync engine's `BATCH`) on the real SQLCipher writer connection. A fake server would hold the whole corpus in
  the benchmark process (about 2 GB of MIME), distort RSS and make the run take hours. What this leaves out (HTTP,
  gateway, scheduling) is measured separately by `bench_sync_through_fake_google`, which runs the full engine
  (`sync_account`: list, fetch, parse, commit, publish) against `tests/support/fake_google.rs` on 10k messages.
  Corpus generation is timed and excluded from the ingest rate.
* **Queries** run twice: through `mcp::call_tool` (authorization, deadline, audit record: the "at the service" time of
  spec 8.1) and over loopback HTTP with the real MCP layer (end to end, with response bytes). "First call" is the
  first call after restarting the `App` over the same data directory (empty SQLite page caches, warm OS page cache;
  the OS cache is not dropped because that needs root). p50/p95 are over 20 to 100 warm repetitions after 3 warm-ups.
  The run asserts zero Gmail calls for all of them.
* **RSS** is read from `/proc/self/status` (`VmRSS`, and `VmHWM` reset per phase through `clear_refs`). It is the
  whole benchmark process: index, state store, HTTP server and client, the fake Google server and the test harness
  (about 20 MiB when idle). Container memory (page cache) is not measured.
* **Not measured:** the live Gmail escape hatch (needs a real or latency-modelled upstream), sync lag, PDF/DOCX
  attachment text (the corpus has plain-text and CSV attachment text plus binary images), real Gmail quota (only the
  call counts of the fake run), cold OS cache.

## Corpus

250k messages, 8.1 KiB average raw (about 2 GB in total) with a skewed size distribution (60 % up to about 1.5 KB of
text, 30 % up to 8 KB, 9 % up to 40 KB, 1 % up to about 200 KB; the body index stops at `max_body_chars`). Words are
Zipf distributed (30k word vocabulary); the terms the queries use appear in a known share of the mail: `project` 25 %,
`meeting` 12 %, `invoice` 4 %, `budget` 2 %, `quarterly` 0.4 %, `zebrafish` in about 27 messages. Senders are Zipf
distributed over 5000 contacts, plus newsletters (15 % of threads, with `List-Unsubscribe`) and no-reply
notifications (10 %); 50 % of the threads are single messages, the rest have 2 to 40 messages with replies from the
mailbox itself. Dates span five years with a mild recency skew (about 1.4 % of mail is under a week old). Labels: INBOX,
UNREAD (about 25 % of inbox mail), SENT, STARRED, IMPORTANT, category labels, and 120 user labels with a Zipf
distribution, 0 to 3 per message. 12 % of messages carry an attachment (text, CSV or a binary image); about 10 % of the
CSV attachments contain the term `ledgerline`. About a third of the mail has an HTML part (newsletters mostly HTML only). Mailbox sizes
follow a Zipf curve (25 mailboxes: 48,854 down to 3,719 messages).

## Results

### Ingest, disk, memory (250k messages)

| | 1 mailbox | 5 mailboxes | 25 mailboxes |
|---|--:|--:|--:|
| ingest rate (parse + commit, no generation) | 386 msg/s | 409 msg/s | 477 msg/s |
| ingest wall time | 692 s | 655 s | 567 s |
| process CPU while ingesting | 0.8 cores | 0.8 cores | 0.8 cores |
| index on disk after checkpoint | 1103 MiB | 1112 MiB | 1134 MiB |
| per 1000 messages | 4.4 MiB | 4.4 MiB | 4.5 MiB |
| peak RSS during ingest | 64 MiB | 63 MiB | 76 MiB |
| peak RSS, warm sequential queries | 158 MiB | 125 MiB | 229 MiB |
| peak RSS, 4 concurrent clients | 175 MiB | 171 MiB | 260 MiB |
| peak RSS, queries during live ingest | 177 MiB | 231 MiB | 323 MiB |

The rate falls as the index grows (835 msg/s for the first 3,000 messages): about 90 % of the time is the transaction
(FTS postings, address, label and attachment rows), parsing is about 10 %. Through the fake Google server the full
sync engine indexed 10,000 messages in 5 mailboxes at 534 msg/s (18.7 s, 1.0 cores, 23 `messages.list` and 10,000
`messages.get` calls, which is 50,115 quota units at 5 units per call). Backfill speed in production is therefore
bounded by Gmail's per-user rate limit (250 quota units per second when this was written, so about 50 messages per
second and more than 80 minutes for 250k; check the current Gmail API limits), not by Dove's ingest.

RSS: the provisional steady goal of 256 MiB (8.1a) holds for sequential queries at every size (229 MiB at 25
mailboxes, which includes about 20 MiB of harness), is exceeded briefly with four concurrent clients (260 MiB) and
with queries running during ingest (323 MiB). All stay far below the 512 MiB container limit. Ingest stays under
80 MiB; the peaks of the query phase (125 to 229 MiB) do not follow the number of mailboxes monotonically and their
cause was not investigated.

### Latency at 25 mailboxes (250k messages)

Warm, top 20 rows, `select` of ref, received_at, from, subject, snippet. ✔ = p95 within the 8.1 target, ✘ = missed.
"Service" columns are `mcp::call_tool`, "HTTP p95" is end to end over loopback. The `count` and `subject` rows come
from a second run with 5 repetitions (the first run asked for the count without a lag allowance, which the benchmark
has no sync scheduler to satisfy, and used a subject term that is not in the corpus).

| query | rows | first call (ms) | p50 (ms) | p95 (ms) | HTTP p95 (ms) | response bytes | target p95 (ms) |
|---|--:|--:|--:|--:|--:|--:|--:|
| unread inbox, newest 20 | 20 | 3549.6 | 319.3 | 344.1 ✘ | 328.0 | 11654 | 100 |
| from the most frequent sender | 20 | 152.1 | 133.9 | 143.1 ✘ | 148.4 | 11420 | 100 |
| from a mid-frequency sender | 20 | 4.5 | 4.6 | 5.6 ✔ | 7.5 | 11524 | 100 |
| from a rare sender | 4 | 4.5 | 3.5 | 4.5 ✔ | 6.0 | 2976 | 100 |
| from_domain of a newsletter sender | 20 | 9.8 | 4.6 | 5.6 ✔ | 8.1 | 11250 | 100 |
| label Label_10 (frequent user label) | 20 | 214.0 | 207.0 | 216.0 ✘ | 215.2 | 11788 | 100 |
| label Label_100 (rare user label) | 20 | 15.3 | 4.5 | 5.8 ✔ | 6.9 | 11740 | 100 |
| label Label_12 and last 30 days | 20 | 115.2 | 108.6 | 121.0 ✘ | 119.3 | 11672 | 100 |
| has attachment, last year | 20 | 4.7 | 4.2 | 4.7 ✔ | 6.2 | 11822 | 100 |
| starred | 20 | 37.2 | 54.6 | 63.7 ✔ | 68.8 | 11776 | 100 |
| sent by self | 20 | 476.1 | 325.8 | 338.2 ✘ | 347.0 | 11688 | 100 |
| newsletters (category) | 20 | 580.1 | 513.8 | 542.9 ✘ | 532.4 | 11454 | 100 |
| count: unread inbox | 39297 | 314.4 | 305.4 | 338.7 ✘ | 323.6 | 800 | 100 |
| text: project (about 25 % of mail) | 20 | 361.5 | 286.8 | 299.4 ✘ | 301.5 | 11644 | 250 |
| text: meeting (about 12 %) | 20 | 262.1 | 216.2 | 227.5 ✔ | 245.5 | 11922 | 250 |
| text: invoice (about 4 %) | 20 | 159.4 | 122.2 | 127.7 ✔ | 133.5 | 11694 | 250 |
| text: quarterly (about 0.4 %) | 20 | 65.2 | 9.4 | 11.2 ✔ | 12.7 | 11786 | 250 |
| text: zebrafish (about 27 messages) | 20 | 50.2 | 7.5 | 9.4 ✔ | 11.1 | 11782 | 250 |
| text: project AND meeting | 20 | 111.5 | 111.3 | 119.1 ✔ | 121.2 | 11678 | 250 |
| text: project, INBOX, last 90 days | 20 | 347.4 | 316.5 | 331.1 ✘ | 332.4 | 11764 | 250 |
| text: invoice, from a frequent sender | 20 | 102.1 | 127.6 | 137.6 ✔ | 137.9 | 11652 | 250 |
| subject: baba (most frequent word) | 20 | 603.5 | 363.8 | 373.1 ✘ | 360.6 | 12032 | 250 |
| attachment_text: ledgerline | 20 | 541.2 | 521.5 | 556.0 ✘ | 565.4 | 11818 | 250 |
| text: prefix proj* | 20 | 288.7 | 282.8 | 295.6 ✘ | 293.5 | 11644 | 250 |
| group_by thread, newest 20 | 20 | 4097.9 | 2473.8 | 2558.4 | 2542.5 | 6342 | - |
| group_by thread, INBOX | 20 | 1920.0 | 1945.8 | 2049.2 | 2015.9 | 5618 | - |
| group_by thread, awaiting_reply | 20 | 1980.3 | 1917.8 | 1999.1 | 1994.3 | 4410 | - |
| group_by thread, text: project | 20 | 1468.6 | 1407.2 | 1467.2 | 1453.5 | 3374 | - |
| digest last 7 days, INBOX | 20 | 217.5 | 59.6 | 70.8 | 70.2 | 18512 | - |
| digest last 30 days, newsletters | 20 | 584.3 | 554.6 | 587.3 | 582.6 | 18182 | - |
| digest last 365 days | 20 | 536.3 | 312.5 | 324.6 | 335.9 | 18512 | - |
| search_contacts: ann | 20 | 2430.7 | 2302.8 | 2406.3 | 2355.8 | 14357 | - |
| search_contacts: schmidt | 20 | 1912.6 | 1945.6 | 2029.6 | 1979.5 | 15475 | - |
| search_contacts: no query (top) | 20 | 2012.1 | 2038.9 | 2118.6 | 2073.3 | 15425 | - |
| select: subject only | 20 | 3.4 | 3.5 | 5.1 | 6.2 | 2120 | - |
| select: default | 20 | 2.8 | 3.9 | 4.4 | 6.1 | 7310 | - |
| select: detail | 20 | 5.2 | 4.6 | 5.0 | 6.4 | 16976 | - |

Concurrent (4 clients looping over ten of these queries, 25 mailboxes): p95 of the structured queries 818 ms, of the
FTS queries 771 ms, of everything 2.4 s, 5 calls/s in total; queries during a 20,000-message ingest: structured p50
166 ms / p95 368 ms.

### p95 by number of mailboxes (same 250k messages, ms)

| query | 1 mailbox | 5 mailboxes | 25 mailboxes | target |
|---|--:|--:|--:|--:|
| unread inbox, newest 20 | 327.5 | 334.7 | 344.1 | 100 |
| from the most frequent sender | 137.4 | 139.2 | 143.1 | 100 |
| from a mid-frequency sender | 3.7 | 4.0 | 5.6 | 100 |
| from a rare sender | 2.9 | 3.4 | 4.5 | 100 |
| from_domain of a newsletter sender | 4.0 | 4.9 | 5.6 | 100 |
| label Label_10 (frequent user label) | 224.1 | 222.7 | 216.0 | 100 |
| label Label_100 (rare user label) | 4.0 | 4.0 | 5.8 | 100 |
| label Label_12 and last 30 days | 120.0 | 117.4 | 121.0 | 100 |
| has attachment, last year | 2.9 | 3.7 | 4.7 | 100 |
| starred | 59.1 | 58.2 | 63.7 | 100 |
| sent by self | 333.8 | 336.3 | 338.2 | 100 |
| newsletters (category) | 1459.3 | 1032.6 | 542.9 | 100 |
| count: unread inbox | - | - | 338.7 | 100 |
| text: project (about 25 % of mail) | 287.7 | 295.7 | 299.4 | 250 |
| text: meeting (about 12 %) | 227.0 | 220.4 | 227.5 | 250 |
| text: invoice (about 4 %) | 121.9 | 123.3 | 127.7 | 250 |
| text: quarterly (about 0.4 %) | 5.5 | 6.8 | 11.2 | 250 |
| text: zebrafish (about 27 messages) | 3.1 | 4.2 | 9.4 | 250 |
| text: project AND meeting | 102.7 | 106.9 | 119.1 | 250 |
| text: project, INBOX, last 90 days | 320.9 | 318.4 | 331.1 | 250 |
| text: invoice, from a frequent sender | 125.4 | 130.0 | 137.6 | 250 |
| subject: baba (most frequent word) | 358.4 | 371.8 | 373.1 | 250 |
| attachment_text: ledgerline | 1478.6 | 1043.1 | 556.0 | 250 |
| text: prefix proj* | 287.1 | 291.0 | 295.6 | 250 |
| group_by thread, newest 20 | 6328.6 | 4388.5 | 2558.4 | - |
| group_by thread, INBOX | 3655.2 | 2754.9 | 2049.2 | - |
| group_by thread, awaiting_reply | 4706.6 | 2653.2 | 1999.1 | - |
| group_by thread, text: project | 1995.4 | 1608.1 | 1467.2 | - |
| digest last 7 days, INBOX | 63.4 | 63.7 | 70.8 | - |
| digest last 30 days, newsletters | 1520.7 | 1100.5 | 587.3 | - |
| digest last 365 days | 591.1 | 407.6 | 324.6 | - |
| search_contacts: ann | 2276.1 | 2957.5 | 2406.3 | - |
| search_contacts: schmidt | 1771.3 | 2592.5 | 2029.6 | - |
| search_contacts: no query (top) | 3238.8 | 2709.5 | 2118.6 | - |
| select: subject only | 2.9 | 3.0 | 5.1 | - |
| select: default | 2.7 | 3.1 | 4.4 | - |
| select: detail | 4.4 | 3.3 | 5.0 | - |

The 1- and 5-mailbox runs used 20 warm repetitions at most and are not part of the table above; their count query
failed for the benchmark reason described there and is left out.

## Verdict against spec 8.1

* **Not met.** 12 of the 24 queries that have a 8.1 target miss it at 25 mailboxes, and the pattern is the same at 1
  and 5 mailboxes: the structured top-20 target (p95 ≤ 100 ms) is missed by unread-inbox (344 ms), sent-by-self
  (338 ms), newsletters (543 ms), the frequent label (216 ms), the frequent sender (143 ms) and count (339 ms); the FTS
  target (≤ 250 ms) by `project` (299 ms), `project` + INBOX + 90 days (331 ms), prefix `proj*` (296 ms), the most
  frequent subject word (373 ms) and `attachment_text` (556 ms). Queries on selective values (a rare sender, a rare
  label, a rare term, a domain, `has_attachment` in the last year) take 3 to 12 ms.
* **Not covered by a numeric target but slow:** `group_by:"thread"` takes 1.5 to 2.6 s, `search_contacts` about 2 s,
  and the digest over 30 days of newsletters 0.6 s at 25 mailboxes (the thread view and the digest are slower with fewer, larger mailboxes).
* Zero Gmail calls per indexed search: met (asserted for every query). Response bytes: subject-only 2.1 KB, default
  7.3 KB, detail 17.0 KB for 20 rows.
* Baseline RSS < 256 MiB: met for sequential queries, exceeded briefly under concurrency (see above). Peak backfill
  RSS: 76 MiB. Index size about 4.5 MiB per 1000 messages (1.1 GB for 250k).

## Cause

`EXPLAIN QUERY PLAN` (print it with `DOVE_BENCH_EXPLAIN=1`) shows the same shape for every slow search query:

```
SEARCH m USING INTEGER PRIMARY KEY (rowid=?)
LIST SUBQUERY 1
SEARCH labels USING PRIMARY KEY (label=? AND gen=?)
USE TEMP B-TREE FOR ORDER BY
```

(`unread inbox`; FTS queries have the same plan with a `COMPOUND QUERY` over the per-generation `fts_g<N>` tables, and
`from_self` with one `addrs_addr` probe per mailbox.) The planner builds the complete set of matching message ids,
fetches every row and sorts them by `received_at`, so the cost is proportional to the number of matches, not to the
page size. Times grow with the corpus (unread inbox took 91 ms at 50k messages and 320 ms at 250k, the frequent label 70 ms and
207 ms) and do not depend on the number of mailboxes (344, 335 and 328 ms at 25, 5 and 1). The fixed `sqlite_stat1` rows of
index migration V2 say that `labels(label, gen)` matches about 2,500 rows, so the plan is right for a rare value and
wrong for a frequent one; no static statistic can serve both. The opposite plan (walk `messages_recent` in order and
probe) is what makes predicates without an index slow: `category` and `attachment_text` walk the date index until 21
rows match (`SEARCH m USING INDEX messages_recent (spam_trash=?)`), so they cost 1/selectivity.

* The thread view runs `hit`, `tm` and `th` CTEs that aggregate every message of every matching thread before sorting
  (`USE TEMP B-TREE FOR GROUP BY`, `SEARCH m USING INDEX messages_size`): cost proportional to the whole mailbox.
* `search_contacts` aggregates the `addrs` rows of every message that matches.

## Not fixed here

These are design-level changes to the query compiler and the index schema, not a contained fix, and the planner and
cursor semantics are security-relevant, so they are reported rather than patched in a benchmark PR (PLAN A71). Options,
in the order of effect:

1. Pick the strategy per query from a bounded cardinality probe: count up to K (for example 2,000) matches of the most
   selective indexed predicate (label, address, FTS term); at or below K keep the current materialize-and-sort, above K
   walk `messages_recent` (or `messages_date` for one mailbox) and test the predicates with correlated `EXISTS`, which
   stops after `limit + 1` rows. Both paths need identical ordering and cursor keys; the existing contract tests and
   this benchmark's plan output check that.
2. A per-generation `threads` table maintained by ingest (thread id, newest time, count, last in/out), so the first
   page of the thread view is an index walk.
3. A per-generation contacts aggregate maintained by ingest (address, name, received, sent, first/last).
4. An index for `category` and one for attachment-text presence, or a bounded probe as in 1.
