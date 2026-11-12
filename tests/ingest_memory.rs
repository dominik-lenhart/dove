//! Peak heap of indexing one raw Gmail answer (spec 8.1a: up to 32 MiB per body job). Measured with a counting
//! global allocator around the parse path the sync job runs after the capped download.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

struct Counting;
static CUR: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let n = CUR.fetch_add(l.size(), Relaxed) + l.size();
            PEAK.fetch_max(n, Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        CUR.fetch_sub(l.size(), Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, new) };
        if !q.is_null() {
            if new > l.size() {
                let n = CUR.fetch_add(new - l.size(), Relaxed) + (new - l.size());
                PEAK.fetch_max(n, Relaxed);
            } else {
                CUR.fetch_sub(l.size() - new, Relaxed);
            }
        }
        q
    }
}

#[global_allocator]
static A: Counting = Counting;

fn answer(raw_size: usize) -> (Vec<u8>, usize) {
    let text = "lorem ipsum dolor sit amet ".repeat(4000);
    let att = vec![7u8; raw_size.saturating_sub(text.len()) * 3 / 4];
    let raw = mail_builder::MessageBuilder::new()
        .from("a@example.com")
        .to("b@example.com")
        .subject("big")
        .text_body(text)
        .attachment("application/octet-stream", "blob.bin", att)
        .write_to_vec()
        .unwrap();
    let len = raw.len();
    let v = serde_json::json!({"id": "abc123", "threadId": "t1", "labelIds": ["INBOX"], "internalDate": "1",
        "sizeEstimate": len, "snippet": "s", "raw": dove::util::b64url(&raw)});
    let mut body = serde_json::to_vec(&v).unwrap();
    // The capped download allocates the declared length exactly.
    body.shrink_to_fit();
    (body, len)
}

/// Peak heap above the baseline while one job holds the downloaded body and indexes it.
fn peak_for(raw_size: usize, max_message_bytes: usize) -> (usize, usize, usize) {
    let (body, raw_len) = answer(raw_size);
    let body_len = body.len();
    let base = CUR.load(Relaxed) - body.capacity();
    PEAK.store(CUR.load(Relaxed), Relaxed);
    let doc = dove::index::sync::doc_from_raw_answer(body, max_message_bytes, 200_000).unwrap();
    assert!(doc.meta_complete, "parsed, not metadata-only");
    drop(doc);
    (raw_len, body_len, PEAK.load(Relaxed) - base)
}

/// A message just under the index limit stays within the 32 MiB per-job budget of spec 8.1a.
#[test]
fn a_message_at_the_index_limit_fits_the_job_budget() {
    let max = dove::config::IndexConfig::default().max_message_bytes;
    let (raw, body, peak) = peak_for(max - 1024 * 1024, max);
    assert!(raw <= max && body <= dove::index::sync::raw_response_cap(max), "{raw} {body}");
    assert!(peak <= 32 * 1024 * 1024, "peak {peak} bytes for a {raw}-byte message");
}

/// Peak heap per message size (`cargo test --test ingest_memory -- --ignored --nocapture`).
#[test]
#[ignore = "measurement"]
fn measure_peak_heap_per_body_job() {
    for mib in [4usize, 8, 12, 16, 21] {
        let (raw, body, peak) = peak_for(mib * 1024 * 1024, 22 * 1024 * 1024);
        println!("raw {:>9} B  body {:>9} B  peak {:>6.1} MiB", raw, body, peak as f64 / 1048576.0);
    }
}
