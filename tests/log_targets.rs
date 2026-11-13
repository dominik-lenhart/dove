//! Content parsers quote untrusted input in their warnings (lopdf prints PDF font dictionaries, html5ever
//! complains about markup). Their events must never reach the service log, even at `DOVE_LOG=trace`.

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A one-page PDF whose trailer `/Size` is off by one, which lopdf reports through the `log` crate.
fn pdf_with_wrong_size() -> Vec<u8> {
    use lopdf::{Document, Object, dictionary};
    let mut doc = Document::with_version("1.5");
    let pages_id = doc.new_object_id();
    let page_id = doc.add_object(dictionary! {"Type" => "Page", "Parent" => pages_id});
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {"Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1}),
    );
    let catalog_id = doc.add_object(dictionary! {"Type" => "Catalog", "Pages" => pages_id});
    doc.trailer.set("Root", catalog_id);
    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap();
    let text = String::from_utf8_lossy(&out).into_owned();
    let at = text.rfind("/Size ").expect("trailer has /Size") + "/Size ".len();
    let end = at + text[at..].find(|c: char| !c.is_ascii_digit()).unwrap();
    let n: u32 = text[at..end].parse().unwrap();
    format!("{}{}{}", &text[..at], n + 1, &text[end..]).into_bytes()
}

#[test]
fn content_parser_warnings_never_reach_the_log() {
    let sink = Sink::default();
    assert!(dove::logging::install_service_logging(sink.clone(), tracing_subscriber::EnvFilter::new("trace")));

    // Through the `log` bridge: real warnings of the PDF and HTML parsers.
    let lim = dove::attachment_text::Limits {
        max_chars: 10_000,
        max_decompressed: 1 << 20,
        deadline: Instant::now() + Duration::from_secs(10),
    };
    let _ = dove::attachment_text::extract(&pdf_with_wrong_size(), dove::attachment_text::Kind::Pdf, &lim);
    let _ = dove::content::html_to_text("<table>CANARY-FOSTER-5d1e<tr><td>x</td></tr></table>");
    // Through tracing directly, as a dependency that uses tracing would log.
    tracing::warn!(target: "lopdf::reader", "CANARY-TRACING-8b2c");
    // Control: Dove's own events still arrive.
    tracing::warn!(target: "dove::index::sync", "control event");

    let log = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
    assert!(log.contains("control event"), "{log}");
    for needle in ["CANARY", "Size entry", "foster parenting", "lopdf", "html5ever"] {
        assert!(!log.contains(needle), "{needle} reached the log: {log}");
    }
}
