//! Fake Google server for integration tests (OAuth token endpoint, JWKS, allowlisted Gmail routes).
//!
//! Everything is served from one origin. Requests outside the exact allowlist (spec 7.5) are recorded as
//! violations and answered 403; call `assert_no_violations` at the end of a test.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// TEST-ONLY RSA-2048 private key (PKCS#1 DER, base64). Never used for anything real.
const TEST_KEY_DER_B64: &str = "MIIEowIBAAKCAQEAsf7xfWsI4ZUaH5rI0SfFoIh/9GWEc9Szm1sEXfVvzG+WN2EPtvmFB6BytZVpsEspIVCFfEEUjZUV6MLzqNjHRNV0VvD97wofVILlijQ0B0CCx90o+IW9oHIUoZ3rm43ro0jnb9WWbcJ1SlkhGzezCMsVuQLEfcB1f5JvTaTblC9F/AtjxAWRMwZ3YbjHzIWEMUzxCwCy2twLupqwxKw0z8h09hRvxOw6U6Q27QFZ3z934qO1mVAW1xkBcJ5VoBN98H69CFvvlFfi3EPcMpT2U3JA1RafYXOhHnFjmqe2eqpYv6qE0datn22QPuZfz28eUouU1o9vl2O8XrgcggQhRwIDAQABAoIBABh6B/2oszMeJ1ZS7oGV4rSAK3mmtM+e33H3fVgUW7g1B2b8fHDmICKGha+tvmJlUOB0Fl8aA02y7i0wvdlUB2xSSWoj6q+Ck1YHnVwOG1zR719fl3Y8IfGcg8oeZsYLKUJY0Kai1vRR/4IRU/ROX7AlCTWEtBOHh0DbQ14IfmotLqTKpduT7laQ9Hf1B4WHkoydbPeTGSv7MfuJi3iUtCpJ7m2xPXYp7CayxLK/nu7SPJ7L/6EoK1WKoUT0vrU28/0JJHflHhpO86wwtUMIw4GAPiJ/eloNcAjdzmY60xl+aW8NRMd9Lnt5SJFNeEwX870DajgzirFC5GRzvIqH6k0CgYEA2GyJKwh9xipGJ/BcVB8wF4PF4u9gwgUQyYN/AD1CgOAUnMzr9GEVuv9mPltT+79MTppHSqJ9RNGrU0RwoYfDjZagpuFDfXapjf50/uJUIv31KfxwVkHqzAKUeCgnbzij38xpse1uHlB5OMDf7asV2M4mb69x7zQXBrDU2b+0sAsCgYEA0ot4slUYQ45uYuTcNDO9K63zGslV2JfSDHlRL/gXCMfZz/ZNQjr0larADzQVnhBP7qzgjPY2uYZD25sIX5CAzQwhc4vGBpPWz4d3b9H7n1319TTp9msJ/M6fOns4WYEl3jC8sXI9rU0AR9VYI4kygb5i7D9Y/wq1ULgYlq1VbTUCgYEArxKFl5kj3WUfIXnPxoEAL1V6g8xu8iSU4t6Low7rOEOMiRdAHI1Yvc+SzwikFHc4bDFjUF3Hhh8yP4aSsiiYKXZa+QQqy1htap8X14QQ2cmkRFWgLjbekC/aGKUq2U7xSb4bFkLiHIWuuhlUS/dlEeAZuaksOnth0RjE5mys5ucCgYBFKTuEmR9XUbpBEhyjqTtC1ek9q1VfyL9fCZr5vu0SHVQXVDkcwHEHmQdt9xYCzijzpiY9J8PiPZCc2thtS/KDaLC0W/24u2ec1EsPmFKnjx30ZmVUZOTq/pSfiUqBXEMsMaZKQ9Su0NR+xD4nrjHBHOEx6b06SjI1ScQJ+vZM4QKBgAKO8iYWmO5o+Fz3YFPfRR/oLgbptHhioCyPX0yV/n88wwx5KpyTdbTGYawRjSAI3NDEG6YQ/SwvU6X4rxvlW0DfPPAnEvcPoEPmsau+6tmJqjghQlVvLjunlV2KRhRRL1Y8q6T162mfjDtZ8S85JZjk7PhnyCNfNpcStptCiTiO";
/// Matching public modulus (base64url, no padding). The exponent is 65537.
const TEST_KEY_N: &str = "sf7xfWsI4ZUaH5rI0SfFoIh_9GWEc9Szm1sEXfVvzG-WN2EPtvmFB6BytZVpsEspIVCFfEEUjZUV6MLzqNjHRNV0VvD97wofVILlijQ0B0CCx90o-IW9oHIUoZ3rm43ro0jnb9WWbcJ1SlkhGzezCMsVuQLEfcB1f5JvTaTblC9F_AtjxAWRMwZ3YbjHzIWEMUzxCwCy2twLupqwxKw0z8h09hRvxOw6U6Q27QFZ3z934qO1mVAW1xkBcJ5VoBN98H69CFvvlFfi3EPcMpT2U3JA1RafYXOhHnFjmqe2eqpYv6qE0datn22QPuZfz28eUouU1o9vl2O8XrgcggQhRw";
const TEST_KEY_E: &str = "AQAB";
const KID: &str = "fake-google-key-1";
const SYSTEM_LABELS: [&str; 8] = ["INBOX", "SENT", "DRAFT", "SPAM", "TRASH", "UNREAD", "STARRED", "IMPORTANT"];

#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub mailbox: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CodeSpec {
    pub email: String,
    pub sub: String,
    pub email_verified: bool,
    pub scopes: Vec<String>,
    pub code_challenge: String,
    pub aud: Option<String>,
    pub with_refresh_token: bool,
}

#[derive(Default, Clone)]
pub struct MessageSpec {
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub labels: Vec<String>,
    pub thread_id: Option<String>,
    pub internal_date_ms: i64,
    /// (filename, mime, bytes)
    pub attachments: Vec<(String, String, Vec<u8>)>,
    pub raw: Option<Vec<u8>>,
    pub message_id_header: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Option<String>,
}

pub enum Fault {
    /// Answer with this status and JSON body without applying the request.
    Status(u16, Value),
    /// Sleep, then handle normally.
    Delay(Duration),
    /// Apply the request, then never answer (the client must time out).
    DropAfterApply,
}

#[derive(Clone)]
struct Msg {
    id: String,
    thread_id: String,
    labels: Vec<String>,
    raw: Vec<u8>,
    internal_date: i64,
    history_id: u64,
    seq: u64,
}

#[derive(Default)]
struct Rec {
    id: u64,
    added: Vec<Value>,
    deleted: Vec<Value>,
    labels_added: Vec<Value>,
    labels_removed: Vec<Value>,
}

struct Mailbox {
    email: String,
    sub: String,
    messages: Vec<Msg>,
    drafts: Vec<(String, String)>,
    user_labels: Vec<String>,
    history_id: u64,
    history: Vec<Rec>,
    history_floor: u64,
    send_as: Vec<String>,
    sent: Vec<String>,
}

struct RefreshToken {
    email: String,
    valid: bool,
}

struct CodeEntry {
    spec: CodeSpec,
    used: bool,
}

struct Inner {
    client_id: String,
    client_secret: String,
    base_url: String,
    mailboxes: BTreeMap<String, Mailbox>,
    codes: HashMap<String, CodeEntry>,
    refresh: HashMap<String, RefreshToken>,
    revoked: Vec<String>,
    access: HashMap<String, String>,
    requests: Vec<RecordedRequest>,
    violations: Vec<String>,
    faults: Vec<(String, String, Fault)>,
    counter: u64,
}

pub struct FakeGoogle {
    pub base_url: String,
    pub client_id: String,
    pub client_secret: String,
    inner: Arc<Mutex<Inner>>,
}

type Resp = (u16, Value);

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

fn rand_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    getrandom::fill(&mut b).unwrap();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn gmail_err(code: u16, status: &str) -> Resp {
    (code, json!({"error": {"code": code, "status": status}}))
}

fn oauth_err(code: u16, err: &str) -> Resp {
    (code, json!({"error": err}))
}

fn b64u(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn decode_raw(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

fn build_raw(m: &MessageSpec) -> Vec<u8> {
    use mail_builder::MessageBuilder;
    let date_ms = if m.internal_date_ms == 0 { now_ms() } else { m.internal_date_ms };
    let mut b = MessageBuilder::new().from(m.from.clone()).subject(m.subject.clone()).date(date_ms / 1000);
    if !m.to.is_empty() {
        b = b.to(m.to.clone());
    }
    if !m.cc.is_empty() {
        b = b.cc(m.cc.clone());
    }
    if !m.bcc.is_empty() {
        b = b.bcc(m.bcc.clone());
    }
    let strip = |s: &str| s.trim().trim_start_matches('<').trim_end_matches('>').to_string();
    if let Some(v) = &m.message_id_header {
        b = b.message_id(strip(v));
    }
    if let Some(v) = &m.in_reply_to {
        b = b.in_reply_to(strip(v));
    }
    if let Some(v) = &m.references {
        let ids: Vec<String> = v.split_whitespace().map(strip).collect();
        b = b.references(ids);
    }
    if let Some(t) = &m.text {
        b = b.text_body(t.clone());
    }
    if let Some(h) = &m.html {
        b = b.html_body(h.clone());
    }
    if m.text.is_none() && m.html.is_none() {
        b = b.text_body(String::new());
    }
    for (name, mime, bytes) in &m.attachments {
        b = b.attachment(mime.clone(), name.clone(), bytes.clone());
    }
    b.write_to_vec().unwrap()
}

fn parsed_text(raw: &[u8]) -> String {
    let Some(msg) = mail_parser::MessageParser::default().parse(raw) else {
        return String::new();
    };
    let mut out = String::new();
    for t in msg.text_bodies() {
        out.push_str(&t);
        out.push('\n');
    }
    out
}

fn snippet(raw: &[u8]) -> String {
    let t = parsed_text(raw);
    let flat: Vec<&str> = t.split_whitespace().collect();
    flat.join(" ").chars().take(100).collect()
}

fn header_value(raw: &[u8], name: &str) -> String {
    let text = String::from_utf8_lossy(raw);
    let head = text.split("\r\n\r\n").next().unwrap_or("");
    let head = head.split("\n\n").next().unwrap_or(head);
    for line in head.lines() {
        if let Some((n, v)) = line.split_once(':')
            && n.eq_ignore_ascii_case(name)
        {
            return v.trim().to_string();
        }
    }
    String::new()
}

fn msg_ref(m: &Msg) -> Value {
    json!({"id": m.id, "threadId": m.thread_id})
}

fn msg_with_labels(m: &Msg) -> Value {
    json!({"id": m.id, "threadId": m.thread_id, "labelIds": m.labels})
}

fn msg_json(m: &Msg, with_raw: bool) -> Value {
    let mut v = json!({
        "id": m.id,
        "threadId": m.thread_id,
        "labelIds": m.labels,
        "snippet": snippet(&m.raw),
        "historyId": m.history_id.to_string(),
        "internalDate": m.internal_date.to_string(),
        "sizeEstimate": m.raw.len(),
    });
    if with_raw {
        v["raw"] = Value::String(b64u(&m.raw));
    }
    v
}

impl Mailbox {
    fn new(email: &str, sub: &str) -> Self {
        Mailbox {
            email: email.to_string(),
            sub: sub.to_string(),
            messages: vec![],
            drafts: vec![],
            user_labels: vec![],
            history_id: 1000,
            history: vec![],
            history_floor: 0,
            send_as: vec![],
            sent: vec![],
        }
    }

    fn new_rec(&mut self) -> Rec {
        self.history_id += 1;
        Rec { id: self.history_id, ..Default::default() }
    }

    fn resolve_label(&mut self, name: &str) -> String {
        if SYSTEM_LABELS.contains(&name) {
            return name.to_string();
        }
        if let Some(i) = self.user_labels.iter().position(|l| l == name) {
            return format!("Label_{}", i + 1);
        }
        if let Some(n) = name.strip_prefix("Label_").and_then(|n| n.parse::<usize>().ok())
            && (1..=self.user_labels.len()).contains(&n)
        {
            return name.to_string();
        }
        self.user_labels.push(name.to_string());
        format!("Label_{}", self.user_labels.len())
    }

    fn lookup_label(&self, name: &str) -> String {
        if let Some(i) = self.user_labels.iter().position(|l| l == name) {
            return format!("Label_{}", i + 1);
        }
        name.to_string()
    }

    fn thread_exists(&self, t: &str) -> bool {
        self.messages.iter().any(|m| m.thread_id == t)
    }

    fn insert(
        &mut self,
        rec: &Rec,
        c: &mut u64,
        thread: Option<String>,
        labels: Vec<String>,
        raw: Vec<u8>,
        date: i64,
    ) -> Msg {
        *c += 1;
        let m = Msg {
            id: rand_hex(8),
            thread_id: thread.unwrap_or_else(|| rand_hex(8)),
            labels,
            raw,
            internal_date: date,
            history_id: rec.id,
            seq: *c,
        };
        self.messages.push(m.clone());
        m
    }

    fn find(&self, id: &str) -> Option<&Msg> {
        self.messages.iter().find(|m| m.id == id)
    }

    fn remove_msg(&mut self, id: &str) -> Option<Msg> {
        let i = self.messages.iter().position(|m| m.id == id)?;
        Some(self.messages.remove(i))
    }

    fn add_message(&mut self, c: &mut u64, spec: MessageSpec) -> String {
        let raw = spec.raw.clone().unwrap_or_else(|| build_raw(&spec));
        let labels: Vec<String> = spec.labels.iter().map(|l| self.resolve_label(l)).collect();
        let date = if spec.internal_date_ms == 0 { now_ms() } else { spec.internal_date_ms };
        let mut rec = self.new_rec();
        let m = self.insert(&rec, c, spec.thread_id, labels, raw, date);
        rec.added.push(msg_with_labels(&m));
        self.history.push(rec);
        m.id
    }

    fn delete_message(&mut self, id: &str) {
        let m = self.remove_msg(id).unwrap_or_else(|| panic!("no message {id}"));
        let mut rec = self.new_rec();
        rec.deleted.push(msg_ref(&m));
        self.history.push(rec);
        self.drafts.retain(|(_, mid)| mid != id);
    }

    fn set_labels(&mut self, id: &str, add: &[&str], remove: &[&str]) {
        let add: Vec<String> = add.iter().map(|l| self.resolve_label(l)).collect();
        let remove: Vec<String> = remove.iter().map(|l| self.lookup_label(l)).collect();
        let mut rec = self.new_rec();
        let hid = rec.id;
        let m = self.messages.iter_mut().find(|m| m.id == id).unwrap_or_else(|| panic!("no message {id}"));
        let added: Vec<String> = add.into_iter().filter(|l| !m.labels.contains(l)).collect();
        m.labels.extend(added.iter().cloned());
        let removed: Vec<String> = remove.into_iter().filter(|l| m.labels.contains(l)).collect();
        m.labels.retain(|l| !removed.contains(l));
        m.history_id = hid;
        let mv = msg_with_labels(m);
        if !added.is_empty() {
            rec.labels_added.push(json!({"message": mv, "labelIds": added}));
        }
        if !removed.is_empty() {
            rec.labels_removed.push(json!({"message": mv, "labelIds": removed}));
        }
        self.history.push(rec);
    }

    fn create_draft(&mut self, c: &mut u64, raw: Vec<u8>, thread: Option<String>) -> (String, Msg) {
        let thread = thread.filter(|t| self.thread_exists(t));
        let mut rec = self.new_rec();
        let m = self.insert(&rec, c, thread, vec!["DRAFT".into()], raw, now_ms());
        rec.added.push(msg_with_labels(&m));
        self.history.push(rec);
        let did = rand_hex(8);
        self.drafts.push((did.clone(), m.id.clone()));
        (did, m)
    }

    /// Replace a draft's message with a new message id. Returns None if the draft is unknown.
    fn replace_draft(&mut self, c: &mut u64, did: &str, raw: Vec<u8>, thread: Option<String>) -> Option<Msg> {
        let idx = self.drafts.iter().position(|(d, _)| d == did)?;
        let old_id = self.drafts[idx].1.clone();
        let old = self.remove_msg(&old_id)?;
        let thread = thread.filter(|t| self.thread_exists(t)).or(Some(old.thread_id.clone()));
        let mut rec = self.new_rec();
        rec.deleted.push(msg_ref(&old));
        let m = self.insert(&rec, c, thread, vec!["DRAFT".into()], raw, now_ms());
        rec.added.push(msg_with_labels(&m));
        self.history.push(rec);
        self.drafts[idx].1 = m.id.clone();
        Some(m)
    }

    fn delete_draft(&mut self, did: &str) -> bool {
        let Some(idx) = self.drafts.iter().position(|(d, _)| d == did) else {
            return false;
        };
        let (_, mid) = self.drafts.remove(idx);
        if let Some(m) = self.remove_msg(&mid) {
            let mut rec = self.new_rec();
            rec.deleted.push(msg_ref(&m));
            self.history.push(rec);
        }
        true
    }

    fn send_draft(&mut self, did: &str) -> Option<Msg> {
        let idx = self.drafts.iter().position(|(d, _)| d == did)?;
        let (_, mid) = self.drafts.remove(idx);
        let mut rec = self.new_rec();
        let hid = rec.id;
        let m = self.messages.iter_mut().find(|m| m.id == mid)?;
        m.labels.retain(|l| l != "DRAFT");
        m.labels.push("SENT".into());
        m.history_id = hid;
        let mv = msg_with_labels(m);
        rec.labels_removed.push(json!({"message": mv, "labelIds": ["DRAFT"]}));
        rec.labels_added.push(json!({"message": mv, "labelIds": ["SENT"]}));
        let out = m.clone();
        self.history.push(rec);
        self.sent.push(mid);
        Some(out)
    }
}

fn rec_json(r: &Rec) -> Value {
    let mut seen: Vec<String> = vec![];
    let mut messages = vec![];
    let all = r
        .added
        .iter()
        .chain(r.deleted.iter())
        .chain(r.labels_added.iter().map(|v| &v["message"]))
        .chain(r.labels_removed.iter().map(|v| &v["message"]));
    for m in all {
        let id = m["id"].as_str().unwrap().to_string();
        if !seen.contains(&id) {
            seen.push(id);
            messages.push(json!({"id": m["id"], "threadId": m["threadId"]}));
        }
    }
    let mut v = json!({"id": r.id.to_string(), "messages": messages});
    if !r.added.is_empty() {
        v["messagesAdded"] = Value::Array(r.added.iter().map(|m| json!({"message": m})).collect());
    }
    if !r.deleted.is_empty() {
        v["messagesDeleted"] = Value::Array(r.deleted.iter().map(|m| json!({"message": m})).collect());
    }
    if !r.labels_added.is_empty() {
        v["labelsAdded"] = Value::Array(r.labels_added.clone());
    }
    if !r.labels_removed.is_empty() {
        v["labelsRemoved"] = Value::Array(r.labels_removed.clone());
    }
    v
}

struct Query(Vec<(String, String)>);

impl Query {
    fn parse(s: &str) -> Self {
        Query(url::form_urlencoded::parse(s.as_bytes()).into_owned().collect())
    }
    fn get(&self, k: &str) -> Option<&str> {
        self.0.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
    fn all(&self, k: &str) -> Vec<&str> {
        self.0.iter().filter(|(n, _)| n == k).map(|(_, v)| v.as_str()).collect()
    }
    fn usize(&self, k: &str, default: usize) -> usize {
        self.get(k).and_then(|v| v.parse().ok()).unwrap_or(default)
    }
}

fn page(total: usize, q: &Query, default_max: usize, max: usize) -> (usize, usize) {
    let start = q.get("pageToken").and_then(|t| t.parse::<usize>().ok()).unwrap_or(0).min(total);
    let n = q.usize("maxResults", default_max).clamp(1, max);
    (start, (start + n).min(total))
}

fn matches_q(m: &Msg, terms: &[String]) -> bool {
    let hay = format!("{}\n{}", String::from_utf8_lossy(&m.raw), parsed_text(&m.raw)).to_lowercase();
    let from = header_value(&m.raw, "from").to_lowercase();
    terms.iter().all(|t| match t.strip_prefix("from:") {
        Some(a) => from.contains(a),
        None => hay.contains(t),
    })
}

impl Inner {
    fn next_id_counter(&mut self) -> &mut u64 {
        &mut self.counter
    }

    fn bearer_email(&self, auth: Option<&str>) -> Option<String> {
        let tok = auth?.strip_prefix("Bearer ")?;
        self.access.get(tok).cloned()
    }

    fn mint_access(&mut self, email: &str) -> String {
        let t = format!("ya29.fake-{}", rand_hex(16));
        self.access.insert(t.clone(), email.to_string());
        t
    }

    fn issue_refresh(&mut self, email: &str) -> String {
        let t = format!("1//fake-{}", rand_hex(16));
        self.refresh.insert(t.clone(), RefreshToken { email: email.to_string(), valid: true });
        t
    }

    fn sign_id_token(&self, spec: &CodeSpec) -> String {
        let now = (now_ms() / 1000) as u64;
        let claims = json!({
            "iss": "https://accounts.google.com",
            "aud": spec.aud.clone().unwrap_or_else(|| self.client_id.clone()),
            "sub": spec.sub,
            "email": spec.email,
            "email_verified": spec.email_verified,
            "iat": now,
            "exp": now + 3600,
        });
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(KID.to_string());
        let der = STANDARD.decode(TEST_KEY_DER_B64).unwrap();
        jsonwebtoken::encode(&header, &claims, &jsonwebtoken::EncodingKey::from_rsa_der(&der)).unwrap()
    }

    fn token_endpoint(&mut self, form: &Query) -> Resp {
        match form.get("grant_type") {
            Some("authorization_code") => {
                let (Some(code), Some(verifier), Some(cid), Some(secret), Some(_redirect)) = (
                    form.get("code"),
                    form.get("code_verifier"),
                    form.get("client_id"),
                    form.get("client_secret"),
                    form.get("redirect_uri"),
                ) else {
                    return oauth_err(400, "invalid_request");
                };
                if cid != self.client_id || secret != self.client_secret {
                    return oauth_err(400, "invalid_grant");
                }
                let Some(entry) = self.codes.get(code) else {
                    return oauth_err(400, "invalid_grant");
                };
                if entry.used {
                    return oauth_err(400, "invalid_grant");
                }
                let challenge = b64u(&Sha256::digest(verifier.as_bytes()));
                if challenge != entry.spec.code_challenge {
                    return oauth_err(400, "invalid_grant");
                }
                let spec = entry.spec.clone();
                self.codes.get_mut(code).unwrap().used = true;
                let access = self.mint_access(&spec.email);
                let mut body = json!({
                    "access_token": access,
                    "expires_in": 3599,
                    "scope": spec.scopes.join(" "),
                    "token_type": "Bearer",
                    "id_token": self.sign_id_token(&spec),
                });
                if spec.with_refresh_token {
                    body["refresh_token"] = Value::String(self.issue_refresh(&spec.email));
                }
                (200, body)
            }
            Some("refresh_token") => {
                if form.get("client_id") != Some(self.client_id.as_str())
                    || form.get("client_secret") != Some(self.client_secret.as_str())
                {
                    return oauth_err(401, "invalid_client");
                }
                let Some(rt) = form.get("refresh_token").and_then(|t| self.refresh.get(t)) else {
                    return oauth_err(400, "invalid_grant");
                };
                if !rt.valid {
                    return oauth_err(400, "invalid_grant");
                }
                let email = rt.email.clone();
                let access = self.mint_access(&email);
                (
                    200,
                    json!({"access_token": access, "expires_in": 3599, "token_type": "Bearer", "scope": "openid email https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.compose"}),
                )
            }
            _ => oauth_err(400, "unsupported_grant_type"),
        }
    }

    fn revoke(&mut self, form: &Query) -> Resp {
        if let Some(t) = form.get("token") {
            if let Some(rt) = self.refresh.get_mut(t) {
                rt.valid = false;
            }
            self.revoked.push(t.to_string());
        }
        (200, json!({}))
    }

    fn dispatch(&mut self, method: &str, path: &str, query: &str, auth: Option<&str>, body: &[u8]) -> Resp {
        let q = Query::parse(query);
        let gmail_rest = path.strip_prefix("/gmail/v1/users/me/");
        let allowed = match (method, path, gmail_rest) {
            ("POST", "/token", _) | ("POST", "/revoke", _) | ("GET", "/oauth2/v3/certs", _) => true,
            (_, _, Some(rest)) => {
                let segs: Vec<&str> = rest.split('/').collect();
                matches!(
                    (method, segs.as_slice()),
                    ("GET", ["profile" | "labels" | "messages" | "history" | "drafts"])
                        | ("GET", ["messages" | "threads" | "drafts", _])
                        | ("GET", ["settings", "sendAs"])
                        | ("POST", ["drafts"])
                        | ("PUT", ["drafts", _])
                        | ("POST", ["drafts", "send"])
                ) && segs.iter().all(|s| !s.is_empty())
            }
            _ => false,
        };
        if !allowed {
            self.violations.push(format!("{method} {path}"));
            return (403, json!({"error": {"code": 403, "message": "fake-google: request outside allowlist"}}));
        }
        match (method, path) {
            ("POST", "/token") => return self.token_endpoint(&Query::parse(&String::from_utf8_lossy(body))),
            ("POST", "/revoke") => return self.revoke(&Query::parse(&String::from_utf8_lossy(body))),
            ("GET", "/oauth2/v3/certs") => {
                return (
                    200,
                    json!({"keys": [{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": KID, "n": TEST_KEY_N, "e": TEST_KEY_E}]}),
                );
            }
            _ => {}
        }
        let Some(email) = self.bearer_email(auth).filter(|e| self.mailboxes.contains_key(e)) else {
            return gmail_err(401, "UNAUTHENTICATED");
        };
        let rest = gmail_rest.unwrap();
        let segs: Vec<&str> = rest.split('/').collect();
        let mut counter = self.counter;
        let out = {
            let mb = self.mailboxes.get_mut(&email).unwrap();
            gmail(mb, &mut counter, method, &segs, &q, body)
        };
        self.counter = counter;
        out
    }
}

fn not_found() -> Resp {
    (404, json!({"error": {"code": 404, "status": "NOT_FOUND"}}))
}

fn bad_request() -> Resp {
    (400, json!({"error": {"code": 400, "status": "INVALID_ARGUMENT"}}))
}

fn draft_body(body: &[u8]) -> Option<(Vec<u8>, Option<String>)> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let raw = decode_raw(v["message"]["raw"].as_str()?)?;
    Some((raw, v["message"]["threadId"].as_str().map(String::from)))
}

fn gmail(mb: &mut Mailbox, c: &mut u64, method: &str, segs: &[&str], q: &Query, body: &[u8]) -> Resp {
    let full_raw = |f: Option<&str>| matches!(f, None | Some("raw") | Some("full"));
    match (method, segs) {
        ("GET", ["profile"]) => {
            let mut threads: Vec<&str> = mb.messages.iter().map(|m| m.thread_id.as_str()).collect();
            threads.sort();
            threads.dedup();
            (
                200,
                json!({
                    "emailAddress": mb.email,
                    "messagesTotal": mb.messages.len(),
                    "threadsTotal": threads.len(),
                    "historyId": mb.history_id.to_string(),
                }),
            )
        }
        ("GET", ["labels"]) => {
            let mut labels: Vec<Value> =
                SYSTEM_LABELS.iter().map(|l| json!({"id": l, "name": l, "type": "system"})).collect();
            for (i, n) in mb.user_labels.iter().enumerate() {
                labels.push(json!({"id": format!("Label_{}", i + 1), "name": n, "type": "user"}));
            }
            (200, json!({"labels": labels}))
        }
        ("GET", ["messages"]) => {
            let want: Vec<String> = q.all("labelIds").iter().map(|l| mb.lookup_label(l)).collect();
            let include_spam = q.get("includeSpamTrash") == Some("true");
            let terms: Vec<String> = q.get("q").unwrap_or("").split_whitespace().map(|t| t.to_lowercase()).collect();
            let mut hits: Vec<&Msg> = mb
                .messages
                .iter()
                .filter(|m| {
                    let hidden = ["SPAM", "TRASH"]
                        .iter()
                        .any(|h| m.labels.iter().any(|l| l == h) && !want.iter().any(|w| w == h));
                    (include_spam || !hidden) && want.iter().all(|w| m.labels.contains(w)) && matches_q(m, &terms)
                })
                .collect();
            hits.sort_by_key(|m| std::cmp::Reverse((m.internal_date, m.seq)));
            let (s, e) = page(hits.len(), q, 100, 500);
            let mut out = json!({"resultSizeEstimate": hits.len()});
            if !hits.is_empty() {
                out["messages"] = Value::Array(hits[s..e].iter().map(|m| msg_ref(m)).collect());
            }
            if e < hits.len() {
                out["nextPageToken"] = Value::String(e.to_string());
            }
            (200, out)
        }
        ("GET", ["messages", id]) => match mb.find(id) {
            Some(m) => (200, msg_json(m, full_raw(q.get("format")))),
            None => not_found(),
        },
        ("GET", ["threads", id]) => {
            let mut ms: Vec<&Msg> = mb.messages.iter().filter(|m| m.thread_id == *id).collect();
            if ms.is_empty() {
                return not_found();
            }
            ms.sort_by_key(|m| (m.internal_date, m.seq));
            let hid = ms.iter().map(|m| m.history_id).max().unwrap();
            (
                200,
                json!({"id": id, "historyId": hid.to_string(), "messages": ms.iter().map(|m| msg_json(m, false)).collect::<Vec<_>>()}),
            )
        }
        ("GET", ["history"]) => {
            let Some(start) = q.get("startHistoryId").and_then(|s| s.parse::<u64>().ok()) else {
                return bad_request();
            };
            if start < mb.history_floor {
                return not_found();
            }
            let recs: Vec<&Rec> = mb.history.iter().filter(|r| r.id > start).collect();
            let (s, e) = page(recs.len(), q, 100, 500);
            let mut out = json!({"historyId": mb.history_id.to_string()});
            if !recs.is_empty() {
                out["history"] = Value::Array(recs[s..e].iter().map(|r| rec_json(r)).collect());
            }
            if e < recs.len() {
                out["nextPageToken"] = Value::String(e.to_string());
            }
            (200, out)
        }
        ("GET", ["drafts"]) => {
            let (s, e) = page(mb.drafts.len(), q, 100, 500);
            let mut out = json!({"resultSizeEstimate": mb.drafts.len()});
            if !mb.drafts.is_empty() {
                let items: Vec<Value> = mb.drafts[s..e]
                    .iter()
                    .filter_map(|(d, mid)| mb.find(mid).map(|m| json!({"id": d, "message": msg_ref(m)})))
                    .collect();
                out["drafts"] = Value::Array(items);
            }
            if e < mb.drafts.len() {
                out["nextPageToken"] = Value::String(e.to_string());
            }
            (200, out)
        }
        ("GET", ["drafts", id]) => {
            let Some((_, mid)) = mb.drafts.iter().find(|(d, _)| d == id) else {
                return not_found();
            };
            match mb.find(mid) {
                Some(m) => (200, json!({"id": id, "message": msg_json(m, full_raw(q.get("format")))})),
                None => not_found(),
            }
        }
        ("POST", ["drafts"]) => {
            let Some((raw, thread)) = draft_body(body) else {
                return bad_request();
            };
            let (did, m) = mb.create_draft(c, raw, thread);
            (200, json!({"id": did, "message": msg_with_labels(&m)}))
        }
        ("PUT", ["drafts", id]) => {
            let Some((raw, thread)) = draft_body(body) else {
                return bad_request();
            };
            match mb.replace_draft(c, id, raw, thread) {
                Some(m) => (200, json!({"id": id, "message": msg_with_labels(&m)})),
                None => not_found(),
            }
        }
        ("POST", ["drafts", "send"]) => {
            let did = serde_json::from_slice::<Value>(body).ok().and_then(|v| v["id"].as_str().map(String::from));
            let Some(did) = did else {
                return bad_request();
            };
            match mb.send_draft(&did) {
                Some(m) => (200, msg_with_labels(&m)),
                None => not_found(),
            }
        }
        ("GET", ["settings", "sendAs"]) => {
            let mut v =
                vec![json!({"sendAsEmail": mb.email, "displayName": mb.email, "isPrimary": true, "isDefault": true})];
            for a in &mb.send_as {
                v.push(json!({"sendAsEmail": a, "displayName": a, "isPrimary": false, "isDefault": false}));
            }
            (200, json!({"sendAs": v}))
        }
        _ => not_found(),
    }
}

async fn handle(State(inner): State<Arc<Mutex<Inner>>>, req: Request<Body>) -> Response<Body> {
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, 32 * 1024 * 1024).await.unwrap_or_default();
    let method = parts.method.as_str().to_string();
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().unwrap_or("").to_string();
    let auth = parts.headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).map(String::from);

    let fault = {
        let mut g = inner.lock().unwrap();
        let mailbox = g.bearer_email(auth.as_deref());
        g.requests.push(RecordedRequest { method: method.clone(), path: path.clone(), query: query.clone(), mailbox });
        let idx = g.faults.iter().position(|(m, s, _)| *m == method && path.contains(s.as_str()));
        idx.map(|i| g.faults.remove(i).2)
    };
    let mut drop_after = false;
    match fault {
        Some(Fault::Status(code, v)) => return json_response(code, v),
        Some(Fault::Delay(d)) => tokio::time::sleep(d).await,
        Some(Fault::DropAfterApply) => drop_after = true,
        None => {}
    }
    let (code, v) = inner.lock().unwrap().dispatch(&method, &path, &query, auth.as_deref(), &body);
    if drop_after {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
    json_response(code, v)
}

fn json_response(code: u16, v: Value) -> Response<Body> {
    Response::builder()
        .status(StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&v).unwrap()))
        .unwrap()
}

impl FakeGoogle {
    pub async fn start(client_id: &str, client_secret: &str) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let inner = Arc::new(Mutex::new(Inner {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            base_url: base_url.clone(),
            mailboxes: BTreeMap::new(),
            codes: HashMap::new(),
            refresh: HashMap::new(),
            revoked: vec![],
            access: HashMap::new(),
            requests: vec![],
            violations: vec![],
            faults: vec![],
            counter: 0,
        }));
        let app = Router::new().fallback(handle).with_state(inner.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        FakeGoogle { base_url, client_id: client_id.into(), client_secret: client_secret.into(), inner }
    }

    fn with_mailbox<T>(&self, email: &str, f: impl FnOnce(&mut Mailbox, &mut u64) -> T) -> T {
        let mut g = self.inner.lock().unwrap();
        let mut c = *g.next_id_counter();
        let out = {
            let mb = g.mailboxes.get_mut(email).unwrap_or_else(|| panic!("fake-google: unknown mailbox {email}"));
            f(mb, &mut c)
        };
        g.counter = c;
        out
    }

    pub fn add_mailbox(&self, email: &str, sub: &str) {
        self.inner.lock().unwrap().mailboxes.insert(email.to_string(), Mailbox::new(email, sub));
    }

    pub fn add_send_as(&self, email: &str, alias: &str) {
        self.with_mailbox(email, |mb, _| mb.send_as.push(alias.to_string()));
    }

    pub fn issue_refresh_token(&self, email: &str) -> String {
        self.inner.lock().unwrap().issue_refresh(email)
    }

    pub fn invalidate_refresh_tokens(&self, email: &str) {
        let mut g = self.inner.lock().unwrap();
        for rt in g.refresh.values_mut().filter(|r| r.email == email) {
            rt.valid = false;
        }
    }

    pub fn revoked_tokens(&self) -> Vec<String> {
        self.inner.lock().unwrap().revoked.clone()
    }

    pub fn access_token_for(&self, email: &str) -> String {
        self.inner.lock().unwrap().mint_access(email)
    }

    pub fn register_code(&self, code: &str, spec: CodeSpec) {
        self.inner.lock().unwrap().codes.insert(code.to_string(), CodeEntry { spec, used: false });
    }

    pub fn add_message(&self, email: &str, m: MessageSpec) -> String {
        self.with_mailbox(email, |mb, c| mb.add_message(c, m))
    }

    pub fn delete_message(&self, email: &str, id: &str) {
        self.with_mailbox(email, |mb, _| mb.delete_message(id));
    }

    pub fn set_labels(&self, email: &str, id: &str, add: &[&str], remove: &[&str]) {
        self.with_mailbox(email, |mb, _| mb.set_labels(id, add, remove));
    }

    pub fn history_id(&self, email: &str) -> u64 {
        self.with_mailbox(email, |mb, _| mb.history_id)
    }

    /// Simulates an external client (Apple Mail) saving an edit: the draft gets a new message id.
    pub fn replace_draft_externally(&self, email: &str, draft_id: &str, raw: &[u8]) {
        self.with_mailbox(email, |mb, c| {
            mb.replace_draft(c, draft_id, raw.to_vec(), None).unwrap_or_else(|| panic!("no draft {draft_id}"));
        });
    }

    pub fn delete_draft_externally(&self, email: &str, draft_id: &str) {
        self.with_mailbox(email, |mb, _| assert!(mb.delete_draft(draft_id), "no draft {draft_id}"));
    }

    pub fn draft_raw(&self, email: &str, draft_id: &str) -> Option<Vec<u8>> {
        self.with_mailbox(email, |mb, _| {
            let (_, mid) = mb.drafts.iter().find(|(d, _)| d == draft_id)?;
            mb.find(mid).map(|m| m.raw.clone())
        })
    }

    /// (draft id, message id)
    pub fn drafts(&self, email: &str) -> Vec<(String, String)> {
        self.with_mailbox(email, |mb, _| mb.drafts.clone())
    }

    pub fn sent_messages(&self, email: &str) -> Vec<String> {
        self.with_mailbox(email, |mb, _| mb.sent.clone())
    }

    pub fn message_raw(&self, email: &str, id: &str) -> Option<Vec<u8>> {
        self.with_mailbox(email, |mb, _| mb.find(id).map(|m| m.raw.clone()))
    }

    pub fn set_history_floor(&self, email: &str, history_id: u64) {
        self.with_mailbox(email, |mb, _| mb.history_floor = history_id);
    }

    /// Fault for the next request whose method matches and whose path contains `path_suffix`.
    pub fn fail_next(&self, method: &str, path_suffix: &str, fault: Fault) {
        self.inner.lock().unwrap().faults.push((method.to_string(), path_suffix.to_string(), fault));
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.inner.lock().unwrap().requests.clone()
    }

    pub fn count(&self, method: &str, path_contains: &str) -> usize {
        self.inner
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|r| r.method == method && r.path.contains(path_contains))
            .count()
    }

    pub fn clear_requests(&self) {
        self.inner.lock().unwrap().requests.clear();
    }

    /// Forget recorded violations (for tests that provoke one on purpose).
    pub fn clear_violations(&self) {
        self.inner.lock().unwrap().violations.clear();
    }

    pub fn violations(&self) -> Vec<String> {
        self.inner.lock().unwrap().violations.clone()
    }

    pub fn assert_no_violations(&self) {
        let v = self.violations();
        assert!(v.is_empty(), "fake-google: requests outside the allowlist: {v:?}");
    }

    /// The mailbox's Google `sub` (used by tests that build CodeSpecs).
    pub fn sub_of(&self, email: &str) -> String {
        self.with_mailbox(email, |mb, _| mb.sub.clone())
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.inner.lock().unwrap().base_url, path)
    }
}
