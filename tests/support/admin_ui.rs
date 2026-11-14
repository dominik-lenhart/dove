//! Admin web UI test helpers: a cookie-keeping browser without redirects, enrolment and sign-in with the software
//! authenticator (`dove::admin_ui::soft_authenticator`).

use dove::admin::AdminRequest;
use dove::admin_ui::soft_authenticator::{Assertion, SoftAuthenticator};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{Value, json};

use super::harness::Harness;

pub const ORIGIN: &str = "https://dove-admin.tail1234.ts.net";
pub const AHOST: &str = "dove-admin.tail1234.ts.net";

/// A harness with the admin UI enabled at [`ORIGIN`].
pub async fn start() -> Harness {
    start_with(|_| {}).await
}

pub async fn start_with(customize: impl FnOnce(&mut dove::config::Config)) -> Harness {
    Harness::start_with(|c| {
        c.admin_ui.enabled = true;
        c.admin_ui.origin = Some(ORIGIN.into());
        customize(c)
    })
    .await
}

pub fn b64d(v: &Value) -> Vec<u8> {
    dove::util::b64url_decode(v.as_str().unwrap()).unwrap()
}

pub struct Resp {
    pub status: u16,
    pub headers: HeaderMap,
    pub text: String,
}

impl Resp {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::Null)
    }
    pub fn header(&self, name: &str) -> String {
        self.headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
    }
}

/// A browser on the admin origin: keeps the session cookie, follows no redirects, sends `Origin` and
/// `Sec-Fetch-Site: same-origin` with POSTs and the CSRF token it read from the last page.
pub struct Browser {
    pub base: String,
    pub cookie: Option<String>,
    pub csrf: Option<String>,
    /// Extra headers on every request (tests of the guard).
    pub extra: Vec<(String, String)>,
    client: reqwest::Client,
}

impl Browser {
    pub fn new(h: &Harness) -> Self {
        let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
        Self { base: h.base.clone(), cookie: None, csrf: None, extra: vec![], client }
    }

    fn headers(&self, post: bool) -> HeaderMap {
        let mut m = HeaderMap::new();
        m.insert("host", HeaderValue::from_static(AHOST));
        if let Some(c) = &self.cookie {
            m.insert("cookie", format!("{}={c}", dove::admin_ui::COOKIE).parse().unwrap());
        }
        if post {
            m.insert("origin", HeaderValue::from_static(ORIGIN));
            m.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        }
        for (k, v) in &self.extra {
            m.insert(HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        m
    }

    async fn done(&mut self, r: reqwest::Response) -> Resp {
        let status = r.status().as_u16();
        let headers = r.headers().clone();
        let text = r.text().await.unwrap_or_default();
        if let Some(c) = headers.get("set-cookie").and_then(|v| v.to_str().ok()) {
            let v = c.split(';').next().unwrap().split_once('=').unwrap().1.to_string();
            self.cookie = if v.is_empty() { None } else { Some(v) };
        }
        if let Some(i) = text.find("name=\"dove-csrf\" content=\"") {
            let rest = &text[i + 26..];
            self.csrf = Some(rest[..rest.find('"').unwrap()].to_string());
        }
        Resp { status, headers, text }
    }

    pub async fn get(&mut self, path: &str) -> Resp {
        let r = self.client.get(format!("{}{path}", self.base)).headers(self.headers(false)).send().await.unwrap();
        self.done(r).await
    }

    /// A raw request with exactly these headers on top of Host (no cookie, Origin or CSRF unless given).
    pub async fn raw(&mut self, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Resp {
        let mut m = HeaderMap::new();
        m.insert("host", HeaderValue::from_static(AHOST));
        for (k, v) in headers {
            m.insert(HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let r = self
            .client
            .request(method, format!("{}{path}", self.base))
            .headers(m)
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        self.done(r).await
    }

    pub async fn post_json(&mut self, path: &str, body: Value) -> Resp {
        let mut h = self.headers(true);
        if let Some(t) = &self.csrf {
            h.insert("x-dove-csrf", t.parse().unwrap());
        }
        let r = self.client.post(format!("{}{path}", self.base)).headers(h).json(&body).send().await.unwrap();
        self.done(r).await
    }

    /// A form post with the CSRF field from the last page (unless `fields` names `csrf` itself).
    pub async fn post_form(&mut self, path: &str, fields: &[(&str, &str)]) -> Resp {
        let mut pairs: Vec<(String, String)> = fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        if !fields.iter().any(|(k, _)| *k == "csrf")
            && let Some(t) = &self.csrf
        {
            pairs.push(("csrf".into(), t.clone()));
        }
        let r = self
            .client
            .post(format!("{}{path}", self.base))
            .headers(self.headers(true))
            .form(&pairs)
            .send()
            .await
            .unwrap();
        self.done(r).await
    }
}

/// The enrolment token from `dove admin passkey add`.
pub async fn enrol_link(h: &Harness, name: &str) -> String {
    let v = h.admin(AdminRequest::PasskeysAdd { name: name.into() }).await.unwrap();
    v["open_this_link"].as_str().unwrap().split_once('#').unwrap().1.to_string()
}

/// Enrols a new ES256 passkey named `name` through the pages and signs `b` in with it.
pub async fn enrol(h: &Harness, b: &mut Browser, name: &str) -> SoftAuthenticator {
    let mut a = SoftAuthenticator::es256(ORIGIN);
    enrol_with(h, b, name, &mut a).await;
    a
}

pub async fn enrol_with(h: &Harness, b: &mut Browser, name: &str, a: &mut SoftAuthenticator) -> Resp {
    let token = enrol_link(h, name).await;
    let o = b.post_json("/admin/enroll/options", json!({ "token": token })).await;
    assert_eq!(o.status, 200, "{}", o.text);
    let o = o.json();
    let reg = a.register(&b64d(&o["publicKey"]["challenge"]), &b64d(&o["publicKey"]["user"]["id"]));
    let r = b.post_json("/admin/enroll/finish", json!({ "id": o["id"], "credential": reg.to_json() })).await;
    if r.status == 200 {
        b.get("/admin").await;
    }
    r
}

/// Login options; returns (ceremony id, challenge).
pub async fn login_options(b: &mut Browser) -> (Value, Vec<u8>) {
    let o = b.post_json("/admin/login/options", json!({})).await;
    assert_eq!(o.status, 200, "{}", o.text);
    let o = o.json();
    (o["id"].clone(), b64d(&o["publicKey"]["challenge"]))
}

pub async fn login_finish(b: &mut Browser, id: &Value, a: &Assertion) -> Resp {
    b.post_json("/admin/login/finish", json!({ "id": id, "credential": a.to_json() })).await
}

/// Signs `b` in with `a`; panics unless it worked.
pub async fn login(b: &mut Browser, a: &mut SoftAuthenticator) {
    let (id, ch) = login_options(b).await;
    let r = login_finish(b, &id, &a.assert(&ch)).await;
    assert_eq!(r.status, 200, "{}", r.text);
    b.get("/admin").await;
}

/// Starts a step-up form post; returns (pending id, challenge, allowed credential id).
pub async fn stepup_begin(b: &mut Browser, path: &str, fields: &[(&str, &str)]) -> (Value, Vec<u8>, Vec<u8>) {
    let r = b.post_form(path, fields).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let v = r.json();
    let s = &v["stepup"];
    assert!(s.is_object(), "{v}");
    (s["id"].clone(), b64d(&s["publicKey"]["challenge"]), b64d(&s["publicKey"]["allowCredentials"][0]["id"]))
}

pub async fn stepup_finish(b: &mut Browser, id: &Value, a: &Assertion) -> Resp {
    b.post_json("/admin/stepup", json!({ "id": id, "credential": a.to_json() })).await
}
