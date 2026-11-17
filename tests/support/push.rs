//! A fake Web Push service on loopback and a browser-side device that decrypts what it receives.

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use dove::push::{Subscription, SubscriptionKeys, ece};
use dove::util;
use serde_json::Value;

pub type Hit = (String, axum::http::HeaderMap, Vec<u8>);

/// A push service on loopback: records each POST and answers with a settable status.
#[derive(Clone)]
pub struct PushService {
    pub hits: Arc<Mutex<Vec<Hit>>>,
    pub status: Arc<AtomicU16>,
    pub base: String,
}

impl PushService {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let s = PushService {
            hits: Arc::default(),
            status: Arc::new(AtomicU16::new(201)),
            base: format!("http://{}", listener.local_addr().unwrap()),
        };
        let sc = s.clone();
        let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let sc = sc.clone();
            async move {
                let path = req.uri().path().to_string();
                let headers = req.headers().clone();
                let body = axum::body::to_bytes(req.into_body(), 1 << 20).await.unwrap().to_vec();
                sc.hits.lock().unwrap().push((path, headers, body));
                axum::http::StatusCode::from_u16(sc.status.load(Ordering::SeqCst)).unwrap()
            }
        });
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        s
    }

    pub fn hits(&self) -> Vec<Hit> {
        self.hits.lock().unwrap().clone()
    }

    pub fn set(&self, status: u16) {
        self.status.store(status, Ordering::SeqCst);
    }
}

/// A browser's side of a subscription: its ECDH private key and auth secret.
pub struct Device {
    pub private: [u8; 32],
    pub auth: [u8; 16],
    pub path: String,
}

impl Device {
    pub fn new(n: u8) -> Self {
        Device { private: [n; 32], auth: [n.wrapping_add(100); 16], path: format!("/push/dev{n}") }
    }

    pub fn subscription(&self, svc: &PushService) -> Subscription {
        Subscription {
            endpoint: format!("{}{}", svc.base, self.path),
            keys: SubscriptionKeys {
                p256dh: util::b64url(&ece::public_key(&self.private).unwrap()),
                auth: util::b64url(&self.auth),
            },
        }
    }

    pub fn json(&self, svc: &PushService) -> Value {
        serde_json::to_value(self.subscription(svc)).unwrap()
    }

    /// Decrypts a push like the browser would; returns the padded plaintext.
    pub fn open(&self, body: &[u8]) -> Vec<u8> {
        ece::decrypt(body, &self.private, &self.auth).expect("the push decrypts with the device's keys")
    }
}
