//! `dove upgrade` and the new-version notice against a local fake release server.
//!
//! Fixtures (`tests/fixtures/update/`): release archives built by `build.py` and signed with a throwaway minisign key
//! made for these tests only (`test.pub`; the secret key was not kept). To rebuild: run `python3 -I build.py <dir>`,
//! then `minisign -S -s <key> -m <dir>/<tag>/SHA256SUMS -t "dove <tag>"` per tag, plus
//! `SHA256SUMS.wrong-comment.minisig` for v0.2.0 with `-t "dove v0.1.0"`, and replace `test.pub`. The tar fixtures are
//! byte-for-byte reproducible, so only the signatures change with a new key.
//!   v0.2.0: valid release (linux gnu and musl, aarch64-apple-darwin, and the x86_64-pc-windows-msvc `.zip`)
//!   v0.3.0: signed, but the archive also holds `dove-v0.3.0-<target>/../../evil`
//!   v0.4.0: signed, but `dove` is a symlink to /bin/sh
//!   v0.5.0: signed Windows zip that also holds `dove-v0.5.0-<target>/../../evil.exe`

// Unix only: the tests check file modes and run as a non-root user. The Windows replacement of a running binary is
// tested in `dove::update::windows`.
#![cfg(unix)]

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use dove::update::notice::{self, CHECK_INTERVAL_SECS, CacheEntry};
use dove::update::{self, Decision, Source};
use semver::Version;

const TARGET: &str = "x86_64-unknown-linux-gnu";
const MUSL: &str = "x86_64-unknown-linux-musl";
const WINDOWS: &str = "x86_64-pc-windows-msvc";
const NEW_BINARY: &[u8] = b"#!/bin/sh\necho 'dove 0.2.0'\n";
const OLD_BINARY: &[u8] = b"old dove binary\n";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/update")
}

#[derive(Default)]
struct State {
    files: HashMap<String, (StatusCode, Vec<u8>)>,
    /// (path, user-agent, accept)
    log: Vec<(String, String, String)>,
}

#[derive(Clone)]
struct FakeReleases {
    base: String,
    state: Arc<Mutex<State>>,
}

impl FakeReleases {
    async fn start() -> Self {
        let state = Arc::new(Mutex::new(State::default()));
        let s = state.clone();
        let app = axum::Router::new().fallback(move |req: Request<Body>| {
            let s = s.clone();
            async move {
                let header = |n: &str| req.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                let path = req.uri().path().to_string();
                let mut st = s.lock().unwrap();
                st.log.push((path.clone(), header("user-agent"), header("accept")));
                match st.files.get(&path) {
                    Some((code, body)) => (*code, body.clone()).into_response(),
                    None => Response::builder().status(404).body(Body::from("Not Found")).unwrap(),
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { base, state }
    }

    fn latest_path() -> String {
        format!("/repos/{}/releases/latest", update::repo_slug())
    }

    fn asset_path(tag: &str, name: &str) -> String {
        format!("/{}/releases/download/{tag}/{name}", update::repo_slug())
    }

    fn set_latest(&self, tag: &str) {
        let body = serde_json::json!({ "tag_name": tag, "name": format!("Dove {tag}"), "prerelease": false });
        self.state.lock().unwrap().files.insert(Self::latest_path(), (StatusCode::OK, body.to_string().into_bytes()));
    }

    fn set_latest_status(&self, code: u16) {
        self.state
            .lock()
            .unwrap()
            .files
            .insert(Self::latest_path(), (StatusCode::from_u16(code).unwrap(), b"{}".to_vec()));
    }

    /// Serves every fixture file of a release.
    fn publish(&self, tag: &str) {
        for entry in std::fs::read_dir(fixtures().join(tag)).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            self.put(tag, &name, std::fs::read(entry.path()).unwrap());
        }
    }

    fn put(&self, tag: &str, name: &str, body: Vec<u8>) {
        self.state.lock().unwrap().files.insert(Self::asset_path(tag, name), (StatusCode::OK, body));
    }

    fn remove(&self, tag: &str, name: &str) {
        self.state.lock().unwrap().files.remove(&Self::asset_path(tag, name));
    }

    fn requests(&self) -> Vec<(String, String, String)> {
        self.state.lock().unwrap().log.clone()
    }

    fn source(&self, current: &str) -> Source {
        Source {
            api_base: self.base.clone(),
            download_base: self.base.clone(),
            public_key: std::fs::read_to_string(fixtures().join("test.pub")).unwrap(),
            current: Version::parse(current).unwrap(),
            target: Some(TARGET.into()),
        }
    }
}

fn http() -> reqwest::Client {
    update::http_client(Duration::from_secs(10)).unwrap()
}

/// A directory holding only `dove` with the old content.
fn installed() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("dove");
    std::fs::write(&exe, OLD_BINARY).unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    (dir, exe)
}

fn dir_names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> =
        std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    v.sort();
    v
}

#[tokio::test]
async fn valid_upgrade_replaces_the_binary() {
    let fake = FakeReleases::start().await;
    fake.set_latest("v0.2.0");
    fake.publish("v0.2.0");
    let src = fake.source("0.1.0");
    let (dir, exe) = installed();

    let latest = update::latest_release(&src, &http()).await.unwrap();
    assert_eq!(latest, Version::new(0, 2, 0));
    let Decision::Install(v) = update::decide(&src.current, Some(&latest), None) else { panic!("no install") };
    update::install(&src, &http(), &v, &exe).await.unwrap();

    assert_eq!(std::fs::read(&exe).unwrap(), NEW_BINARY, "the linux build, not the darwin one");
    assert_eq!(std::fs::metadata(&exe).unwrap().permissions().mode() & 0o777, 0o755);
    assert_eq!(dir_names(dir.path()), ["dove"], "no temporary files left");
    let out = std::process::Command::new(&exe).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "dove 0.2.0\n");

    let log = fake.requests();
    let (path, ua, accept) = &log[0];
    assert_eq!(path, &FakeReleases::latest_path());
    assert_eq!(ua, concat!("dove-cli/", env!("CARGO_PKG_VERSION")));
    assert_eq!(accept, "application/vnd.github+json");
    let paths: Vec<&str> = log.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(
        paths[1..],
        [
            FakeReleases::asset_path("v0.2.0", "SHA256SUMS"),
            FakeReleases::asset_path("v0.2.0", "SHA256SUMS.minisig"),
            FakeReleases::asset_path("v0.2.0", "dove-v0.2.0-x86_64-unknown-linux-gnu.tar.gz"),
        ]
    );
}

/// A musl build keeps getting musl assets: the target decides the archive, and the gnu archive is never touched.
#[tokio::test]
async fn musl_target_installs_the_musl_archive() {
    let fake = FakeReleases::start().await;
    fake.publish("v0.2.0");
    let mut src = fake.source("0.1.0");
    src.target = Some(MUSL.into());
    let (dir, exe) = installed();
    update::install(&src, &http(), &Version::new(0, 2, 0), &exe).await.unwrap();
    let out = std::process::Command::new(&exe).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "dove 0.2.0 (musl)\n");
    assert_eq!(dir_names(dir.path()), ["dove"]);
    let paths: Vec<String> = fake.requests().into_iter().map(|r| r.0).collect();
    assert!(paths.contains(&FakeReleases::asset_path("v0.2.0", "dove-v0.2.0-x86_64-unknown-linux-musl.tar.gz")));
    assert!(paths.iter().all(|p| !p.contains("linux-gnu")), "{paths:?}");
}

/// Windows releases are `.zip` archives with `dove.exe`; the binary comes out of the zip after the same signature
/// and checksum checks (the file is replaced through the same path as on Unix, here only to see the bytes).
#[tokio::test]
async fn windows_target_reads_the_zip_archive() {
    let fake = FakeReleases::start().await;
    fake.publish("v0.2.0");
    let mut src = fake.source("0.1.0");
    src.target = Some(WINDOWS.into());
    let bytes = update::fetch_binary(&src, &http(), &Version::new(0, 2, 0)).await.unwrap();
    assert_eq!(bytes, b"MZ dove 0.2.0 (windows)\n");
    let paths: Vec<String> = fake.requests().into_iter().map(|r| r.0).collect();
    assert_eq!(
        paths,
        [
            FakeReleases::asset_path("v0.2.0", "SHA256SUMS"),
            FakeReleases::asset_path("v0.2.0", "SHA256SUMS.minisig"),
            FakeReleases::asset_path("v0.2.0", "dove-v0.2.0-x86_64-pc-windows-msvc.zip"),
        ]
    );
}

/// Each case changes one thing about an otherwise valid release; every one must be refused with the installed binary
/// untouched and no temporary file left behind.
#[tokio::test]
async fn tampered_or_unusable_releases_are_refused() {
    let sums = std::fs::read(fixtures().join("v0.2.0/SHA256SUMS")).unwrap();
    let archive = "dove-v0.2.0-x86_64-unknown-linux-gnu.tar.gz";
    type Setup = Box<dyn Fn(&FakeReleases, &mut Source)>;
    let cases: Vec<(&str, &str, Setup, &str)> = vec![
        (
            "bad signature",
            "0.2.0",
            Box::new({
                let sums = sums.clone();
                move |f, _| {
                    let mut s = sums.clone();
                    s.extend_from_slice(format!("{}  dove-v0.2.0-evil.tar.gz\n", "0".repeat(64)).as_bytes());
                    f.put("v0.2.0", "SHA256SUMS", s);
                }
            }),
            "signature check failed",
        ),
        (
            "signed by another key (the production key is not the test key)",
            "0.2.0",
            Box::new(|_, s| s.public_key = update::RELEASE_PUBLIC_KEY.into()),
            "signature check failed",
        ),
        (
            "trusted comment names another release",
            "0.2.0",
            Box::new(|f, _| {
                let sig = std::fs::read(fixtures().join("v0.2.0/SHA256SUMS.wrong-comment.minisig")).unwrap();
                f.put("v0.2.0", "SHA256SUMS.minisig", sig);
            }),
            "belongs to another release",
        ),
        (
            "archive does not match the signed checksum",
            "0.2.0",
            Box::new(move |f, _| {
                let mut a = std::fs::read(fixtures().join("v0.2.0").join(archive)).unwrap();
                let n = a.len();
                a[n - 9] ^= 0x01;
                f.put("v0.2.0", archive, a);
            }),
            "checksum mismatch",
        ),
        ("path traversal entry", "0.3.0", Box::new(|_, _| {}), "unsafe path"),
        ("path traversal entry in a zip", "0.5.0", Box::new(|_, s| s.target = Some(WINDOWS.into())), "unsafe path"),
        (
            "zip does not match the signed checksum",
            "0.2.0",
            Box::new(|f, s| {
                s.target = Some(WINDOWS.into());
                let name = "dove-v0.2.0-x86_64-pc-windows-msvc.zip";
                let mut a = std::fs::read(fixtures().join("v0.2.0").join(name)).unwrap();
                a[30] ^= 0x01;
                f.put("v0.2.0", name, a);
            }),
            "checksum mismatch",
        ),
        ("dove is a symlink", "0.4.0", Box::new(|_, _| {}), "link or special file"),
        (
            "no build for this target",
            "0.2.0",
            Box::new(|_, s| s.target = Some("x86_64-apple-darwin".into())),
            "no build for this platform",
        ),
        ("archive missing", "0.2.0", Box::new(move |f, _| f.remove("v0.2.0", archive)), "has no asset"),
        ("signature missing", "0.2.0", Box::new(|f, _| f.remove("v0.2.0", "SHA256SUMS.minisig")), "has no asset"),
        ("release missing", "0.9.0", Box::new(|_, _| {}), "has no asset SHA256SUMS"),
        ("unsupported platform", "0.2.0", Box::new(|_, s| s.target = None), "no release builds exist"),
    ];
    for (name, version, setup, expected) in cases {
        let fake = FakeReleases::start().await;
        for tag in ["v0.2.0", "v0.3.0", "v0.4.0", "v0.5.0"] {
            fake.publish(tag);
        }
        let mut src = fake.source("0.1.0");
        setup(&fake, &mut src);
        let (dir, exe) = installed();
        let err = update::install(&src, &http(), &Version::parse(version).unwrap(), &exe).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains(expected), "{name}: {msg}");
        assert_eq!(std::fs::read(&exe).unwrap(), OLD_BINARY, "{name}: binary changed");
        assert_eq!(dir_names(dir.path()), ["dove"], "{name}: leftovers");
        assert!(!dir.path().join("../evil").exists() && !dir.path().join("evil").exists(), "{name}");
    }
}

#[tokio::test]
async fn older_release_only_when_requested_explicitly() {
    let fake = FakeReleases::start().await;
    fake.set_latest("v0.2.0");
    fake.publish("v0.2.0");
    let src = fake.source("0.3.0");
    let (_dir, exe) = installed();

    let latest = update::latest_release(&src, &http()).await.unwrap();
    assert_eq!(update::decide(&src.current, Some(&latest), None), Decision::UpToDate { latest: latest.clone() });
    assert_eq!(fake.requests().len(), 1, "nothing downloaded");
    assert_eq!(std::fs::read(&exe).unwrap(), OLD_BINARY);

    let requested = update::parse_requested("0.2.0").unwrap();
    let Decision::Install(v) = update::decide(&src.current, None, Some(&requested)) else { panic!("no downgrade") };
    update::install(&src, &http(), &v, &exe).await.unwrap();
    assert_eq!(std::fs::read(&exe).unwrap(), NEW_BINARY);
}

#[tokio::test]
async fn unwritable_directory_fails_before_downloading() {
    if nix::unistd::geteuid().is_root() {
        return; // root writes anywhere
    }
    let fake = FakeReleases::start().await;
    fake.publish("v0.2.0");
    let src = fake.source("0.1.0");
    let (dir, exe) = installed();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
    let err = update::install(&src, &http(), &Version::new(0, 2, 0), &exe).await.unwrap_err();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(err.to_string().contains("run `sudo dove upgrade`"), "{err:#}");
    assert!(fake.requests().is_empty(), "checked before any download");
    assert_eq!(std::fs::read(&exe).unwrap(), OLD_BINARY);
    // The write path itself gives the same hint.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
    let err = update::replace_binary(&exe, NEW_BINARY).unwrap_err();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(err.to_string().contains("sudo dove upgrade"), "{err:#}");
}

#[tokio::test]
async fn latest_release_lookup_errors() {
    let fake = FakeReleases::start().await;
    let src = fake.source("0.1.0");
    let err = update::latest_release(&src, &http()).await.unwrap_err();
    assert!(err.to_string().contains("no Dove release"), "{err:#}");
    fake.set_latest_status(403);
    assert!(update::latest_release(&src, &http()).await.unwrap_err().to_string().contains("rate limit"));
    fake.set_latest("v0.3.0-rc.1");
    assert!(update::latest_release(&src, &http()).await.unwrap_err().to_string().contains("not a stable release"));
    fake.set_latest("nightly");
    assert!(update::latest_release(&src, &http()).await.is_err());
}

#[tokio::test]
async fn notice_cache_limits_lookups_to_one_per_day() {
    let fake = FakeReleases::start().await;
    fake.set_latest("v0.2.0");
    let src = fake.source("0.1.0");
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("dove").join("update-check.json");
    let t0 = 1_800_000_000;
    let lookups = || fake.requests().len();

    // No cache: one lookup, cached.
    let latest = notice::latest_known(Some(&cache), &src, &http(), t0).await;
    assert_eq!(latest, Some(Version::new(0, 2, 0)));
    assert_eq!(lookups(), 1);
    assert_eq!(notice::read_cache(&cache), Some(CacheEntry { checked_at: t0, latest: Some("v0.2.0".into()) }));
    assert_eq!(
        notice::notice_line(latest.as_ref(), &src.current).unwrap(),
        "A new Dove version is available: v0.2.0 (installed v0.1.0). Run: dove upgrade"
    );

    // Fresh cache: no request, even though the server now knows a newer release.
    fake.set_latest("v0.3.0");
    let latest = notice::latest_known(Some(&cache), &src, &http(), t0 + CHECK_INTERVAL_SECS - 1).await;
    assert_eq!((latest, lookups()), (Some(Version::new(0, 2, 0)), 1));

    // Stale cache: looked up again.
    let t1 = t0 + CHECK_INTERVAL_SECS;
    let latest = notice::latest_known(Some(&cache), &src, &http(), t1).await;
    assert_eq!((latest, lookups()), (Some(Version::new(0, 3, 0)), 2));

    // A failed lookup is cached too (keeping the last known release), so the next command does not retry.
    fake.set_latest_status(500);
    let t2 = t1 + CHECK_INTERVAL_SECS;
    let latest = notice::latest_known(Some(&cache), &src, &http(), t2).await;
    assert_eq!((latest, lookups()), (Some(Version::new(0, 3, 0)), 3));
    assert_eq!(notice::read_cache(&cache).unwrap().checked_at, t2);
    notice::latest_known(Some(&cache), &src, &http(), t2 + 60).await;
    assert_eq!(lookups(), 3, "failure was cached");

    // A corrupt cache counts as stale.
    fake.set_latest("v0.3.1");
    std::fs::write(&cache, b"\x00garbage").unwrap();
    let latest = notice::latest_known(Some(&cache), &src, &http(), t2 + 120).await;
    assert_eq!((latest, lookups()), (Some(Version::new(0, 3, 1)), 4));

    // No usable cache location: still answers, without failing.
    assert_eq!(notice::latest_known(None, &src, &http(), t2).await, Some(Version::new(0, 3, 1)));
}

#[tokio::test]
async fn notice_lookup_is_bounded_when_the_network_hangs() {
    // A server that accepts connections and never answers.
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", silent.local_addr().unwrap());
    let src = Source { api_base: base.clone(), download_base: base, ..FakeReleases::start().await.source("0.1.0") };
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("update-check.json");
    let started = Instant::now();
    let http = update::http_client(Duration::from_millis(300)).unwrap();
    assert_eq!(notice::latest_known(Some(&cache), &src, &http, 1_800_000_000).await, None);
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    assert_eq!(notice::read_cache(&cache), Some(CacheEntry { checked_at: 1_800_000_000, latest: None }));
    drop(silent);
}

/// The updater is CLI-only: nothing outside the CLI entry points reaches it, so `serve` never runs it.
#[test]
fn only_the_cli_reaches_the_updater() {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&src, &mut files);
    let allowed = ["cli.rs", "main.rs", "lib.rs"];
    let mut users = Vec::new();
    for f in files {
        let rel = f.strip_prefix(&src).unwrap().to_string_lossy().to_string();
        if rel.starts_with("update/") || allowed.contains(&rel.as_str()) {
            continue;
        }
        let text = std::fs::read_to_string(&f).unwrap();
        if text.contains("crate::update") || text.contains("dove::update") || text.contains("super::update") {
            users.push(rel);
        }
    }
    assert!(users.is_empty(), "updater referenced from {users:?}");
    let serve = std::fs::read_to_string(src.join("serve.rs")).unwrap();
    assert!(!serve.contains("update::"), "serve must not reach the updater");
}
