//! `dove tailscale setup` and its doctor check against a fake `tailscale` executable (never the real one: the
//! host's Tailscale serves other things). The fake keeps its state in files, records every call, and answers
//! `status --json` and `serve status --json` like the real CLI, so setup can be run twice and repaired.

mod support;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use dove::tailscale::{PUBLIC_PATHS, Tailscale, doctor_check};
use serde_json::{Value, json};

const HOST: &str = "dove.tail1234.ts.net";

/// Behaves like the parts of the Tailscale CLI Dove uses. State directory: `$FAKE_TS_DIR` with `serve.txt`
/// (`port path target` per line), `funnel.txt` (ports), `status.json`, and optional `deny` (refuse changes like a
/// user who is not the operator). `log` records every call.
const FAKE: &str = r#"#!/bin/sh
D="$FAKE_TS_DIR"
echo "$*" >> "$D/log"
if [ "$1" = status ] && [ "$2" = "--json" ]; then cat "$D/status.json"; exit 0; fi
if [ "$1" = serve ] && [ "$2" = status ]; then
  host=$(cat "$D/host")
  touch "$D/serve.txt" "$D/funnel.txt"
  awk -v host="$host" -v funnel="$(tr '\n' ' ' < "$D/funnel.txt")" '
    { ports[$1] = ports[$1] (ports[$1] ? "," : "") sprintf("\"%s\":{\"Proxy\":\"%s\"}", $2, $3) }
    END {
      printf "{\"TCP\":{},\"Web\":{"; n = 0
      for (p in ports) { printf "%s\"%s:%s\":{\"Handlers\":{%s}}", (n++ ? "," : ""), host, p, ports[p] }
      printf "},\"AllowFunnel\":{"; m = split(funnel, f, " "); k = 0
      for (i = 1; i <= m; i++) if (f[i] != "") printf "%s\"%s:%s\":true", (k++ ? "," : ""), host, f[i]
      printf "}}\n"
    }' "$D/serve.txt"
  exit 0
fi
if [ -e "$D/deny" ]; then
  echo "Access denied: serve config write access denied; use 'sudo tailscale', or run 'sudo tailscale set --operator=\$USER'" >&2
  exit 1
fi
cmd=$1; shift
port=443; path=; target=
while [ $# -gt 0 ]; do
  case "$1" in
    --https=*) port=${1#--https=} ;;
    --set-path) path=$2; shift ;;
    --bg|--yes) ;;
    *) target=$1 ;;
  esac
  shift
done
touch "$D/serve.txt" "$D/funnel.txt"
if [ "$cmd" = serve ]; then
  grep -v "^$port $path " "$D/serve.txt" > "$D/serve.tmp"; mv "$D/serve.tmp" "$D/serve.txt"
  [ "$target" = off ] || echo "$port $path $target" >> "$D/serve.txt"
elif [ "$cmd" = funnel ]; then
  grep -v "^$port$" "$D/funnel.txt" > "$D/funnel.tmp"; mv "$D/funnel.tmp" "$D/funnel.txt"
  [ "$target" = off ] || echo "$port" >> "$D/funnel.txt"
fi
exit 0
"#;

/// The fake executable, written once per test process (writing it per test races with other tests' forks).
fn fake_bin() -> &'static PathBuf {
    static BIN: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();
    &BIN.get_or_init(|| {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("tailscale");
        std::fs::write(&bin, FAKE).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        (dir, bin)
    })
    .1
}

struct Fake {
    state: tempfile::TempDir,
}

impl Fake {
    fn new() -> Self {
        Self::with_status(json!({ "BackendState": "Running",
            "Self": { "DNSName": format!("{HOST}."), "CapMap": { "funnel": null, "https": null } },
            "CertDomains": [HOST] }))
    }

    fn with_status(status: Value) -> Self {
        fake_bin();
        let state = tempfile::tempdir().unwrap();
        std::fs::write(state.path().join("status.json"), status.to_string()).unwrap();
        std::fs::write(state.path().join("host"), HOST).unwrap();
        Self { state }
    }

    fn ts(&self) -> Tailscale {
        Tailscale::at(fake_bin()).with_env("FAKE_TS_DIR", self.state.path().to_str().unwrap())
    }

    fn file(&self, name: &str) -> String {
        std::fs::read_to_string(self.state.path().join(name)).unwrap_or_default()
    }

    /// Calls that are not reads of the state.
    fn changes(&self) -> Vec<String> {
        self.file("log").lines().filter(|l| !l.contains("status")).map(String::from).collect()
    }

    fn mounted(&self) -> Vec<String> {
        let mut v: Vec<String> =
            self.file("serve.txt").lines().map(|l| l.split(' ').nth(1).unwrap().to_string()).collect();
        v.sort();
        v
    }

    fn deny(&self) {
        std::fs::write(self.state.path().join("deny"), "").unwrap();
    }
}

fn config_text() -> String {
    let example = dove::config::EXAMPLE.to_string();
    format!("{example}\n# trailing comment that must survive\n")
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Runs the real `dove` binary with only the fake `tailscale` in PATH.
fn dove(fake: &Fake, config: &Path, args: &[&str]) -> Run {
    // The fake comes first; the system directories only provide the shell tools the fake script uses.
    let bin = format!("{}:/usr/bin:/bin", fake_bin().parent().unwrap().to_str().unwrap());
    let home = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_dove"))
        .env_clear()
        .env("PATH", bin)
        .env("HOME", home.path())
        .env("FAKE_TS_DIR", fake.state.path())
        .env("DOVE_NO_UPDATE_CHECK", "1")
        .args(["tailscale", "setup", "--config"])
        .arg(config)
        .args(args)
        .output()
        .unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn config_file(text: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, text).unwrap();
    (dir, path)
}

fn public_url_of(path: &Path) -> String {
    let v: toml::Value = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    v["public_url"].as_str().unwrap().to_string()
}

#[test]
fn setup_mounts_exactly_the_public_paths_and_is_idempotent() {
    let fake = Fake::new();
    let original = config_text();
    let (_d, cfg) = config_file(&original);
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o640)).unwrap();
    }

    let r = dove(&fake, &cfg, &[]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&cfg).unwrap().permissions().mode() & 0o7777, 0o640, "the config keeps its mode");
    }
    let mut want: Vec<String> = PUBLIC_PATHS.iter().map(|s| (*s).to_string()).collect();
    want.sort();
    assert_eq!(fake.mounted(), want);
    assert_eq!(fake.changes().len(), PUBLIC_PATHS.len());
    // Every mount forwards to Dove's configured loopback listener; /healthz is not among them.
    assert!(fake.file("serve.txt").lines().all(|l| l.starts_with("443 ") && l.contains(" http://127.0.0.1:8787/")));
    assert!(!fake.file("serve.txt").contains("healthz"));
    assert!(fake.file("funnel.txt").is_empty(), "no Funnel unless asked");
    assert_eq!(public_url_of(&cfg), format!("https://{HOST}"));
    // Only public_url changed; comments and layout are as they were.
    assert_eq!(
        std::fs::read_to_string(&cfg).unwrap(),
        original.replace("https://dove.example.com", &format!("https://{HOST}"))
    );
    assert!(r.stdout.contains("only from devices on your tailnet"), "{}", r.stdout);
    assert!(r.stdout.contains("systemctl restart dove"));

    // Second run: nothing to do, nothing changes.
    let before = fake.changes();
    let r = dove(&fake, &cfg, &[]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(fake.changes(), before, "no tailscale command on the second run");
    assert!(r.stdout.contains("Nothing to change"), "{}", r.stdout);
    assert_eq!(
        std::fs::read_to_string(&cfg).unwrap(),
        original.replace("https://dove.example.com", &format!("https://{HOST}"))
    );
}

#[test]
fn setup_repairs_a_drifted_mount_and_drops_an_old_one() {
    let fake = Fake::new();
    let (_d, cfg) = config_file(&config_text());
    assert_eq!(dove(&fake, &cfg, &[]).code, 0);
    // Someone pointed /mcp elsewhere, and an old Dove release had published /healthz.
    let lines: String =
        fake.file("serve.txt")
            .lines()
            .map(|l| {
                if l.starts_with("443 /mcp ") {
                    "443 /mcp http://127.0.0.1:9999/mcp".to_string()
                } else {
                    l.to_string()
                }
            })
            .chain(["443 /healthz http://127.0.0.1:8787/healthz".to_string()])
            .map(|l| l + "\n")
            .collect();
    std::fs::write(fake.state.path().join("serve.txt"), lines).unwrap();
    std::fs::remove_file(fake.state.path().join("log")).unwrap();

    let r = dove(&fake, &cfg, &[]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(fake.changes().len(), 2, "{:?}", fake.changes());
    assert!(fake.file("serve.txt").contains("443 /mcp http://127.0.0.1:8787/mcp"));
    assert!(!fake.file("serve.txt").contains("healthz"));
}

#[test]
fn dry_run_prints_the_commands_and_changes_nothing() {
    let fake = Fake::new();
    let original = config_text();
    let (_d, cfg) = config_file(&original);
    let r = dove(&fake, &cfg, &["--dry-run"]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert!(fake.changes().is_empty());
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), original);
    for p in PUBLIC_PATHS {
        assert!(
            r.stdout
                .contains(&format!("tailscale serve --bg --yes --https=443 --set-path {p} http://127.0.0.1:8787{p}")),
            "{p}\n{}",
            r.stdout
        );
    }
    assert!(r.stdout.contains(&format!("public_url = \"https://{HOST}\"")), "{}", r.stdout);
}

#[test]
fn port_flag_sets_the_url_and_the_https_port() {
    let fake = Fake::new();
    let (_d, cfg) = config_file(&config_text());
    let r = dove(&fake, &cfg, &["--port", "8443"]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(public_url_of(&cfg), format!("https://{HOST}:8443"));
    assert!(fake.file("serve.txt").lines().all(|l| l.starts_with("8443 ")));
}

#[test]
fn funnel_needs_the_flag_warns_and_checks_the_port() {
    let fake = Fake::new();
    let (_d, cfg) = config_file(&config_text());
    let r = dove(&fake, &cfg, &["--funnel"]);
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert!(r.stdout.contains("WARNING") && r.stdout.contains("reachable from the entire internet"), "{}", r.stdout);
    assert_eq!(fake.file("funnel.txt").trim(), "443");
    assert!(fake.changes().iter().any(|c| c.starts_with("funnel ")));

    // Funnel only exists on three ports.
    let fake = Fake::new();
    let (_d, cfg) = config_file(&config_text());
    let r = dove(&fake, &cfg, &["--funnel", "--port", "3000"]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("443, 8443 and 10000"), "{}", r.stderr);
    assert!(fake.changes().is_empty());

    // A node whose policy forbids Funnel.
    let fake =
        Fake::with_status(json!({ "BackendState": "Running", "Self": { "DNSName": format!("{HOST}."), "CapMap": {} },
                                          "CertDomains": [HOST] }));
    let (_d, cfg) = config_file(&config_text());
    let r = dove(&fake, &cfg, &["--funnel"]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("Funnel is not enabled"), "{}", r.stderr);
    assert!(fake.changes().is_empty());
}

#[test]
fn funnel_that_is_already_on_is_reported_but_not_changed() {
    let fake = Fake::new();
    let (_d, cfg) = config_file(&config_text());
    assert_eq!(dove(&fake, &cfg, &["--funnel"]).code, 0);
    let before = fake.changes();
    let r = dove(&fake, &cfg, &[]);
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("Funnel is already ON"), "{}", r.stdout);
    assert_eq!(fake.changes(), before);
    assert_eq!(fake.file("funnel.txt").trim(), "443");
}

#[test]
fn a_foreign_handler_on_the_port_stops_setup_before_anything_changes() {
    let fake = Fake::new();
    std::fs::write(fake.state.path().join("serve.txt"), "443 /grafana http://127.0.0.1:3000\n").unwrap();
    let original = config_text();
    let (_d, cfg) = config_file(&original);
    let r = dove(&fake, &cfg, &[]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("/grafana") && r.stderr.contains("--port"), "{}", r.stderr);
    assert!(fake.changes().is_empty());
    assert_eq!(fake.file("serve.txt"), "443 /grafana http://127.0.0.1:3000\n", "the other app is untouched");
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), original);
}

#[test]
fn without_operator_rights_setup_says_what_to_run_with_sudo() {
    let fake = Fake::new();
    fake.deny();
    let original = config_text();
    let (_d, cfg) = config_file(&original);
    let r = dove(&fake, &cfg, &[]);
    assert_ne!(r.code, 0);
    assert!(
        r.stdout.contains("sudo dove tailscale setup") && r.stdout.contains("sudo tailscale set --operator"),
        "{}",
        r.stdout
    );
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), original, "the config is only written after Tailscale accepted");
}

#[test]
fn an_unwritable_config_stops_setup_before_tailscale_is_touched() {
    use std::os::unix::fs::PermissionsExt;
    let fake = Fake::new();
    let (d, cfg) = config_file(&config_text());
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
    // Root ignores directory modes; the check only means something for the unprivileged user tests run as.
    if nix::unistd::getuid().is_root() {
        return;
    }
    let r = dove(&fake, &cfg, &[]);
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_ne!(r.code, 0);
    assert!(r.stdout.contains("permission denied") && r.stdout.contains("sudo dove tailscale setup"), "{}", r.stdout);
    assert!(fake.changes().is_empty());
}

#[test]
fn tailscale_that_is_off_or_missing_is_a_clear_error() {
    let fake = Fake::with_status(json!({ "BackendState": "Stopped", "Self": { "DNSName": format!("{HOST}.") } }));
    let (_d, cfg) = config_file(&config_text());
    let r = dove(&fake, &cfg, &[]);
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("not connected"), "{}", r.stderr);

    let fake = Fake::with_status(
        json!({ "BackendState": "Running", "Self": { "DNSName": format!("{HOST}.") }, "CertDomains": [] }),
    );
    let r = dove(&fake, &cfg, &[]);
    assert!(r.stderr.contains("HTTPS certificates"), "{}", r.stderr);

    // No `tailscale` in PATH at all.
    let empty = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_dove"))
        .env_clear()
        .env("PATH", empty.path())
        .env("DOVE_NO_UPDATE_CHECK", "1")
        .args(["tailscale", "setup", "--dry-run", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("`tailscale` command was not found"));
}

// ------------------------------------------------------------------ doctor

const LISTEN: &str = "127.0.0.1:8787";

async fn check(fake: &Fake, url: &str) -> Option<Value> {
    doctor_check(url, LISTEN, &fake.ts()).await
}

#[tokio::test]
async fn doctor_compares_the_serve_configuration_with_dove_s_public_paths() {
    let fake = Fake::new();
    let (_d, cfg) = config_file(&config_text());
    assert_eq!(dove(&fake, &cfg, &[]).code, 0);
    let url = format!("https://{HOST}");

    let ok = check(&fake, &url).await.unwrap();
    assert_eq!(ok["check"], "tailscale_serve");
    assert_eq!(ok["ok"], true, "{ok}");

    // A missing mount, a wrong target and a leftover path are each reported by name.
    let lines: String = fake
        .file("serve.txt")
        .lines()
        .filter(|l| !l.contains(" /connect/redeem "))
        .map(|l| if l.contains(" /mcp ") { "443 /mcp http://127.0.0.1:9999/mcp".to_string() } else { l.to_string() })
        .chain(["443 /healthz http://127.0.0.1:8787/healthz".to_string()])
        .map(|l| l + "\n")
        .collect();
    std::fs::write(fake.state.path().join("serve.txt"), lines).unwrap();
    let bad = check(&fake, &url).await.unwrap();
    assert_eq!(bad["ok"], false);
    let d = bad["detail"].as_str().unwrap();
    assert!(
        d.contains("missing: /connect/redeem") && d.contains("different target: /mcp") && d.contains("/healthz"),
        "{d}"
    );
    assert!(d.contains("dove tailscale setup"));

    // Funnel on is shown, not failed.
    assert_eq!(dove(&fake, &cfg, &["--funnel"]).code, 0);
    let on = check(&fake, &url).await.unwrap();
    assert_eq!(on["ok"], true);
    assert!(on["detail"].as_str().unwrap().contains("Funnel is ON"));
}

#[tokio::test]
async fn doctor_stays_silent_unless_the_public_url_is_a_tailscale_name() {
    let fake = Fake::new();
    assert!(check(&fake, "https://dove.example.com").await.is_none());
    // No tailscale binary: only a problem when the URL says Tailscale is in use.
    let missing = Tailscale::at("/nonexistent/tailscale");
    assert!(doctor_check("https://dove.example.com", LISTEN, &missing).await.is_none());
    let r = doctor_check(&format!("https://{HOST}"), LISTEN, &missing).await.unwrap();
    assert_eq!(r["ok"], false);
    assert!(r["detail"].as_str().unwrap().contains("not found"), "{r}");
    // The node was renamed since setup.
    let renamed =
        Fake::with_status(json!({ "BackendState": "Running", "Self": { "DNSName": "other.tail1234.ts.net." },
                                            "CertDomains": ["other.tail1234.ts.net"] }));
    let r = check(&renamed, &format!("https://{HOST}")).await.unwrap();
    assert_eq!(r["ok"], false);
    assert!(r["detail"].as_str().unwrap().contains("other.tail1234.ts.net"), "{r}");
}

#[tokio::test]
async fn the_service_doctor_reports_what_the_cli_needs_for_the_tailscale_check() {
    use support::harness::Harness;
    let h = Harness::start().await;
    let mut v = h.admin(dove::admin::AdminRequest::Doctor).await.unwrap();
    let row = v.as_array().unwrap().iter().find(|c| c["check"] == "public_url").cloned().expect("public_url row");
    assert_eq!(row["listen"], h.app().cfg.listen.to_string());
    assert_eq!(row["detail"], h.app().cfg.public_base());
    // Not a tailnet name here: the CLI adds nothing.
    let n = v.as_array().unwrap().len();
    dove::tailscale::add_doctor_check(&mut v, &Fake::new().ts()).await;
    assert_eq!(v.as_array().unwrap().len(), n);
    // With a tailnet name the row is added, built from the service's own address and listener.
    let mut v = json!([{ "check": "public_url", "ok": true, "detail": format!("https://{HOST}"), "listen": LISTEN }]);
    let fake = Fake::new();
    dove::tailscale::add_doctor_check(&mut v, &fake.ts()).await;
    assert_eq!(v.as_array().unwrap().last().unwrap()["check"], "tailscale_serve");
}
