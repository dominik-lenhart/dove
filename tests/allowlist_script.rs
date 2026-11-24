//! `deploy/nginx/dove-allowlist.py` writes the `geo` block that decides who reaches `/mcp` and the OAuth machine
//! endpoints behind the restricted nginx/Angie setup. These tests run the real script with `python3`: what it renders,
//! that it refuses ranges that would open the endpoints to everyone, and that a failed config test or a refused
//! answer leaves the previous allowlist in place. The OpenAI download is replaced by a stub in the test process; no
//! test reaches the network.

// Unix only: runs python3 and shell tools.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy/nginx/dove-allowlist.py")
}

/// Runs the script's `main` with `args`. With `openai = Some(json)`, `urllib.request.urlopen` answers that body;
/// without it, any download fails the test (callers then pass `--no-openai`).
fn run(args: &[&str], openai: Option<&str>) -> Output {
    let stub = match openai {
        Some(body) => format!(
            "class R:\n    status = 200\n    def __enter__(self): return self\n    def __exit__(self, *a): return False\n    \
             def read(self, n=-1): return {body:?}.encode()\n\
             urllib.request.urlopen = lambda req, timeout=None: R()\n"
        ),
        None => "def _no(*a, **k): raise AssertionError('network access')\nurllib.request.urlopen = _no\n".into(),
    };
    let prog = format!(
        "import importlib.util, sys, urllib.request\n\
         spec = importlib.util.spec_from_file_location('allow', sys.argv[1])\n\
         m = importlib.util.module_from_spec(spec)\n\
         spec.loader.exec_module(m)\n\
         {stub}\
         sys.argv = ['dove-allowlist.py'] + sys.argv[2:]\n\
         try:\n    code = m.main()\n\
         except Exception as e:\n    print(f'dove-allowlist: {{e}}', file=sys.stderr)\n    code = 1\n\
         sys.exit(code)\n"
    );
    Command::new("python3")
        .arg("-I")
        .arg("-B")
        .arg("-c")
        .arg(prog)
        .arg(script())
        .args(args)
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("python3 must be installed to run these tests")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn geo_entries(text: &str) -> Vec<String> {
    text.lines().map(str::trim).filter(|l| l.ends_with(" 1;")).map(|l| l.trim_end_matches(" 1;").to_string()).collect()
}

fn write(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
}

const OPENAI_OK: &str =
    r#"{"prefixes": [{"ipv4Prefix": "23.102.140.112/28"}, {"ipv6Prefix": "2603:1030:a0b::/48"}, {"other": "x"}]}"#;

/// The rendered block allows exactly Anthropic's ranges, the published OpenAI prefixes and the operator's extras,
/// each once, and denies everything else by default. Extras may be private (the host's own LAN or Tailscale address).
#[test]
fn renders_anthropic_openai_and_extra_prefixes_once_with_default_deny() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("dove_allow.conf");
    let extra = dir.path().join("extra.txt");
    write(&extra, "# own addresses\n100.64.0.7/32  # tailscale\n\n160.79.104.0/21\n10.1.2.0/24\n");

    let o = run(&["--out", out.to_str().unwrap(), "--extra", extra.to_str().unwrap()], Some(OPENAI_OK));
    assert!(o.status.success(), "{}", stderr(&o));
    let text = std::fs::read_to_string(&out).unwrap();

    assert!(text.contains("geo $dove_ip_ok {\n    default 0;\n"), "{text}");
    assert!(text.trim_end().ends_with('}'), "{text}");
    assert_eq!(
        geo_entries(&text),
        [
            "160.79.104.0/21",
            "153.61.208.0/20",
            "23.102.140.112/28",
            "2603:1030:a0b::/48",
            "100.64.0.7/32",
            "10.1.2.0/24",
        ],
        "an Anthropic range repeated in the extras must appear once"
    );
}

/// A second run with the same input does not touch the file (no rewrite, no reload).
#[test]
fn an_unchanged_allowlist_is_not_rewritten_or_reloaded() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("dove_allow.conf");
    let marker = dir.path().join("reloaded");
    let reload = format!("touch {}", marker.display());

    let o = run(&["--out", out.to_str().unwrap(), "--no-openai", "--reload", &reload], None);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(marker.exists(), "the first run writes and reloads");
    std::fs::remove_file(&marker).unwrap();

    let o = run(&["--out", out.to_str().unwrap(), "--no-openai", "--reload", &reload], None);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(!marker.exists(), "an identical allowlist must not trigger a reload");
}

/// A broken or hostile OpenAI answer must never widen the allowlist: too wide, non-public or empty answers fail the
/// run and the previous file stays byte for byte.
#[test]
fn refused_openai_answers_keep_the_previous_allowlist() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("dove_allow.conf");
    write(&out, "previous\n");

    for (body, why) in [
        (r#"{"prefixes": [{"ipv4Prefix": "0.0.0.0/0"}]}"#, "implausibly wide"),
        (r#"{"prefixes": [{"ipv4Prefix": "23.0.0.0/11"}]}"#, "implausibly wide"),
        (r#"{"prefixes": [{"ipv6Prefix": "2603::/16"}]}"#, "implausibly wide"),
        (r#"{"prefixes": [{"ipv4Prefix": "10.0.0.0/16"}]}"#, "not a public address range"),
        (r#"{"prefixes": [{"ipv4Prefix": "127.0.0.0/24"}]}"#, "not a public address range"),
        (r#"{"prefixes": []}"#, "no prefixes"),
        (r#"{"prefixes": [{"ipv4Prefix": "not-an-ip"}]}"#, "does not appear to be"),
    ] {
        let o = run(&["--out", out.to_str().unwrap()], Some(body));
        assert!(!o.status.success(), "{body} must fail the run");
        assert!(stderr(&o).contains(why), "{body}: {}", stderr(&o));
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "previous\n", "{body} changed the file");
    }
}

/// The width limit applies to the operator's extras too, so a typo such as `/8` cannot open the endpoints.
#[test]
fn a_too_wide_extra_prefix_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("dove_allow.conf");
    let extra = dir.path().join("extra.txt");
    write(&extra, "100.0.0.0/8\n");
    write(&out, "previous\n");

    let o = run(&["--out", out.to_str().unwrap(), "--no-openai", "--extra", extra.to_str().unwrap()], None);
    assert!(!o.status.success());
    assert!(stderr(&o).contains("implausibly wide"), "{}", stderr(&o));
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "previous\n");
}

/// When the proxy's config test fails, the previous allowlist is restored (or the new file removed when there was
/// none), and the reload never runs.
#[test]
fn a_failed_config_test_restores_the_previous_allowlist_and_skips_the_reload() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("reloaded");
    let reload = format!("touch {}", marker.display());

    let out = dir.path().join("dove_allow.conf");
    write(&out, "previous\n");
    let o = run(&["--out", out.to_str().unwrap(), "--no-openai", "--test", "false", "--reload", &reload], None);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stderr(&o).contains("previous allowlist was restored"), "{}", stderr(&o));
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "previous\n");
    assert!(!marker.exists(), "the reload must not run after a failed config test");

    let fresh = dir.path().join("fresh.conf");
    let o = run(&["--out", fresh.to_str().unwrap(), "--no-openai", "--test", "false"], None);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(!fresh.exists(), "a new allowlist must be removed when the config test fails");
}
