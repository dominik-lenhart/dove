//! Packaging files that cannot be built in a normal test run stay consistent: the Debian unit and the metadata that
//! `cargo deb` reads. (The `.deb` itself is built and inspected by the release workflow.)

// Unix only: checks file modes and runs the Homebrew render script.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The unit's directives: no comments, no blank lines.
fn directives(text: &str) -> Vec<String> {
    text.lines().map(str::trim_end).filter(|l| !l.is_empty() && !l.starts_with('#')).map(str::to_string).collect()
}

fn deb_metadata() -> toml::Table {
    let manifest: toml::Table = std::fs::read_to_string(root().join("Cargo.toml")).unwrap().parse().unwrap();
    manifest["package"]["metadata"]["deb"].as_table().expect("[package.metadata.deb]").clone()
}

/// The package ships deploy/deb/dove.service; it must be the reference unit with only the binary path changed, so a
/// hardening change in deploy/systemd/dove.service cannot silently skip the package.
#[test]
fn deb_unit_is_the_reference_unit_with_the_packaged_binary_path() {
    let reference = std::fs::read_to_string(root().join("deploy/systemd/dove.service")).unwrap();
    let deb = std::fs::read_to_string(root().join("deploy/deb/dove.service")).unwrap();
    let expected: Vec<String> =
        directives(&reference).into_iter().map(|l| l.replace("/usr/local/bin/dove", "/usr/bin/dove")).collect();
    assert_eq!(directives(&deb), expected);
    assert!(
        directives(&deb).iter().any(|l| l.starts_with("ExecStart=/usr/bin/dove ")),
        "ExecStart must use the path the package installs the binary to"
    );
}

/// Every asset source exists (except the binary, which the release build produces), the binary goes to /usr/bin, the
/// maintainer scripts are executable, and the sysusers/tmpfiles snippets are the ones `dove.service` relies on.
#[test]
fn deb_metadata_points_at_existing_files() {
    let deb = deb_metadata();
    let assets = deb["assets"].as_array().unwrap();
    let mut dests = Vec::new();
    for a in assets {
        let a = a.as_array().unwrap();
        let (src, dst) = (a[0].as_str().unwrap(), a[1].as_str().unwrap());
        if src != "target/release/dove" {
            assert!(root().join(src).is_file(), "asset source {src} is missing");
        }
        dests.push((src, dst));
    }
    assert!(dests.contains(&("target/release/dove", "usr/bin/")), "{dests:?}");
    assert!(dests.contains(&("deploy/deb/dove.service", "usr/lib/systemd/system/dove.service")), "{dests:?}");
    assert!(dests.contains(&("deploy/systemd/dove.sysusers.conf", "usr/lib/sysusers.d/dove.conf")), "{dests:?}");
    assert!(dests.contains(&("deploy/systemd/dove.tmpfiles.conf", "usr/lib/tmpfiles.d/dove.conf")), "{dests:?}");

    let scripts = root().join(deb["maintainer-scripts"].as_str().unwrap());
    for name in ["postinst", "prerm", "postrm"] {
        let p = scripts.join(name);
        let mode = std::fs::metadata(&p).unwrap_or_else(|_| panic!("{} is missing", p.display())).permissions().mode();
        assert!(mode & 0o111 != 0, "{} is not executable", p.display());
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.starts_with("#!/bin/sh\n"), "{name} must be POSIX sh");
    }
}

/// The scripts create no secrets: nothing in them writes key material, and the credentials directory stays root-only.
#[test]
fn deb_postinst_creates_no_secrets() {
    let post = std::fs::read_to_string(Path::new(&root()).join("deploy/deb/postinst")).unwrap();
    for needle in ["kek", "pepper", "index_key", "google_client_secret", "proxy_secret", "openssl", "/dev/urandom"] {
        assert!(!post.contains(needle), "postinst mentions {needle}");
    }
    assert!(post.contains("install -d -m 0700 -o root -g root /etc/dove/credentials"));
    assert!(post.contains("install -d -m 0750 -o root -g dove /etc/dove"));
    // Commands only (the next-steps message may name `systemctl enable`): never enable or start the service.
    for line in post.lines().map(str::trim_start) {
        for cmd in ["systemctl enable", "systemctl start", "systemctl restart", "systemctl reenable"] {
            assert!(!line.starts_with(cmd), "postinst runs `{cmd}`");
        }
    }
}

const TARGETS: [(&str, char); 4] = [
    ("aarch64-apple-darwin", 'a'),
    ("x86_64-apple-darwin", 'b'),
    ("aarch64-unknown-linux-gnu", 'c'),
    ("x86_64-unknown-linux-gnu", 'd'),
];

fn render(version: &str, sums: &str) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("SHA256SUMS");
    std::fs::write(&path, sums).unwrap();
    std::process::Command::new("sh")
        .arg(root().join("deploy/homebrew/render.sh"))
        .arg(version)
        .arg(&path)
        .output()
        .unwrap()
}

fn sums_for(version: &str, skip: Option<&str>) -> String {
    let mut s = String::new();
    for (t, c) in TARGETS {
        if Some(t) != skip {
            s += &format!("{}  dove-v{version}-{t}.tar.gz\n", c.to_string().repeat(64));
        }
    }
    // Other assets in the same list (musl, zip, deb) must not confuse the lookup.
    s += &format!("{}  dove-v{version}-x86_64-unknown-linux-musl.tar.gz\n", "e".repeat(64));
    s += &format!("{}  dove-v{version}-x86_64-pc-windows-msvc.zip\n", "f".repeat(64));
    s += &format!("{}  dove_{version}_amd64.deb\n", "0".repeat(64));
    s
}

/// The tap formula pairs every download URL with the checksum of that very archive.
#[test]
fn homebrew_formula_pairs_each_url_with_its_checksum() {
    let out = render("1.2.3", &sums_for("1.2.3", None));
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let formula = String::from_utf8(out.stdout).unwrap();
    assert!(!formula.contains('@'), "unreplaced placeholder:\n{formula}");
    let lines: Vec<&str> = formula.lines().map(str::trim).collect();
    for (target, c) in TARGETS {
        let url = format!(
            "url \"https://github.com/dominik-lenhart/dove/releases/download/v1.2.3/dove-v1.2.3-{target}.tar.gz\""
        );
        let at = lines.iter().position(|l| *l == url).unwrap_or_else(|| panic!("no url for {target}:\n{formula}"));
        assert_eq!(lines[at + 1], format!("sha256 \"{}\"", c.to_string().repeat(64)), "{target}");
    }
}

#[test]
fn homebrew_render_refuses_incomplete_or_odd_input() {
    for (target, _) in TARGETS {
        let out = render("1.2.3", &sums_for("1.2.3", Some(target)));
        assert!(!out.status.success(), "rendered without {target}");
        assert!(String::from_utf8_lossy(&out.stderr).contains(target), "{}", String::from_utf8_lossy(&out.stderr));
    }
    let twice = sums_for("1.2.3", None) + &format!("{}  dove-v1.2.3-x86_64-apple-darwin.tar.gz\n", "9".repeat(64));
    assert!(!render("1.2.3", &twice).status.success());
    assert!(!render("1.2.3", &sums_for("1.2.4", None)).status.success(), "sums of another release");
    assert!(!render("1.2.3-rc.1", &sums_for("1.2.3-rc.1", None)).status.success(), "prereleases are not in the tap");
    let short = sums_for("1.2.3", None).replacen(&"a".repeat(64), &"a".repeat(63), 1);
    assert!(!render("1.2.3", &short).status.success());
}

// ------------------------------------------------------------------ install.sh

/// Fake `curl`, `wget` and `minisign`, written once per process (writing executables while other tests fork races
/// into ETXTBSY). The fetchers log their arguments to `$FAKE_LOG` and serve files from `$FAKE_FILES` by the URL's
/// last segment; minisign prints `$FAKE_MINISIGN_OUT` and succeeds. Nothing touches the network.
fn fake_tools() -> &'static Path {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let fetcher = r#"#!/bin/sh
printf '%s\n' "$0 $*" >> "$FAKE_LOG"
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o | -O) out="$2"; shift 2 ;;
    *) url="$1"; shift ;;
  esac
done
cp "$FAKE_FILES/${url##*/}" "$out"
"#;
        for (name, body) in
            [("curl", fetcher), ("wget", fetcher), ("minisign", "#!/bin/sh\nprintf '%s\\n' \"$FAKE_MINISIGN_OUT\"\n")]
        {
            let p = dir.path().join(name);
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        dir
    })
    .path()
}

/// A PATH directory holding the system tools install.sh needs plus the chosen fakes (and nothing else, so the
/// script cannot fall back to a real curl or minisign).
fn tool_path(dir: &Path, fakes: &[&str]) -> PathBuf {
    let bin = dir.join("bin");
    std::fs::create_dir(&bin).unwrap();
    let system = [
        "sh",
        "mktemp",
        "rm",
        "awk",
        "wc",
        "sha256sum",
        "shasum",
        "tar",
        "gzip",
        "mkdir",
        "cp",
        "chmod",
        "mv",
        "cut",
        "grep",
        "tr",
        "sed",
        "tail",
        "uname",
        "id",
        "cat",
        "printf",
    ];
    for tool in system {
        if let Some(p) = ["/usr/bin", "/bin"].iter().map(|d| Path::new(d).join(tool)).find(|p| p.exists()) {
            std::os::unix::fs::symlink(p, bin.join(tool)).unwrap();
        }
    }
    for f in fakes {
        std::os::unix::fs::symlink(fake_tools().join(f), bin.join(f)).unwrap();
    }
    bin
}

struct InstallRun {
    ok: bool,
    stderr: String,
    log: String,
    installed: Option<Vec<u8>>,
}

/// Runs install.sh for `version` against a fake release with the given fetcher and minisign output.
fn run_install_sh(version: &str, fakes: &[&str], minisign_out: &str) -> InstallRun {
    let dir = tempfile::tempdir().unwrap();
    let target = match std::env::consts::OS {
        "linux" => format!("{}-unknown-linux-gnu", std::env::consts::ARCH),
        "macos" => format!("{}-apple-darwin", std::env::consts::ARCH),
        os => panic!("unsupported test platform {os}"),
    };
    let name = format!("dove-v{version}-{target}");
    let files = dir.path().join("files");
    std::fs::create_dir_all(files.join(&name)).unwrap();
    std::fs::write(files.join(&name).join("dove"), b"fake dove binary").unwrap();
    let tar = std::process::Command::new("tar")
        .args(["-czf", &format!("{name}.tar.gz"), &format!("{name}/dove")])
        .current_dir(&files)
        .status()
        .unwrap();
    assert!(tar.success());
    use sha2::Digest;
    let sum = sha2::Sha256::digest(std::fs::read(files.join(format!("{name}.tar.gz"))).unwrap());
    let hex: String = sum.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(files.join("SHA256SUMS"), format!("{hex}  {name}.tar.gz\n")).unwrap();
    std::fs::write(files.join("SHA256SUMS.minisig"), "untrusted comment: fake\n").unwrap();
    let bin = tool_path(dir.path(), fakes);
    let (log, dest) = (dir.path().join("log"), dir.path().join("dest"));
    let out = std::process::Command::new("/bin/sh")
        .arg(root().join("install.sh"))
        .env_clear()
        .env("PATH", &bin)
        .env("HOME", dir.path())
        .env("TMPDIR", dir.path())
        .env("DOVE_VERSION", version)
        .env("DOVE_LIBC", "gnu")
        .env("DOVE_INSTALL_DIR", &dest)
        .env("FAKE_LOG", &log)
        .env("FAKE_FILES", &files)
        .env("FAKE_MINISIGN_OUT", minisign_out)
        .output()
        .unwrap();
    InstallRun {
        ok: out.status.success(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        log: std::fs::read_to_string(&log).unwrap_or_default(),
        installed: std::fs::read(dest.join("dove")).ok(),
    }
}

/// minisign's trusted comment must be exactly `dove <tag>`: a signature of another release whose comment merely
/// contains the tag (a release candidate of the same version, a longer version) is refused.
#[test]
fn install_sh_requires_the_exact_trusted_comment() {
    let verified = "Signature and comment signature verified";
    let ok = run_install_sh("1.2.3", &["curl", "minisign"], &format!("{verified}\nTrusted comment: dove v1.2.3"));
    assert!(ok.ok, "{}", ok.stderr);
    assert_eq!(ok.installed.as_deref(), Some(&b"fake dove binary"[..]));
    for replayed in ["dove v1.2.3-rc.1", "dove v1.2.30", "dove v1.2.3 extra", "xdove v1.2.3"] {
        let r = run_install_sh("1.2.3", &["curl", "minisign"], &format!("{verified}\nTrusted comment: {replayed}"));
        assert!(!r.ok, "accepted '{replayed}'");
        assert!(r.stderr.contains("not for dove v1.2.3"), "{replayed}: {}", r.stderr);
        assert!(r.installed.is_none(), "{replayed}");
    }
}

/// Without curl the wget fallback refuses plain HTTP (a redirect to http:// included).
#[test]
fn install_sh_wget_fallback_is_https_only() {
    let r = run_install_sh("1.2.3", &["wget"], "");
    assert!(r.ok, "{}", r.stderr);
    let calls: Vec<&str> = r.log.lines().collect();
    assert_eq!(calls.len(), 3, "{}", r.log);
    for c in calls {
        assert!(c.contains("/wget ") && c.contains(" --https-only "), "{c}");
        assert!(c.contains(" https://github.com/dominik-lenhart/dove/releases/download/v1.2.3/"), "{c}");
    }
}

/// install.ps1 cannot run here (no PowerShell); keep its trusted-comment check an exact line comparison.
#[test]
fn install_ps1_compares_the_whole_trusted_comment_line() {
    let ps1 = std::fs::read_to_string(root().join("install.ps1")).unwrap();
    assert!(ps1.contains(r#"-ccontains "Trusted comment: dove $tag""#), "exact line check missing");
    assert!(!ps1.contains(r#".Contains("dove $tag")"#), "substring check is back");
}
