//! Packaging files that cannot be built in a normal test run stay consistent: the Debian unit and the metadata that
//! `cargo deb` reads. (The `.deb` itself is built and inspected by the release workflow.)

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
