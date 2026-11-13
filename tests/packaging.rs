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
