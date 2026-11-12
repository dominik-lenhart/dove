//! AC19: an agent shell running under a different OS user cannot use admin verbs, even with a misconfigured,
//! world-accessible socket, and cannot read service state or secrets. The positive case runs as the operator uid.
//!
//! Needs a real second uid: runs the actual `dove` binary as `nobody` via passwordless `sudo -n -u nobody`.
//! Ignored by default; run with `cargo test --test agent_shell -- --ignored` on a host that allows it.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use dove::admin::server;
use dove::testing::TestEnv;

const EXIT_NOT_RUN: &str = "sudo -n -u nobody is not available on this host";

fn sudo_nobody_available() -> bool {
    Command::new("sudo").args(["-n", "-u", "nobody", "true"]).status().is_ok_and(|s| s.success())
}

/// A copy of the CLI that `nobody` can execute (the build tree is under a private home directory).
fn public_binary(dir: &Path) -> PathBuf {
    let bin = dir.join("dove");
    std::fs::copy(env!("CARGO_BIN_EXE_dove"), &bin).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

fn run(as_nobody: bool, bin: &Path, socket: &Path, args: &[&str]) -> (bool, String) {
    let mut cmd = if as_nobody {
        let mut c = Command::new("sudo");
        c.args(["-n", "-u", "nobody", "--"]).arg(bin);
        c
    } else {
        Command::new(bin)
    };
    let out =
        cmd.args(args).arg("--socket").arg(socket).arg("--json").env_remove("DOVE_ADMIN_SOCKET").output().unwrap();
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs passwordless sudo to run as nobody"]
async fn agent_uid_cannot_administer_or_read_service_state() {
    assert!(sudo_nobody_available(), "{EXIT_NOT_RUN}");
    // Operator uid = the uid running this test; the agent is `nobody`.
    let env = TestEnv::new();
    env.add_account("info", "info@acme.test", "1//fake-refresh");
    // Public scratch area: the binary and a deliberately world-accessible socket (worst-case misconfiguration).
    let public = tempfile::Builder::new().prefix("dove-ac19-").tempdir_in("/tmp").unwrap();
    std::fs::set_permissions(public.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let bin = public_binary(public.path());
    let socket = public.path().join("admin.sock");
    let listener = server::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).unwrap();
    let srv = tokio::spawn(server::serve(env.app.clone(), listener));

    // Operator: set up a project and a draft-only agent token.
    let (ok, out) = run(false, &bin, &socket, &["projects", "create", "acme"]);
    assert!(ok, "{out}");
    let (ok, out) = run(false, &bin, &socket, &["projects", "add-account", "acme", "info"]);
    assert!(ok, "{out}");
    let (ok, out) =
        run(false, &bin, &socket, &["clients", "create", "--project", "acme", "--grant", "info=read,draft", "agent"]);
    assert!(ok, "{out}");

    let snapshot = |env: &TestEnv| {
        env.app
            .store
            .call_blocking(|c| {
                let grants: String = c.query_row(
                    "SELECT group_concat(client_id || ':' || account_id || ':' || actions, ';') FROM client_mailboxes",
                    [],
                    |r| r.get::<_, Option<String>>(0).map(Option::unwrap_or_default),
                )?;
                let clients: i64 = c.query_row("SELECT count(*) FROM clients", [], |r| r.get(0))?;
                Ok((grants, clients))
            })
            .unwrap()
    };
    let before = snapshot(&env);

    // Agent uid: every escalation path through the supported CLI fails and changes nothing.
    let attempts: &[&[&str]] = &[
        &["clients", "set-grants", "--grant", "info=read,draft,send", "agent"],
        &["clients", "create", "--project", "acme", "--grant", "info=read,draft,send", "stronger"],
        &["clients", "create", "--project", "acme", "--grant", "info=read,draft", "another"],
        &["clients", "rotate", "agent"],
        &["clients", "list"],
        &["projects", "add-account", "acme", "info"],
        &["audit", "tail"],
        &["keys", "rotate"],
    ];
    for args in attempts {
        let (ok, out) = run(true, &bin, &socket, args);
        assert!(!ok, "{args:?} succeeded as nobody: {out}");
        assert!(out.to_lowercase().contains("denied") || out.to_lowercase().contains("not allowed"), "{args:?}: {out}");
    }
    assert_eq!(snapshot(&env), before, "denied attempts must not change state");
    let denied: i64 = env
        .app
        .store
        .call_blocking(|c| {
            Ok(c.query_row("SELECT count(*) FROM audit WHERE tool_or_action = 'admin.denied'", [], |r| r.get(0))?)
        })
        .unwrap();
    assert_eq!(denied, attempts.len() as i64, "each denied attempt is audited");

    // The agent uid cannot read the state store, secrets or config of the service.
    for p in
        [env.app.cfg.state_db_path(), env.app.cfg.secrets.kek_file.clone(), env.app.cfg.secrets.pepper_file.clone()]
    {
        let out = Command::new("sudo").args(["-n", "-u", "nobody", "--", "cat"]).arg(&p).output().unwrap();
        assert!(!out.status.success(), "nobody could read {}", p.display());
    }

    // Positive control: the operator uid still administers.
    let (ok, out) = run(false, &bin, &socket, &["clients", "list"]);
    assert!(ok && out.contains("agent"), "{out}");
    srv.abort();
}
