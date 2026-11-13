//! The admin channel's transport and peer identity.
//!
//! Unix: a Unix socket (mode 0660 in a directory only the service and the operator group can enter); the peer is
//! the connecting process's uid from `SO_PEERCRED`/`getpeereid`. Windows (PLAN A58): a named pipe whose DACL grants
//! access to the service's own user only, created as the first instance (a pipe another user created first makes
//! startup fail); the peer is the user SID of the client process (`GetNamedPipeClientProcessId` → process token).
//! The CLI checks the server's SID the same way before it sends a request. Admin never goes over HTTP.

#[cfg(unix)]
use std::path::Path;

#[cfg(unix)]
use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite};

/// Who is on the other end of an admin connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peer {
    /// Unix: the peer's uid.
    Uid(u32),
    /// Windows: the client's user SID and the service's own user SID.
    Sid { client: String, service: String },
    /// The identity could not be determined; never allowed.
    Unknown,
}

impl Peer {
    /// The audit actor name.
    pub fn label(&self) -> String {
        match self {
            Peer::Uid(uid) => format!("uid:{uid}"),
            Peer::Sid { client, .. } => format!("sid:{client}"),
            Peer::Unknown => "unknown".into(),
        }
    }
}

/// Whether the CLI may send a request to the admin pipe's server (Windows, P2): it must run as the same user, at an
/// integrity level at least the client's. A low-integrity (sandboxed) process of the same user could otherwise create
/// the pipe first and collect admin requests, IMAP passwords included. Kept platform-independent so it is tested
/// everywhere.
pub fn server_ok(server_sid: &str, server_integrity: u32, my_sid: &str, my_integrity: u32) -> Result<(), String> {
    if server_sid.is_empty() || server_sid != my_sid {
        return Err(format!("it is served by another Windows user ({server_sid})"));
    }
    if server_integrity < my_integrity {
        return Err(format!(
            "it is served at a lower integrity level ({server_integrity:#x}) than this program ({my_integrity:#x})"
        ));
    }
    Ok(())
}

/// A connected admin stream.
pub trait AdminStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> AdminStream for T {}

#[cfg(unix)]
pub struct Listener(tokio::net::UnixListener);

#[cfg(unix)]
impl Listener {
    pub async fn accept(&mut self) -> std::io::Result<(Box<dyn AdminStream>, Peer)> {
        let (stream, _) = self.0.accept().await?;
        let peer = match stream.peer_cred() {
            Ok(c) => Peer::Uid(c.uid()),
            Err(e) => {
                tracing::warn!(error = %e, "cannot read admin peer credentials");
                Peer::Unknown
            }
        };
        Ok((Box::new(stream), peer))
    }
}

/// Binds the admin socket with mode 0660. The directory is expected to be owned by the service user and the
/// operator group (for example systemd `RuntimeDirectory=dove` with `RuntimeDirectoryMode=0750`).
#[cfg(unix)]
pub fn bind(path: &Path) -> anyhow::Result<Listener> {
    use std::os::unix::fs::PermissionsExt;
    if path.exists() {
        // Only a stale socket is removed: when something still answers there, this is a second instance, and
        // unlinking would cut the running service off from its admin channel (L1).
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            anyhow::bail!(
                "another Dove instance is already running with the admin socket {} (stop it first)",
                path.display()
            );
        }
        std::fs::remove_file(path).with_context(|| format!("cannot remove stale socket {}", path.display()))?;
    }
    let listener =
        tokio::net::UnixListener::bind(path).with_context(|| format!("cannot bind admin socket {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(Listener(listener))
}

/// Connects to the admin socket.
#[cfg(unix)]
pub async fn connect(socket: &Path) -> anyhow::Result<Box<dyn AdminStream>> {
    let stream = tokio::net::UnixStream::connect(socket).await.with_context(|| {
        format!(
            "cannot connect to the admin socket {} (is the service running and are you the operator?)",
            socket.display()
        )
    })?;
    Ok(Box::new(stream))
}

#[cfg(windows)]
pub use self::pipe::{Listener, bind, connect};

#[cfg(windows)]
mod pipe {
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    use anyhow::{Context, bail};
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};

    use super::{AdminStream, Peer};
    use crate::platform::windows::{self as win, SecurityDescriptor};

    const ERROR_PIPE_BUSY: i32 = 231;

    pub struct Listener {
        name: String,
        service_sid: String,
        sd: SecurityDescriptor,
        /// The instance waiting for the next client; `None` after creating it failed (P3). The pipe name may then
        /// lapse once the connected client is done, so the next accept creates it again as the *first* instance:
        /// joining a pipe someone else created in the meantime would hand them part of our clients.
        next: Option<NamedPipeServer>,
        #[cfg(test)]
        pub(crate) fail_next_create: bool,
    }

    /// The pipe's DACL: full access for the service's user, nothing for anyone else (the default DACL of a pipe
    /// would give Everyone read access).
    fn descriptor(sid: &str) -> anyhow::Result<SecurityDescriptor> {
        SecurityDescriptor::from_sddl(&format!("D:P(A;;GA;;;{sid})")).context("cannot build the admin pipe DACL")
    }

    fn create(name: &str, sd: &SecurityDescriptor, first: bool) -> std::io::Result<NamedPipeServer> {
        let mut sa = sd.attributes();
        let mut opts = ServerOptions::new();
        opts.first_pipe_instance(first).reject_remote_clients(true);
        // SAFETY: `sa` points at a live security descriptor for the duration of the call.
        unsafe { opts.create_with_security_attributes_raw(name, &mut sa as *mut _ as *mut std::ffi::c_void) }
    }

    pub fn bind(path: &Path) -> anyhow::Result<Listener> {
        let name = path.to_string_lossy().into_owned();
        if !name.starts_with(r"\\.\pipe\") {
            bail!(r"admin.socket_path must be a pipe name like \\.\pipe\dove-admin-<SID> on Windows");
        }
        let service_sid = win::current_user_sid()?.to_string_sid()?;
        let sd = descriptor(&service_sid)?;
        let next = create(&name, &sd, true).with_context(|| {
            format!(
                "cannot create the admin pipe {name} (is Dove already running, or did another program take the name?)"
            )
        })?;
        Ok(Listener {
            name,
            service_sid,
            sd,
            next: Some(next),
            #[cfg(test)]
            fail_next_create: false,
        })
    }

    impl Listener {
        fn create_next(&mut self, first: bool) -> std::io::Result<NamedPipeServer> {
            #[cfg(test)]
            if std::mem::take(&mut self.fail_next_create) {
                return Err(std::io::Error::other("injected failure"));
            }
            create(&self.name, &self.sd, first)
        }

        pub async fn accept(&mut self) -> std::io::Result<(Box<dyn AdminStream>, Peer)> {
            let waiting = match self.next.take() {
                Some(s) => s,
                // Fails while an earlier client is still connected (the serve loop retries) or when another process
                // took the name: then nothing is served rather than a shared pipe.
                None => self.create_next(true)?,
            };
            waiting.connect().await?;
            // The connected client is served even when the next instance cannot be created now (P3): it would
            // otherwise hang until it times out. The next accept tries again.
            self.next = match self.create_next(false) {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!(error = %e, "cannot create the next admin pipe instance; retrying on the next accept");
                    None
                }
            };
            let connected = waiting;
            let peer = match win::pipe_client_sid(connected.as_raw_handle()).and_then(|s| s.to_string_sid()) {
                Ok(client) => Peer::Sid { client, service: self.service_sid.clone() },
                Err(e) => {
                    tracing::warn!(error = %e, "cannot read the admin pipe client's identity");
                    Peer::Unknown
                }
            };
            Ok((Box::new(connected), peer))
        }

        /// The handle of the instance waiting for the next client (tests inspect its DACL).
        #[cfg(test)]
        pub(crate) fn raw_handle(&self) -> std::os::windows::io::RawHandle {
            self.next.as_ref().expect("a waiting instance").as_raw_handle()
        }
    }

    pub async fn connect(socket: &Path) -> anyhow::Result<Box<dyn AdminStream>> {
        let name = socket.to_string_lossy().into_owned();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let client = loop {
            match ClientOptions::new().open(&name) {
                Ok(c) => break c,
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("cannot connect to the admin pipe {name} (is Dove running as this Windows user?)")
                    });
                }
            }
        };
        // Never talk to a pipe another user, or a lower-integrity process of this user, created under our name: it
        // could collect a mailbox password (P2).
        let server =
            win::pipe_server_identity(client.as_raw_handle()).context("cannot identify the admin pipe's owner")?;
        let me = win::current_identity()?;
        if let Err(why) =
            super::server_ok(&server.sid.to_string_sid()?, server.integrity, &me.sid.to_string_sid()?, me.integrity)
        {
            bail!("refusing to use the admin pipe {name}: {why}");
        }
        Ok(Box::new(client))
    }
}

#[cfg(test)]
mod tests {
    use super::server_ok;

    const ME: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    const MEDIUM: u32 = 0x2000;

    /// The CLI's check of the admin pipe's server (P2): same user and at least the client's integrity level.
    #[test]
    fn pipe_server_must_be_the_same_user_at_no_lower_integrity() {
        server_ok(ME, MEDIUM, ME, MEDIUM).unwrap();
        server_ok(ME, 0x3000, ME, MEDIUM).unwrap();
        let other = server_ok("S-1-5-21-1111111111-2222222222-3333333333-1002", MEDIUM, ME, MEDIUM).unwrap_err();
        assert!(other.contains("another Windows user"), "{other}");
        assert!(server_ok("", MEDIUM, "", MEDIUM).is_err());
        let low = server_ok(ME, 0x1000, ME, MEDIUM).unwrap_err();
        assert!(low.contains("lower integrity"), "{low}");
        assert!(server_ok(ME, MEDIUM, ME, 0x3000).is_err(), "an elevated CLI never talks to a medium pipe server");
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;

    /// A second bind on a live socket is refused and leaves the running listener reachable; a stale socket file (no
    /// listener) is replaced (L1).
    #[tokio::test]
    async fn a_live_socket_is_never_unlinked() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("admin.sock");
        let _live = bind(&path).unwrap();
        let err = bind(&path).err().unwrap().to_string();
        assert!(err.contains("already running"), "{err}");
        tokio::net::UnixStream::connect(&path).await.expect("the first instance keeps its socket");

        let stale = d.path().join("stale.sock");
        drop(bind(&stale).unwrap());
        assert!(stale.exists());
        let _l = bind(&stale).unwrap();
        tokio::net::UnixStream::connect(&stale).await.unwrap();
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::sync::Arc;

    use super::*;
    use crate::admin::{AdminRequest, client};
    use crate::platform::windows as win;

    fn env_with_pipe() -> (crate::testing::TestEnv, std::path::PathBuf) {
        let name = std::path::PathBuf::from(format!(r"\\.\pipe\dove-test-{}", crate::util::new_id()));
        let n = name.clone();
        (crate::testing::TestEnv::with(move |c| c.admin.socket_path = n), name)
    }

    /// The pipe's DACL lets in exactly the service's user: no Everyone/anonymous read as with a default pipe DACL.
    #[tokio::test]
    async fn pipe_dacl_grants_only_the_service_user() {
        let (_env, name) = env_with_pipe();
        let l = bind(&name).unwrap();
        let me = win::current_user_sid().unwrap().to_string_sid().unwrap();
        assert_eq!(win::handle_allowed_sids(l.raw_handle()).unwrap(), Some(vec![me]));
    }

    /// Another process (or user) cannot create the pipe first and wait for requests: binding an existing name fails.
    #[tokio::test]
    async fn an_existing_pipe_name_is_refused() {
        let (_env, name) = env_with_pipe();
        let _first = bind(&name).unwrap();
        let err = bind(&name).err().unwrap();
        assert!(format!("{err:#}").contains("cannot create the admin pipe"), "{err:#}");
    }

    /// End to end over a real pipe: the client checks the server's SID, the server reads the client's SID from its
    /// process token, and the audit actor names it.
    #[tokio::test]
    async fn the_service_user_administers_over_the_pipe() {
        let (env, name) = env_with_pipe();
        let app: Arc<_> = env.app.clone();
        let l = bind(&name).unwrap();
        let task = tokio::spawn(crate::admin::server::serve(app.clone(), l));
        let v = client::send(&name, &AdminRequest::Version).await.unwrap();
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
        // Several connections in a row: a fresh instance waits for each next client.
        for i in 0..3 {
            client::send(&name, &AdminRequest::ProjectsCreate { name: format!("p{i}") }).await.unwrap();
        }
        let tail = app.store.call(|c| crate::audit::tail(c, 1)).await.unwrap();
        task.abort();
        let me = win::current_user_sid().unwrap().to_string_sid().unwrap();
        assert_eq!(serde_json::to_value(tail).unwrap()[0]["actor"], format!("sid:{me}"));
    }

    /// When the next pipe instance cannot be created after a client connected, that client is still served, and the
    /// listener recovers on the next accept (P3).
    #[tokio::test]
    async fn a_client_is_served_when_the_next_instance_fails() {
        let (env, name) = env_with_pipe();
        let mut l = bind(&name).unwrap();
        l.fail_next_create = true;
        let task = tokio::spawn(crate::admin::server::serve(env.app.clone(), l));
        let v = tokio::time::timeout(std::time::Duration::from_secs(10), client::send(&name, &AdminRequest::Version))
            .await
            .expect("the connected client must not hang")
            .unwrap();
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
        // The listener creates the pipe again (as the first instance, once the earlier connection is gone).
        let mut again = None;
        for _ in 0..50 {
            match client::send(&name, &AdminRequest::Version).await {
                Ok(v) => {
                    again = Some(v);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
            }
        }
        assert_eq!(again.expect("the listener recovers")["version"], env!("CARGO_PKG_VERSION"));
        task.abort();
    }
}
