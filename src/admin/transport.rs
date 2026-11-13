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
        next: NamedPipeServer,
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
        Ok(Listener { name, service_sid, sd, next })
    }

    impl Listener {
        pub async fn accept(&mut self) -> std::io::Result<(Box<dyn AdminStream>, Peer)> {
            self.next.connect().await?;
            let fresh = create(&self.name, &self.sd, false)?;
            let connected = std::mem::replace(&mut self.next, fresh);
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
            self.next.as_raw_handle()
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
        // Never talk to a pipe another user created under our name (it could collect a mailbox password).
        let server = win::pipe_server_sid(client.as_raw_handle()).context("cannot identify the admin pipe's owner")?;
        if server != win::current_user_sid()? {
            bail!("the admin pipe {name} is served by another Windows user; refusing to use it");
        }
        Ok(Box::new(client))
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
        let me = win::current_user_sid().unwrap().to_string_sid().unwrap();
        assert_eq!(serde_json::to_value(tail).unwrap()[0]["actor"], format!("sid:{me}"));
        task.abort();
    }
}
