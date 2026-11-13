//! Command-line interface. Admin subcommands talk to the local admin socket; `serve` runs the service.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use serde_json::Value;

use crate::admin::{AdminRequest, client as admin_client, ops::parse_grant_args};
use crate::audit::SearchFilter;
use crate::config;

#[derive(Parser)]
#[command(name = "dove", version, about = "Dove: a self-hosted mail MCP server for AI agents")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Args, Clone)]
pub struct AdminOpts {
    /// Admin socket (Windows: pipe) of the local service. Access is decided by the service from your OS user. Default:
    /// /run/dove/admin.sock when it exists, else the one in the local-mode config (`dove local init`).
    #[arg(long, global = true, env = "DOVE_ADMIN_SOCKET")]
    pub socket: Option<PathBuf>,
    /// Print raw JSON.
    #[arg(long, global = true)]
    pub json: bool,
}

impl AdminOpts {
    /// The admin endpoint for this command (see [`resolve_admin_socket`]).
    pub fn target(&self) -> anyhow::Result<AdminTarget> {
        resolve_admin_socket(self.socket.clone())
    }
}

/// Which Dove instance an admin command talks to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminTarget {
    /// `--socket` / `DOVE_ADMIN_SOCKET`.
    Explicit(PathBuf),
    /// The server-mode service (`/run/dove/admin.sock`, or the default when nothing else is found).
    Server(PathBuf),
    /// This user's local-mode instance (`dove local init`).
    Local(PathBuf),
}

impl AdminTarget {
    pub fn path(&self) -> &std::path::Path {
        match self {
            AdminTarget::Explicit(p) | AdminTarget::Server(p) | AdminTarget::Local(p) => p,
        }
    }

    /// The stderr line naming the instance that answered (L3).
    pub fn answered_by(&self) -> String {
        match self {
            AdminTarget::Explicit(p) => format!("dove: answered by the admin socket {}", p.display()),
            AdminTarget::Server(p) => format!("dove: answered by the server instance ({})", p.display()),
            AdminTarget::Local(p) => format!("dove: answered by your local instance ({})", p.display()),
        }
    }
}

/// The admin endpoint from the environment: `--socket`/`DOVE_ADMIN_SOCKET`, else the server-mode socket or this
/// user's local-mode instance, refusing to guess when both exist.
pub fn resolve_admin_socket(explicit: Option<PathBuf>) -> anyhow::Result<AdminTarget> {
    #[cfg(unix)]
    let server = std::path::Path::new(config::DEFAULT_ADMIN_SOCKET).exists();
    #[cfg(windows)]
    let server = false;
    let local = crate::platform::paths::local_paths().ok().filter(|p| p.config_file.exists()).map(|paths| {
        config::Config::load(&paths.config_file).map(|c| c.admin.socket_path).unwrap_or_else(|_| paths.admin_socket())
    });
    choose_admin_socket(explicit, server, local, default_server_socket())
}

fn default_server_socket() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from(config::DEFAULT_ADMIN_SOCKET)
    }
    #[cfg(windows)]
    {
        PathBuf::from(crate::platform::paths::default_admin_pipe())
    }
}

/// The decision behind [`resolve_admin_socket`]: an explicit socket wins; a visible server-mode socket and a local
/// config together are ambiguous and refused (L3: an admin command must never switch instances silently); else
/// whichever exists; else the server default.
pub fn choose_admin_socket(
    explicit: Option<PathBuf>,
    server_socket_exists: bool,
    local_socket: Option<PathBuf>,
    server_default: PathBuf,
) -> anyhow::Result<AdminTarget> {
    Ok(match (explicit, server_socket_exists, local_socket) {
        (Some(p), _, _) => AdminTarget::Explicit(p),
        (None, true, Some(local)) => anyhow::bail!(
            "both a server-mode Dove ({}) and your local-mode Dove ({}) are present; choose one with --socket",
            server_default.display(),
            local.display()
        ),
        (None, true, None) => AdminTarget::Server(server_default),
        (None, false, Some(local)) => AdminTarget::Local(local),
        (None, false, None) => AdminTarget::Server(server_default),
    })
}

/// Sends one admin request and names the instance that answered on stderr.
async fn admin_send(admin: &AdminOpts, req: &AdminRequest) -> anyhow::Result<Value> {
    let target = admin.target()?;
    let v = admin_client::send(target.path(), req).await?;
    eprintln!("{}", target.answered_by());
    Ok(v)
}

#[derive(Subcommand)]
pub enum Command {
    /// Run the service.
    Serve {
        #[arg(long, default_value = "/etc/dove/config.toml")]
        config: PathBuf,
    },
    /// Print an example configuration.
    ConfigExample,
    /// Manage connected mailboxes: Gmail and IMAP/SMTP (admin).
    #[command(subcommand)]
    Accounts(AccountsCmd),
    /// Manage projects (admin).
    #[command(subcommand)]
    Projects(ProjectsCmd),
    /// Manage client connections and their grants (admin).
    #[command(subcommand)]
    Clients(ClientsCmd),
    /// Inspect and verify the audit log (admin).
    #[command(subcommand)]
    Audit(AuditCmd),
    /// Key management.
    #[command(subcommand)]
    Keys(KeysCmd),
    /// Manage the per-mailbox search index (admin).
    #[command(subcommand)]
    Index(IndexCmd),
    /// Publish Dove on your tailnet with Tailscale Serve (run as the operator; does not use the admin socket).
    #[command(subcommand)]
    Tailscale(TailscaleCmd),
    /// Unknown-outcome draft operations (admin).
    #[command(subcommand)]
    Operations(OperationsCmd),
    /// Webhook sinks for watch push delivery (admin).
    #[command(subcommand)]
    Sinks(SinksCmd),
    /// Check configuration, permissions and reachability (admin). With --profile: check a remote profile instead.
    Doctor {
        /// Check this remote client profile (config, credential, network, grants). Never uses the admin socket.
        #[arg(long)]
        profile: Option<String>,
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Dove on your own computer: per-user setup, foreground start and login item (local mode).
    #[command(subcommand)]
    Local(crate::local::LocalCmd),
    /// Export projects, clients and accounts without secrets (admin).
    Export {
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Update this dove binary to the latest signed release (alias: update).
    #[command(visible_alias = "update")]
    Upgrade(UpgradeArgs),
    /// Remote client commands (login, search, mcp install, ...). They use only a connection token over HTTPS.
    #[command(flatten)]
    Remote(Box<crate::client::RemoteCmd>),
}

/// `dove upgrade`: downloads the release, checks its minisign signature and checksum, and replaces this binary.
#[derive(Args)]
#[command(after_help = "Exit codes: 0 done or up to date; 10 with --check: a newer release exists; 1 error.\n\
    Set DOVE_NO_UPDATE_CHECK=1 to turn off the daily new-version notice of other commands.")]
pub struct UpgradeArgs {
    /// Only report whether a newer release exists (exit code 10 if so, 0 if up to date).
    #[arg(long, conflicts_with = "version")]
    pub check: bool,
    /// Install this release (X.Y.Z) instead of the latest.
    #[arg(long, value_name = "X.Y.Z")]
    pub version: Option<String>,
    /// Allow --version to name a release older than this binary (prints a warning; older releases may lack
    /// security fixes).
    #[arg(long, requires = "version")]
    pub allow_downgrade: bool,
    /// Admin socket of a local service, asked for its version after the upgrade (failures are ignored).
    #[arg(long, env = "DOVE_ADMIN_SOCKET", hide = true)]
    pub socket: Option<PathBuf>,
}

/// Whether the daily new-version notice may follow this command: not for the service, the MCP stdio bridge (its
/// stderr belongs to the MCP host) or the upgrade itself.
pub fn update_notice_applies(cmd: &Command) -> bool {
    use crate::client::{McpCmd, RemoteCmd};
    match cmd {
        Command::Serve { .. } | Command::Upgrade(_) => false,
        Command::Local(crate::local::LocalCmd::Start { .. }) => false,
        Command::Remote(r) => !matches!(**r, RemoteCmd::Mcp(McpCmd::Stdio { .. })),
        _ => true,
    }
}

#[derive(Subcommand)]
pub enum AccountsCmd {
    List {
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Start the Google authorization for a new mailbox and print the link to open.
    Connect {
        #[arg(long)]
        alias: String,
        #[arg(long)]
        email: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Connect an IMAP/SMTP mailbox (Strato, iCloud, any provider with app passwords). Both logins are verified
    /// before anything is stored. The password is read from the terminal without echo, or from stdin.
    ConnectImap(Box<ConnectImapArgs>),
    /// Gmail: print a new authorization link. IMAP: ask for the new (app) password and verify it.
    Reconnect {
        alias: String,
        /// IMAP only: read the new password from stdin instead of the terminal.
        #[arg(long)]
        password_stdin: bool,
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Gmail: revoke the grant at Google. Deletes the stored credentials and index data locally.
    Remove {
        alias: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
    Disable {
        alias: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
    Enable {
        alias: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
    Check {
        alias: Option<String>,
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Send-as aliases of an IMAP mailbox (Gmail keeps its send-as list in Gmail settings).
    #[command(subcommand)]
    Aliases(AliasesCmd),
    /// Plain-text signatures appended to new drafts, per mailbox or per alias.
    #[command(subcommand)]
    Signature(SignatureCmd),
}

#[derive(Subcommand)]
pub enum AliasesCmd {
    /// Allow `create_draft` to use ADDRESS as `from_address` for this mailbox. The SMTP envelope sender stays the
    /// login address unless --envelope is given, which is only right if the SMTP server accepts the alias there.
    Add {
        mailbox: String,
        address: String,
        /// Display name used when the agent gives only the address.
        #[arg(long)]
        name: Option<String>,
        /// The SMTP server accepts this alias as envelope sender (MAIL FROM).
        #[arg(long)]
        envelope: bool,
        #[command(flatten)]
        admin: AdminOpts,
    },
    List {
        mailbox: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
    Remove {
        mailbox: String,
        address: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
}

#[derive(Subcommand)]
pub enum SignatureCmd {
    /// Set or clear a signature. It is appended as "-- " plus the text after the body of a new draft (before a
    /// quote or forward block) unless the agent passes signature: false; update_draft never adds it again.
    Set {
        mailbox: String,
        /// Set the signature of this alias instead of the mailbox's.
        #[arg(long)]
        alias: Option<String>,
        /// Plain-text file with the signature (`-` reads stdin), at most 4096 bytes.
        #[arg(long, conflicts_with = "clear", required_unless_present = "clear")]
        file: Option<PathBuf>,
        /// Remove the signature.
        #[arg(long)]
        clear: bool,
        #[command(flatten)]
        admin: AdminOpts,
    },
    Show {
        mailbox: String,
        #[arg(long)]
        alias: Option<String>,
        #[command(flatten)]
        admin: AdminOpts,
    },
}

/// Reads a signature file (`-`: stdin), refusing anything larger than the cap before it is sent.
fn read_signature(path: &std::path::Path) -> anyhow::Result<String> {
    use std::io::Read;
    let cap = (crate::identity::MAX_SIGNATURE_BYTES * 4) as u64;
    let mut buf = Vec::new();
    if path == std::path::Path::new("-") {
        std::io::stdin().lock().take(cap + 1).read_to_end(&mut buf)?;
    } else {
        std::fs::File::open(path)
            .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?
            .take(cap + 1)
            .read_to_end(&mut buf)?;
    }
    if buf.len() as u64 > cap {
        anyhow::bail!("the signature file is far larger than the {} byte limit", crate::identity::MAX_SIGNATURE_BYTES);
    }
    String::from_utf8(buf).map_err(|_| anyhow::anyhow!("the signature file is not UTF-8 text"))
}

#[derive(Args)]
pub struct ConnectImapArgs {
    alias: String,
    #[arg(long)]
    email: String,
    /// IMAP login name (default: the email address).
    #[arg(long)]
    username: Option<String>,
    /// SMTP login name, if it differs from the IMAP one.
    #[arg(long)]
    smtp_username: Option<String>,
    #[arg(long)]
    imap_host: Option<String>,
    /// Default 993 (implicit TLS) or 143 (STARTTLS).
    #[arg(long)]
    imap_port: Option<u16>,
    /// implicit or starttls (default implicit).
    #[arg(long)]
    imap_tls: Option<String>,
    #[arg(long)]
    smtp_host: Option<String>,
    /// Default 465 (implicit TLS) or 587 (STARTTLS).
    #[arg(long)]
    smtp_port: Option<u16>,
    /// implicit or starttls (default implicit).
    #[arg(long)]
    smtp_tls: Option<String>,
    /// Drafts folder name, when the server marks none and none is called Drafts/Entwürfe/Draft.
    #[arg(long)]
    drafts_folder: Option<String>,
    /// Known provider settings: strato, icloud or gmail (chosen from the address when possible; gmail for Google
    /// Workspace domains).
    #[arg(long)]
    preset: Option<String>,
    /// Read the password from stdin (one line) instead of prompting.
    #[arg(long)]
    password_stdin: bool,
    #[command(flatten)]
    admin: AdminOpts,
}

/// Builds an endpoint from `--<which>-host/-port/-tls`; `None` when nothing is given (the preset applies). A port or
/// TLS override without a host uses the preset's host (`preset_host`).
fn endpoint(
    which: &str,
    host: Option<String>,
    port: Option<u16>,
    tls: Option<String>,
    ports: (u16, u16),
    preset_host: Option<&str>,
) -> anyhow::Result<Option<crate::imap::ServerEndpoint>> {
    use crate::imap::{ServerEndpoint, TlsMode};
    let host = match (host, preset_host) {
        (Some(h), _) => h,
        (None, _) if port.is_none() && tls.is_none() => return Ok(None),
        (None, Some(h)) => h.to_string(),
        (None, None) => anyhow::bail!("--{which}-port and --{which}-tls need --{which}-host or a known --preset"),
    };
    let tls = match tls.as_deref() {
        Some(t) => TlsMode::parse(t).ok_or_else(|| anyhow::anyhow!("--{which}-tls must be implicit or starttls"))?,
        None => TlsMode::Implicit,
    };
    let port = port.unwrap_or(if tls == TlsMode::Implicit { ports.0 } else { ports.1 });
    Ok(Some(ServerEndpoint { host: host.trim().to_string(), port, tls }))
}

/// Reads a mailbox password: from the terminal without echo, or one line from stdin. Only the line ending is
/// removed (passwords may start or end with spaces).
fn read_password(prompt: &str, from_stdin: bool) -> anyhow::Result<crate::admin::Password> {
    use std::io::{BufRead, IsTerminal};
    let pw = if from_stdin || !std::io::stdin().is_terminal() {
        let mut line = zeroize::Zeroizing::new(String::new());
        std::io::stdin().lock().read_line(&mut line)?;
        let end = line.trim_end_matches(['\r', '\n']).len();
        zeroize::Zeroizing::new(line[..end].to_string())
    } else {
        zeroize::Zeroizing::new(
            rpassword::prompt_password(prompt).map_err(|e| anyhow::anyhow!("cannot read from the terminal: {e}"))?,
        )
    };
    if pw.is_empty() {
        anyhow::bail!("no password given");
    }
    Ok(crate::admin::Password(pw))
}

/// `accounts reconnect`: Gmail accounts get a new authorization link; IMAP accounts are asked for the password.
async fn reconnect(alias: String, password_stdin: bool, admin: &AdminOpts) -> anyhow::Result<Value> {
    let list = admin_send(admin, &AdminRequest::AccountsList).await?;
    let provider = list
        .as_array()
        .and_then(|a| a.iter().find(|r| r["alias"] == alias.as_str()))
        .and_then(|r| r["provider"].as_str())
        .unwrap_or("gmail")
        .to_string();
    let req = if provider == "imap" {
        let password = read_password(&format!("New password for '{alias}': "), password_stdin)?;
        AdminRequest::AccountsReconnectImap { alias, password }
    } else {
        AdminRequest::AccountsReconnect { alias }
    };
    admin_send(admin, &req).await
}

#[derive(Subcommand)]
pub enum ProjectsCmd {
    Create {
        name: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
    AddAccount {
        project: String,
        alias: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
    RemoveAccount {
        project: String,
        alias: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
    List {
        #[command(flatten)]
        admin: AdminOpts,
    },
    Show {
        name: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
}

#[derive(Subcommand)]
pub enum ClientsCmd {
    /// Create a client token. Prints the token once.
    Create {
        name: String,
        #[arg(long)]
        project: String,
        /// alias=<actions or preset>, repeatable. Actions: read, draft, organize, delete, send. Presets: reader,
        /// drafter, assistant, full (send is never in a preset: `work=assistant,send`).
        #[arg(long = "grant", required = true)]
        grants: Vec<String>,
        #[arg(long)]
        expires: Option<String>,
        #[arg(long = "allow-ip")]
        allow_ip: Vec<String>,
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Atomically replace the whole grant set.
    SetGrants {
        name: String,
        /// alias=<actions or preset>, repeatable (as for `create`).
        #[arg(long = "grant", required = true)]
        grants: Vec<String>,
        #[command(flatten)]
        admin: AdminOpts,
    },
    Rotate {
        name: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
    Revoke {
        name: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
    Show {
        name: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
    List {
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Create a one-time invitation for `dove login` or the OAuth approval page.
    Invite {
        name: String,
        #[arg(long)]
        project: String,
        /// `all` (expanded once, now) or a comma-separated alias list.
        #[arg(long, default_value = "all")]
        accounts: String,
        /// Actions and presets for every invited mailbox (`read`, `assistant`, `full,send`, ...).
        #[arg(long, default_value = "read")]
        capabilities: String,
        #[arg(long)]
        expires: Option<String>,
        #[arg(long = "allow-ip")]
        allow_ip: Vec<String>,
        #[command(flatten)]
        admin: AdminOpts,
    },
}

#[derive(Subcommand)]
pub enum AuditCmd {
    Tail {
        #[arg(long, default_value_t = 50)]
        limit: i64,
        #[command(flatten)]
        admin: AdminOpts,
    },
    Search {
        #[arg(long)]
        actor: Option<String>,
        #[arg(long)]
        tool: Option<String>,
        #[arg(long)]
        account: Option<String>,
        #[arg(long)]
        result: Option<String>,
        #[arg(long)]
        limit: Option<i64>,
        #[command(flatten)]
        admin: AdminOpts,
    },
    Verify {
        #[command(flatten)]
        admin: AdminOpts,
    },
    Prune {
        #[command(flatten)]
        admin: AdminOpts,
    },
}

#[derive(Subcommand)]
pub enum KeysCmd {
    /// Print a new key line for a key file (KEK, pepper or index key). Local only, talks to nothing.
    Generate {
        #[arg(long, default_value_t = 1)]
        version: u32,
    },
    /// Re-wrap all grants under the newest KEK version in the KEK file (admin).
    Rotate {
        #[command(flatten)]
        admin: AdminOpts,
    },
}

#[derive(Subcommand)]
pub enum IndexCmd {
    Enable {
        alias: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
    Disable {
        alias: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
    Status {
        alias: Option<String>,
        #[command(flatten)]
        admin: AdminOpts,
    },
    Rebuild {
        alias: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
}

#[derive(Subcommand)]
pub enum TailscaleCmd {
    /// Mount Dove's public paths (and only those) on this node's MagicDNS name with `tailscale serve`, and set
    /// `public_url` in the config file. Safe to run again. Restart Dove afterwards.
    Setup {
        /// Config file to read and update.
        #[arg(long, default_value = "/etc/dove/config.toml")]
        config: PathBuf,
        /// HTTPS port on the tailnet name.
        #[arg(long, default_value_t = 443)]
        port: u16,
        /// ALSO make Dove reachable from the internet (Tailscale Funnel). Off unless you ask for it.
        #[arg(long)]
        funnel: bool,
        /// Print the commands and the config change without running anything.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
pub enum OperationsCmd {
    List {
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Remove a create-operation record after verifying the mailbox by hand.
    Remove {
        #[arg(long)]
        client: String,
        #[arg(long)]
        account: String,
        #[arg(long)]
        request_key: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
}

#[derive(Subcommand)]
pub enum SinksCmd {
    /// Register a webhook sink: an HTTPS URL that receives signed, content-free watch events.
    Add {
        name: String,
        /// Project whose clients may use the sink (other projects never see it).
        #[arg(long)]
        project: String,
        /// HTTPS URL (no query or fragment). Only this exact URL is ever contacted.
        #[arg(long)]
        url: String,
        /// File with the HMAC signing secret (at least 32 characters, mode 0600 or stricter), e.g. from
        /// `openssl rand -hex 32`. The service keeps it sealed; the receiver needs the same secret.
        #[arg(long)]
        secret_file: PathBuf,
        #[command(flatten)]
        admin: AdminOpts,
    },
    List {
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Remove a sink. Watches that named it keep working without push.
    Remove {
        name: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Move a sink to a project; needed for sinks created before 0.6, which belong to no project and serve no
    /// client. Watches of other projects' clients lose the sink (pull only).
    SetProject {
        name: String,
        #[arg(long)]
        project: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
}

fn split_list(s: &str) -> Vec<String> {
    s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
}

/// Maps an admin subcommand to its socket request.
fn admin_request(cmd: Command) -> anyhow::Result<(AdminOpts, AdminRequest)> {
    use AdminRequest as R;
    Ok(match cmd {
        Command::Accounts(c) => match c {
            AccountsCmd::List { admin } => (admin, R::AccountsList),
            AccountsCmd::Connect { alias, email, admin } => (admin, R::AccountsConnect { alias, email }),
            AccountsCmd::ConnectImap(a) => {
                let a = *a;
                let preset = match a.preset.as_deref() {
                    Some(name) => crate::imap::presets::by_name(name),
                    None => crate::imap::presets::for_email(&a.email),
                };
                let (imap_default, smtp_default) = match &preset {
                    Some(p) => (Some(p.imap.host.as_str()), Some(p.smtp.host.as_str())),
                    None => (None, None),
                };
                let imap = endpoint("imap", a.imap_host, a.imap_port, a.imap_tls, (993, 143), imap_default)?;
                let smtp = endpoint("smtp", a.smtp_host, a.smtp_port, a.smtp_tls, (465, 587), smtp_default)?;
                let password = read_password(&format!("Password for {}: ", a.email), a.password_stdin)?;
                (
                    a.admin,
                    R::AccountsConnectImap {
                        alias: a.alias,
                        email: a.email,
                        username: a.username,
                        smtp_username: a.smtp_username,
                        password,
                        imap,
                        smtp,
                        drafts_folder: a.drafts_folder,
                        preset: a.preset,
                    },
                )
            }
            AccountsCmd::Reconnect { .. } => unreachable!("handled in run"),
            AccountsCmd::Remove { alias, admin } => (admin, R::AccountsRemove { alias }),
            AccountsCmd::Disable { alias, admin } => (admin, R::AccountsDisable { alias }),
            AccountsCmd::Enable { alias, admin } => (admin, R::AccountsEnable { alias }),
            AccountsCmd::Check { alias, admin } => (admin, R::AccountsCheck { alias }),
            AccountsCmd::Aliases(a) => match a {
                AliasesCmd::Add { mailbox, address, name, envelope, admin } => {
                    (admin, R::AccountsAliasAdd { account: mailbox, address, name, envelope })
                }
                AliasesCmd::List { mailbox, admin } => (admin, R::AccountsAliasList { account: mailbox }),
                AliasesCmd::Remove { mailbox, address, admin } => {
                    (admin, R::AccountsAliasRemove { account: mailbox, address })
                }
            },
            AccountsCmd::Signature(c) => match c {
                SignatureCmd::Set { mailbox, alias, file, clear, admin } => {
                    let signature = match (&file, clear) {
                        (Some(f), false) => Some(read_signature(f)?),
                        _ => None,
                    };
                    (admin, R::AccountsSignatureSet { account: mailbox, alias, signature })
                }
                SignatureCmd::Show { mailbox, alias, admin } => {
                    (admin, R::AccountsSignatureShow { account: mailbox, alias })
                }
            },
        },
        Command::Projects(c) => match c {
            ProjectsCmd::Create { name, admin } => (admin, R::ProjectsCreate { name }),
            ProjectsCmd::AddAccount { project, alias, admin } => {
                (admin, R::ProjectsAddAccount { project, account: alias })
            }
            ProjectsCmd::RemoveAccount { project, alias, admin } => {
                (admin, R::ProjectsRemoveAccount { project, account: alias })
            }
            ProjectsCmd::List { admin } => (admin, R::ProjectsList),
            ProjectsCmd::Show { name, admin } => (admin, R::ProjectsShow { name }),
        },
        Command::Clients(c) => match c {
            ClientsCmd::Create { name, project, grants, expires, allow_ip, admin } => {
                (admin, R::ClientsCreate { name, project, grants: parse_grant_args(&grants)?, expires, allow_ip })
            }
            ClientsCmd::SetGrants { name, grants, admin } => {
                (admin, R::ClientsSetGrants { name, grants: parse_grant_args(&grants)? })
            }
            ClientsCmd::Rotate { name, admin } => (admin, R::ClientsRotate { name }),
            ClientsCmd::Revoke { name, admin } => (admin, R::ClientsRevoke { name }),
            ClientsCmd::Show { name, admin } => (admin, R::ClientsShow { name }),
            ClientsCmd::List { admin } => (admin, R::ClientsList),
            ClientsCmd::Invite { name, project, accounts, capabilities, expires, allow_ip, admin } => (
                admin,
                R::ClientsInvite { name, project, accounts: split_list(&accounts), capabilities, expires, allow_ip },
            ),
        },
        Command::Audit(c) => match c {
            AuditCmd::Tail { limit, admin } => (admin, R::AuditTail { limit: Some(limit) }),
            AuditCmd::Search { actor, tool, account, result, limit, admin } => (
                admin,
                R::AuditSearch {
                    filter: SearchFilter { actor, tool, account, result_code: result, since: None, limit },
                },
            ),
            AuditCmd::Verify { admin } => (admin, R::AuditVerify),
            AuditCmd::Prune { admin } => (admin, R::AuditPrune),
        },
        Command::Keys(KeysCmd::Rotate { admin }) => (admin, R::KeysRotate),
        Command::Index(c) => match c {
            IndexCmd::Enable { alias, admin } => (admin, R::IndexEnable { alias }),
            IndexCmd::Disable { alias, admin } => (admin, R::IndexDisable { alias }),
            IndexCmd::Status { alias, admin } => (admin, R::IndexStatus { alias }),
            IndexCmd::Rebuild { alias, admin } => (admin, R::IndexRebuild { alias }),
        },
        Command::Operations(c) => match c {
            OperationsCmd::List { admin } => (admin, R::OperationsList),
            OperationsCmd::Remove { client, account, request_key, admin } => {
                (admin, R::OperationsRemove { client, account, request_key })
            }
        },
        Command::Sinks(c) => match c {
            SinksCmd::Add { name, project, url, secret_file, admin } => {
                let secret = crate::secrets::read_secret_string(&secret_file)?;
                (admin, R::SinksAdd { name, project, url, secret: crate::admin::Password(secret) })
            }
            SinksCmd::SetProject { name, project, admin } => (admin, R::SinksSetProject { name, project }),
            SinksCmd::List { admin } => (admin, R::SinksList),
            SinksCmd::Remove { name, admin } => (admin, R::SinksRemove { name }),
        },
        Command::Doctor { .. } | Command::Tailscale(_) => unreachable!("handled in run_command"),
        Command::Export { admin } => (admin, R::Export),
        Command::Serve { .. }
        | Command::ConfigExample
        | Command::Remote(_)
        | Command::Local(_)
        | Command::Upgrade(_)
        | Command::Keys(KeysCmd::Generate { .. }) => {
            unreachable!("not an admin command")
        }
    })
}

fn print(value: &Value, json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(value).unwrap_or_default());
        return;
    }
    // Human output: YAML-like rendering of the JSON value, keeping secrets shown once where returned.
    fn render(v: &Value, indent: usize, out: &mut String) {
        let pad = " ".repeat(indent);
        match v {
            Value::Object(map) => {
                for (k, val) in map {
                    match val {
                        Value::Object(_) | Value::Array(_) if !is_empty(val) => {
                            out.push_str(&format!("{pad}{k}:\n"));
                            render(val, indent + 2, out);
                        }
                        _ => out.push_str(&format!("{pad}{k}: {}\n", scalar(val))),
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    match item {
                        Value::Object(_) => {
                            let mut inner = String::new();
                            render(item, indent + 2, &mut inner);
                            let trimmed = inner.trim_start();
                            out.push_str(&format!("{pad}- {trimmed}"));
                        }
                        _ => out.push_str(&format!("{pad}- {}\n", scalar(item))),
                    }
                }
            }
            _ => out.push_str(&format!("{pad}{}\n", scalar(v))),
        }
    }
    fn is_empty(v: &Value) -> bool {
        matches!(v, Value::Array(a) if a.is_empty()) || matches!(v, Value::Object(o) if o.is_empty())
    }
    fn scalar(v: &Value) -> String {
        match v {
            Value::String(s) => s.clone(),
            Value::Null => "-".into(),
            Value::Array(_) => "[]".into(),
            Value::Object(_) => "{}".into(),
            other => other.to_string(),
        }
    }
    let mut out = String::new();
    render(value, 0, &mut out);
    print!("{out}");
}

/// Runs a command and returns the process exit code (errors are exit code 1, printed by the caller).
pub async fn run(cli: Cli) -> anyhow::Result<u8> {
    match cli.command {
        Command::Upgrade(a) => {
            let opts = crate::update::UpgradeOpts {
                check: a.check,
                version: a.version,
                allow_downgrade: a.allow_downgrade,
                // Best effort: an ambiguous setup only skips the restart hint.
                socket: resolve_admin_socket(a.socket).ok().map(|t| t.path().to_path_buf()),
            };
            crate::update::run_upgrade(opts).await
        }
        other => run_command(other).await.map(|()| 0),
    }
}

/// Adds this binary's version to the service's doctor checks. A difference means the service still runs another
/// release (typically: upgraded binary, service not restarted).
fn add_binary_version(checks: &mut Value) {
    let restart = if is_local(checks) { "dove local install" } else { "sudo systemctl restart dove" };
    let Some(list) = checks.as_array_mut() else { return };
    let binary = env!("CARGO_PKG_VERSION");
    let service = list.iter().find(|c| c["check"] == "service_version").and_then(|c| c["detail"].as_str());
    let (ok, detail) = match service {
        Some(s) if s == binary => (true, binary.to_string()),
        Some(s) => (false, format!("{binary}, but the service runs {s}: restart it ({restart})")),
        None => (
            false,
            format!("{binary}, but the service does not report its version (older release): restart it ({restart})"),
        ),
    };
    list.push(serde_json::json!({ "check": "binary_version", "ok": ok, "detail": detail }));
}

/// Whether doctor checks come from a local-mode service.
fn is_local(checks: &Value) -> bool {
    checks.as_array().is_some_and(|l| l.iter().any(|c| c["check"] == "mode" && c["detail"] == "local"))
}

async fn run_command(command: Command) -> anyhow::Result<()> {
    match command {
        Command::Serve { config } => crate::serve::run(&config).await,
        Command::ConfigExample => {
            print!("{}", config::EXAMPLE);
            Ok(())
        }
        Command::Keys(KeysCmd::Generate { version }) => {
            println!("{}", crate::secrets::generate_key_line(version));
            Ok(())
        }
        // Remote commands never reach the admin socket (spec 5.6).
        Command::Remote(cmd) => crate::client::run(*cmd).await,
        Command::Local(cmd) => crate::local::run(cmd).await,
        Command::Doctor { profile: Some(p), admin } => crate::client::doctor(Some(&p), admin.json).await,
        Command::Tailscale(TailscaleCmd::Setup { config, port, funnel, dry_run }) => {
            let opts = crate::tailscale::SetupOpts { config, port, funnel, dry_run };
            crate::tailscale::setup(&opts, &crate::tailscale::Tailscale::from_path(), &mut std::io::stdout()).await
        }
        Command::Doctor { profile: None, admin } => {
            let mut v = admin_send(&admin, &AdminRequest::Doctor).await?;
            add_binary_version(&mut v);
            if !is_local(&v) {
                crate::tailscale::add_doctor_check(&mut v, &crate::tailscale::Tailscale::from_path()).await;
            }
            print(&v, admin.json);
            Ok(())
        }
        Command::Accounts(AccountsCmd::Reconnect { alias, password_stdin, admin }) => {
            let v = reconnect(alias, password_stdin, &admin).await?;
            print(&v, admin.json);
            Ok(())
        }
        other => {
            let (opts, req) = admin_request(other)?;
            let v = admin_send(&opts, &req).await?;
            print(&v, opts.json);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imap::TlsMode;

    /// The admin endpoint's order (L3): explicit wins, a server socket and a local config together are refused
    /// instead of silently picking one, otherwise whichever exists, and the server default last.
    #[test]
    fn admin_socket_resolution_order() {
        let server = || PathBuf::from("/run/dove/admin.sock");
        let local = || Some(PathBuf::from("/home/a/.local/share/dove/admin.sock"));
        let mine = PathBuf::from("/tmp/x.sock");
        for (srv, loc) in [(true, local()), (false, local()), (true, None), (false, None)] {
            assert_eq!(
                choose_admin_socket(Some(mine.clone()), srv, loc, server()).unwrap(),
                AdminTarget::Explicit(mine.clone())
            );
        }
        let err = choose_admin_socket(None, true, local(), server()).unwrap_err().to_string();
        assert!(err.contains("--socket") && err.contains("/run/dove/admin.sock"), "{err}");
        assert_eq!(choose_admin_socket(None, true, None, server()).unwrap(), AdminTarget::Server(server()));
        assert_eq!(choose_admin_socket(None, false, local(), server()).unwrap(), AdminTarget::Local(local().unwrap()));
        assert_eq!(choose_admin_socket(None, false, None, server()).unwrap(), AdminTarget::Server(server()));
        assert!(AdminTarget::Local(local().unwrap()).answered_by().contains("local instance"));
        assert!(AdminTarget::Server(server()).answered_by().contains("server instance"));
    }

    #[test]
    fn port_override_uses_the_preset_host() {
        let ep = endpoint("smtp", None, Some(587), Some("starttls".into()), (465, 587), Some("smtp.strato.de"))
            .unwrap()
            .unwrap();
        assert_eq!((ep.host.as_str(), ep.port, ep.tls), ("smtp.strato.de", 587, TlsMode::StartTls));
        assert!(endpoint("smtp", None, None, None, (465, 587), Some("smtp.strato.de")).unwrap().is_none());
        assert!(endpoint("smtp", None, Some(587), None, (465, 587), None).is_err(), "no host and no preset");
    }

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("dove").chain(args.iter().copied()))
    }

    #[test]
    fn sinks_add_needs_a_project() {
        let add = ["sinks", "add", "n8n", "--url", "https://hooks.example.com/x", "--secret-file", "/tmp/s"];
        assert!(parse(&add).is_err(), "--project is required");
        let with_project: Vec<&str> = add.iter().copied().chain(["--project", "acme"]).collect();
        let Command::Sinks(SinksCmd::Add { project, .. }) = parse(&with_project).unwrap().command else { panic!() };
        assert_eq!(project, "acme");
        let Command::Sinks(SinksCmd::SetProject { name, project, .. }) =
            parse(&["sinks", "set-project", "n8n", "--project", "beta"]).unwrap().command
        else {
            panic!()
        };
        assert_eq!((name.as_str(), project.as_str()), ("n8n", "beta"));
    }

    #[test]
    fn upgrade_command_line() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
        let Command::Upgrade(a) = parse(&["upgrade", "--version", "0.2.0"]).unwrap().command else { panic!() };
        assert_eq!((a.check, a.version.as_deref()), (false, Some("0.2.0")));
        let Command::Upgrade(a) = parse(&["update", "--check"]).unwrap().command else { panic!("alias") };
        assert!(a.check && a.version.is_none());
        assert!(parse(&["upgrade", "--check", "--version", "0.2.0"]).is_err());
        assert!(!a.allow_downgrade);
        let Command::Upgrade(a) = parse(&["upgrade", "--version", "0.2.0", "--allow-downgrade"]).unwrap().command
        else {
            panic!()
        };
        assert!(a.allow_downgrade);
        assert!(parse(&["upgrade", "--allow-downgrade"]).is_err(), "only together with --version");
        // The top-level --version still prints the binary version.
        assert_eq!(parse(&["--version"]).err().map(|e| e.kind()), Some(clap::error::ErrorKind::DisplayVersion));
    }

    #[test]
    fn notice_skips_service_stdio_bridge_and_upgrade() {
        let applies = |args: &[&str]| update_notice_applies(&parse(args).unwrap().command);
        assert!(!applies(&["serve"]));
        assert!(!applies(&["mcp", "stdio"]));
        assert!(!applies(&["upgrade"]));
        assert!(!applies(&["update", "--check"]));
        assert!(applies(&["config-example"]));
        assert!(applies(&["mcp", "install", "--client", "claude-code"]));
        assert!(applies(&["accounts", "list"]));
        assert!(applies(&["status"]));
    }

    #[test]
    fn doctor_compares_binary_and_service_version() {
        let binary = env!("CARGO_PKG_VERSION");
        let row = |v: &Value| v.as_array().unwrap().iter().find(|c| c["check"] == "binary_version").cloned().unwrap();
        let mut same = serde_json::json!([{ "check": "service_version", "ok": true, "detail": binary }]);
        add_binary_version(&mut same);
        assert_eq!(row(&same)["ok"], true);
        let mut other = serde_json::json!([{ "check": "service_version", "ok": true, "detail": "0.0.1" }]);
        add_binary_version(&mut other);
        assert_eq!(row(&other)["ok"], false);
        assert!(row(&other)["detail"].as_str().unwrap().contains("restart"));
        let mut old = serde_json::json!([{ "check": "config", "ok": true, "detail": "" }]);
        add_binary_version(&mut old);
        assert_eq!(row(&old)["ok"], false);
    }
}
