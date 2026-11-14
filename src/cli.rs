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
    /// Agent requests: review and approve scheduled sends (admin).
    #[command(subcommand)]
    Requests(RequestsCmd),
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

/// Longest sink URL read from `--url-file -`.
const MAX_SINK_URL_BYTES: u64 = 8 * 1024;

/// The sink URL from `--url` or `--url-file` (clap allows exactly one). A file is read like a secret file (owner-only
/// mode), `-` reads standard input; both are trimmed. `--url` still works but warns on `warn` that the URL lands in
/// shell history and the process list. Neither the warning nor any error ever contains the URL.
fn sink_url(
    url: Option<String>,
    url_file: Option<PathBuf>,
    stdin: &mut dyn std::io::Read,
    warn: &mut dyn std::io::Write,
) -> anyhow::Result<String> {
    use std::io::Read;
    let url = match (url, url_file) {
        (Some(url), None) => {
            writeln!(
                warn,
                "warning: --url puts the sink URL in your shell history and the process list; use --url-file <path> \
                 or --url-file - (standard input) instead"
            )?;
            return Ok(url);
        }
        (None, Some(path)) if path == std::path::Path::new("-") => {
            let mut buf = Vec::new();
            stdin.take(MAX_SINK_URL_BYTES + 1).read_to_end(&mut buf)?;
            if buf.len() as u64 > MAX_SINK_URL_BYTES {
                anyhow::bail!("the sink URL on standard input is longer than {MAX_SINK_URL_BYTES} bytes");
            }
            String::from_utf8(buf).map_err(|_| anyhow::anyhow!("the sink URL on standard input is not UTF-8"))?
        }
        (None, Some(path)) => crate::secrets::read_secret_string(&path)
            .map_err(|e| anyhow::anyhow!("cannot read the sink URL file: {e:#}"))?
            .to_string(),
        _ => anyhow::bail!("pass exactly one of --url and --url-file"),
    };
    let url = url.trim();
    if url.is_empty() {
        anyhow::bail!("no sink URL given");
    }
    Ok(url.to_string())
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
        /// Hide passwords, keys and one-time codes in overview results (snippets, subjects); full reads stay intact.
        /// Without this flag or `--no-redact-secrets`, the server's `clients.redact_secrets_default` decides.
        #[arg(long, conflicts_with = "no_redact_secrets")]
        redact_secrets: bool,
        /// Do not hide secrets, even when the server's `clients.redact_secrets_default` is on.
        #[arg(long)]
        no_redact_secrets: bool,
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
    /// Hide (`on`) or show (`off`) passwords, keys and one-time codes in a connection's overview results
    /// (search_messages, digest and list_drafts subjects and snippets). Also works on an open invitation.
    SetRedaction {
        name: String,
        #[arg(value_parser = ["on", "off"])]
        mode: String,
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
        /// The connection hides passwords, keys and one-time codes in overview results. Without this flag or
        /// `--no-redact-secrets`, the server's `clients.redact_secrets_default` decides.
        #[arg(long, conflicts_with = "no_redact_secrets")]
        redact_secrets: bool,
        /// The connection shows secrets, even when the server's `clients.redact_secrets_default` is on.
        #[arg(long)]
        no_redact_secrets: bool,
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
        /// HTTPS URL (no query or fragment). Only this exact URL is ever contacted. Prefer `--url-file`: a URL on the
        /// command line lands in shell history and the process list, and webhook URLs often carry credentials.
        #[arg(long, required_unless_present = "url_file", conflicts_with = "url_file")]
        url: Option<String>,
        /// File holding the URL (surrounding whitespace trimmed; no group or other access, like `--secret-file`), or
        /// `-` to read it from standard input.
        #[arg(long)]
        url_file: Option<PathBuf>,
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

#[derive(Subcommand)]
pub enum RequestsCmd {
    /// Every connection's requests, newest first.
    List {
        /// Only requests with this status (pending, approved, denied, cancelled, expired, done).
        #[arg(long)]
        status: Option<String>,
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// A request with the agent's note and each draft as it is now (sender, recipients, subject, text, attachments).
    Show {
        id: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Show the drafts, ask, then approve exactly the revisions shown. If a draft changes in between, nothing is
    /// approved.
    Approve {
        id: String,
        /// Approve only these items (comma-separated indexes, e.g. 0,2); the others are denied. Default: all.
        #[arg(long, value_delimiter = ',')]
        items: Option<Vec<u32>>,
        /// Items whose time has already passed: skip them (default) or send them now.
        #[arg(long, value_enum, default_value = "skip")]
        late: LateArg,
        /// Access requests: grant for this long instead of what the agent asked (only shorter; on a request for a
        /// permanent grant it makes the grant temporary). Minutes, or with a unit: 90m, 8h, 7d (at most 30d).
        #[arg(long, value_parser = parse_duration_minutes)]
        duration: Option<u32>,
        /// Do not ask for confirmation (the drafts are still printed).
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Deny a pending request.
    Deny {
        id: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Stop unsent items of a request (all, or the chosen ones).
    Cancel {
        id: String,
        /// Only these items (comma-separated indexes).
        #[arg(long, value_delimiter = ',')]
        items: Option<Vec<u32>>,
        #[command(flatten)]
        admin: AdminOpts,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum LateArg {
    Skip,
    Send,
}

impl From<LateArg> for crate::admin::Late {
    fn from(l: LateArg) -> Self {
        match l {
            LateArg::Skip => crate::admin::Late::Skip,
            LateArg::Send => crate::admin::Late::Send,
        }
    }
}

/// Untrusted text (draft content, agent notes) made safe for a terminal: control characters other than newline and
/// tab, and bidirectional overrides, are shown as `�`, so mail cannot move the cursor, recolour or reorder the
/// screen the operator approves from.
pub fn terminal_safe(s: &str) -> String {
    s.chars()
        .map(|c| if (c.is_control() && c != '\n' && c != '\t') || is_bidi_control(c) { '\u{FFFD}' } else { c })
        .collect()
}

/// Bidirectional embeddings, overrides, isolates and marks.
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}')
}

/// JSON output for a terminal: serde escapes C0 controls but writes DEL, C1 controls (U+0080 to U+009F) and bidi
/// controls raw. Those can only sit inside JSON strings, so they become `\uXXXX` escapes: the value is unchanged.
fn json_text(value: &Value) -> String {
    let mut out = String::new();
    for c in serde_json::to_string_pretty(value).unwrap_or_default().chars() {
        if (c.is_control() && c != '\n') || is_bidi_control(c) {
            out.push_str(&format!("\\u{:04X}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// Renders `requests show` for the operator's terminal.
fn render_request(v: &Value) -> String {
    let t = |x: &Value| terminal_safe(x.as_str().unwrap_or("-"));
    if v["kind"] == "access" {
        return render_access_request(v);
    }
    let list = |x: &Value| {
        x.as_array()
            .map(|a| a.iter().filter_map(Value::as_str).map(terminal_safe).collect::<Vec<_>>().join(", "))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "-".into())
    };
    let mut out = format!(
        "Request {} ({}) from connection '{}' (project {}) on mailbox {}: {}\ncreated {}, expires {}{}\n",
        t(&v["request_id"]),
        t(&v["kind"]),
        t(&v["client"]),
        t(&v["project"]),
        t(&v["account"]),
        t(&v["status"]),
        t(&v["created_at"]),
        t(&v["expires_at"]),
        if v["unless_reply"] == true { "; each item is skipped if someone replies in its thread first" } else { "" },
    );
    if let Some(n) = v["note"].as_str() {
        out.push_str(&format!("Note from the agent (untrusted):\n  {}\n", terminal_safe(n).replace('\n', "\n  ")));
    }
    for it in v["items"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "\n[{}] {} at {}{}{}\n",
            it["idx"],
            t(&it["state"]),
            t(&it["send_at"]),
            if it["late"] == true { "  (time has passed: --late send|skip)" } else { "" },
            it["reason"].as_str().map(|r| format!("  reason: {}", terminal_safe(r))).unwrap_or_default(),
        ));
        if let Some(e) = it["error"].as_str() {
            out.push_str(&format!("    draft cannot be read: {}\n", terminal_safe(e)));
            continue;
        }
        if it.get("revision").is_none() {
            continue;
        }
        out.push_str(&format!("    draft {} revision {}", t(&it["draft_id"]), t(&it["revision"])));
        if it["changed_since_request"] == true {
            out.push_str("  (changed since the agent asked)");
        }
        if it["sendable"] != true {
            out.push_str("  (changed outside Dove: cannot be sent)");
        }
        out.push('\n');
        out.push_str(&format!("    From: {}\n    To: {}\n", t(&it["from"]), list(&it["to"])));
        for k in ["cc", "bcc"] {
            if it[k].as_array().is_some_and(|a| !a.is_empty()) {
                out.push_str(&format!("    {}: {}\n", if k == "cc" { "Cc" } else { "Bcc" }, list(&it[k])));
            }
        }
        out.push_str(&format!("    Subject: {}\n", t(&it["subject"])));
        for a in it["attachments"].as_array().into_iter().flatten() {
            out.push_str(&format!("    Attachment: {} ({} bytes)\n", t(&a["name"]), a["size"]));
        }
        out.push_str("    ----\n");
        let body = terminal_safe(it["body_text"].as_str().unwrap_or(""));
        for line in body.lines() {
            out.push_str(&format!("    | {line}\n"));
        }
        if it["body_truncated"] == true {
            out.push_str("    | [text truncated]\n");
        }
    }
    out
}

/// `--duration` of `requests approve`: minutes (`90`) or a duration with a unit (`90m`, `8h`, `7d`), whole minutes,
/// from 1 minute to 30 days.
fn parse_duration_minutes(s: &str) -> Result<u32, String> {
    let s = s.trim();
    let secs = if s.bytes().all(|b| b.is_ascii_digit()) && !s.is_empty() {
        s.parse::<i64>().ok().and_then(|m| m.checked_mul(60))
    } else {
        crate::util::parse_duration_secs(s)
    };
    match secs {
        Some(x) if x % 60 == 0 && (60..=crate::requests::access::MAX_DURATION_MINUTES * 60).contains(&x) => {
            Ok((x / 60) as u32)
        }
        _ => Err("expected whole minutes from 1 minute to 30 days, e.g. 90, 90m, 8h or 7d".into()),
    }
}

/// `dove requests approve` of an access request: print what is asked, confirm, then approve.
async fn requests_approve_access(
    id: String,
    shown_v: &Value,
    items: Option<Vec<u32>>,
    duration: Option<u32>,
    yes: bool,
    admin: &AdminOpts,
) -> anyhow::Result<()> {
    let grants: Vec<&Value> = shown_v["grants"].as_array().map(|a| a.iter().collect()).unwrap_or_default();
    let chosen = grants
        .iter()
        .filter(|g| items.as_ref().is_none_or(|l| g["idx"].as_u64().is_some_and(|n| l.contains(&(n as u32)))))
        .count();
    if !yes {
        let how = match (duration, shown_v["duration_minutes"].as_i64()) {
            (Some(m), _) => format!("for {m} minute(s)"),
            (None, Some(m)) => format!("for {m} minute(s)"),
            (None, None) => "permanently".into(),
        };
        let mut prompt = format!("\nGrant {chosen} mailbox right(s) {how}");
        if chosen < grants.len() {
            prompt.push_str(&format!(", leave out {}", grants.len() - chosen));
        }
        eprint!("{prompt}? [y/N] ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            anyhow::bail!("not approved");
        }
    }
    let req = AdminRequest::RequestsApprove {
        id,
        shown: vec![],
        items,
        late: crate::admin::Late::Skip,
        duration_minutes: duration,
    };
    let v = admin_send(admin, &req).await?;
    print(&v, admin.json);
    Ok(())
}

/// `dove requests show` of an access request: what is asked per mailbox next to what the connection has now.
fn render_access_request(v: &Value) -> String {
    let t = |x: &Value| terminal_safe(x.as_str().unwrap_or("-"));
    let how = match (v["duration_minutes"].as_i64(), v["granted_until"].as_str()) {
        (_, Some(until)) => format!("temporary, until {}", terminal_safe(until)),
        (Some(m), None) => format!("for {m} minute(s) from approval"),
        (None, None) => "permanent".into(),
    };
    let mut out = format!(
        "Request {} (access) from connection '{}' (project {}): {}\nasks {how}; created {}, expires {}\n",
        t(&v["request_id"]),
        t(&v["client"]),
        t(&v["project"]),
        t(&v["status"]),
        t(&v["created_at"]),
        t(&v["expires_at"]),
    );
    if let Some(n) = v["note"].as_str() {
        out.push_str(&format!("Note from the agent (untrusted):\n  {}\n", terminal_safe(n).replace('\n', "\n  ")));
    }
    for g in v["grants"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "\n[{}] {} on mailbox {}: asks {}\n    has now: {}",
            g["idx"],
            t(&g["state"]),
            t(&g["account"]),
            t(&g["asked"]),
            g["has"].as_str().map(terminal_safe).unwrap_or_else(|| "nothing".into()),
        ));
        for x in g["temporary"].as_array().into_iter().flatten() {
            out.push_str(&format!("; {} until {}", t(&x["actions"]), t(&x["expires_at"])));
        }
        if g["in_project"] != true {
            out.push_str("  (no longer in the project: cannot be granted)");
        }
        out.push('\n');
    }
    out
}

/// `dove requests approve`: Show, print, confirm, then Approve with the revisions that were printed.
async fn requests_approve(
    id: String,
    items: Option<Vec<u32>>,
    late: LateArg,
    duration: Option<u32>,
    yes: bool,
    admin: &AdminOpts,
) -> anyhow::Result<()> {
    let shown_v = admin_send(admin, &AdminRequest::RequestsShow { id: id.clone() }).await?;
    if admin.json {
        print(&shown_v, true);
    } else {
        print!("{}", render_request(&shown_v));
    }
    if shown_v["kind"] == "access" {
        return requests_approve_access(id, &shown_v, items, duration, yes, admin).await;
    }
    if duration.is_some() {
        anyhow::bail!("--duration applies to access requests only");
    }
    let all: Vec<&Value> = shown_v["items"].as_array().map(|a| a.iter().collect()).unwrap_or_default();
    let pending: Vec<&Value> = all.iter().copied().filter(|i| i["state"] == "pending").collect();
    let chosen: Vec<&Value> = match &items {
        Some(list) => {
            pending.iter().copied().filter(|i| i["idx"].as_u64().is_some_and(|n| list.contains(&(n as u32)))).collect()
        }
        None => pending.clone(),
    };
    if chosen.is_empty() {
        anyhow::bail!("no pending item to approve");
    }
    let mut shown = Vec::new();
    for i in &chosen {
        let idx = i["idx"].as_u64().unwrap_or(0) as u32;
        let rev = i["revision"].as_str().filter(|_| i["sendable"] == true).ok_or_else(|| {
            anyhow::anyhow!("item {idx} cannot be approved (see above); untick it with --items or deny the request")
        })?;
        shown.push(crate::admin::ShownItem { idx, revision: rev.to_string() });
    }
    let late_items = chosen.iter().filter(|i| i["late"] == true).count();
    let sending = chosen.len() - if late == LateArg::Skip { late_items } else { 0 };
    if !yes {
        let mut prompt = format!("\nApprove {sending} mail(s)");
        if late_items > 0 {
            prompt.push_str(&format!(
                " ({late_items} past their time: {})",
                if late == LateArg::Skip { "skipped" } else { "sent now" }
            ));
        }
        if chosen.len() < pending.len() {
            prompt.push_str(&format!(", deny {} other(s)", pending.len() - chosen.len()));
        }
        eprint!("{prompt}? [y/N] ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            anyhow::bail!("not approved");
        }
    }
    let req = AdminRequest::RequestsApprove { id, shown, items, late: late.into(), duration_minutes: None };
    let v = admin_send(admin, &req).await?;
    print(&v, admin.json);
    Ok(())
}

/// `--redact-secrets` / `--no-redact-secrets` (clap refuses both); neither leaves it to the server's default.
fn redaction(on: bool, off: bool) -> Option<bool> {
    match (on, off) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
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
            ClientsCmd::Create {
                name,
                project,
                grants,
                expires,
                allow_ip,
                redact_secrets,
                no_redact_secrets,
                admin,
            } => (
                admin,
                R::ClientsCreate {
                    name,
                    project,
                    grants: parse_grant_args(&grants)?,
                    expires,
                    allow_ip,
                    redact_secrets: redaction(redact_secrets, no_redact_secrets),
                },
            ),
            ClientsCmd::SetGrants { name, grants, admin } => {
                (admin, R::ClientsSetGrants { name, grants: parse_grant_args(&grants)? })
            }
            ClientsCmd::Rotate { name, admin } => (admin, R::ClientsRotate { name }),
            ClientsCmd::Revoke { name, admin } => (admin, R::ClientsRevoke { name }),
            ClientsCmd::Show { name, admin } => (admin, R::ClientsShow { name }),
            ClientsCmd::SetRedaction { name, mode, admin } => {
                (admin, R::ClientsSetRedaction { name, enabled: mode == "on" })
            }
            ClientsCmd::List { admin } => (admin, R::ClientsList),
            ClientsCmd::Invite {
                name,
                project,
                accounts,
                capabilities,
                expires,
                allow_ip,
                redact_secrets,
                no_redact_secrets,
                admin,
            } => (
                admin,
                R::ClientsInvite {
                    name,
                    project,
                    accounts: split_list(&accounts),
                    capabilities,
                    expires,
                    allow_ip,
                    redact_secrets: redaction(redact_secrets, no_redact_secrets),
                },
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
            SinksCmd::Add { name, project, url, url_file, secret_file, admin } => {
                let url = sink_url(url, url_file, &mut std::io::stdin().lock(), &mut std::io::stderr())?;
                let secret = crate::secrets::read_secret_string(&secret_file)?;
                (admin, R::SinksAdd { name, project, url, secret: crate::admin::Password(secret) })
            }
            SinksCmd::SetProject { name, project, admin } => (admin, R::SinksSetProject { name, project }),
            SinksCmd::List { admin } => (admin, R::SinksList),
            SinksCmd::Remove { name, admin } => (admin, R::SinksRemove { name }),
        },
        Command::Requests(c) => match c {
            RequestsCmd::List { status, admin } => (admin, R::RequestsList { status }),
            RequestsCmd::Show { id, admin } => (admin, R::RequestsShow { id }),
            RequestsCmd::Deny { id, admin } => (admin, R::RequestsDeny { id }),
            RequestsCmd::Cancel { id, items, admin } => (admin, R::RequestsCancel { id, items }),
            RequestsCmd::Approve { .. } => unreachable!("handled in run_command"),
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
        println!("{}", json_text(value));
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
        Command::Requests(RequestsCmd::Approve { id, items, late, duration, yes, admin }) => {
            requests_approve(id, items, late, duration, yes, &admin).await
        }
        Command::Requests(RequestsCmd::Show { id, admin }) if !admin.json => {
            let v = admin_send(&admin, &AdminRequest::RequestsShow { id }).await?;
            print!("{}", render_request(&v));
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

    /// `--url-file` (a file or `-` for stdin) and `--url` are alternatives; `--url` warns about shell history, and
    /// neither the warning nor an error repeats the URL.
    #[test]
    fn sinks_add_reads_the_url_from_a_file_or_stdin() {
        let url = "https://hooks.example.com/x/T0K3N";
        let base = ["sinks", "add", "n8n", "--project", "acme", "--secret-file", "/tmp/s"];
        let with = |extra: &[&str]| parse(&base.iter().copied().chain(extra.iter().copied()).collect::<Vec<_>>());
        assert!(with(&[]).is_err(), "one of --url and --url-file is required");
        assert!(with(&["--url", url, "--url-file", "-"]).is_err(), "not both");
        let Command::Sinks(SinksCmd::Add { url: u, url_file: f, .. }) = with(&["--url-file", "-"]).unwrap().command
        else {
            panic!()
        };
        assert_eq!((u, f), (None, Some(PathBuf::from("-"))));

        let (mut none, mut warn) = (std::io::empty(), Vec::new());
        // stdin, trimmed, no warning.
        let got = sink_url(None, Some("-".into()), &mut format!("  {url}\n").as_bytes(), &mut warn).unwrap();
        assert_eq!((got.as_str(), warn.is_empty()), (url, true));
        assert!(sink_url(None, Some("-".into()), &mut &b" \n"[..], &mut warn).is_err(), "empty");
        let long = vec![b'a'; MAX_SINK_URL_BYTES as usize + 1];
        assert!(sink_url(None, Some("-".into()), &mut long.as_slice(), &mut warn).is_err(), "too long");
        // --url keeps working, with a warning that names the alternative but not the URL.
        assert_eq!(sink_url(Some(url.into()), None, &mut none, &mut warn).unwrap(), url);
        let w = String::from_utf8(warn).unwrap();
        assert!(w.contains("shell history") && w.contains("--url-file") && !w.contains("T0K3N"), "{w}");
        // A file: owner-only mode like a secret file, trimmed.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("url");
        std::fs::write(&path, format!("{url}\n")).unwrap();
        crate::platform::restrict_file(&path).unwrap();
        let mut warn = Vec::new();
        assert_eq!(sink_url(None, Some(path.clone()), &mut none, &mut warn).unwrap(), url);
        assert!(warn.is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let e = format!("{:#}", sink_url(None, Some(path), &mut none, &mut warn).unwrap_err());
            assert!(!e.contains("T0K3N"), "{e}");
        }
    }

    /// No flag leaves redaction to the server's `clients.redact_secrets_default` (`None`, not sent at all, so an older
    /// service still parses the request); `--no-redact-secrets` is an explicit opt-out; both flags are refused.
    #[test]
    fn redaction_flags_are_tri_state() {
        let create = ["clients", "create", "bot", "--project", "acme", "--grant", "info=read"];
        let invite = ["clients", "invite", "bot", "--project", "acme"];
        for base in [&create[..], &invite[..]] {
            let req = |extra: &[&str]| {
                let cli = parse(&base.iter().copied().chain(extra.iter().copied()).collect::<Vec<_>>())?;
                Ok::<_, clap::Error>(admin_request(cli.command).unwrap().1)
            };
            let flag = |r: &AdminRequest| match r {
                AdminRequest::ClientsCreate { redact_secrets, .. }
                | AdminRequest::ClientsInvite { redact_secrets, .. } => *redact_secrets,
                _ => panic!(),
            };
            assert_eq!(flag(&req(&[]).unwrap()), None);
            assert_eq!(flag(&req(&["--redact-secrets"]).unwrap()), Some(true));
            assert_eq!(flag(&req(&["--no-redact-secrets"]).unwrap()), Some(false));
            assert!(req(&["--redact-secrets", "--no-redact-secrets"]).is_err());
            let wire = serde_json::to_value(req(&[]).unwrap()).unwrap();
            assert!(wire.get("redact_secrets").is_none(), "{wire}");
        }
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
    fn requests_subcommands_parse() {
        let Command::Requests(RequestsCmd::List { status, .. }) =
            parse(&["requests", "list", "--status", "pending"]).unwrap().command
        else {
            panic!()
        };
        assert_eq!(status.as_deref(), Some("pending"));
        let Command::Requests(RequestsCmd::Show { id, .. }) = parse(&["requests", "show", "r_1"]).unwrap().command
        else {
            panic!()
        };
        assert_eq!(id, "r_1");
        let Command::Requests(RequestsCmd::Approve { id, items, late, yes, .. }) =
            parse(&["requests", "approve", "r_1", "--items", "0,2", "--late", "send", "--yes"]).unwrap().command
        else {
            panic!()
        };
        assert_eq!((id.as_str(), items, late, yes), ("r_1", Some(vec![0, 2]), LateArg::Send, true));
        // Defaults: every item, skip late ones, ask first.
        let Command::Requests(RequestsCmd::Approve { items, late, yes, .. }) =
            parse(&["requests", "approve", "r_1"]).unwrap().command
        else {
            panic!()
        };
        assert_eq!((items, late, yes), (None, LateArg::Skip, false));
        assert!(parse(&["requests", "approve", "r_1", "--late", "later"]).is_err());
        // Access approvals: --duration in minutes or with a unit, only whole minutes up to 30 days.
        for (arg, want) in [("90", 90), ("90m", 90), ("8h", 480), ("7d", 10_080), ("30d", 43_200)] {
            let Command::Requests(RequestsCmd::Approve { duration, .. }) =
                parse(&["requests", "approve", "r_1", "--duration", arg]).unwrap().command
            else {
                panic!()
            };
            assert_eq!(duration, Some(want), "{arg}");
        }
        for bad in ["0", "31d", "30s", "90x", "", "-5"] {
            assert!(parse(&["requests", "approve", "r_1", "--duration", bad]).is_err(), "{bad}");
        }
        assert!(parse(&["requests", "approve"]).is_err(), "the id is required");
        let Command::Requests(RequestsCmd::Deny { id, .. }) = parse(&["requests", "deny", "r_2"]).unwrap().command
        else {
            panic!()
        };
        assert_eq!(id, "r_2");
        let Command::Requests(RequestsCmd::Cancel { id, items, .. }) =
            parse(&["requests", "cancel", "r_3", "--items", "1"]).unwrap().command
        else {
            panic!()
        };
        assert_eq!((id.as_str(), items), ("r_3", Some(vec![1])));
        let (_, req) = admin_request(parse(&["requests", "cancel", "r_3"]).unwrap().command).unwrap();
        assert!(matches!(req, AdminRequest::RequestsCancel { items: None, .. }));
    }

    /// `--json` output keeps the value but never writes DEL, C1 or bidi controls raw.
    #[test]
    fn json_output_escapes_terminal_controls() {
        let v = serde_json::json!({ "body_text": "a\u{7f}b\u{85}c\u{9b}31m\u{202E}d\u{2067}e\x1b[0m\n", "k\u{9d}": 1 });
        let out = json_text(&v);
        assert!(!out.chars().any(|c| (c.is_control() && c != '\n') || is_bidi_control(c)), "{out:?}");
        assert!(out.contains("\\u009B") && out.contains("\\u202E"), "{out}");
        assert_eq!(serde_json::from_str::<Value>(&out).unwrap(), v);
    }

    /// Draft text is untrusted: escape sequences and bidi overrides never reach the operator's terminal raw.
    #[test]
    fn untrusted_text_is_terminal_safe() {
        let s = terminal_safe("ok\x1b[2J\x1b]0;x\x07line\n\ttab\u{202E}evil\u{2066}\r");
        assert!(
            !s.chars().any(|c| (c.is_control() && c != '\n' && c != '\t') || c == '\u{202E}' || c == '\u{2066}'),
            "{s:?}"
        );
        assert!(s.starts_with("ok\u{FFFD}[2J") && s.contains("line\n\ttab"), "{s:?}");
        let v = serde_json::json!({ "request_id": "r_1", "note": "a\x1b[31mred", "items": [
            { "idx": 0, "state": "pending", "send_at": "t", "draft_id": "d", "revision": "r", "sendable": true,
              "from": "x\x1b[0m", "to": ["y"], "subject": "s\x07", "body_text": "b\x1bc", "attachments": [] }
        ]});
        assert!(!render_request(&v).contains('\x1b') && !render_request(&v).contains('\x07'));
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
