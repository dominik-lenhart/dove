//! Remote client commands (spec 5.6): `login`, `logout`, `status`, `search`, `message`, `thread`, `draft`, `batch`,
//! `mcp install|stdio`, `connect-info`, `doctor --profile`.
//!
//! These commands talk only to the remote HTTP endpoints with the profile's connection token. This module has no
//! path to the admin socket or admin verbs (checked by a test), and no flag selects another transport, so a remote
//! command can never exceed the rights of its connection.

pub mod install;
pub mod profile;
pub mod remote;
pub mod stdio;

use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use anyhow::{Context, anyhow, bail};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use install::{HostClient, Scope};
use profile::{CredentialRef, Profile, ProfileFile};
use remote::Remote;

#[derive(Args, Clone)]
pub struct ProfileOpts {
    /// Local profile (see `dove login`). Optional when only one profile exists.
    #[arg(long)]
    pub profile: Option<String>,
    /// Print JSON (structured result, including cursor/coverage/error metadata).
    #[arg(long)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum RemoteCmd {
    /// Redeem a one-time invitation and store this connection's credential (prompted, or read from stdin).
    Login {
        #[arg(long)]
        server: String,
        #[arg(long)]
        profile: String,
        /// Store the credential in this file (mode 0600) instead of the OS credential store. Explicit choice only.
        #[arg(long)]
        secret_file: Option<PathBuf>,
        /// Read an operator-issued connection token (dove_...) from stdin instead of redeeming an invitation.
        #[arg(long)]
        token_stdin: bool,
        /// Replace an existing profile of the same name.
        #[arg(long)]
        force: bool,
    },
    /// Remove the local credential and profile; optionally revoke the connection on the server.
    Logout {
        #[arg(long)]
        profile: Option<String>,
        /// Also revoke the connection on the server.
        #[arg(long)]
        revoke: bool,
        /// Keep the server-side connection without asking.
        #[arg(long, conflicts_with = "revoke")]
        keep_remote: bool,
    },
    /// Show connectivity and the mailboxes/actions this connection may use.
    Status {
        #[command(flatten)]
        p: ProfileOpts,
    },
    /// Search mail (search_messages). Use flags for common filters or --query-file for a full JSON query.
    Search(SearchArgs),
    /// Read one message (get_message).
    #[command(subcommand)]
    Message(MessageCmd),
    /// Read one thread (get_thread).
    #[command(subcommand)]
    Thread(ThreadCmd),
    /// Create, read, revise or send drafts.
    #[command(subcommand)]
    Draft(DraftCmd),
    /// Run several reads in one call (batch_read). JSON from --file or stdin.
    Batch {
        #[command(flatten)]
        p: ProfileOpts,
        /// JSON file with {"items": [...]}; `-` or omitted reads stdin.
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// MCP host integration.
    #[command(subcommand)]
    Mcp(McpCmd),
    /// Print the remote MCP URL and short setup steps for MCP hosts.
    ConnectInfo {
        #[arg(long)]
        profile: Option<String>,
        /// Server URL when no profile exists yet.
        #[arg(long)]
        server: Option<String>,
    },
}

#[derive(Args, Clone)]
pub struct SearchArgs {
    #[command(flatten)]
    pub p: ProfileOpts,
    /// Mailbox alias or address (repeatable). Default: all readable mailboxes.
    #[arg(long = "account")]
    pub accounts: Vec<String>,
    #[arg(long)]
    pub from: Option<String>,
    #[arg(long)]
    pub from_domain: Option<String>,
    #[arg(long)]
    pub to: Option<String>,
    /// Subject words (all must match).
    #[arg(long)]
    pub subject: Option<String>,
    /// Words in subject or body (all must match).
    #[arg(long)]
    pub text: Option<String>,
    #[arg(long)]
    pub label: Option<String>,
    /// Received at or after (RFC 3339, or YYYY-MM-DD as UTC midnight).
    #[arg(long)]
    pub after: Option<String>,
    /// Received before (RFC 3339, or YYYY-MM-DD as UTC midnight).
    #[arg(long)]
    pub before: Option<String>,
    #[arg(long)]
    pub unread: bool,
    #[arg(long)]
    pub has_attachment: bool,
    /// Comma-separated output columns, e.g. subject,from,received_at.
    #[arg(long)]
    pub select: Option<String>,
    /// field:dir, e.g. received_at:asc (repeatable, at most two).
    #[arg(long = "order-by")]
    pub order_by: Vec<String>,
    #[arg(long)]
    pub limit: Option<u32>,
    #[arg(long)]
    pub cursor: Option<String>,
    /// Return only an exact count.
    #[arg(long)]
    pub count: bool,
    /// Fail with index_incomplete instead of returning partial results.
    #[arg(long)]
    pub require_complete: bool,
    /// Use Gmail's native search syntax (live) instead of the index.
    #[arg(long)]
    pub gmail_query: Option<String>,
    /// Full search_messages arguments as JSON; `-` reads stdin. Cannot be combined with filter flags.
    #[arg(long)]
    pub query_file: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum MessageCmd {
    Get {
        #[command(flatten)]
        p: ProfileOpts,
        #[arg(long)]
        account: Option<String>,
        #[arg(long)]
        id: Option<String>,
        /// Opaque ref from search (replaces --account/--id).
        #[arg(long = "ref")]
        reference: Option<String>,
        #[arg(long)]
        max_body_chars: Option<u32>,
        /// Extra headers, comma-separated (e.g. Reply-To,List-Unsubscribe).
        #[arg(long)]
        headers: Option<String>,
    },
    /// Attachments of a message.
    #[command(subcommand)]
    Attachment(AttachmentCmd),
}

#[derive(Subcommand)]
pub enum AttachmentCmd {
    /// Save one attachment as a file (mode 0600). Refuses to overwrite and never opens the file.
    Save {
        #[command(flatten)]
        p: ProfileOpts,
        /// Opaque message ref from search or get_message.
        #[arg(long = "ref")]
        reference: String,
        /// Attachment id from get_message (e.g. part-2).
        #[arg(long)]
        attachment_id: String,
        /// Target directory (default: the current directory).
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum ThreadCmd {
    Get {
        #[command(flatten)]
        p: ProfileOpts,
        #[arg(long)]
        account: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        max_body_chars: Option<u32>,
    },
}

#[derive(Args, Clone)]
pub struct DraftContent {
    #[arg(long)]
    pub to: Vec<String>,
    #[arg(long)]
    pub cc: Vec<String>,
    #[arg(long)]
    pub bcc: Vec<String>,
    #[arg(long)]
    pub subject: Option<String>,
    #[arg(long, conflicts_with = "body_file")]
    pub body: Option<String>,
    /// Body text from a file; `-` reads stdin.
    #[arg(long)]
    pub body_file: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum DraftCmd {
    Create {
        #[command(flatten)]
        p: ProfileOpts,
        #[arg(long)]
        account: String,
        #[command(flatten)]
        content: DraftContent,
        /// Message id to reply to (threads the draft).
        #[arg(long)]
        reply_to: Option<String>,
        /// Send-as address of the mailbox.
        #[arg(long)]
        from: Option<String>,
        /// Idempotency key; reuse the printed key to retry the same draft safely. Generated when omitted.
        #[arg(long)]
        request_key: Option<String>,
    },
    Get {
        #[command(flatten)]
        p: ProfileOpts,
        #[arg(long)]
        account: String,
        #[arg(long)]
        id: String,
    },
    Update {
        #[command(flatten)]
        p: ProfileOpts,
        #[arg(long)]
        account: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        revision: String,
        #[command(flatten)]
        content: DraftContent,
    },
    Send {
        #[command(flatten)]
        p: ProfileOpts,
        #[arg(long)]
        account: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        revision: String,
    },
}

#[derive(Subcommand)]
pub enum McpCmd {
    /// Add `dove mcp stdio --profile <p>` to Claude Code or Codex (user scope by default).
    Install {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long, value_enum)]
        client: HostClient,
        #[arg(long, value_enum, default_value = "user")]
        scope: Scope,
        /// Server entry name. Default: dove-<profile>.
        #[arg(long)]
        name: Option<String>,
    },
    /// Bridge stdio MCP to the remote Streamable HTTP endpoint (started by the MCP host).
    Stdio {
        #[arg(long)]
        profile: Option<String>,
    },
}

/// Runs a remote command. Never touches the admin socket.
pub async fn run(cmd: RemoteCmd) -> anyhow::Result<()> {
    match cmd {
        RemoteCmd::Login { server, profile, secret_file, token_stdin, force } => {
            login(&server, &profile, secret_file, token_stdin, force).await
        }
        RemoteCmd::Logout { profile, revoke, keep_remote } => logout(profile.as_deref(), revoke, keep_remote).await,
        RemoteCmd::Status { p } => status(&p).await,
        RemoteCmd::Search(a) => search(a).await,
        RemoteCmd::Message(MessageCmd::Attachment(AttachmentCmd::Save { p, reference, attachment_id, out })) => {
            save_attachment(&p, &reference, &attachment_id, out).await
        }
        RemoteCmd::Message(MessageCmd::Get { p, account, id, reference, max_body_chars, headers }) => {
            let mut args = json!({});
            match (reference, account, id) {
                (Some(r), None, None) => args["ref"] = json!(r),
                (None, Some(a), Some(i)) => {
                    args["account"] = json!(a);
                    args["message_id"] = json!(i);
                }
                _ => bail!("use either --ref, or --account with --id"),
            }
            if let Some(n) = max_body_chars {
                args["max_body_chars"] = json!(n);
            }
            if let Some(h) = headers {
                args["include_headers"] = json!(split_csv(&h));
            }
            tool(&p, "get_message", args).await
        }
        RemoteCmd::Thread(ThreadCmd::Get { p, account, id, max_body_chars }) => {
            let mut args = json!({ "account": account, "thread_id": id });
            if let Some(n) = max_body_chars {
                args["max_body_chars"] = json!(n);
            }
            tool(&p, "get_thread", args).await
        }
        RemoteCmd::Draft(d) => draft(d).await,
        RemoteCmd::Batch { p, file } => {
            let text = read_input(file.as_deref())?;
            let v: Value = serde_json::from_str(&text).context("batch input is not JSON")?;
            let args = if v.is_array() { json!({ "items": v }) } else { v };
            tool(&p, "batch_read", args).await
        }
        RemoteCmd::Mcp(McpCmd::Install { profile, client, scope, name }) => {
            mcp_install(profile.as_deref(), client, scope, name.as_deref())
        }
        RemoteCmd::Mcp(McpCmd::Stdio { profile }) => {
            let (_, p, token) = load(profile.as_deref())?;
            stdio::run(&p.server, token).await
        }
        RemoteCmd::ConnectInfo { profile, server } => connect_info(profile.as_deref(), server.as_deref()).await,
    }
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
}

fn read_input(path: Option<&std::path::Path>) -> anyhow::Result<String> {
    match path {
        Some(p) if p.as_os_str() != "-" => {
            std::fs::read_to_string(p).with_context(|| format!("cannot read {}", p.display()))
        }
        _ => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            Ok(s)
        }
    }
}

/// Loads a profile and its credential.
fn load(name: Option<&str>) -> anyhow::Result<(String, Profile, Zeroizing<String>)> {
    let file = ProfileFile::load()?;
    let (name, p) = file.resolve(name)?;
    let token = profile::load_token(&p.credential_ref()?, &name, &p.server)?;
    Ok((name, p, token))
}

fn remote_for(name: Option<&str>) -> anyhow::Result<(String, Profile, Remote)> {
    let (name, p, token) = load(name)?;
    let r = Remote::new(&p.server, token)?;
    Ok((name, p, r))
}

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

fn rights_lines(accounts: &[Value]) -> Vec<String> {
    accounts
        .iter()
        .map(|a| {
            let actions = a["actions"]
                .as_array()
                .map(|x| x.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(","))
                .or_else(|| a["actions"].as_str().map(str::to_string))
                .unwrap_or_default();
            let status = a["status"].as_str().map(|s| format!(" [{s}]")).unwrap_or_default();
            format!(
                "  {} <{}>: {actions}{status}",
                a["account"].as_str().unwrap_or("?"),
                a["email"].as_str().unwrap_or("?")
            )
        })
        .collect()
}

/// Calls one tool and prints its result. Tool errors exit non-zero.
async fn tool(p: &ProfileOpts, name: &str, args: Value) -> anyhow::Result<()> {
    let (_, _, r) = remote_for(p.profile.as_deref())?;
    let res = r.call_tool(name, args).await?;
    print_tool(p.json, &res)
}

/// `dove message attachment save`: writes the bytes of one attachment to `<out>/<sanitised filename>`, mode 0600,
/// failing if the file exists. The file is never opened or executed.
async fn save_attachment(
    p: &ProfileOpts,
    reference: &str,
    attachment_id: &str,
    out: Option<PathBuf>,
) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let (_, _, r) = remote_for(p.profile.as_deref())?;
    let res = r.call_tool("get_attachment", json!({ "ref": reference, "attachment_id": attachment_id })).await?;
    if res.is_error {
        return print_tool(p.json, &res);
    }
    let blob = res
        .content
        .iter()
        .find_map(|c| (c["type"] == "resource").then(|| c["resource"]["blob"].as_str()).flatten())
        .ok_or_else(|| anyhow!("the server returned no attachment bytes"))?;
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, blob)
        .context("the server returned undecodable attachment bytes")?;
    if res.structured["size_bytes"].as_u64() != Some(bytes.len() as u64) {
        bail!("the attachment size does not match what the server announced");
    }
    // The server sanitises the name already; do it again so a hostile name can never leave the target directory.
    let name = crate::tools::attachments::sanitize_filename(res.structured["filename"].as_str());
    let path = out.unwrap_or_else(|| PathBuf::from(".")).join(&name);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("cannot create {} (an existing file is never overwritten)", path.display()))?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    if p.json {
        print_json(&json!({ "ok": true, "result": { "path": path, "size_bytes": bytes.len(),
                                                     "mime_type": res.structured["mime_type"] } }));
    } else {
        println!("saved {} ({} bytes)", path.display(), bytes.len());
    }
    Ok(())
}

fn print_tool(json_out: bool, res: &remote::ToolResult) -> anyhow::Result<()> {
    if json_out {
        print_json(&json!({ "ok": !res.is_error, "result": res.structured }));
    } else if !res.is_error {
        println!("{}", res.text);
    }
    if res.is_error {
        let e = res.structured.get("error").unwrap_or(&res.structured);
        bail!("{}: {}", e["code"].as_str().unwrap_or("error"), e["message"].as_str().unwrap_or(&res.text));
    }
    Ok(())
}

fn date_value(s: &str) -> anyhow::Result<String> {
    if crate::util::parse_rfc3339_ms(s).is_some() {
        return Ok(s.to_string());
    }
    let d = time::Date::parse(s, time::macros::format_description!("[year]-[month]-[day]"))
        .map_err(|_| anyhow!("dates must be RFC 3339 with an offset or YYYY-MM-DD"))?;
    Ok(format!("{d}T00:00:00Z"))
}

/// Builds `search_messages` arguments from flags (or takes them verbatim from --query-file).
pub fn search_args(a: &SearchArgs) -> anyhow::Result<Value> {
    let has_flags = !a.accounts.is_empty()
        || a.from.is_some()
        || a.from_domain.is_some()
        || a.to.is_some()
        || a.subject.is_some()
        || a.text.is_some()
        || a.label.is_some()
        || a.after.is_some()
        || a.before.is_some()
        || a.unread
        || a.has_attachment
        || a.select.is_some()
        || !a.order_by.is_empty()
        || a.limit.is_some()
        || a.cursor.is_some()
        || a.count
        || a.require_complete
        || a.gmail_query.is_some();
    if let Some(f) = &a.query_file {
        if has_flags {
            bail!("--query-file cannot be combined with filter flags");
        }
        let v: Value = serde_json::from_str(&read_input(Some(f))?).context("query file is not JSON")?;
        if !v.is_object() {
            bail!("the query must be a JSON object of search_messages arguments");
        }
        return Ok(v);
    }
    let mut args = json!({});
    if !a.accounts.is_empty() {
        args["accounts"] = json!(a.accounts);
    }
    if let Some(cursor) = &a.cursor {
        args["cursor"] = json!(cursor);
        return Ok(args);
    }
    if let Some(q) = &a.gmail_query {
        args["source"] = json!("gmail");
        args["gmail_query"] = json!(q);
    }
    let mut preds = Vec::new();
    let eq = |f: &str, v: Value| json!({ "field": f, "op": "eq", "value": v });
    if let Some(v) = &a.from {
        preds.push(eq("from", json!(v)));
    }
    if let Some(v) = &a.from_domain {
        preds.push(eq("from_domain", json!(v)));
    }
    if let Some(v) = &a.to {
        preds.push(eq("to", json!(v)));
    }
    if let Some(v) = &a.label {
        preds.push(eq("label", json!(v)));
    }
    if let Some(v) = &a.subject {
        preds.push(json!({ "field": "subject", "op": "terms", "value": v }));
    }
    if let Some(v) = &a.text {
        preds.push(json!({ "field": "text", "op": "terms", "value": v }));
    }
    if let Some(v) = &a.after {
        preds.push(json!({ "field": "received_at", "op": "gte", "value": date_value(v)? }));
    }
    if let Some(v) = &a.before {
        preds.push(json!({ "field": "received_at", "op": "lt", "value": date_value(v)? }));
    }
    if a.unread {
        preds.push(eq("is_unread", json!(true)));
    }
    if a.has_attachment {
        preds.push(eq("has_attachment", json!(true)));
    }
    if !preds.is_empty() {
        if a.gmail_query.is_some() {
            bail!("--gmail-query cannot be combined with index filters");
        }
        args["where"] = json!({ "all": preds });
    }
    if let Some(s) = &a.select {
        args["select"] = json!(split_csv(s));
    }
    if !a.order_by.is_empty() {
        let mut keys = Vec::new();
        for o in &a.order_by {
            let (f, d) = o.split_once(':').unwrap_or((o.as_str(), "desc"));
            keys.push(json!({ "field": f, "dir": d }));
        }
        args["order_by"] = json!(keys);
    }
    if let Some(l) = a.limit {
        args["limit"] = json!(l);
    }
    if a.count {
        args["count_only"] = json!(true);
    }
    if a.require_complete {
        args["coverage_policy"] = json!("require_complete");
    }
    Ok(args)
}

async fn search(a: SearchArgs) -> anyhow::Result<()> {
    let args = search_args(&a)?;
    tool(&a.p, "search_messages", args).await
}

fn draft_changes(c: &DraftContent) -> anyhow::Result<Value> {
    let mut v = json!({});
    for (k, list) in [("to", &c.to), ("cc", &c.cc), ("bcc", &c.bcc)] {
        if !list.is_empty() {
            v[k] = json!(list);
        }
    }
    if let Some(s) = &c.subject {
        v["subject"] = json!(s);
    }
    if let Some(b) = &c.body {
        v["body_text"] = json!(b);
    } else if let Some(f) = &c.body_file {
        v["body_text"] = json!(read_input(Some(f))?);
    }
    Ok(v)
}

async fn draft(d: DraftCmd) -> anyhow::Result<()> {
    match d {
        DraftCmd::Create { p, account, content, reply_to, from, request_key } => {
            let key = request_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let mut args = draft_changes(&content)?;
            args["account"] = json!(account);
            args["request_key"] = json!(key);
            if let Some(r) = reply_to {
                args["reply_to_message_id"] = json!(r);
            }
            if let Some(f) = from {
                args["from_address"] = json!(f);
            }
            eprintln!("request key: {key} (reuse it with --request-key to retry this draft safely)");
            let (_, _, r) = remote_for(p.profile.as_deref())?;
            // A transport failure may hide a created draft; one retry with the same key cannot create a second one.
            let res = match r.call_tool("create_draft", args.clone()).await {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("dove: {e}; retrying once with the same request key");
                    r.call_tool("create_draft", args).await.with_context(|| {
                        format!("outcome unknown; retry later with --request-key {key}, never with a new key")
                    })?
                }
            };
            print_tool(p.json, &res)
        }
        DraftCmd::Get { p, account, id } => tool(&p, "get_draft", json!({ "account": account, "draft_id": id })).await,
        DraftCmd::Update { p, account, id, revision, content } => {
            let changes = draft_changes(&content)?;
            if changes.as_object().is_some_and(|o| o.is_empty()) {
                bail!("nothing to change; pass --to/--cc/--bcc/--subject/--body/--body-file");
            }
            tool(
                &p,
                "update_draft",
                json!({ "account": account, "draft_id": id, "expected_revision": revision, "changes": changes }),
            )
            .await
        }
        DraftCmd::Send { p, account, id, revision } => {
            tool(&p, "send_draft", json!({ "account": account, "draft_id": id, "expected_revision": revision })).await
        }
    }
}

fn read_secret_input(prompt: &str) -> anyhow::Result<Zeroizing<String>> {
    if std::io::stdin().is_terminal() {
        Ok(Zeroizing::new(rpassword::prompt_password(prompt).context("cannot read from the terminal")?))
    } else {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin().read_line(&mut line)?;
        Ok(Zeroizing::new(line.trim().to_string()))
    }
}

async fn login(
    server: &str,
    name: &str,
    secret_file: Option<PathBuf>,
    token_stdin: bool,
    force: bool,
) -> anyhow::Result<()> {
    let server = profile::normalize_server(server)?;
    if !profile::valid_profile_name(name) {
        bail!("profile names use a-z, 0-9, - and _ (max 64)");
    }
    let mut file = ProfileFile::load()?;
    if file.profiles.contains_key(name) && !force {
        bail!("profile '{name}' exists; use --force to replace it or `dove logout --profile {name}` first");
    }
    // Decide where the credential goes before anything is redeemed: never a silent fallback.
    let cred = match secret_file {
        Some(p) => CredentialRef::File(profile::secret_file_path(&p)?),
        None => {
            profile::keyring_available(name, &server).map_err(|e| {
                anyhow!("{e}. Re-run with --secret-file <path> to keep the credential in a file readable only by you (0600).")
            })?;
            CredentialRef::Keyring
        }
    };
    let (token, connection, project, mailboxes) = if token_stdin {
        let token = read_secret_input("Connection token: ")?;
        if !crate::tokens::looks_valid(crate::tokens::CLIENT_TOKEN_PREFIX, &token) {
            bail!("that is not a Dove connection token");
        }
        let r = Remote::new(&server, token.clone())?;
        let rights = r.rights().await?;
        (token, "(operator-issued)".to_string(), "-".to_string(), rights)
    } else {
        let invitation = read_secret_input("One-time invitation: ")?;
        if invitation.is_empty() {
            bail!("no invitation entered");
        }
        let v = remote::redeem(&server, &invitation).await?;
        let token = Zeroizing::new(v["token"].as_str().ok_or_else(|| anyhow!("server returned no token"))?.to_string());
        (
            token,
            v["connection"].as_str().unwrap_or("").to_string(),
            v["project"].as_str().unwrap_or("").to_string(),
            v["mailboxes"].as_array().cloned().unwrap_or_default(),
        )
    };
    if let Err(e) = profile::store_token(&cred, name, &server, &token) {
        bail!(
            "{e:#}. The connection '{connection}' was created but its credential could not be saved; ask the operator \
             to revoke it and issue a new invitation."
        );
    }
    let credential = match &cred {
        CredentialRef::Keyring => "keyring".to_string(),
        CredentialRef::File(p) => format!("file:{}", p.display()),
    };
    file.profiles
        .insert(name.to_string(), Profile { server: server.clone(), connection: connection.clone(), credential });
    file.save()?;
    println!("Logged in. Profile '{name}' -> {server}");
    println!("Connection: {connection} (project {project})");
    println!("Credential: {}", cred.describe());
    println!("Mailboxes and actions:");
    for l in rights_lines(&mailboxes) {
        println!("{l}");
    }
    println!("Next: dove status --profile {name}; dove mcp install --profile {name} --client claude-code");
    Ok(())
}

async fn logout(name: Option<&str>, revoke: bool, keep_remote: bool) -> anyhow::Result<()> {
    let mut file = ProfileFile::load()?;
    let (name, p) = file.resolve(name)?;
    let cred = p.credential_ref()?;
    let do_revoke = if revoke {
        true
    } else if keep_remote || !std::io::stdin().is_terminal() {
        false
    } else {
        eprint!("Also revoke connection '{}' on the server? [y/N] ", p.connection);
        let mut a = String::new();
        std::io::stdin().read_line(&mut a)?;
        matches!(a.trim(), "y" | "Y" | "yes")
    };
    if do_revoke {
        let token = profile::load_token(&cred, &name, &p.server)?;
        Remote::new(&p.server, token)?.revoke_self().await?;
        println!("Revoked connection '{}' on the server.", p.connection);
    }
    profile::delete_token(&cred, &name, &p.server)?;
    file.profiles.remove(&name);
    file.save()?;
    println!("Removed local profile '{name}' and its credential.");
    if !do_revoke {
        println!(
            "The connection stays valid on the server. Revoke it with `dove logout --revoke` or ask the operator."
        );
    }
    Ok(())
}

async fn status(p: &ProfileOpts) -> anyhow::Result<()> {
    let (name, prof, r) = remote_for(p.profile.as_deref())?;
    let rights = r.rights().await?;
    let tools = r.tool_names().await?;
    if p.json {
        print_json(&json!({ "profile": name, "server": prof.server, "connection": prof.connection,
                            "credential": prof.credential_ref()?.describe(), "connected": true,
                            "mailboxes": rights, "tools": tools }));
        return Ok(());
    }
    println!("Profile: {name}\nServer: {} (reachable, credential accepted)", prof.server);
    println!("Connection: {}\nCredential: {}", prof.connection, prof.credential_ref()?.describe());
    println!("Mailboxes and actions:");
    for l in rights_lines(&rights) {
        println!("{l}");
    }
    println!("Tools: {}", tools.join(", "));
    Ok(())
}

fn mcp_install(name: Option<&str>, client: HostClient, scope: Scope, entry_name: Option<&str>) -> anyhow::Result<()> {
    let file = ProfileFile::load()?;
    let (profile_name, _) = file.resolve(name)?;
    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("cannot determine the absolute path of the dove executable")?;
    let entry = install::Entry::for_profile(&profile_name, entry_name, &exe);
    if !entry.name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        bail!("--name may use letters, digits, - and _");
    }
    let path = install::config_path(client, scope, &profile::home_dir()?, &std::env::current_dir()?);
    let mode = if scope == Scope::User { 0o600 } else { 0o644 };
    let outcome = install::install(client, &path, &entry, mode)?;
    let verb = match outcome {
        install::Outcome::Installed => "Added",
        install::Outcome::Updated => "Updated",
        install::Outcome::Unchanged => "Already present:",
    };
    println!("{verb} MCP server '{}' in {}", entry.name, path.display());
    println!("Command: {} {}", entry.command, entry.args.join(" "));
    println!("No credential is written to this file; the bridge reads it from the profile's credential store.");
    Ok(())
}

async fn connect_info(name: Option<&str>, server: Option<&str>) -> anyhow::Result<()> {
    let (server, prof) = match server {
        Some(s) => (profile::normalize_server(s)?, None),
        None => {
            let file = ProfileFile::load()?;
            let (n, p) = file.resolve(name)?;
            (p.server.clone(), Some(n))
        }
    };
    println!("Remote MCP URL: {server}/mcp\n");
    println!("Claude Code or Codex on this computer:");
    println!("  dove login --server {server} --profile <name>     (enter the invitation when asked)");
    println!("  dove mcp install --profile <name> --client claude-code|codex");
    println!("Claude or ChatGPT (web/desktop): add a custom connector / MCP server with the URL above, choose OAuth");
    println!("  sign-in, enter the operator's one-time invitation on Dove's approval page, check project, mailboxes");
    println!("  and application, then approve.");
    println!("(Host menus change often; these steps are not verified against current host versions.)");
    if let Some(n) = prof {
        match remote_for(Some(&n)) {
            Ok((_, _, r)) => match r.rights().await {
                Ok(rights) => {
                    println!("\nProfile '{n}' rights:");
                    for l in rights_lines(&rights) {
                        println!("{l}");
                    }
                }
                Err(e) => println!("\nProfile '{n}': {e}"),
            },
            Err(e) => println!("\nProfile '{n}': {e}"),
        }
    }
    Ok(())
}

/// `dove doctor --profile`: reports missing config, credentials, network access or grants without secrets.
pub async fn doctor(name: Option<&str>, json_out: bool) -> anyhow::Result<()> {
    let mut checks: Vec<(String, bool, String)> = Vec::new();
    let mut add = |n: &str, ok: bool, d: String| checks.push((n.to_string(), ok, d));
    let path = profile::profiles_path()?;
    let file = ProfileFile::load();
    add("profile_file", file.is_ok(), path.display().to_string());
    let resolved = file.and_then(|f| f.resolve(name));
    add("profile", resolved.is_ok(), resolved.as_ref().map(|(n, _)| n.clone()).unwrap_or_else(|e| e.to_string()));
    let mut rights = None;
    if let Ok((n, p)) = &resolved {
        let server_ok = profile::normalize_server(&p.server).is_ok();
        add("server_url", server_ok, p.server.clone());
        let token = p.credential_ref().and_then(|c| profile::load_token(&c, n, &p.server).map(|t| (c, t)));
        add(
            "credential",
            token.is_ok(),
            match &token {
                Ok((c, _)) => format!("present in {}", c.describe()),
                Err(e) => e.to_string(),
            },
        );
        let http = remote::http_client()?;
        let health = http.get(format!("{}/healthz", p.server)).send().await;
        add(
            "network",
            health.as_ref().is_ok_and(|r| r.status().is_success()),
            match health {
                Ok(r) => format!("/healthz HTTP {}", r.status().as_u16()),
                Err(e) => format!("unreachable ({})", e.without_url()),
            },
        );
        let prm = http.get(format!("{}/.well-known/oauth-protected-resource", p.server)).send().await;
        add("discovery", prm.as_ref().is_ok_and(|r| r.status().is_success()), "protected resource metadata".into());
        if let Ok((_, t)) = token {
            let r = Remote::new(&p.server, t)?;
            match r.rights().await {
                Ok(acc) => {
                    let usable = acc.iter().any(|a| a["status"] == "active");
                    add("grants", !acc.is_empty() && usable, format!("{} mailbox(es)", acc.len()));
                    rights = Some(acc);
                }
                Err(e) => add("grants", false, e.to_string()),
            }
        }
    }
    let ok = checks.iter().all(|c| c.1);
    if json_out {
        print_json(&json!({
            "ok": ok,
            "checks": checks.iter().map(|(n, o, d)| json!({ "check": n, "ok": o, "detail": d })).collect::<Vec<_>>(),
            "mailboxes": rights,
        }));
    } else {
        for (n, o, d) in &checks {
            println!("{} {n}: {d}", if *o { "ok  " } else { "FAIL" });
        }
        if let Some(r) = &rights {
            println!("Mailboxes and actions:");
            for l in rights_lines(r) {
                println!("{l}");
            }
        }
    }
    if !ok {
        bail!("doctor found problems");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// Structural check for spec 5.6: remote commands have no path to the admin socket or admin verbs.
    #[test]
    fn remote_commands_do_not_reference_admin() {
        for (name, src) in [
            ("mod.rs", include_str!("mod.rs")),
            ("profile.rs", include_str!("profile.rs")),
            ("remote.rs", include_str!("remote.rs")),
            ("stdio.rs", include_str!("stdio.rs")),
            ("install.rs", include_str!("install.rs")),
        ] {
            let code = src.split("#[cfg(test)]").next().unwrap();
            for needle in ["crate::admin", "AdminRequest", "UnixStream", "admin_client", "DOVE_ADMIN_SOCKET"] {
                assert!(!code.contains(needle), "{name} references {needle}");
            }
        }
    }
}
