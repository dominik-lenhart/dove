//! `dove watch`: create, list and delete watches, read their events, and `listen`, which runs a fixed local command
//! once per new event.
//!
//! `listen` only makes outgoing calls to the Dove server (`list_watch_events`), so the machine that runs the agent
//! needs no open port, relay or webhook receiver. The command it starts is fixed by the operator; it learns about the
//! event only through `DOVE_*` environment variables that carry ids and times, never mail content. The agent then
//! reads the mail through its normal, audited tools. Events are handled one at a time, in order; the cursor is saved
//! after each handled event (mode 0600, under the client config directory), so a restart neither repeats nor skips
//! one, and a lock file keeps a second listener on the same profile from running the command twice.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::profile;
use super::remote::Remote;
use super::{ProfileOpts, print_tool, read_input, remote_for};

#[derive(Subcommand)]
pub enum WatchCmd {
    /// Watch a mailbox (create_watch): new mail from an address or domain, a reply in a thread, new mail matching a
    /// search condition, or no reply in a thread by a deadline.
    Create(CreateArgs),
    /// This connection's watches (list_watches).
    List {
        #[command(flatten)]
        p: ProfileOpts,
    },
    /// End a watch (delete_watch).
    Delete {
        #[command(flatten)]
        p: ProfileOpts,
        #[arg(long)]
        id: String,
    },
    /// Events of this connection's watches, oldest first (list_watch_events). Events carry ids, never content.
    Events {
        #[command(flatten)]
        p: ProfileOpts,
        /// Only events after this cursor (the `next_cursor` of an earlier call).
        #[arg(long)]
        cursor: Option<String>,
        /// Only events of this watch.
        #[arg(long)]
        watch: Option<String>,
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Poll for new events and run COMMAND once per event, in order, one at a time. COMMAND gets only ids and times
    /// in DOVE_* environment variables (DOVE_EVENT_ID, DOVE_WATCH_ID, DOVE_EVENT_KIND, DOVE_ACCOUNT, DOVE_MESSAGE_ID,
    /// DOVE_THREAD_ID, DOVE_RECEIVED_AT, DOVE_PROFILE), never mail content. Example:
    /// `dove watch listen --profile ops -- claude -p --resume <session-id> --fork-session "A Dove watch fired ..."`
    Listen(ListenArgs),
}

#[derive(Args)]
pub struct CreateArgs {
    #[command(flatten)]
    pub p: ProfileOpts,
    /// Mailbox alias or address.
    #[arg(long)]
    pub account: String,
    /// New mail from this address (ann@example.com) or domain (example.com).
    #[arg(long, group = "kind")]
    pub from: Option<String>,
    /// A new message from someone else in this thread.
    #[arg(long, value_name = "THREAD_ID", group = "kind")]
    pub reply_in: Option<String>,
    /// New mail matching a search_messages `where` condition (JSON file, `-` reads stdin).
    #[arg(long, value_name = "FILE", group = "kind")]
    pub where_file: Option<PathBuf>,
    /// No message from others in this thread before --deadline (fires once, at the deadline).
    #[arg(long, value_name = "THREAD_ID", group = "kind", requires = "deadline")]
    pub no_reply_in: Option<String>,
    /// RFC 3339 instant, with --no-reply-in.
    #[arg(long)]
    pub deadline: Option<String>,
    /// When the watch ends (RFC 3339). Default 30 days, at most 180.
    #[arg(long)]
    pub expires: Option<String>,
    /// Also push events to this operator webhook sink.
    #[arg(long)]
    pub sink: Option<String>,
}

#[derive(Args)]
pub struct ListenArgs {
    /// Local profile (see `dove login`). Optional when only one profile exists.
    #[arg(long)]
    pub profile: Option<String>,
    /// Only events of this watch (default: all watches of this connection).
    #[arg(long)]
    pub watch: Option<String>,
    /// Seconds between polls.
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(10..=86_400))]
    pub interval: u64,
    /// Poll once, handle what is there, and exit (for cron or a systemd timer).
    #[arg(long)]
    pub once: bool,
    /// On the first start, also handle events that already exist. By default they are skipped, so installing a
    /// listener never replays up to 14 days of old events into an agent.
    #[arg(long)]
    pub include_existing: bool,
    /// Attempts per event before it is skipped (a failed COMMAND is retried on the next poll).
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u32).range(1..=100))]
    pub max_attempts: u32,
    /// Seconds COMMAND may run before it is killed (counts as a failed attempt).
    #[arg(long, default_value_t = 1800, value_parser = clap::value_parser!(u64).range(1..=86_400))]
    pub timeout: u64,
    /// The command and its arguments, after `--`. Run directly, not through a shell.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

pub async fn run(cmd: WatchCmd) -> anyhow::Result<()> {
    match cmd {
        WatchCmd::Create(a) => create(a).await,
        WatchCmd::List { p } => call(&p, "list_watches", json!({})).await,
        WatchCmd::Delete { p, id } => call(&p, "delete_watch", json!({ "watch_id": id })).await,
        WatchCmd::Events { p, cursor, watch, limit } => {
            let mut args = json!({});
            if let Some(c) = cursor {
                args["cursor"] = json!(c);
            }
            if let Some(w) = watch {
                args["watch_id"] = json!(w);
            }
            if let Some(n) = limit {
                args["limit"] = json!(n);
            }
            call(&p, "list_watch_events", args).await
        }
        WatchCmd::Listen(a) => listen(a).await,
    }
}

async fn call(p: &ProfileOpts, name: &str, args: Value) -> anyhow::Result<()> {
    let (_, _, r) = remote_for(p.profile.as_deref())?;
    let res = r.call_tool(name, args).await?;
    print_tool(p.json, &res)
}

async fn create(a: CreateArgs) -> anyhow::Result<()> {
    let mut args = json!({ "account": a.account });
    if let Some(f) = a.from {
        args["kind"] = json!("from");
        args["from"] = json!(f);
    } else if let Some(t) = a.reply_in {
        args["kind"] = json!("thread_reply");
        args["thread_id"] = json!(t);
    } else if let Some(file) = a.where_file {
        let text = read_input(Some(&file))?;
        let w: Value = serde_json::from_str(&text).context("--where-file is not JSON")?;
        args["kind"] = json!("query");
        args["where"] = w;
    } else if let Some(t) = a.no_reply_in {
        args["kind"] = json!("no_reply_by");
        args["thread_id"] = json!(t);
        args["deadline"] = json!(a.deadline);
    } else {
        bail!("choose what to watch: --from, --reply-in, --where-file or --no-reply-in");
    }
    if let Some(e) = a.expires {
        args["expires_at"] = json!(e);
    }
    if let Some(s) = a.sink {
        args["sink"] = json!(s);
    }
    call(&a.p, "create_watch", args).await
}

/// Listener state per profile (and watch filter): the cursor after the last handled event and the failed attempts
/// of the event at the head of the queue.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct State {
    pub cursor: Option<String>,
    #[serde(default)]
    pub attempts: BTreeMap<String, u32>,
}

/// `<config dir>/watch-listen/<profile>[.<watch>].json`
pub fn state_path(profile: &str, watch: Option<&str>) -> anyhow::Result<PathBuf> {
    let name = match watch {
        Some(w) => format!("{profile}.{w}.json"),
        None => format!("{profile}.json"),
    };
    Ok(profile::config_dir()?.join("watch-listen").join(name))
}

fn load_state(path: &Path) -> anyhow::Result<Option<State>> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(serde_json::from_slice(&b).with_context(|| format!("{} is not valid", path.display()))?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
    }
}

fn save_state(path: &Path, s: &State) -> anyhow::Result<()> {
    profile::atomic_write(path, &serde_json::to_vec_pretty(s)?, 0o600)
}

/// The environment COMMAND receives for one event. Only id-like values are passed: anything with control
/// characters, spaces or over 320 bytes is refused, so a value can never smuggle text into the agent's environment.
pub fn event_env(profile: &str, e: &Value) -> anyhow::Result<Vec<(&'static str, String)>> {
    let fields = [
        ("DOVE_EVENT_ID", "event_id"),
        ("DOVE_WATCH_ID", "watch_id"),
        ("DOVE_EVENT_KIND", "kind"),
        ("DOVE_ACCOUNT", "account"),
        ("DOVE_MESSAGE_ID", "message_id"),
        ("DOVE_THREAD_ID", "thread_id"),
        ("DOVE_RECEIVED_AT", "received_at"),
    ];
    let mut out = vec![("DOVE_PROFILE", profile.to_string())];
    for (var, key) in fields {
        let v = match &e[key] {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Null => String::new(),
            _ => bail!("event field {key} has an unexpected type"),
        };
        if v.len() > 320 || !v.bytes().all(|b| b.is_ascii_graphic()) {
            bail!("event field {key} is not an id");
        }
        out.push((var, v));
    }
    if out[1].1.is_empty() {
        bail!("event without event_id");
    }
    Ok(out)
}

async fn listen(a: ListenArgs) -> anyhow::Result<()> {
    let (name, _, r) = remote_for(a.profile.as_deref())?;
    let path = state_path(&name, a.watch.as_deref())?;
    let dir = path.parent().ok_or_else(|| anyhow!("no state directory"))?;
    crate::platform::ensure_private_dir(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    // One listener per profile and watch filter: a second one would run COMMAND twice for the same event.
    let lock_path = path.with_extension("lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("cannot open {}", lock_path.display()))?;
    if lock.try_lock().is_err() {
        bail!("another `dove watch listen` already runs for profile '{name}' ({})", lock_path.display());
    }
    let mut state = match load_state(&path)? {
        Some(s) => s,
        None => {
            let s = if a.include_existing {
                State::default()
            } else {
                let (cursor, skipped) = skip_existing(&r, a.watch.as_deref()).await?;
                eprintln!("dove watch listen: first start, skipped {skipped} existing event(s)");
                State { cursor: Some(cursor), attempts: BTreeMap::new() }
            };
            save_state(&path, &s)?;
            s
        }
    };
    eprintln!("dove watch listen: profile '{name}', state {}", path.display());
    loop {
        match poll(&r, &name, &a, &path, &mut state).await {
            Ok(n) if n > 0 => eprintln!("dove watch listen: handled {n} event(s)"),
            Ok(_) => {}
            Err(e) if a.once => return Err(e),
            // A revoked or expired connection will not come back by waiting.
            Err(e) if e.to_string().contains("rejected this connection's credential") => return Err(e),
            Err(e) => eprintln!("dove watch listen: {e:#}; retrying in {}s", a.interval),
        }
        if a.once {
            return Ok(());
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(a.interval)) => {}
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}

/// Pages to the end of the event log and returns the cursor there.
async fn skip_existing(r: &Remote, watch: Option<&str>) -> anyhow::Result<(String, usize)> {
    let mut cursor: Option<String> = None;
    let mut skipped = 0;
    loop {
        let page = events_page(r, cursor.as_deref(), watch, 200).await?;
        skipped += page["events"].as_array().map_or(0, Vec::len);
        cursor = Some(next_cursor(&page)?);
        if page["has_more"] != true {
            return Ok((cursor.unwrap_or_default(), skipped));
        }
    }
}

async fn events_page(r: &Remote, cursor: Option<&str>, watch: Option<&str>, limit: u32) -> anyhow::Result<Value> {
    let mut args = json!({ "limit": limit });
    if let Some(c) = cursor {
        args["cursor"] = json!(c);
    }
    if let Some(w) = watch {
        args["watch_id"] = json!(w);
    }
    let res = r.call_tool("list_watch_events", args).await?;
    if res.is_error {
        let e = res.structured.get("error").unwrap_or(&res.structured);
        bail!("{}: {}", e["code"].as_str().unwrap_or("error"), e["message"].as_str().unwrap_or(&res.text));
    }
    Ok(res.structured)
}

fn next_cursor(page: &Value) -> anyhow::Result<String> {
    page["next_cursor"].as_str().map(str::to_string).ok_or_else(|| anyhow!("the server returned no next_cursor"))
}

/// Handles the events after the saved cursor, one per request so the cursor can be saved after each. Returns how
/// many were handled; stops at an event whose COMMAND failed (it is retried on the next poll).
async fn poll(r: &Remote, profile: &str, a: &ListenArgs, path: &Path, state: &mut State) -> anyhow::Result<usize> {
    let mut handled = 0;
    loop {
        let page = events_page(r, state.cursor.as_deref(), a.watch.as_deref(), 1).await?;
        let Some(event) = page["events"].as_array().and_then(|v| v.first()).cloned() else {
            return Ok(handled);
        };
        let next = next_cursor(&page)?;
        let event_id = event["event_id"].as_str().unwrap_or("?").to_string();
        let ok = match event_env(profile, &event) {
            Ok(env) => run_command(&a.command, &env, Duration::from_secs(a.timeout)).await,
            Err(e) => {
                eprintln!("dove watch listen: skipping event {event_id}: {e}");
                true
            }
        };
        if ok {
            state.attempts.clear();
        } else {
            let n = state.attempts.entry(event_id.clone()).or_insert(0);
            *n += 1;
            if *n < a.max_attempts {
                eprintln!(
                    "dove watch listen: event {event_id} failed (attempt {n} of {}), retrying later",
                    a.max_attempts
                );
                save_state(path, state)?;
                return Ok(handled);
            }
            eprintln!("dove watch listen: event {event_id} failed {n} times, skipping it");
            state.attempts.clear();
        }
        state.cursor = Some(next);
        save_state(path, state)?;
        handled += 1;
    }
}

/// Runs COMMAND with the event environment; true on exit status 0 within the timeout.
async fn run_command(command: &[String], env: &[(&'static str, String)], timeout: Duration) -> bool {
    let event_id = env.iter().find(|(k, _)| *k == "DOVE_EVENT_ID").map(|(_, v)| v.as_str()).unwrap_or("?");
    let mut c = tokio::process::Command::new(&command[0]);
    c.args(&command[1..]).stdin(std::process::Stdio::null()).kill_on_drop(true);
    for (k, v) in env {
        c.env(k, v);
    }
    let mut child = match c.spawn() {
        Ok(ch) => ch,
        Err(e) => {
            eprintln!("dove watch listen: cannot start {}: {e}", command[0]);
            return false;
        }
    };
    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(s)) if s.success() => {
            eprintln!("dove watch listen: event {event_id} handled");
            true
        }
        Ok(Ok(s)) => {
            eprintln!("dove watch listen: command exited with {s} for event {event_id}");
            false
        }
        Ok(Err(e)) => {
            eprintln!("dove watch listen: waiting for the command failed: {e}");
            false
        }
        Err(_) => {
            let _ = child.kill().await;
            eprintln!("dove watch listen: command timed out after {}s for event {event_id}", timeout.as_secs());
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_env_passes_ids_only() {
        let e = json!({ "event_id": "we_1", "watch_id": "w_x", "kind": "from", "account": "info",
                        "message_id": "f3-1-42", "thread_id": null, "received_at": "2026-11-14T10:00:00Z" });
        let env = event_env("ops", &e).unwrap();
        assert_eq!(env[0], ("DOVE_PROFILE", "ops".to_string()));
        assert!(env.contains(&("DOVE_MESSAGE_ID", "f3-1-42".to_string())));
        assert!(env.contains(&("DOVE_THREAD_ID", String::new())));
        for bad in [json!("two words"), json!("line\nbreak"), json!("x".repeat(321)), json!({"a": 1})] {
            let mut e2 = e.clone();
            e2["message_id"] = bad;
            assert!(event_env("ops", &e2).is_err());
        }
        let mut e3 = e.clone();
        e3["event_id"] = Value::Null;
        assert!(event_env("ops", &e3).is_err());
    }
}
