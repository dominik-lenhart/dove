# Dove

**Give your AI agents a key to your mail, not the whole keyring.**

Dove is a self-hosted [MCP](https://modelcontextprotocol.io) server that lets AI agents read, search and draft
mail in your own mailboxes: IMAP/SMTP accounts with password or app-password login (Strato, iCloud and most other
providers) and Gmail. Each agent
gets a token that sees only the mailboxes you grant it. Agents write drafts. You review and send them from the
mail client you already use.

[![CI](https://github.com/dominik-lenhart/dove/actions/workflows/ci.yml/badge.svg)](https://github.com/dominik-lenhart/dove/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/dominik-lenhart/dove?sort=semver)](https://github.com/dominik-lenhart/dove/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

```text
  Claude, ChatGPT, Codex, your own agent            you, in Apple Mail / Thunderbird / Gmail
             │  MCP over HTTPS, scoped token                     │  review, edit, send
             ▼                                                   ▼
  ┌──────────────────────────────────────┐            ┌──────────────────────┐
  │ Dove (your server)                   │  IMAP/SMTP │ your mailboxes       │
  │  policy · audit · encrypted index    │◀──────────▶│ Inbox, Sent, Drafts  │
  │  drafts, never silent sends          │  Gmail API │                      │
  └──────────────────────────────────────┘            └──────────────────────┘
```

> **Status: early.** Dove is tested against fake IMAP, SMTP and Google servers, and the IMAP path has been checked
> against a real Strato mailbox. Gmail, iCloud and most agent hosts have not been tried against the real services
> yet. See [Status](#status) before you rely on it.

## Why

An agent that helps with mail needs to read it, and an agent that has your mail password can do anything with it.
Dove sits in between:

- **Scoped tokens.** A token belongs to one project and sees only the mailboxes and actions you granted
  (`read`, `draft`, `organize`, `delete`, `send`). Anything else, including whether another mailbox exists, returns the
  same `not_found`.
- **Drafts by default.** Agents create and revise drafts that show up in your normal Drafts folder. Sending is off
  unless you enable it on the server *and* grant it to one token for one mailbox.
- **Nothing is deleted for good.** Dove has no permanent delete. With `organize` an agent can mark, label, archive
  and move mail; only with `delete` can it move mail to Trash, where you can restore it. The only messages Dove ever
  removes from a folder are its own drafts and the originals of a move it just completed on a server without IMAP
  `MOVE`.
- **An audit trail.** Every tool call produces one hash-chained audit record, without mail content.
- **Your server, your keys.** Passwords and Google tokens are encrypted at rest with a key that lives outside the
  data directory. The search index is SQLCipher-encrypted. The server sends nothing anywhere except to your mail
  providers and to webhook sinks you register yourself (content-free watch events).

## What agents can do

| Tool | What it does |
| --- | --- |
| `list_accounts`, `list_labels` | Mailboxes this token may use, their folders and labels |
| `search_messages` | Typed search over a local encrypted full-text index: sender, recipient, subject, text, attachment text, date, folder, unread, attachments, category |
| `search_contacts` | Who does this mailbox actually correspond with? Ranked by how much and how recently you exchanged mail; automated senders are left out |
| `digest` | Threads with new mail since a time, newest first, with a short snippet: the inbox catch-up |
| `get_message`, `get_thread`, `batch_read` | Read mail and threads. HTML becomes clean text, nothing is marked as read. Messages carry a category and calendar invitations an event summary |
| `get_attachment` | Fetch an attachment as an MCP resource (up to 10 MiB), or with `as_text` its extracted text (PDF, DOCX, ODT, text, CSV) |
| `list_drafts`, `get_draft` | Drafts in the mailbox's Drafts folder |
| `create_draft`, `update_draft` | New mail, replies (threaded and quoted) and forwards (with attachments), sent from the mailbox address or an alias you configured, with your signature. Attach files by reference or inline. Revision-checked: a draft you edited yourself is never overwritten |
| `delete_draft` | Delete a draft Dove created and nobody changed (Gmail: to Trash) |
| `update_messages` | Mark read or unread, star, add or remove labels (Gmail labels, IMAP keywords); needs `organize` |
| `move_messages` | Move to a folder or label, archive, back to the inbox; to Trash or Spam only with `delete` |
| `send_draft` | Only when both send gates are open, only drafts Dove created and nobody changed |
| `create_watch`, `list_watches`, `delete_watch` | Get told about new mail instead of polling: a reply in a thread, mail from an address or domain, mail matching a search, or no reply by a deadline. Per token, at most 50, expire after 30 days by default |
| `list_watch_events` | Pull watch events (ids and times only, no content; kept 14 days). Optionally pushed to a signed webhook the operator registered (`dove sinks add`) |

### Permissions

Each token gets actions per mailbox. Presets cover the usual cases; you can also list actions or mix both
(`--grant work=assistant,send`):

| Preset | Actions | For |
| --- | --- | --- |
| `reader` | `read` | search, read, attachments |
| `drafter` | `read,draft` | plus create, edit and delete its own drafts |
| `assistant` | `read,draft,organize` | plus mark read/unread, star, label, archive, move between folders |
| `full` | `read,draft,organize,delete` | plus move to Trash or Spam (recoverable) |

`send` is in no preset; it needs an explicit grant and `allow_send = true` on the server. `organize` is reversible and
destroys nothing, so the approval page pre-selects it. `delete` is opt-in because a steered agent could hide mail from
you in Trash, and Spam counts as delete because providers purge it. Presets are expanded when you create the token:
changing a preset in a later version never widens an existing token.

The index classifies every message at ingest as `personal`, `newsletter`, `notification` or `calendar` (from headers
such as `List-Unsubscribe`, `Auto-Submitted`, `Precedence`, no-reply senders and calendar parts) and, unless you turn
it off, reads the text of PDF, DOCX, ODT, text and CSV attachments into the full-text index so a search finds a word
inside an invoice. That costs some CPU at ingest and no extra mail-server traffic; see
[docs/deployment.md](docs/deployment.md) for the limits and `index.attachment_text`.

New INBOX mail is indexed within seconds through IMAP IDLE. Mail content always reaches the model inside a clearly
marked envelope; hidden HTML and invisible Unicode are stripped and Dove never loads remote content.

## Install

The server runs on Linux. The CLI also runs on macOS, where you use it to connect to a Dove server.

```sh
curl -fsSL https://github.com/dominik-lenhart/dove/releases/latest/download/install.sh | sh
```

The script picks the right build for your OS and CPU, checks its SHA-256 and, if `minisign` is installed, its
signature, and installs `dove` to `~/.local/bin` (or `/usr/local/bin` as root). Prefer to look first? Download
`install.sh` from the [latest release](https://github.com/dominik-lenhart/dove/releases/latest) and read it.

Other ways:

- **Container:** `ghcr.io/dominik-lenhart/dove` (linux/amd64 and linux/arm64). A Compose file with a Caddy proxy is in
  [`deploy/`](deploy/).
- **Release archives:** signed `.tar.gz` builds for Linux and macOS on the
  [releases page](https://github.com/dominik-lenhart/dove/releases). [`docs/releasing.md`](docs/releasing.md)
  explains how to verify them.
- **From source:** Rust 1.100+ (pinned in `rust-toolchain.toml`), a C compiler, `perl` and `make`, then `cargo build --release --locked`.

## Quickstart

This sets up a server with one IMAP mailbox and connects Claude Code. The full guide, with systemd, Compose,
proxy configuration and Gmail, is [`docs/deployment.md`](docs/deployment.md).

**1. Keys and configuration** (on the server)

```sh
sudo mkdir -p /etc/dove/credentials
sudo sh -c 'umask 077; for n in kek pepper index_key; do dove keys generate > /etc/dove/credentials/$n; done'
dove config-example | sudo tee /etc/dove/config.toml   # set public_url and operator_uid
sudo systemctl enable --now dove                         # unit in deploy/systemd/
dove doctor
```

**2. Connect a mailbox.** Dove logs in to IMAP and SMTP before it stores anything. Strato and iCloud are detected from
the address; for other providers pass `--imap-host` and `--smtp-host`. Use an app password where your provider has
them.

```sh
dove accounts connect-imap --alias work --email me@example.com
```

**3. Create a project and a token for an agent**

```sh
dove projects create assistant
dove projects add-account assistant work
dove clients create claude --project assistant --grant work=assistant --expires 90d   # prints the token once
```

**4. Connect the agent.** Put Dove behind HTTPS (Caddy and nginx allowlists are in [`deploy/`](deploy/)), then:

```sh
claude mcp add --transport http dove https://dove.example.com/mcp --header "Authorization: Bearer dove_..."
```

ChatGPT and Claude on the web connect through Dove's own OAuth flow instead of a pasted token: create an invitation
with `dove clients invite` and approve it in the browser.

## The CLI for agents in a shell

Agents that work in a terminal can use the same tools without MCP. On the agent's machine:

```sh
dove login --server https://dove.example.com --profile work   # redeems an invitation, token goes to the OS keychain
dove search --from anna@example.com --unread --after 2026-11-01
dove message get --account work --id <id>
dove draft create --account work --reply-to <id> --body-file reply.txt
dove mcp install --client claude-code     # wires Claude Code or Codex to Dove through a local stdio bridge
```

Every command takes `--json`. Admin commands (`accounts`, `projects`, `clients`, `audit`, ...) only work on the server
for the operator's OS user, over a Unix socket. A token can never reach them.

## Updates

```sh
dove upgrade            # download, verify the signature, replace the binary
dove upgrade --check    # only report
```

Releases are signed with minisign, and `dove upgrade` checks the signature against the public key built into the
binary before it replaces anything. On a server, restart the service afterwards (`sudo systemctl restart dove`);
`dove upgrade` tells you when the running service is older than the binary. With Compose, pin a version tag and run
`docker compose pull && docker compose up -d`.

The CLI looks for a new release at most once a day and prints a one-line hint on stderr when there is one. That
request goes to the GitHub API and carries nothing but the CLI version. Turn it off with `DOVE_NO_UPDATE_CHECK=1`.
The server process never checks for updates.

## Security model in short

Dove limits what a leaked token, a copied state file or a prompt-injected agent can reach to what that token was
granted. The full threat model is in [`docs/spec.md`](docs/spec.md) (section 6).

**Covered:** leaked or over-trusted tokens (scoped, expiring, revocable, optionally IP-bound, rate-limited,
audited), a copied state store (secrets encrypted under keys that are not in it, tokens stored as keyed hashes), an
agent shell trying to administer Dove (admin only over a Unix socket with an OS user check), DNS rebinding and OAuth
callback attacks, header injection into drafts, secrets or mail content leaking into logs.

**Not covered:** a compromised host (whoever controls the machine can use the credentials in memory), prompt
injection itself (Dove limits its reach; an agent that has been steered can still use every permission its token
holds), and whatever your model provider does with the mail an agent reads.

**Sending.** `send_draft` needs two gates: `allow_send = true` in the server configuration, and a `send` grant for one
token on one mailbox. Even then it only sends a draft Dove created and nobody changed, takes no recipients or content
of its own, and never resubmits after an unknown outcome. A token with a send grant can send without asking you, so
give it to a separate token for a mailbox where you accept that, and prefer sending from your mail client. For Gmail,
note that Google's `gmail.compose` scope itself includes sending; Dove's gates are a policy layer in front of it.

## Tailscale

Dove can sit behind Tailscale instead of a reverse proxy: `dove tailscale setup` publishes exactly Dove's public paths
on your node's `.ts.net` name (tailnet only; `--funnel` opens it to the internet, on request only). Claude Code, Codex
and the CLI on your tailnet devices can use it; ChatGPT and claude.ai need Funnel. See the
[deployment guide](docs/deployment.md#tailscale).

## Drafts and your mail client

Dove writes drafts into the mailbox's server-side Drafts folder, so they appear in Apple Mail, Thunderbird or the Gmail
web app like any other draft. Edits are sequential: `update_draft` carries the revision the agent last saw, and if the
draft changed since, the agent gets `draft_conflict` and nothing is written. Once you save a change yourself, the
draft is yours and Dove will not touch it again. An editor window you have not saved yet is invisible to the server,
so Dove cannot see it.

## Status

| Area | State |
| --- | --- |
| IMAP/SMTP mailboxes: connect, read, search, attachments, drafts, replies, forwards, IDLE push | done; checked against real Strato |
| SMTP send behind both gates | done (fake SMTP); not tried against a real provider |
| Gmail: connect, read, drafts, send, search index | done (fake Google); not tried against real Gmail |
| Encrypted search index and sync | done |
| Client CLI, OAuth for MCP hosts | done (tested over raw MCP); Claude Code, ChatGPT and Claude web not tried yet |
| Signed releases, container image, `dove upgrade` | done; first public release pending |
| iCloud, other IMAP providers, large mailboxes, benchmarks | open |

Plan, assumptions and evidence: [`docs/PLAN.md`](docs/PLAN.md). What was checked on real systems:
[deployment guide](docs/deployment.md#what-has-been-verified).

## Documentation

- [`docs/deployment.md`](docs/deployment.md): install, configuration, proxies, mailboxes, backup, upgrades
- [`docs/spec.md`](docs/spec.md): specification and threat model
- [`docs/releasing.md`](docs/releasing.md): release process and verifying downloads
- [`SECURITY.md`](SECURITY.md): reporting vulnerabilities
- [`AGENTS.md`](AGENTS.md): codebase guide for contributors and coding agents

## Contributing

Issues and pull requests are welcome. Please report security problems privately as described in
[`SECURITY.md`](SECURITY.md), not in public issues.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked -- --test-threads=2
```

The name nods to the messenger dove and to Dovecot. Dove has no relation to the Dovecot project.

## License

[Apache License 2.0](LICENSE).
