<div align="center">

# Dove

**One MCP server for all your mailboxes.**

Connect your work Gmail, your private iCloud, the info@ mailbox at your hoster and whatever else you have, and let
Claude, ChatGPT, Codex or your own agents search, read, organize and draft across all of them at once. Self-hosted,
with a scoped token per agent, drafts instead of silent sends, and nothing ever deleted for good.

[![CI](https://github.com/dominik-lenhart/dove/actions/workflows/ci.yml/badge.svg)](https://github.com/dominik-lenhart/dove/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/dominik-lenhart/dove?sort=semver)](https://github.com/dominik-lenhart/dove/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

[Why Dove](#why-dove) · [Quickstart](#quickstart) · [What agents can do](#what-agents-can-do) · [Permissions](#permissions) ·
[Security](#security-model) · [Deployment guide](docs/deployment.md)

</div>

## Why Dove

Mail connectors for AI agents usually give the agent one Gmail account. Real mail rarely lives in one place: a work
Google account, a private iCloud or GMX address, a domain mailbox at Strato or IONOS, a shared support inbox. With one
connector per provider, an agent sees a slice of your mail and never the whole picture.

Dove connects all of them, Gmail and any IMAP provider side by side, behind one MCP endpoint. One search covers every
mailbox, the digest sorts them into one list, contacts are ranked across all of them, and replies are drafted in the
mailbox the thread lives in. You still decide per agent which mailboxes it sees and what it may do in each.

## What it feels like

> **You:** Anything important in my inboxes since yesterday?
>
> **Agent:** *(calls `digest` across work, private and info@)* Three threads need you: Anna's offer for the Berlin
> project in your work mailbox (the attached PDF says 18,400 EUR), a calendar invite from Marco in your private
> iCloud for Thursday 10:00, and your tax advisor asking for two receipts at info@. The other 14 are newsletters and
> notifications.
>
> **You:** Draft a reply to Anna: we accept, start date 1 December. And tell me when she answers.
>
> **Agent:** *(calls `create_draft`, then `create_watch`)* The draft is in your work Drafts folder, threaded and with
> your signature. I'll get an event as soon as Anna replies.

You open the draft in Apple Mail, change a word, and press send yourself. The agent never had your passwords, saw only
the mailboxes its token was granted, and could not have sent or deleted anything.

## How it works

```text
  Claude · ChatGPT · Codex · your agent                 you, in Apple Mail / Thunderbird / Gmail
        │  MCP over HTTPS, one scoped token each                │  review, edit, send
        ▼                                                       ▼
  ┌───────────────────────────────────────────┐   IMAP/SMTP  ┌────────────────────────────┐
  │ Dove, on your server                      │◀────────────▶│ your mailboxes             │
  │  per-token policy · audit log             │   Gmail API  │ Strato, iCloud, Gmail, ... │
  │  encrypted search index · IDLE push       │              │ Inbox, Drafts, Sent        │
  └───────────────────────────────────────────┘              └────────────────────────────┘
```

Dove connects to your mailboxes once, keeps an encrypted full-text index that IMAP IDLE updates within seconds, and
answers agents through MCP tools. Every agent gets its own token with its own mailboxes and actions. Drafts land in
your normal Drafts folder, so your mail client is the review step.

## Highlights

- **All your mailboxes at once.** Gmail and any IMAP/SMTP provider behind one endpoint. Search, digest and contacts
  span every mailbox a token may use; one slow or broken mailbox is reported on its own instead of failing the call.
- **Works with the mail you have.** Any IMAP/SMTP account with password or app-password login (presets for Strato,
  iCloud and Gmail). Gmail works with just an app password, labels included; the Gmail API through your own Google
  Cloud project stays available. Send-as aliases and per-mailbox signatures.
- **Search that understands mail.** Typed search over sender, recipient, subject, body, folder, unread, date and
  attachment text (PDF, DOCX, ODT, CSV). Every message is classified as personal, newsletter, notification or
  calendar, so "what's important" works without reading everything.
- **Built for agents.** An inbox `digest`, a ranked contact lookup, calendar invites as structured events, and
  **watches** that tell an agent when someone replies or when nobody replied by a deadline, pulled as events or
  pushed to a signed webhook.
- **Granular permissions.** `read`, `draft`, `organize`, `delete` and `send` per token and mailbox, with presets.
  Organize (mark read, star, label, archive, move) is reversible; delete only ever moves to Trash; send needs two
  separate switches.
- **Safe by construction.** There is no permanent delete. Mail reaches the model inside a marked untrusted-content
  envelope with hidden HTML and invisible Unicode stripped. One hash-chained audit record per call, never with mail
  content. Admin only over a local Unix socket that tokens cannot reach.
- **Yours.** One Rust binary, encrypted state and index, no telemetry, no hosted service. Signed releases with
  `dove upgrade`. Runs behind Caddy, nginx or Tailscale.

## Quickstart

You need a Linux server you control and an HTTPS name for it (or Tailscale). About fifteen minutes.

**1. Install**

```sh
curl -fsSL https://github.com/dominik-lenhart/dove/releases/latest/download/install.sh | sudo sh
```

The installer picks the build for your OS and CPU (a static musl build on Alpine and other musl systems) and checks
its SHA-256 and, when `minisign` is installed, its signature. Other ways to get the same binary:

- Debian and Ubuntu: download `dove_<version>_amd64.deb` or `_arm64.deb` from the
  [latest release](https://github.com/dominik-lenhart/dove/releases/latest) and run `sudo apt install ./dove_*.deb`.
  It installs the binary, the systemd unit and the `dove` service account, and creates `/etc/dove`; it generates no
  secrets and starts nothing.
- Homebrew (macOS and Linux): `brew install dominik-lenhart/tap/dove`. This installs the binary only, no service.
- Windows: `irm https://github.com/dominik-lenhart/dove/releases/latest/download/install.ps1 | iex`. It installs
  `dove.exe` for the current user, no administrator rights needed. Windows builds are not part of the releases until
  the Windows port is released, see the [changelog](CHANGELOG.md).
- Container: `ghcr.io/dominik-lenhart/dove` (amd64, arm64) with the Compose file in [`deploy/`](deploy/).

**2. Configure and start**

```sh
sudo mkdir -p /etc/dove/credentials
sudo sh -c 'umask 077; for n in kek pepper index_key; do dove keys generate > /etc/dove/credentials/$n; done'
dove config-example | sudo tee /etc/dove/config.toml    # set public_url and operator_uid
sudo systemctl enable --now dove                          # unit in deploy/systemd/
dove doctor
```

On a Tailscale node, `dove tailscale setup` sets `public_url` and publishes exactly Dove's public paths for you.

**3. Connect a mailbox.** Dove verifies the IMAP and SMTP login before it stores anything; the password is encrypted
at rest.

```sh
dove accounts connect-imap work --email me@example.com
```

For Gmail, turn on 2-Step Verification, create an app password at <https://myaccount.google.com/apppasswords> and use
it here (`--email you@gmail.com`; Google Workspace addresses add `--preset gmail`); see
[Gmail with an app password](docs/deployment.md#gmail-with-an-app-password). The Gmail API through your own Google
Cloud OAuth client is the alternative: [Google Cloud setup](docs/deployment.md#google-cloud-setup).

**4. Give an agent a token**

```sh
dove projects create assistant
dove projects add-account assistant work
dove clients create claude --project assistant --grant work=assistant --expires 90d   # prints the token once
```

**5. Connect the agent**

```sh
claude mcp add --transport http dove https://dove.example.com/mcp --header "Authorization: Bearer dove_..."
```

ChatGPT and Claude on the web connect through Dove's OAuth approval page instead; `dove clients invite` creates the
link. The [deployment guide](docs/deployment.md) covers proxies, Compose, backups and upgrades in detail.

**No server? Run it on your own computer.** Local mode runs Dove as your user on macOS, Linux or Windows, for Claude
Desktop, Claude Code, Codex and other MCP hosts on the same machine, over `http://127.0.0.1` without a domain or proxy:

```sh
dove local init && dove local install       # per-user config, keys and autostart
dove accounts connect-imap personal --email you@example.com
dove mcp install --client claude-desktop --profile desktop   # after `dove clients invite` and `dove login`
```

An agent with a shell as the same OS user can read Dove's files and use its admin channel, so local mode protects
against remote callers and leaked tokens, not against your own agent's shell. Details and the full steps:
[Local mode](docs/deployment.md#local-mode).

## What agents can do

| Tool | What it does | Needs |
| --- | --- | --- |
| `digest` | Threads with new mail since a time, newest first, with category and a short snippet | `read` |
| `search_messages` | Typed search: from, to, subject, text, attachment text, folder, date, unread, attachments, category | `read` |
| `search_contacts` | People this mailbox corresponds with, ranked by how much and how recently | `read` |
| `get_message`, `get_thread`, `batch_read` | Read mail as clean text; calendar invites as events; nothing is marked as read | `read` |
| `get_attachment` | An attachment as an MCP resource (up to 10 MiB), or its extracted text with `as_text` | `read` |
| `list_accounts`, `list_labels` | Mailboxes this token may use, their folders, labels and send-as addresses | `read` |
| `create_watch`, `list_watch_events` | Be told about a reply, mail from someone, mail matching a search, or no reply by a deadline | `read` |
| `list_drafts`, `get_draft` | Drafts in the mailbox's Drafts folder | `read` |
| `create_draft`, `update_draft` | New mail, threaded and quoted replies, forwards with attachments, files by reference or inline, alias and signature | `draft` |
| `delete_draft` | Delete a draft Dove created and nobody changed | `draft` |
| `update_messages` | Mark read or unread, star, add or remove labels and keywords | `organize` |
| `move_messages` | Archive, move to a folder or label, back to the inbox; to Trash or Spam only with `delete` | `organize` |
| `send_draft` | Send a draft Dove created and nobody changed; off unless both send gates are open | `send` |

Writes are revision-checked: once you edit a draft yourself, Dove never overwrites it. Watches belong to the token
that created them and carry only ids and times; the agent reads content through its normal, audited tools.

Agents that live in a terminal can use the same tools through the CLI (`dove login`, `dove search`,
`dove draft create`, every command with `--json`), or wire Claude Code and Codex to Dove with `dove mcp install`.

## Permissions

Grants are per token and per mailbox. Presets cover the usual cases, and you can add single actions
(`--grant work=assistant,send`):

| Preset | Actions | Adds |
| --- | --- | --- |
| `reader` | `read` | search, read, attachments, contacts, digest, watches |
| `drafter` | `read,draft` | create, edit and delete its own drafts |
| `assistant` | `read,draft,organize` | mark read, star, label, archive, move between folders |
| `full` | `read,draft,organize,delete` | move to Trash or Spam (recoverable) |

- **`organize`** is reversible, so the approval page pre-selects it.
- **`delete`** is opt-in: a steered agent could hide mail in Trash. It never deletes permanently; there is no tool
  for that.
- **`send`** is in no preset. It needs an explicit grant on one mailbox *and* `allow_send = true` in the server
  configuration. It only sends drafts Dove created and nobody changed, never with recipients or content of its own,
  and never twice after an unknown outcome.

Presets are expanded when the token is created, so a later change to a preset never widens an existing token.

## Security model

Dove limits what a leaked token, a copied state file or a prompt-injected agent can reach to what that token was
granted. Unknown and out-of-scope mailboxes and ids return the same `not_found`, so a token cannot even learn what
else exists. Full threat model: [`docs/spec.md`](docs/spec.md), section 6.

| Covered | Not covered |
| --- | --- |
| Leaked or over-trusted tokens: scoped, expiring, revocable, optionally IP-bound, rate-limited, audited | A compromised host: whoever controls the machine can use the credentials in memory |
| A copied state store: secrets encrypted under keys that are not in it, tokens stored as keyed hashes | Prompt injection itself: Dove limits its reach, but a steered agent can use every permission its token holds |
| An agent shell trying to administer Dove: admin only over a Unix socket (Windows: named pipe) with an OS user check, when the agent runs as another OS user | What your model provider does with the mail an agent reads |
| DNS rebinding, OAuth callback attacks, header injection into drafts, mail content in logs | Your mailbox provider's own account security |

For Gmail, note that Google's `gmail.compose` scope itself includes sending; Dove's send gates are a policy layer in
front of it. Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).

## Updates

```sh
sudo dove upgrade && sudo systemctl restart dove
```

Releases are signed with minisign, and `dove upgrade` verifies the signature against the key built into the binary
before it replaces anything; it also tells you when the running service is older than the binary. With Compose, pin
a version tag and run `docker compose pull && docker compose up -d`. The CLI checks for a new release at most once a
day and prints a one-line hint (`DOVE_NO_UPDATE_CHECK=1` turns it off). The server itself never phones home.

## Status

Dove is young. It has a large test suite against fake IMAP, SMTP and Google servers, and its IMAP path has been
running against a real mailbox since the first release. Before you rely on it:

| Area | State |
| --- | --- |
| IMAP: connect, read, search, attachments, drafts, replies, forwards, IDLE push | checked against real Strato |
| Organize, digest, watches | checked against real Gmail and Strato (watch creation; event delivery against fake servers) |
| Contacts, categories, attachment text, aliases, signatures | done against fake servers |
| Claude Code and Codex, through `dove mcp install` and direct HTTP | checked |
| SMTP send behind both gates | checked against real Strato SMTP and the Gmail API |
| Gmail API | checked against a real account: connect, read, search, digest, organize, drafts, send, watches |
| Gmail over IMAP (app password) | checked against a real account: connect, labels, search, digest, organize, Trash and back, drafts |
| ChatGPT connector through the OAuth approval page | checked: approval, token refresh, `list_accounts`, `digest` and `search_messages` across 11 mailboxes, reading messages and threads |
| iCloud over IMAP | checked: connect, index, search, read |
| Claude web connector, iCloud drafts and send, very large mailboxes, benchmarks | open |

What was checked on real systems is listed in the
[deployment guide](docs/deployment.md#what-has-been-verified); decisions and evidence are in
[`docs/PLAN.md`](docs/PLAN.md).

## Documentation

| | |
| --- | --- |
| [Deployment guide](docs/deployment.md) | install, configuration, proxies, Tailscale, mailboxes, Gmail, watches and sinks, backup, upgrades |
| [Specification](docs/spec.md) | tools, data model, threat model |
| [Releasing](docs/releasing.md) | release process and verifying downloads |
| [Security policy](SECURITY.md) | reporting vulnerabilities |
| [AGENTS.md](AGENTS.md) | codebase guide for contributors and coding agents |
| [Changelog](CHANGELOG.md) | what changed in each version |

## Contributing

Issues and pull requests are welcome; security problems go to the private channel in [`SECURITY.md`](SECURITY.md).
Building needs Rust (pinned in `rust-toolchain.toml`), a C compiler, `perl` and `make`.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked -- --test-threads=2
```

The name nods to the messenger dove and to Dovecot; Dove has no relation to the Dovecot project.
Licensed under the [Apache License 2.0](LICENSE).
