# Dove

Dove is a self-hosted [MCP](https://modelcontextprotocol.io) server that gives AI agents token-scoped **read and
draft** access to Gmail mailboxes. You run one instance on your own server, with your own Google Cloud project. Each
agent gets its own token that sees only the mailboxes you grant it, and can put reply drafts into those mailboxes.
You review and send from your normal mail client (Apple Mail is the reference client).

> **Status: early, not production-proven.** The server core and the draft and send paths are implemented and tested
> against a fake Google server. Nothing has been verified against real Gmail, real Google consent, Apple Mail or any
> real agent host yet. Read [Project status](#project-status) before you rely on it.

One Rust package (`dove-mcp`), one binary (`dove`). The name nods to the messenger dove and to Dovecot; Dove has no
relation to the Dovecot project.

**No telemetry.** Dove sends nothing anywhere except to Google (OAuth and Gmail API, fixed hosts) and to a
notification webhook if you configure one. It does not check for updates or phone home.

- Specification: [`docs/spec.md`](docs/spec.md) · Plan, status and assumptions: [`docs/PLAN.md`](docs/PLAN.md)
- Deployment guide: [`docs/deployment.md`](docs/deployment.md) · Security policy: [`SECURITY.md`](SECURITY.md)

## What it does

- **Projects and tokens.** A project groups mailboxes. A client token belongs to one project and sees only the
  intersection of its explicit per-mailbox grants (`read`, `draft`, `send`) and the project's current mailboxes.
  Unknown and out-of-scope mailboxes and ids return the identical `not_found`.
- **Tools** (implemented): `list_accounts`, `list_labels`, `get_message`, `get_thread`, `list_drafts`, `get_draft`,
  `create_draft` (idempotent by `request_key`), `update_draft` (revision-checked), `batch_read`, and `send_draft`
  when enabled. Not implemented yet: `search_messages` and the encrypted search index.
- **Untrusted content handling.** Mail text reaches the model inside a clearly delimited envelope; HTML is reduced to
  text without hidden content, invisible Unicode is stripped, and Dove never follows links or fetches remote images.
- **Audit.** One hash-chained audit record per tool call and per admin action, without mail content.
- **Encryption at rest.** Google refresh tokens are stored under per-mailbox keys wrapped by a key you keep outside
  the data directory. Client tokens are stored as keyed hashes only.

## Threat model in short

Dove is designed so that a leaked client token, a copied state file or a prompt-injected agent can reach only what
that token was granted. Full table: spec section 6.2.

**What Dove protects against**

- A leaked or over-trusted **client token**: scoped to one project and listed mailboxes, optional IP binding and expiry,
  individually revocable, rate-limited, every use audited with its source IP.
- A **copied state store**: refresh tokens are encrypted under keys that are not in the store; client tokens are
  hashed with a separate secret.
- An **agent shell** that tries to administer Dove: admin actions go only through a Unix socket, which checks the
  caller's OS user id. Agent tokens are never accepted there.
- **Browser and DNS-rebinding attacks** on the MCP endpoint (Host and Origin checks, loopback-only listener) and
  OAuth callback attacks (state, PKCE, identity and scope checks).
- **Header injection** into drafts and **data leaking through logs** (a redaction layer; no bodies, subjects,
  addresses or tokens in logs or audit records).

**What Dove does not protect against**

- **A compromised host.** Whoever controls the machine or the service account can use the Google tokens in memory,
  which can read mail and, with the compose scope, send it. Host compromise exceeds Dove's policy boundary.
- **Prompt injection is mitigated, not solved.** Mail is untrusted input to a language model. Scoping reduces what an
  injection can reach, and delimiters make content easier to treat as data, but an agent that has been steered can
  still misuse every permission its token holds, including `send` if you granted it.
- **Your Google account security.** Protect each mailbox with 2-step verification. Google-side token theft is out of
  scope.
- **Mail the model provider sees.** Whatever Dove returns to an agent may reach that agent's model provider.
- **Someone who is you.** A shell running as the operator user cannot be told apart from the operator.

## Compose scope and sending: two gates and what they mean

Dove asks Google for `gmail.readonly` and `gmail.compose`. `gmail.compose` is the smallest scope that lets Dove
create and edit drafts, and Google defines it to include **sending** mail. The Google grant itself therefore carries
the ability to send. Dove's controls are a policy layer in front of that ability, not a limit inside Google.

Sending through Dove (`send_draft`) is **off by default** and needs **both** gates (spec 6.3):

1. **Instance gate:** `allow_send = true` in the server's local configuration file. Only the deployment owner can set
   it. MCP calls and the CLI cannot.
2. **Token gate:** an explicit `send` grant for one token on one named mailbox, issued by the operator
   (`--grant alias=read,draft,send`). A global switch never upgrades a read/draft token, and the tool does not exist
   for tokens without an effective send grant.

Even then, only an existing draft that Dove created and that nobody has changed since can be sent; `send_draft` takes
no recipients, content or raw MIME. Policy is rechecked immediately before dispatch, the in-flight state is persisted
before the request, and an unknown outcome (lost response, restart) blocks resubmission until you verify the Sent
folder. Sends are audited and rate-limited separately (default 20 per hour per client).

**What a standing send permission implies.** A token with a send grant may send on that mailbox without any per-message
human confirmation. A marker in an email is not an approval boundary, and an agent that read a malicious email can be
induced to send a draft it created. Grant `send` only to a separate, dedicated token for a mailbox where you accept
that risk, keep the draft-only token for everything else, and prefer reviewing and sending from your mail client.

## Apple Mail and sequential editing

Dove is built around this flow: an agent drafts and revises, you review in Apple Mail (using the mailbox's server-side
Drafts), edit if you like, and send yourself.

- Agent edits are **sequential**. `update_draft` carries the revision the agent last saw; Dove reads Gmail fresh
  and compares. If anything changed, you get `draft_conflict` before anything is modified.
- **A human edit makes a draft human-owned.** Once you save a change in your mail client, Dove treats the draft as
  yours and **never overwrites it**; it returns the conflict with the latest content, and the agent can either wait
  for you or, if you ask, create a separate proposed draft. A draft that has since been sent or deleted returns
  `not_found`; Dove never recreates or adopts a missing draft.
- **Limitations.** An unsaved editor window in Apple Mail is invisible to Gmail. Gmail has no atomic "write only if
  unchanged" for drafts, so a save by you that lands between Dove's fresh read and its write cannot be detected. Dove
  protects previously saved edits, not simultaneous ones. A message that exists only "On My Mac" is outside Dove.
- Drafts that Dove cannot rewrite faithfully (externally added HTML parts, attachments) are rejected with
  `draft_conflict` instead of being flattened.

Apple Mail interplay is **not verified yet** (see below).

## Quickstart

Prerequisites: a Linux host, a DNS name, Rust 1.90+ with a C toolchain, and a Google Cloud project. The complete
procedure with systemd, container and proxy files is in [`docs/deployment.md`](docs/deployment.md). Short form:

```sh
export PATH=$HOME/.cargo/bin:$PATH
cargo build --release --locked
sudo install -m 0755 target/release/dove /usr/local/bin/dove

# keys (printed to stdout, nothing else happens) and configuration
sudo sh -c 'umask 077; for n in kek pepper index_key; do dove keys generate > /etc/dove/credentials/$n; done'
dove config-example | sudo tee /etc/dove/config.toml       # edit: public_url, google.client_id, operator_uid

sudo systemctl enable --now dove                              # unit in deploy/systemd/
dove doctor                                                   # configuration, permissions, reachability
dove accounts connect --alias work-info --email info@example.com
dove projects create acme && dove projects add-account acme work-info
dove clients create support-agent --project acme --grant work-info=read,draft --expires 90d
```

The last command prints the client token once. Put a reverse proxy in front (Caddy and nginx allowlists are in
[`deploy/`](deploy/)) and connect an MCP host, for example:

```sh
claude mcp add --transport http dove https://dove.example.com/mcp --header "Authorization: Bearer dove_..."
```

Google setup (including the unverified-app warning and why the app must be **In production**) is in the deployment
guide. A container build and a Compose example are in `deploy/` too.

## Project status

Plan and evidence: [`docs/PLAN.md`](docs/PLAN.md). Everything below that is "done" was tested against the fake Google
server in `tests/support/`, not against real services.

| Area | State |
| --- | --- |
| Foundation: config and startup checks, vault, state store, audit chain, admin socket, client tokens | done |
| Google connect flow, token manager, outbound allowlist gateway | done (fake Google) |
| MCP transport and read tools, untrusted-content envelope | done (fake Google) |
| `create_draft`, `update_draft`, `send_draft` behind both gates, `batch_read` | done (fake Google); `batch_read` search items wait for search |
| Encrypted search index, sync engine, typed `search_messages` | **not implemented** |
| Client onboarding (`dove login`, `mcp install`, `mcp stdio`) and downstream OAuth for ChatGPT and Claude | **not implemented** (the proxy allowlist already contains the routes) |
| Restart and crash recovery tests, log canary test, benchmarks | open |
| Deployment files, CI, docs | present, partially verified ([deployment guide](docs/deployment.md#what-has-been-verified)) |

### Not yet verified

Do not assume any of the following works until it has been checked and recorded:

- **Real Gmail and Google consent.** That an unverified app in production status obtains a long-lived refresh token
  for the restricted Gmail scopes with a real account; real draft create, revise and send round-trips; Workspace
  admin policies.
- **Apple Mail.** Server-side Drafts round-trips, threading, how Apple Mail changes a Dove draft's ids, and the
  sequential-editing behaviour above (spec acceptance criterion 5, a release gate).
- **Agent hosts.** ChatGPT, Claude, Claude Code and Codex: connecting, OAuth, tool discovery, plan and workspace
  restrictions (spec criteria 22 and 23).
- **Performance and memory.** The targets in spec 8.1 (search latency, live-read latency) and 8.1a (under 256 MiB
  steady RSS, 512 MiB reference limit, 1 GiB profile) are unmeasured. No benchmark has run on reference hardware.
- **Production deployment.** The systemd unit, container and proxy files have not run on a production host with real
  TLS and Google.

## Licence

Placeholder: Apache-2.0, as declared in `Cargo.toml`, until the owner decides on the final licence (plan assumption
A7, spec 13.7). There is no `LICENSE` file yet; do not treat this repository as licensed until one is added.

## Contributing and development

See [`AGENTS.md`](AGENTS.md) for layout, conventions and learnings. Commands:

```sh
export PATH=$HOME/.cargo/bin:$PATH
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked -- --test-threads=2
```

CI runs these, a secret scan and a dependency audit (`deny.toml`). Report vulnerabilities privately as described in
[`SECURITY.md`](SECURITY.md), not in public issues.
