# Connecting clients

How a new computer or MCP host gets a restricted connection to a running Dove server (spec 5.2a, 5.6). Host menu
names below are unverified against current ChatGPT, Claude, Claude Code and Codex versions.

## 1. Operator: issue an invitation

On the server, as the operator:

```sh
dove clients invite laptop --project acme --accounts all --capabilities read
dove clients invite web-claude --project acme --accounts info,billing --capabilities read,draft --expires 90d
```

`all` expands to the project's current mailboxes once; mailboxes added later are not included. The command prints a
`dovei_...` invitation once. It is valid for 10 minutes and for one redemption. Hand it over on a trusted channel.
`--expires` and `--allow-ip` apply to the connection that the invitation creates. Removing a mailbox from the
project cancels the project's open invitations. Each redemption creates a normal connection that shows up in
`dove clients list` and is revoked with `dove clients revoke <name>`.

## 2a. A computer with Claude Code or Codex

```sh
dove login --server https://dove.example.com --profile acme      # prompts for the invitation
dove status --profile acme
dove mcp install --profile acme --client claude-code              # or --client codex; --scope project is opt-in
```

The connection token goes to the OS credential store. Without one (for example a headless Linux box), `login`
stops and asks for an explicit `--secret-file <path>`; the file is written with mode 0600. Headless setups can feed
an operator-issued `dove_...` token with `--token-stdin`. The invitation is never accepted as an argument.

`mcp install` writes a stdio entry `<absolute path to dove> mcp stdio --profile acme` into `~/.claude.json`
(`.mcp.json` for project scope) or `~/.codex/config.toml` (`.codex/config.toml` for project scope). It keeps all
other entries, refuses to touch a file it cannot parse, and is a no-op when the entry is already current. No
credential is written to these files.

Other commands: `search`, `message get`, `thread get`, `draft create|get|update|send`, `batch`, `connect-info`,
`doctor --profile acme`, `logout [--revoke]`. All accept `--json`. `draft create` prints its request key; retry a
failed create with `--request-key <key>`, never with a new key.

## 2b. ChatGPT or Claude (web/desktop)

Add a custom connector / MCP server with the URL `https://dove.example.com/mcp` and choose OAuth. The host
discovers Dove through `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server`,
registers itself dynamically and opens Dove's approval page. Enter the invitation there, check the project,
mailboxes and application, untick anything you do not want, and approve. The host then refreshes its tokens on its
own. Registering an application grants nothing; only the invitation does.

Pre-registered applications (for hosts or policies that do not use dynamic registration) go into the server
configuration; restart the service afterwards:

```toml
[[oauth.clients]]
client_id = "claude-web"
client_name = "Claude"
redirect_uris = ["https://claude.ai/api/mcp/auth_callback"]   # the host's exact callback URL
secret_file = "/run/credentials/dove.service/oauth_claude_secret"  # optional; omit for a public PKCE client
```

## Reverse proxy allowlist

Forward exactly these paths to Dove (everything else 404 at the proxy):

```text
POST        /mcp
GET         /healthz
GET         /oauth/google/callback
GET         /.well-known/oauth-protected-resource
GET         /.well-known/oauth-protected-resource/mcp
GET         /.well-known/oauth-authorization-server
GET, POST   /oauth/dove/authorize
POST        /oauth/dove/token
POST        /oauth/dove/register
POST        /oauth/dove/revoke
POST        /connect/redeem
```
