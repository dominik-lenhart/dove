# Changelog

All notable changes to Dove are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/) as described in [docs/releasing.md](docs/releasing.md).

## [Unreleased]

### Added

- Scheduled sends approved by the owner. `request_send` asks for own drafts to be sent at fixed times (or spread over
  a window), optionally only if nobody answered the thread in the meantime (`unless_reply`; an answer already in Trash
  counts). The owner reviews each
  draft with `dove requests show` and approves with `dove requests approve`, which binds the exact revision shown;
  a draft changed afterwards is not sent. Nothing is retried after an unknown outcome, and an item that could not go
  out within `[requests] late_grace_minutes` (60) is dropped as `missed`. Agents follow their requests with
  `list_requests` and `cancel_request`. Needs `draft` on the mailbox, not `send` or `allow_send`; turn it off with
  `[requests] enabled = false`. Closed requests are deleted after `[requests] retention_days` (90), and each
  connection keeps at most 500 of them.

## [0.9.0] - 2026-11-14

### Added

- `dove watch create|list|delete|events` manage watches from the CLI, and `dove watch listen` wakes a local agent on
  new mail: it pulls watch events over outgoing HTTPS and runs a fixed command once per event, in order, with only
  ids and times in `DOVE_*` environment variables. The cursor is saved after each event (mode 0600), old events are
  skipped on the first start, failing commands are retried up to `--max-attempts`, and a lock file keeps a second
  listener on the same profile from running the command twice. Pin it to an agent session with
  `claude -p --resume <session-id> --fork-session`.
- `get_message` reads several messages in one call: pass `refs` from search_messages (or `account` +
  `message_ids`), up to 20. Each id gets its own result or error under batch_read's 64 KiB response budget; a single
  id answers as before.
- `create_watch` with `kind: no_reply_by` takes a `message_id` instead of a `thread_id`: "tell me if nobody answers
  this mail by Friday". The event names that message, so the agent can read it and follow up; a reply from someone
  else ends the watch quietly, and a message that is already answered ends it at once (`end_reason: replied`). CLI:
  `dove watch create --no-reply-to <message-id> --deadline <time>`.

### Changed

- `get_thread` is faster. On IMAP all members are read over one connection, with each folder opened once and one
  metadata fetch per folder (a one-folder thread of N messages needs N + 2 commands instead of 4N). On Gmail, a thread
  asked for by `message_id` needs one request less. Long threads stop fetching once the body budget is spent. IMAP
  reads and index sync no longer send a separate size probe per message.
- `search_messages`, `digest` and `search_contacts` argument errors name the argument and say how to fix it. The
  message starts with the path (`where.all[1].op: ...`), lists what is valid (the operators of that field, the
  columns, the fields, what the tool takes) and, where useful, carries a valid example in `details.example`. Known
  mix-ups get a pointer: `contains` has no substring match (use `terms`), `sender` is `from`, `query` and
  `page_token` are `where` and `cursor`, `limit` over 100 pages with `next_cursor`, a time without offset needs
  `Z` or an offset.
- These tools accept arguments that have exactly one reading: one mailbox name where a list is expected, `account`
  for `accounts` (and `accounts` with one name for `search_contacts`), lists and `where` written as JSON text,
  `"true"`/`"20"` for `true`/`20`, field, operator and enum names in any case, one value where a list is expected
  and a one-element list where a string is, a list of words for `terms`, a single `order_by` object or
  `"received_at desc"`. `received_at` and `digest`'s `since` take a calendar date (`2026-11-01`, that UTC day) and
  `since` also a span back from now (`7d`, `36h`). Several values for a one-value argument, a time without offset
  and unknown account names are still refused; unknown and out-of-scope mailboxes remain the identical `not_found`.
- The audit record of a refused call carries `~invalid=<argument path>` in `object_ids` (for example
  `~invalid=where.all[].op`): which argument failed, never its value.

### Fixed

- Watches no longer treat the owner's own mail from a Gmail send-as address as someone else's: mail with the `SENT`
  label (or in the IMAP Sent folder) never fires a watch and never counts as a reply, like `from_self` in search.
- A `no_reply_by` watch no longer fires when the reply arrived in the same second as the watched message (IMAP dates
  have no milliseconds) and the sync hook had not seen it, for example because it was indexed during a rebuild.

## [0.8.1] - 2026-11-14

### Changed

- Installing and updating the client no longer needs root. The README and the deployment guide now separate the
  server install (`| sudo sh`, root-owned binary, `sudo dove upgrade`) from the client install (`| sh`, `~/.local/bin`,
  `dove upgrade` without sudo, or Homebrew). `install.sh` prints the `PATH` line for your shell (zsh, bash, fish,
  others) when its target directory is not in `PATH`, still without touching shell files, and its closing hint
  says `dove upgrade` without sudo after a user install.
- `dove upgrade` on a binary in a directory you cannot write now names both ways out: `sudo dove upgrade` on a server,
  and for your own computer how to switch to a user install (remove the root-owned binary, rerun `install.sh`
  without sudo, keep `~/.local/bin` in `PATH`).
- `dove upgrade` refuses to replace a binary installed by Homebrew (inside a `Cellar/dove/` directory, also when
  reached through the `bin` symlink) and points to `brew upgrade dove`; the daily new-version notice and
  `dove upgrade --check` say that command for Homebrew installs.

## [0.8.0] - 2026-11-14

### Added

- `dove sinks add --url-file <path>` reads the webhook URL from a file (owner-only mode, trimmed) or from standard
  input with `-`. `--url` still works but warns that the URL lands in shell history and the process list.
- `[clients] redact_secrets_default` in the service config: when `true`, connections created by `clients create`,
  `clients invite` and from invitations (`dove login`, OAuth approval) hide secrets in overview results unless created
  with the new `--no-redact-secrets`. Off unless set; existing connections keep their setting.

### Security

- Setting or removing IMAP junk keywords (`$Junk`, `$NotJunk`, `NonJunk` and any keyword containing `junk` or `spam`,
  in any case) needs the `delete` permission: mail clients train spam filters on them, like moving into or out of
  Junk.

### Fixed

- The hourly organize budget gives back only failures that certainly changed nothing. A Gmail move out of Trash whose
  second write failed, a Gmail write answered with a server error, a lost IMAP STORE or MOVE reply and a copy that kept
  its original now count as spent.
- IMAP `update_messages`: a STORE whose reply was lost, or a failure after part of the change was stored, is reported
  as `outcome_unknown` instead of `upstream_error` or `not_found`.

## [0.7.0] - 2026-11-13

Agent feedback: answering "whom have I not replied to?" took many calls, broad searches were dominated by the
user's own mail, `coverage: partial` did not say whether to wait, and snippets could show credentials.

### Added

- `search_messages` thread view: `group_by: "thread"` returns one row per mailbox and thread with the latest
  message's columns, `message_count`, `matched_count` and reply status (`last_sender_is_self`, `last_inbound_at`,
  `last_outbound_at`, `awaiting_reply`). The thread filter `awaiting_reply: true|false` keeps threads whose latest
  non-draft message is or is not from the mailbox itself. It is a rule over indexed mail, not a judgement whether a
  reply is needed; a reply sent from another mailbox is not seen.
- `from_self` as a filter and a column: the mailbox's own address, its IMAP aliases, or the `SENT` label.
- `dove search --from-self`, `--not-from-self`, `--threads` and `--awaiting-reply`.
- Optional secret redaction per connection (`dove clients set-redaction <name> on|off`, `--redact-secrets` on
  `clients create` and `clients invite`, off by default). Passwords, keys and one-time codes in subjects and snippets
  of `search_messages`, `digest` and `list_drafts` read `[redacted]`, and rows say `redacted: true`. `get_message`,
  `get_thread`, `get_draft` and attachments stay complete. The detector is heuristic: secrets without a label or a
  known format are not caught.

### Changed

- Coverage exceptions and `account_errors` in `search_messages`, `digest` and `search_contacts` carry `resolves`
  (`automatic`, `operator` or `never`), a `hint`, and where known `next_sync_at`, `next_retry_at` and
  `retry_after_seconds`; partial results carry a top-level `hint`. Messages listed but not fetched yet during a
  backfill are reported as `queued`, not as "pending retry".

## [0.6.0] - 2026-11-13

Security hardening from an internal audit. Read "Upgrading" before you update a server with webhook sinks.

### Changed

- Tools that return mail content (`get_message`, `get_thread`, `batch_read`, `search_messages`, `get_attachment`,
  `digest`, `search_contacts`, `list_drafts`, `get_draft`) mark it as untrusted: structured results carry
  `untrusted_content_notice`, and clients without a current `MCP-Protocol-Version` get the JSON inside the
  `<untrusted_email_content>` envelope. Such clients that parsed the text content as JSON need the current protocol
  version or `structuredContent`.
- The OAuth approval page shows the full redirect URI and, for dynamically registered clients, when and from which
  network they registered. A destination outside claude.ai, claude.com, chatgpt.com, chat.openai.com and loopback needs
  an extra confirmation. Dynamically registered clients never get an error redirect before approval.
- `/connect/redeem` checks an invitation's `--allow-ip` list before using it up.
- Failed bearer authentication on `/mcp` is limited per client address (`limits.auth_failures_per_minute`, default 60,
  IPv6 by /64): further failures get 429, valid tokens are always accepted. Loopback and unknown addresses are
  exempt.
- Organize tools have an hourly budget per client (`limits.client_organize_per_hour`, default 500 messages). Moving
  mail out of Spam/Junk needs the `delete` action. Trash and Junk folders are recognized by name in 17 languages.
- Webhook sinks belong to a project (`dove sinks add --project`, `dove sinks set-project`); clients only see sinks of
  their own project. Sink URLs are sealed by the vault, re-sealed by `dove keys rotate`, and `dove sinks list` shows
  only their origin.
- `dove upgrade --version` refuses an older release unless `--allow-downgrade` is given.
- `install.sh` and `install.ps1` require the exact trusted comment `dove <tag>`; the wget fallback is HTTPS only.
- Only Dove and its HTTP/TLS/SQLite stack may write log lines. The mail and attachment parsers (lopdf, html5ever and
  others) quoted untrusted content, such as PDF font dictionaries, in their warnings.
- Deployment: the nginx templates take the client address from the TCP peer even when another site sets
  `real_ip_header` in the `http` context, and log Dove requests without query strings (OAuth codes). The systemd and
  `.deb` units forbid executing files from Dove's writable directories (`NoExecPaths=`). The release workflow refuses
  a tag whose commit is not on `main`.

### Upgrading

- The state store migrates once on start. Existing webhook sinks keep their watches and queued pushes but serve no
  client until you assign a project: `dove sinks set-project <name> --project <project>`.
- An agent that moved mail out of Spam with only `organize` now needs `delete` for that mailbox.

## [0.5.0] - 2026-11-13

### Added

- Local mode (`mode = "local"`): Dove on your own computer as your user, for MCP hosts on the same machine, over
  `http://127.0.0.1:<port>` (plain HTTP only for that loopback origin; server mode is unchanged). `dove local init`
  creates a per-user config, keys and data directory, `dove local start` runs it in the foreground, `dove local stop`
  stops it, and `dove local install` / `uninstall` / `status` manage a login item (systemd user unit, launchd agent or
  Task Scheduler logon task, no administrator rights). See the threat model in the deployment guide's Local mode section.
  The `dove` client sends credentials to a plain-http loopback server only when your OS user holds that port
  (Linux, Windows).
- Windows support in the code: keys protected with DPAPI, private directories by access list, the admin channel as a
  per-user named pipe with a Windows account check, and `dove upgrade` replacing the running `dove.exe`.
- `dove mcp install --client claude-desktop` adds Dove to Claude Desktop's `claude_desktop_config.json`.
- Windows release: `dove-<tag>-x86_64-pc-windows-msvc.zip` (signed like every other asset), installed with
  `install.ps1`. Every Windows release is smoke-tested on a Windows runner (install, local mode start and stop, upgrade).

### Fixed

- Index reads enforce their deadline with a SQLite progress handler. The previous timer interrupt was lost when the
  deadline passed before the first statement started (a slow machine or a slow connection open), and the query then
  ran without a time limit.

## [0.4.0] - 2026-11-13

### Added

- `deploy/nginx/dove-restricted.conf`, `dove-allowlist.py` and a systemd timer: an nginx/Angie site that lets only
  Claude's and ChatGPT's servers (plus addresses you list) reach `/mcp` and the OAuth machine endpoints, with OpenAI's
  published ranges refreshed hourly.
- Static Linux builds for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`. `install.sh` picks them on
  musl systems such as Alpine (`DOVE_LIBC=gnu|musl` overrides), and `dove upgrade` keeps the libc the running binary
  was built for. The `-gnu` assets stay.
- Debian and Ubuntu packages (`dove_<version>_amd64.deb`, `_arm64.deb`) with the binary, the hardened systemd unit and
  the service account. Installing creates `/etc/dove` (0750) but no secrets and starts nothing.
- Homebrew formula `dove` in the tap `dominik-lenhart/homebrew-tap` (`brew install dominik-lenhart/tap/dove`),
  updated by the release workflow for every stable release. It installs the macOS and Linux binaries.
- `install.ps1` for Windows (SHA-256 and signature check, per-user install, no administrator rights), and `dove upgrade`
  reads Windows `.zip` releases. The Windows release build itself stays off until the Windows port lands.

### Changed

- Release builds are faster: `x86_64-apple-darwin` is cross-compiled on the arm64 macOS runner (it took 21 minutes on
  the Intel runner), and a cache warmed on `main` lets tag builds skip the vendored OpenSSL/SQLCipher compile.
- CI runs the tests with four threads, skips documentation-only changes, cancels superseded runs and checks the code
  on macOS (when Rust code changed) and on Windows (allowed to fail until the port is merged).
- The MCP instructions now tell hosts to use Dove for any question about the owner's mail and name the entry points
  (`list_accounts`, `digest`, `search_messages`, `create_draft`), so ChatGPT and Claude pick it without extra prompting.
- The reference proxy configs (`deploy/Caddyfile`, `deploy/nginx/dove.conf`, `dove-restricted.conf`) add
  `Referrer-Policy: no-referrer` only to responses that have none, instead of overriding Dove's own header.

### Fixed

- The OAuth approval page could not be submitted in a browser ("origin not allowed"): under `no-referrer` browsers send
  `Origin: null` with a form POST. The approval page now uses `same-origin`; everything else keeps `no-referrer`. Behind
  nginx or Caddy also update the proxy config (see Changed), or the proxy's header still wins.
- `dove doctor` checked the public URL through `/healthz`, which the proxy allowlists never forward, so the check
  always failed behind a proxy; it now fetches the protected-resource metadata.

## [0.3.0] - 2026-11-13

### Added

- Gmail over IMAP with an app password: no Google Cloud project needed. `dove accounts connect-imap --email
  you@gmail.com` uses the new `gmail` preset (`--preset gmail` for Google Workspace domains); Dove detects Gmail
  (`X-GM-EXT-1`), requires All Mail in IMAP, indexes each message once from All Mail, Spam and Trash with its Gmail
  labels (INBOX, user labels, IMPORTANT, SENT, ...), idles on All Mail, organizes through Gmail labels and `MOVE`
  only (never `\Deleted` or EXPUNGE outside its own drafts) and stores no Sent copy. State store migration 6 widens
  the folder table for the All Mail folder.

### Changed

- `connect-imap` suggests `--smtp-port 587 --smtp-tls starttls` when outgoing port 465 is blocked.
- README leads with the main point: one MCP server for all your mailboxes (new "Why Dove" section).

## [0.2.0] - 2026-11-13

### Added

- IMAP send-as aliases: `dove accounts aliases add|list|remove <mailbox> <address> [--name] [--envelope]`.
  `create_draft` accepts the mailbox address or an alias as `from_address` (anything else is `invalid_argument`),
  `list_accounts` shows `from_addresses` to connections that may draft, and the SMTP envelope sender stays the login
  address unless the alias is marked `--envelope`. A draft whose `From` is no longer an address of the mailbox is not
  sent.
- Plain-text signatures per mailbox and per alias, for Gmail and IMAP: `dove accounts signature set|show <mailbox>
  [--alias <address>] --file <path>|--clear`. `create_draft` appends `-- ` and the signature after the body and before
  a reply quote or forward block unless `signature: false`; `update_draft` never adds it again.
- `dove tailscale setup [--port N] [--funnel] [--dry-run]` publishes Dove's public paths on the node's `.ts.net` name
  with `tailscale serve` and sets `public_url`, idempotently; `--funnel` (internet exposure) only on request, with a
  warning. `dove doctor` checks the serve configuration (`tailscale_serve`). The path allowlist is one list shared with
  `deploy/Caddyfile` and `deploy/nginx/dove.conf`, and a test fails if any of them drift.
- Watches: `create_watch`, `list_watches`, `delete_watch` and `list_watch_events` (under `read`) tell an agent about
  a reply in a thread, mail from an address or domain, mail matching a typed search, or no reply by a deadline,
  instead of polling. Events are produced by the index sync (IMAP IDLE within seconds), carry ids and times only, and
  are kept 14 days. Watches belong to the token that created them (at most 50, 30 days by default, 180 at most) and
  end when the token is revoked or loses access, or the mailbox is disabled or removed.
- Webhook sinks for push delivery of watch events: `dove sinks add <name> --url https://... --secret-file <path>`,
  `dove sinks list`, `dove sinks remove <name>`. Deliveries are signed (`Dove-Signature`, HMAC-SHA256 over timestamp
  and body), retried a bounded number of times, and sent only to the registered URLs; agents name sinks but never
  supply URLs. See docs/deployment.md, "Watches and sinks".
- New grant actions `organize` (mark read/unread, star, labels, archive, move between folders, move out of Trash/Spam)
  and `delete` (move to Trash or Spam; never a permanent delete), and presets `reader`, `drafter`, `assistant` and
  `full` for `--grant`, `--capabilities` and the OAuth approval page (`work=assistant,send` mixes both). Presets are
  stored expanded, so existing tokens keep exactly their grants.
- Tools `update_messages` and `move_messages` (up to 100 ids, per-id results; IMAP ids change on a move and come back
  as `new_id`) and `delete_draft` for drafts Dove created and nobody changed.
- IMAP moves use `MOVE` where offered and otherwise `COPY` plus `\Deleted`/`UID EXPUNGE` of exactly the messages the
  server confirmed as copied.

- `search_contacts`: who the mailbox actually corresponds with, ranked by exchanged mail and recency, without no-reply
  and other automated senders. Works on Gmail and IMAP mailboxes through the index.
- `digest`: threads with new mail since a time, newest first, with snippets, per folder and category, paged with a
  cursor.
- Mail categories (`personal`, `newsletter`, `notification`, `calendar`) assigned at ingest from headers and parts,
  a `category` filter and column in `search_messages`, and `category` in `get_message`.
- Calendar invitations: `get_message` returns the event (method, summary, start, end, time zone, location,
  organizer, attendee count, uid) from a `text/calendar` part.
- Attachment text: PDF, DOCX, ODT, text and CSV attachments are read into the full-text index at ingest, so
  `text` and the new `attachment_text` operator find words inside them. `get_attachment` gets `as_text` and
  `max_chars` to return that text. Bounded in size, time and memory; configure with `index.attachment_text` (on by
  default), `attachment_text_max_bytes`, `attachment_text_max_chars` and `attachment_text_timeout_secs`.

### Changed

- Gmail connects also request `gmail.modify`. Mailboxes connected earlier keep reading, drafting and sending; run
  `dove accounts reconnect <alias>` to use the organize and delete tools and `delete_draft` there.
- The OAuth approval page shows a preset selector per mailbox; `organize` is pre-selected, `delete` and `send` are not,
  and `send` only appears while `allow_send = true`.
- The first start after upgrading rebuilds every indexed mailbox once, to compute categories and attachment text.
  The old index keeps answering searches until the new one is ready; results that need categories or attachment text
  are reported as partial until then.
- New dependency: `lopdf` (PDF text extraction, no default features).

### Fixed

- Gmail snippets (digest, search results) no longer show HTML character references such as `&#39;`.

## [0.1.0] - 2026-11-13

First release.

### Added

- Gmail mailboxes through the Gmail API: search, read, thread and attachment access, and drafts. Sending is off by
  default and needs two gates: `allow_send` in the server configuration and a `send` grant for one token on one
  mailbox.
- IMAP/SMTP mailboxes with password login, including presets for Strato and iCloud, with the same read, draft and
  send tools as Gmail.
- IMAP IDLE push, so the search index follows new mail without waiting for the next poll.
- Encrypted full-text search index (SQLCipher FTS5) with a query compiler, per-account sync and freshness reporting.
- Draft attachments, forward and quoted replies.
- Client onboarding and OAuth for MCP hosts: invitations, project and client management, scoped agent tokens,
  `dove login`, `dove mcp install` and a stdio bridge.
- Hash-chained audit log with one record per tool call, and no mail content in logs or audit records.
- Admin Unix socket (peer-uid checked) for operator commands; agent tokens never reach admin verbs.
- Envelope encryption of Google refresh tokens and IMAP passwords, secrets read only from files with strict modes.
- Deployment material: systemd unit, container image, Compose example with Caddy, reverse proxy allowlists.
- Signed releases for Linux and macOS, a multi-arch image on GHCR, `install.sh`, and `dove upgrade`, which installs a
  release only after verifying its minisign signature. The CLI hints at a new release at most once a day
  (`DOVE_NO_UPDATE_CHECK=1` turns it off); the server never checks for updates.

[Unreleased]: https://github.com/dominik-lenhart/dove/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/dominik-lenhart/dove/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/dominik-lenhart/dove/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/dominik-lenhart/dove/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/dominik-lenhart/dove/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/dominik-lenhart/dove/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/dominik-lenhart/dove/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/dominik-lenhart/dove/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/dominik-lenhart/dove/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/dominik-lenhart/dove/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dominik-lenhart/dove/releases/tag/v0.1.0
