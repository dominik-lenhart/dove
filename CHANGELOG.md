# Changelog

All notable changes to Dove are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/) as described in [docs/releasing.md](docs/releasing.md).

## [Unreleased]

### Added

- `deploy/nginx/dove-restricted.conf`, `dove-allowlist.py` and a systemd timer: an nginx/Angie site that lets only
  Claude's and ChatGPT's servers (plus addresses you list) reach `/mcp` and the OAuth machine endpoints, with OpenAI's
  published ranges refreshed hourly.

### Fixed

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

[Unreleased]: https://github.com/dominik-lenhart/dove/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/dominik-lenhart/dove/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/dominik-lenhart/dove/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dominik-lenhart/dove/releases/tag/v0.1.0
