# Changelog

All notable changes to Dove are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/) as described in [docs/releasing.md](docs/releasing.md).

## [Unreleased]

## [0.1.0] - YYYY-MM-DD

First release.

### Added

- Gmail mailboxes through the Gmail API: search, read, thread and attachment access, drafts and sending, behind two
  separate gates (a token needs the `draft` grant to write drafts and a second, explicit permission to send).
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

[Unreleased]: https://github.com/dominik-lenhart/dove/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dominik-lenhart/dove/releases/tag/v0.1.0
