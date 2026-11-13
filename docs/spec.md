# Dove: a self-hosted mail MCP server for AI agents

Status: working draft 0.5, 12 Nov 2026. Implementation language: Rust. Version 1 targets Gmail and Google Workspace. Apple Mail on macOS is the primary human review client.

Words in capitals (MUST, MUST NOT, SHOULD, MAY) follow RFC 2119.

---

## 1. Purpose

An owner has many mailboxes (the first user has about 25). Several AI agents (Claude Code, Codex and others), each
working on one project, need to read and search the mail of that project's mailboxes and to put reply drafts into
those mailboxes. Agents revise the same draft across turns. The owner normally reviews and sends from Apple Mail.

Dove is a single service on the owner's server. It holds the mailbox authorizations and exposes a Model Context
Protocol (MCP) server to agents. A **project** groups mailboxes. A **client token** belongs to one project and sees
only the intersection of its explicit mailbox grants and that project's current mailboxes.

Dove is published as open source for self-hosting. Every operator runs their own instance with their own Google
Cloud project and OAuth client (section 9). There is no shared hosted service and no client id shipped with the code,
so no operator's grants ever pass through anyone else's infrastructure.

## 2. Goals and non-goals

### Goals

- G1. Search and read authorized mailboxes over HTTPS from compatible MCP clients with bearer headers.
- G2. Create and revise server-side reply and new-mail drafts. Default final sender: the owner in Apple Mail.
- G3. Restrict every operation by project, token, mailbox and action. Sending is an explicit operator opt-in (§6.3).
- G4. Security first. A leaked client token, a malicious email or a stolen database file must cause as little
  damage as possible (section 6).
- G5. OAuth 2.0 against Google with least-privilege scopes. No mailbox passwords and no app passwords.
- G6. Run unattended. Token refresh, re-authorization needs and quota errors are handled, and the owner hears about
  them.
- G7. Small and auditable. One process, a durable state database, a rebuildable search database and few dependencies.

### Non-goals (version 1)

- N1. Raw message sending, scheduled sending and bulk sending are outside v1. Standard tokens have no send permission.
- N2. Deleting, trashing, archiving, labelling or marking messages read. Dove does not change existing mail.
- N3. Gmail settings: filters, forwarding, send-as aliases, vacation replies.
- N4. Permanent raw MIME archives, attachment bytes and attachment text extraction are outside v1 (attachment reads
  and draft attachments were added later, see `docs/superpowers/specs/2026-11-12-imap-smtp-design.md`). Selected mailboxes can persist encrypted searchable message text and metadata (§7.9).
- N5. Arbitrary SQL, vector search and a separate search service are outside v1.
- N6. Multi-user or multi-tenant operation. There is one owner, one administrator, one server.
- N7. General web administration. Operator administration remains local CLI; the minimal connection approval/OAuth page in §5.6 is part of v1.
- N8. Additional mail providers in v1.

## 3. Terms

| Term | Meaning |
| --- | --- |
| Owner | The person who runs Dove and owns or controls all mailboxes. The only administrator. |
| Account | One connected Google mailbox, identified by a stable internal id and an alias such as `acme-info`. |
| Project | A named set of accounts, for example `acme` = {`acme-info`, `acme-support`}. An account MAY belong to several projects. |
| Client | One agent integration. It belongs to exactly one project, holds one client token and has a set of capabilities. |
| Client token | A bearer secret that an MCP client sends. It identifies the client and so its project. |
| Capability | Mailbox-specific permission on a token: `read`, `draft`, or `send`. |
| Grant | The Google OAuth authorization for one account: an encrypted refresh token plus its granted scopes. |
| KEK / DEK | Key-encryption key / data-encryption key (envelope encryption, section 6.4). |
| Own draft | A draft that Dove created for a given project, recorded in the draft ownership table. |

## 4. Usage scenarios

- S1. An agent searches unread INBOX messages across its approved accounts, loads selected threads, creates drafts and revises them on request. The owner finishes in Apple Mail.
- S2. An agent looks for "the invoice from Hetzner in October" across all the project's accounts and reads the
  matching message.
- S3. The owner connects a new mailbox. They run one CLI command, open the printed link, sign in to Google and
  approve. The account then shows up for every project the owner adds it to.
- S4. A Google grant becomes invalid, for example after a password change. The account reports
  `reauth_required` to agents, the owner gets a notification and runs the reconnect command.
- S5. A client token leaks. The owner revokes that one client. All other clients keep working.

## 5. Functional requirements

### 5.1 Accounts

- FR-A1. The owner connects an account with `dove accounts connect --alias <alias> --email <address>`
  (section 7.3). Connecting MUST verify that the Google identity that approved access is exactly `<address>`.
- FR-A2. Account fields: id (random, immutable), alias (unique, `[a-z0-9-]{2,40}`), email, display name (optional),
  status (`active`, `reauth_required`, `disabled`), granted scopes, connected_at, last_used_at, last_error.
- FR-A3. `dove accounts reconnect <alias>` repeats the grant flow for an existing account and replaces the grant
  only after the new grant has been verified.
- FR-A4. `dove accounts remove <alias>` revokes the grant at Google, deletes the grant and its DEK, removes the
  account from all projects and keeps the audit history.
- FR-A5. `dove accounts disable|enable <alias>` blocks or allows use without touching the grant.
- FR-A6. `dove accounts check [<alias>]` refreshes the access token and calls the profile endpoint for each
  account, and prints its status.

### 5.2 Projects and clients

- FR-P1. `dove projects create <name>`, `projects add-account <project> <alias>`,
  `projects remove-account <project> <alias>`, `projects list`, `projects show <name>`.
- FR-P2. `dove clients create support --project acme --grant info=read,draft --grant billing=read [--expires 90d] [--allow-ip <cidr>...]` prints a new token once. Resolve aliases to immutable account IDs at issuance. Require explicit mailbox grants. Adding a project mailbox grants existing tokens zero new access. Each grant containing `draft` or `organize` requires `read`, `delete` requires `organize`, and `send` requires `read` and `draft`. Since 0.2 the grant also accepts presets (`reader`, `drafter`, `assistant`, `full`, never including `send`), expanded at issuance and stored expanded; unknown words are an error.
- FR-P3. `clients set-grants <name> --grant ...` atomically replaces the entire grant set. Show effective account/action pairs in `clients show`. Rotation preserves grants and invalidates the old secret. Revocation blocks the next request. Removing a mailbox from a project deletes its client grants transactionally; re-adding it does not resurrect access.
- Project membership sets the ceiling. One authorized mailbox is one read boundary, including aliases, labels and other projects' messages in that mailbox. Ownership restricts draft mutations only.
- FR-P4. A change to a project or client takes effect on the next request, with no restart.
- FR-P5. Unknown and out-of-scope accounts or object IDs yield identical `not_found`. Apply to explicit inputs, default searches, lists, cursor resumes, caches and errors. Reject a mixed list containing an unauthorized ID before issuing any upstream call.

### 5.2a Quick grant presets

For the trusted operator, `dove clients invite laptop --project acme --accounts all --capabilities read` creates a one-time connection invitation. `--accounts info,billing` selects fewer accounts. `all` expands only the project's current accounts into immutable explicit grants, displays the expansion and never follows later additions. Read is the default preset; read,draft is explicit; send still requires the instance gate and explicit operator permission. A global `all-mail` project can group all currently connected mailboxes for a personally authorized all-mail reader. A new connection always has its own name, credentials, last-use record and revocation.

### 5.3 MCP tools

Single-mailbox tools require `account` (alias or email, resolved within effective grants). `search_messages` accepts optional `accounts`; omission searches all mailboxes with `read`, reporting unavailable ones separately. `list_accounts` needs no account argument. Advertise each tool only when usable for at least one granted mailbox. Enforce the actual grant again on every call, including cached responses.

All results are structured (`structuredContent` with an `outputSchema`) plus a short text rendering. Message content
is always delivered in the untrusted-content envelope from section 6.5.

| Tool | Capability | Purpose |
| --- | --- | --- |
| `list_accounts` | read | Effective mailbox aliases, addresses, status and actions for this token. |
| `search_messages` | read | Filter, project, order and page authorized mail; optional native Gmail search. |
| `batch_read` | read | Issue bounded independent search/message/thread reads in one MCP call. |
| `search_contacts` | read | Correspondents of the authorized, indexed mailboxes, ranked by exchange count and recency (§5.3a). |
| `digest` | read | Threads with mail since a time, newest first, with snippets (§5.3a). |
| `get_message` | read | One message: headers, plain-text body, category, calendar event, attachment metadata. |
| `get_thread` | read | All messages of a thread, oldest first, bodies as in `get_message`. |
| `list_labels` | read | Labels of an account (system and user), for building queries. |
| `list_drafts` | read | Drafts of an account. `own_only` (default true) limits it to drafts this project created. |
| `get_draft` | read | Draft content and current revision in the specified mailbox. |
| `create_draft` | draft | Create a new message, a threaded reply (quoting the original) or a forward, with attachments. |
| `update_draft` | draft | Edit an owned draft, conditional on the expected revision (§5.3); attachments kept unless replaced. |
| `delete_draft` | draft | Delete one owned, unchanged draft (optionally conditional on `expected_revision`). Gmail: `messages.trash` of the draft's message; IMAP: `\Deleted` + `UID EXPUNGE` of exactly the own draft's UID. |
| `update_messages` | organize | Up to 100 ids: add/remove flags (`UNREAD`, `STARRED`) and labels (Gmail user labels, never created; IMAP keywords). Per-id results. |
| `move_messages` | organize (+ delete) | Up to 100 ids to a folder/label, `archive`, `inbox`, `trash` or `spam`. Trash, Spam/Junk and folders below them need `delete`; moving out of them is organize. Per-id results with `new_id` (IMAP ids change). Never a permanent delete. |
| `send_draft` | send | Optional. Submit one existing, owned draft under §6.3. |
| `create_watch` | read | Watch an indexed mailbox: `thread_reply`, `from` (address or domain), `query` (a `where` filter, checked against newly indexed mail only) or `no_reply_by` (fires once at a deadline). Belongs to the creating token; at most 50 active, expiry 30 days by default, 180 at most; optional operator sink by name. |
| `list_watches` | read | This token's watches (active and recently ended, with the reason) and the operator's sink names. |
| `delete_watch` | read | Delete one of this token's watches and its events. |
| `list_watch_events` | read | This token's watch events since an opaque cursor, oldest first, kept 14 days: watch id, kind, account, message id, thread id, received_at; never subject, sender or body. |

Read tools set `readOnlyHint: true`. Update and send set `destructiveHint: true`. Annotations describe tools; the server enforces authorization. Draft deletion remains a human mailbox action in v1.

#### `search_messages`

The default source is `index`. A search returns messages at the authorized index checkpoints. The client translates a natural-language request to a small JSON query; the server never evaluates caller SQL, FTS expressions or identifiers.

```json
{
  "accounts": ["billing", "info"],
  "where": {"all": [
    {"field":"from_domain","op":"eq","value":"hetzner.com"},
    {"field":"has_attachment","op":"eq","value":true},
    {"field":"received_at","op":"gte","value":"2026-10-01T00:00:00+02:00"},
    {"field":"received_at","op":"lt","value":"2026-11-01T00:00:00+01:00"}
  ]},
  "select":["subject"], "order_by":[{"field":"received_at","dir":"desc"}],
  "limit":10, "coverage_policy":"require_complete"
}
```

**Filters and types**

| Fields | Operators and meaning |
| --- | --- |
| `from`, `to`, `cc`, `bcc`, `participant` | `eq` or `in` matches a complete address in visible headers. Multi-value fields match any member. Bcc is searchable only when the mailbox actually contains it. |
| `from_domain`, `recipient_domain` | `eq`, `in`; normalized exact domains, excluding subdomains unless named. Recipient includes To, Cc and visible Bcc. |
| `label`, `thread_id`, `message_id` | `eq`, `in`; labels match any member. Use Gmail system label IDs or mailbox-specific label IDs from `list_labels`. Qualify IDs by mailbox when targeting a specific object. |
| `is_unread`, `is_starred`, `is_draft`, `has_attachment` | Boolean `eq`. Gmail labels supply flags. Attachment means a MIME part marked attachment or carrying a nonempty filename, excluding inline resources with a Content-ID unless explicitly marked attachment. |
| `received_at`, `size_bytes` | `eq`, `lt`, `lte`, `gt`, `gte`. Use RFC 3339 instants with offsets and Gmail internalDate; size is Gmail's size estimate. Date examples use inclusive start, exclusive end. |
| `subject`, `body_text`, `text` | `terms` (all complete tokens), `phrase` (adjacent tokens), `prefix` (one token). `text` covers subject or normalized body. Case-insensitive Unicode tokenization; no stemming in v1. |
| `attachment_name`, `attachment_mime` | Case-insensitive `eq`, `in`; name additionally supports literal `ends_with` (e.g. `.pdf`). |
| `attachment_text` | `terms`, `phrase`, `prefix` over text extracted from PDF, DOCX, ODT, text and CSV attachments at ingest (§7.9). `text` covers subject, body and attachment text; `body_text` stays body only. Messages whose attachments were not read (too large, unreadable, extraction off, ingested by an older version) make the result `partial` with an exception; `require_complete` answers `index_incomplete`. |
| `category` | `eq`, `in` over `personal`, `newsletter`, `notification`, `calendar`. A message without a category (indexed by an older version until its mailbox rebuilds) never matches; the result is `partial` with an exception. Selectable as a column. |

- Combine predicates with `all`, `any` and unary `not`. Empty `where` matches all visible rows; exclude SPAM/TRASH unless `include_spam_trash:true`. Missing scalar or header values do not match a positive predicate; negation complements within the already-authorized candidate set. Normalize addresses consistently at ingest and lookup. Reject unsupported combinations, empty Boolean groups, depth >4, >32 predicates, >100 list values or >256 characters per filter string. Bind values; whitelist columns/operators and encode FTS token literals.
- `select` returns exactly its requested columns. Default: `ref,received_at,from,subject`. `ref` is an opaque account/message handle usable by read tools, with authorization on resolution. Allowed extra columns: account, message_id, thread_id, to, cc, bcc, labels, snippet, size_bytes, attachment names/MIME types, and the filter flags. Wire names for attachment lists are `attachment_names` and `attachment_mime_types`. Subject-only really returns just subjects. Body and raw headers require a detail read. For compact multirow results return `columns` once and positional `rows`; do not repeat the table as prose. Legacy text-only clients receive one compact serialized result.
- `order_by` accepts at most two keys from `received_at`, `size_bytes`, `subject` with `asc|desc`. Default is newest first. Compare subject by normalized case-folded key, missing values last. Append immutable `(account_id,message_id)` ascending as a stable tiebreaker. Top N uses this sort and `limit` (1–100, default 20). Filtering and authorization precede ordering and limiting. Exact counts are opt-in (`count_only:true`, mutually exclusive with select, ordering, paging and limit); never compute totals solely to determine if another page exists.
- Use a scoped keyset cursor with a 15-minute TTL; page size is `limit`. Resume with the cursor only. Bind query, authorization, projection and order. Apply current grants/status before access and again before release if changed in flight. Fetch one extra row to detect another page. Unchanged data yields complete traversal without duplicates or gaps. New syncs can move/delete rows between pages; expose `changed_since_first_page`. An index rebuild, grant change or token revocation invalidates prior cursors. A fresh query is needed for a new consistent top-N.
- Return `coverage:complete|partial`, `as_of` (oldest included mailbox sync time), and per-mailbox exceptions with alias, stage and last successful sync time. Complete refers to all requested mailboxes and fields at their checkpoints, not the live inbox at response time. Optional `max_lag_seconds` demands a recent checkpoint. `coverage_policy:require_complete` returns `index_incomplete` with reasons if completeness/freshness is unmet; default `allow_partial` returns what is covered. Latest, absence and exact-count questions use require_complete; count_only implies it. No query may disclose data from a disabled, known-disconnected, known-invalid-grant or out-of-scope account. For require_complete, default max_lag_seconds to 60; return index_incomplete when a requested mailbox has no successful checkpoint or exceeds this lag. An explicit max_lag_seconds overrides that default. Complete results are exact at the reported checkpoints; this is not an atomic live snapshot across Google accounts.
- Escape hatch `source:gmail, gmail_query:"..."` runs Gmail's native syntax, including on nonindexed mailboxes. It accepts accounts, select (only live-supported fields: ref, account, message_id, thread_id, received_at, from, to, cc, subject, labels, snippet), limit, cursor and spam/trash policy. Preserve upstream order within a mailbox and interleave active mailboxes fairly. Reject local predicates, custom ordering, count and local freshness options on this route. Return source and partial failures explicitly; never silently switch semantics. Buffer unreturned upstream IDs and tokens in a bounded RAM cursor. For simple ID projections skip message GETs. Apply the same authorization and output budget on both sources.

**Batched reads**

`batch_read({items:[{id,op,args}, ...]})` supports up to 20 distinct item IDs; `op` is search_messages, get_message or get_thread. No mutations or nested batches. Resolve and authorize each subrequest exactly as a standalone call. Return one result or stable error per caller ID in input order; coalesce duplicate authorized reads internally. Charge quotas by underlying work. Apply one shared deadline, a 64 KiB response cap and a combined 100 search rows per call. Reserve space for every item status; return a continuation at a complete row/message boundary or an explicit per-item `budget_exceeded` with a smaller request suggestion. Count budgets on the wire; limit body characters on all detail reads. The read batch has no mailbox write operations.

#### `get_message` and `get_thread`

- Input: `account`, `message_id` or `thread_id`, `max_body_chars` (default 20 000, max 100 000),
  A `ref` from search may replace the (account, message_id) pair for get_message. A detail read may specify `select` over documented output fields plus `body_text` and `attachments`. Default detail semantics remain unchanged.
  `include_headers` (optional list of extra header names to return, from an allowlist such as `List-Unsubscribe`,
  `Reply-To`, `Message-ID`, `In-Reply-To`, `References`).
- Output: the fields of a search result plus `reply_to`, `message_id_header`, `body_text`, `body_truncated`,
  `attachments[]` (`attachment_id`, `filename`, `mime_type`, `size_bytes`). The body is the text/plain part if one
  exists, otherwise text converted from text/html (section 6.5).
- Output also carries `category` and, for a message with a `text/calendar` (or `application/ics`) part that parses, `calendar`:
  `method`, `summary`, `start`, `end`, `timezone` (the TZID name; local times carry no offset because Dove ships no
  time zone database), `all_day` (end exclusive, as in iCalendar), `location`, `organizer` (`Name <address>`),
  `attendees_count` (attendee addresses are counted, never listed) and `uid`. Only the first VEVENT is read; input,
  line and field sizes are bounded; a part that does not parse leaves `calendar` out and the category `calendar`.
- Attachment content is not returned by these tools; `get_attachment` fetches it (§5.3a). Apply an aggregate response byte limit to threads as well as a per-message text limit; return an explicit truncation marker and remaining message IDs.

### 5.3a Mail intelligence tools (0.2)

All three work on indexed mailboxes (Gmail and IMAP alike), follow the grants of the token and return their data
inside the untrusted-content envelope. Each call is one audit record; queries and results never reach the audit log.

- **`search_contacts`**: `query` (optional, 2 to 100 characters, matched case-insensitively against address and display
  name as a literal substring, never as a pattern; shorter is `query_too_broad`), `account` (optional alias), `limit`
  (1 to 50, default 20), `include_automated` (default false: no-reply, donotreply, mailer-daemon, postmaster and
  bounce addresses are left out, as are the mailbox's own addresses). Output: `contacts[]` with `address`, `name`,
  `received` (mails from the address), `sent` (mails the mailbox sent to it, To/Cc/Bcc), `last_contact`, `accounts`.
  Only exchanged mail counts: a Cc on mail between third parties does not make a contact. Ranking is
  `ln(1 + 2*sent + received)` times a 90 day half-life on the last contact. Computed at query time from the index over
  at most 2 000 candidate addresses (matching ones, or those of the newest 2 000 messages) and reports `truncated`.
  An aggregate cannot be split by mailbox, so a grant lost mid-call answers `forbidden`.
- **`digest`**: `since` (RFC 3339, required, at most 366 days back), `accounts` (default all readable), `folders`
  (labels, default `INBOX`, at most 10), `category`, `limit` (1 to 50, default 20), `cursor` (alone). One entry per
  thread with a matching message, newest first: `account`, `ref` of the newest message, `thread_id`, `subject`,
  `participants` (up to 5 distinct senders), `count`, `newest_received_at`, `unread`, `category`, `snippet` (one
  cleaned line, at most 160 characters). Spam and trash are excluded. Paging uses the keyset cursor contract of
  `search_messages`, bound to the digest query; a search cursor is `cursor_invalid` here and the other way round.
  Coverage and exceptions are reported as for search.
- **`get_attachment` with `as_text: true`**: same arguments and authorization as the byte route (`ref` or
  `account` + `message_id`, `attachment_id`) plus `max_chars` (default 50 000, max 200 000; without `as_text` it is
  `invalid_argument`). Returns the bounded plain text of a PDF, DOCX, ODT, text or CSV attachment instead of the bytes,
  with `text_truncated`; other types are `invalid_argument`, encrypted or unreadable documents `invalid_argument`,
  attachments above `limits.attachment_bytes` `too_large`, a blown 10 second extraction budget `upstream_error`.

#### `create_draft`

- Input: `account`, `request_key` (client-generated UUID), `to[]`, `cc[]`, `bcc[]`, `subject`, `body_text`, `reply_to_message_id`
  (optional), `from_address` (optional, MUST be one of the account's send-as addresses), `attachments[]` (optional),
  `forward_message_id` or `forward_ref` (optional), `include_attachments` (forwards, default true), `quote_original`
  (replies, default true).
- Attachments: each is either a reference `{ref | account + message_id, attachment_id}` to an attachment of a message
  the caller may read, fetched server-side (the bytes never pass through the agent), or inline `{filename,
  mime_type, content_base64}`. At most 10 per draft and `limits.draft_attachment_bytes` (default 10 MiB) decoded in
  total; exceeding either is `invalid_argument` (count) or `too_large` (bytes), never a silent drop. A referenced
  mailbox without `read` is the identical `not_found`, decided before any upstream call. Filenames are sanitized as
  in `get_attachment`; MIME types must be a plain `type/subtype`.
- Forward mode: subject `Fwd: <original subject>` unless given, the agent's text, then a forwarded-message block
  (From, Date, Subject, To, Cc) and the original plain text, and the original's attachments unless
  `include_attachments` is false. Needs `read` on the source mailbox; source and target may differ.
- Reply quoting: below the agent's text, `On <date>, <sender> wrote:` and the original plain text with `> ` prefixes,
  at most 100 KiB of original text and never beyond the body limit. Quoted and forwarded text is untrusted content
  and goes into the body only; the only header derived from the original is the subject, reduced to one clean line.
- Reply mode (`reply_to_message_id` set): the draft is placed in that message's thread, `In-Reply-To` is set to the
  original `Message-ID`, `References` to the original `References` plus its `Message-ID`, and the subject defaults to
  the original subject, preserving the threading subject. A caller requesting a different subject creates a new conversation, with no claim that threadId can force Gmail grouping. Add a real-account test covering an unchanged subject and a changed subject. Recipients are never inferred; the agent passes them.
- Return `account`, `draft_id`, `message_id`, `thread_id` and an opaque `revision`. The canonical handoff is the server Drafts mailbox of the same Google account in Apple Mail. Gmail web is an optional fallback.
- Before dispatch, durably insert a create-operation row keyed by (client_id, account_id, request_key), with a keyed hash of normalized inputs, state in_flight and no content. Retrying an existing key returns its stored result or outcome_unknown and never dispatches another create. Reusing a key with different inputs returns invalid_argument. Commit ownership, returned IDs and operation success in one transaction after confirmation. A crash after dispatch leaves an unknown outcome. Retain operation rows until explicit operator removal. A new key is a new intent; after an unknown result, the caller must verify the mailbox or obtain a new explicit creation instruction before creating again. Test disconnects and restart before local commit.
- Dove MUST NOT add any header or text that reveals the project, client or agent to recipients. Ownership lives
  only in Dove's own table.

#### Revising drafts and handing over to Apple Mail

- `update_draft(account, draft_id, expected_revision, changes)` patches an owned draft. Omitted fields are preserved. Return a new revision after each confirmed update. A prompt such as “shorten the last paragraph” must leave recipients, subject, reply headers, threading and sender intact.
- Dove-created drafts are text/plain, optionally `multipart/mixed` with the body first and one attachment leaf per
  file. Update keeps those attachments unless `changes.attachments` replaces the list (`[]` removes all). For
  externally added MIME parts, HTML or inline parts that the writer cannot preserve, return `draft_conflict` before mutation. Build the replacement from the current server message; never replace missing fields with defaults.
- Serialize Dove operations per (account, draft_id), then read Gmail fresh, bypassing caches. Compare its message ID to the last Dove-written revision and to the caller's expected revision. A mismatch returns `draft_conflict`; a missing draft returns `not_found`. Never recreate, adopt or reassociate a missing draft by subject or thread.
- Human handoff uses Apple's server-side Drafts mailbox. A message that is only “On My Mac” is outside Dove. Treat external changes as human-owned; on conflict show the latest content and let the owner finish it or explicitly ask for a separate proposed draft. An unsaved Apple Mail editor is invisible to Gmail. Without a documented atomic provider precondition, the fresh check detects previously saved edits but cannot protect against a simultaneous save between GET and PUT. Support sequential editing, with this limitation documented.
- `send_draft(account, draft_id, expected_revision)` uses the same scope, ownership, fresh-read and conflict checks. It accepts no recipients, content or arbitrary raw MIME. See §6.3.

### 5.4 Errors returned to agents

Tool failures return an MCP tool result with `isError: true` and structured content with a stable `code`, a short
human message and, where useful, `retry_after_seconds`. Codes: `not_found`, `forbidden` (capability missing),
`invalid_argument`, `account_unavailable` (disabled or `reauth_required`), `rate_limited`, `upstream_error`,
`internal`, `draft_conflict`, `outcome_unknown`, `cursor_invalid`, `query_too_broad`, `index_incomplete`, `budget_exceeded`, `too_large` (an attachment above `limits.attachment_bytes`, or a draft's attachments above `limits.draft_attachment_bytes`, with the size and limit). Errors disclose no tokens, mail content, stack traces or unauthorized account data.

### 5.5 Administration CLI

- FR-C1. Local administration requires a trusted OS identity separate from the agent's shell identity. On the Linux reference deployment, install a Unix socket with restricted permissions for the operator and service and verify peer credentials against the configured operator UID (or root). Check all admin verbs, including issuing/rotating tokens, changing grants, indexing and restoring state. The client binary conveys no authority. Agent bearer tokens are accepted only on the MCP data plane.
- Keep production config, service units, running binary, admin socket, state, cache/index keys, backup/restore interface and deploy credentials outside agent control. Agent shell has neither operator/service UID, inherited admin SSH access, sudo nor a privileged container socket. Use a separate host or restricted OS account for agents. A shell running as the production operator cannot be distinguished from that operator by a CLI. `allow_send` is deployment-owner configuration; MCP and regular token commands cannot enable the instance gate. Only the authorized operator can grant a token send rights.
- FR-C2. Commands as listed in 5.1 and 5.2, plus `audit tail|search`, `keys rotate` (section 6.4), `doctor` (checks
  configuration, permissions of secret files, reachability of Google, TLS of the public URL) and `export` (projects,
  clients and accounts without secrets, for review).

### 5.6 Client experience and OAuth (v1)

**Usability requirement.** After the server and Google mailboxes are configured, establish an additional restricted connection on a new computer or supported MCP host in under 60 s of active setup in the acceptance fixture. Download time, host-required account/workspace approvals and first mailbox indexing are measured separately. The client must work before backfill completes through explicit live search. Do not require a Rust toolchain, Node, Python, Docker or a database installation on client machines.

**Single client binary.** Ship self-contained signed release binaries for macOS arm64/x64, Linux x64/arm64 and Windows x64. SQLCipher is bundled for server builds; client commands do not open or initialize server databases. The same `dove` executable has remote-user commands and protected local-admin commands. Remote commands cannot select an admin transport or increase their permissions. Client examples (specified interface, not existing software):

```sh
dove login --server https://dove.example.com --profile acme
# Prompts for the one-time invitation from the trusted operator.
dove search --profile acme --from-domain hetzner.com --limit 5 --select subject
dove mcp install --profile acme --client claude-code --scope user
```

- `login` redeems the pre-authorized invitation over HTTPS and stores only that connection's opaque Dove token in the OS credential store. Invitation is at least 128 random bits, hash-only on server, single use, 10-minute expiry, rate-limited, redacted from logs and never put into URLs. Success atomically consumes it and issues one independently revocable connection. Concurrent redemption yields one winner; a lost response requires another invitation, with orphaned connections visible to the operator. A draft-only token cannot mint invitations. Never prompt for Google credentials on a client.
- Profiles contain a server URL and credential reference. `status` shows accessible mailboxes/actions and connectivity; `logout` removes the local credential and offers remote revocation. With no OS credential store, require explicit choice of a 0600 local secret file; never silently fall back. Support stdin token input for authorized headless use. No credentials in generated project files.
- `dove search`, `message get`, `thread get`, `draft create|get|update|send` and `batch` invoke the existing server tools over Streamable HTTP; reuse the typed query schemas and output rules. Provide familiar flags for common searches and `--query-file` / JSON stdin for full expressions. Support both readable output and `--json`, including cursor/partial/error metadata. Draft retries preserve the request_key.
- `mcp install` supports Claude Code and Codex initially. Detect current supported config formats, validate existing files, preserve unrelated entries, use atomic writes and be idempotent. Default to user scope; project scope requires explicit choice and stores only a reference to the local profile. Generate a stdio entry invoking the installed absolute `dove mcp stdio --profile acme` path. The built-in authenticated bridge forwards to the existing remote MCP endpoint, uses stderr for diagnostics, handles cancellation/reconnect, and applies bounded buffers. Remote HTTP OAuth clients can connect directly to the same URL. No separately installed proxy.
- `dove connect-info` prints the remote MCP URL and short current host-specific setup steps. `doctor --profile` reports missing config, credentials, network access or grants without exposing secrets. All commands list the actual configured rights.

**ChatGPT and Claude OAuth.** Promote downstream OAuth to v1. Add the HTTPS `/mcp` URL in the host, choose OAuth sign-in, redeem an operator-issued invitation on Dove's minimal approval page, verify the named project, mailbox grants and application, and approve. Host access/refresh tokens remain bound to that connection and MCP audience. Subsequent normal use refreshes automatically without repeating Google consent. The approval page can only accept or narrow pre-authorized rights. It cannot create projects, add Google mailboxes, enable sending, or raise a grant. The browser's successful linking is separate from registering the OAuth application.

- Implement the MCP authorization profile using reviewed OAuth components: protected-resource metadata, RFC 8414 issuer metadata, authorization code + S256 PKCE, resource/audience validation, exact redirect validation, single-use short-lived authorization codes, rotating refresh tokens with reuse handling and immediate connection revocation. Publish the declared tool security metadata required by each host. Keep downstream Dove tokens and Google's grant/tokens in separate stores and namespaces; never pass a Google token through to an agent.
- Support dynamic OAuth application registration for the clients' automatic-registration option, bounded and rate-limited. Registration has no mailbox authority. Client metadata and redirect changes never alter a mailbox grant. Supply a documented pre-registered client option. Pin and test one supported MCP protocol/auth version and record actual ChatGPT and Claude versions/settings. Follow their current identity/discovery requirements during implementation; unsupported modes fail explicitly.
- Public routes in addition to existing MCP/Google-callback/health paths: GET protected-resource metadata under `/.well-known/oauth-protected-resource`; GET `/.well-known/oauth-authorization-server`; GET/POST `/oauth/dove/authorize`; POST `/oauth/dove/token`, `/oauth/dove/register`, `/oauth/dove/revoke`; POST `/connect/redeem`. These routes expose only the scoped approval/registration/token workflow, with strict request limits, CSRF defenses for browser actions, no-store responses and no-referrer policy. Update the reverse proxy's explicit allowlist. Return a valid discovery challenge on unauthorized MCP requests.
- Persist invitation state, registered applications, authorization-code hashes/bindings and OAuth grant/token families transactionally. Refreshing cannot broaden the account/action intersection. Revoking a connection invalidates both its access and refresh tokens and associated cursors. Authentication changes are part of the audit and secret-redaction tests.

**Context behavior.** A linked host can retrieve authorized mail when its tools are enabled and invoked. Linking does not preload all mail into model context or guarantee background monitoring. Keep tool descriptions and default search results compact. Host plan/settings and conversation-level activation are validated in the compatibility guide.

## 6. Security

### 6.1 Assets and trust boundaries

Assets, most valuable first: Google refresh tokens (read and draft access to 25 mailboxes), the KEK, client tokens,
indexed mail content and metadata, mail in memory, and the audit log.

Boundaries: the internet to the reverse proxy; the proxy to Dove (localhost); Dove to Google APIs (outbound
HTTPS); the MCP client (an agent driven by a language model that reads untrusted mail) to Dove; the owner's CLI to
Dove (local socket).

### 6.2 Threat model

| Threat | Mitigation |
| --- | --- |
| Untrusted mail steers an agent toward disclosure or sending | Restrict reads and drafts per token and mailbox. Sending is off by default. An explicitly send-enabled token can be induced to use the permission it has; an email-content marker is not an approval boundary. |
| A client token leaks | Tokens are per client, scoped to one project and capabilities, optionally IP-bound and expiring. They can be revoked one by one. Use is logged with IP. Rate limits cap the volume of reads. |
| The state store file is copied | Grants are encrypted with keys that are not in the store (6.4). Client tokens are stored as keyed hashes only. |
| Search database copied or old rows retained | Encrypt the entire rebuildable index including FTS pages and WAL. Keep its key separate from the file, exclude the index from backups and gate queries on current mailbox authorization. |
| Agent invokes admin CLI through a shell | Check OS peer identity; deploy CLI, service credentials and configuration according to FR-C1. A token cannot bootstrap administration. |
| Running host compromised | Google tokens in the process may permit reading and sending; host compromise exceeds Dove's policy boundary. Use only the required Google scopes. |
| OAuth callback attacks (CSRF, code injection, account mix-up) | `state` bound to a pending connect record, single use, 10 minute expiry; PKCE (S256); identity check of the approving Google account; scope check (7.3). |
| DNS rebinding or browser-originated requests against the MCP endpoint | Bind to localhost behind the proxy; check `Host` against the configured public host; refuse requests that carry an `Origin` header not on the allowlist (empty by default), as the MCP transport specification requires. |
| Header injection in drafts | Reject CR and LF in every header-bound field; validate addresses with a strict RFC 5322 parser; encode non-ASCII as RFC 2047 or RFC 6532 correctly; build MIME with a maintained library. |
| Data leaks through logs | Structured logs with a redaction layer; never log bodies, subjects, tokens, codes, Authorization headers or query strings of the OAuth callback. A canary test checks it (section 11). |
| Enumeration of other projects' accounts | Identical `not_found` for "does not exist" and "not in your project". |
| Denial of service, quota exhaustion | Per-client rate limits, per-account concurrency limits, request size limits at the proxy and in the service, bounded fan-out. |
| Supply chain | Few dependencies, pinned versions with a lockfile, dependency audit in CI, container image from a pinned base digest. |
| Google grant stolen elsewhere (Google side) | Out of scope; the owner protects their Google accounts with 2-step verification. |

### 6.3 Optional sending

Default `allow_send=false`. The owner must enable it in local server configuration AND explicitly issue a `send` grant to one token for one named mailbox. The operator can keep a separate sending token. A global change never upgrades a read/draft token. The tool is absent if no effective send grant exists. A token with a send grant has standing permission on that mailbox while enabled; no per-message human confirmation is implied.

Only the typed Gmail operation `drafts.send` for an existing, project-owned draft is eligible. Recheck policy immediately before dispatch. Refuse non-owned drafts, externally changed drafts and unknown previous outcomes. No free-form send, batch or schedule. Outbound requests use fixed HTTPS origins, validated path segments, exact method/path matching and disabled redirects. Verify the conditional endpoint with a recording fake. Audit and rate-limit sends independently from reads.

Before a send, atomically persist its in-flight state on the owned draft. Concurrent requests and replay after a crash must never trigger a second submission. On confirmed success record the sent message ID. On lost response or restart with an unresolved send, mark the outcome unknown and block resubmission pending owner verification in Sent. A definitive pre-dispatch failure is safe to retry. No inference from absence in Drafts alone.


### 6.4 Secrets and encryption at rest

- KEK: 256-bit random key in a file readable only by the service user (`0400`), delivered through the platform's
  secret mechanism (for example systemd credentials or a container secret mount). Not in an environment variable,
  because environment variables leak into child processes and diagnostics. Not in the state store. Not in the
  repository. The KEK backup is kept apart from state store backups.
- DEK: one random key per account, used to encrypt that account's refresh token with an AEAD cipher
  (AES-256-GCM or XChaCha20-Poly1305) and a fresh random nonce per encryption. The DEK is stored wrapped by the KEK.
- Associated data binds each ciphertext to its context: `account_id`, record type and key version. A ciphertext
  copied to another account's row fails to decrypt.
- `dove keys rotate` creates a new KEK version and re-wraps all DEKs. The old version is removed after a
  successful re-wrap.
- Removing an account deletes its grant and DEK in current state and purges derived index rows. Prior encrypted state backups may still contain the wrapped DEK and grant; removal does not erase those backup copies. Google revocation independently invalidates access.
- The Google OAuth client secret is stored like the KEK (secret file), not in the configuration file.
- Access tokens live only in memory, with their expiry. They are never written to disk.
- Client tokens: format `dove_` + 32 random bytes in base64url. The prefix makes them easy for secret scanners to find.
  Stored as HMAC-SHA-256 with a server-side pepper from a secret file. Lookup by that hash, so no comparison leaks
  timing. Shown once at creation.
- Decrypted secrets are kept in memory no longer than needed. Process core dumps are disabled.

### 6.5 Untrusted mail content

Mail content is third-party input that will be read by a language model. Dove cannot make prompt injection
impossible, but it reduces what an injection can reach (6.3, project scoping) and makes content easier to treat as data:

- Every body, subject, sender name and snippet is returned inside a clearly delimited field of the structured result.
  The text rendering wraps it in an envelope such as `<untrusted_email_content account="…" message_id="…">…
  </untrusted_email_content>`, with any occurrence of the closing delimiter inside the content escaped.
- Both content items carry the marking in every protocol version. Every tool whose result can contain mail content
  (`get_message`, `get_thread`, `batch_read`, `search_messages`, `get_attachment`, `digest`, `search_contacts`,
  `list_drafts`, `get_draft`) adds the top-level field `untrusted_content_notice` (a fixed warning, declared in its
  `outputSchema`) to the structured result, because some hosts give the model only `structuredContent`. Clients
  before structured output (protocol versions before 2025-06-18, and every client that sends no
  `MCP-Protocol-Version`, which counts as 2025-03-26) get the structured JSON as the text item, inside the envelope.
- Each read tool's description states that returned content is untrusted data and that instructions inside it must not
  be followed.
- HTML to text: parse with a real HTML parser, drop `script`, `style`, `head`, comments and elements hidden by
  attributes or inline styles (`hidden`, `display:none`, `visibility:hidden`, zero font size, zero size), keep link
  text and show the URL in brackets, never fetch remote resources.
- Remove invisible Unicode that has no place in mail text (bidirectional overrides, tag characters, zero-width
  characters except where needed for scripts that use them). Normalise to NFC.
- Truncate to `max_body_chars` and report `body_truncated: true`.
- Dove never follows links, never downloads remote images and never opens attachments in version 1.

### 6.6 Network exposure

- The service listens on `127.0.0.1` only. A reverse proxy terminates TLS (TLS 1.2 or later, HSTS) and forwards only
  the MCP, Google callback, health and downstream connection/OAuth routes explicitly listed in §5.6. Everything else returns 404 at the proxy.
- Request body limit at the proxy and in the service (for example 1 MB; drafts with HTML stay well below).
- `/healthz` returns only "ok" or "degraded", no account names or counts.
- The OAuth callback only completes connect flows the CLI started (7.3). With no pending flow it returns a generic
  error page.
- Optional: an outbound firewall rule that allows the service user to reach only Google's OAuth and Gmail API hosts.

### 6.7 Audit log

- Append-only table or file, one record per tool call and per admin action: timestamp, request id, client name,
  project, tool, account alias, Gmail ids involved (message, thread, draft), result code, duration, result count,
  source IP.
- No content: no subjects, bodies, addresses or queries. Queries MAY be logged as a length and a keyed hash, so
  repeated identical queries can be spotted without storing their text.
- Each record carries the hash of the previous record for consistency verification with `dove audit verify`. A chain stored beside its records does not prove resistance to an attacker rewriting the entire database; that would require an independently retained trusted checkpoint. Retention pruning records the retained boundary.
- Retention: 180 days by default, configurable. Pruning is itself logged.

### 6.8 Privacy

The operator enables full-text indexing by mailbox. An enabled index stores searchable normalized mail text, subjects, visible participants, labels and MIME metadata locally. Server-side deletion propagates on sync. Document sync lag, local storage and removal procedures. Mail returned to a client may reach its model provider; projections control the fields delivered. Logs and audit records continue to exclude mail content.

## 7. Architecture

### 7.1 Components

```text
 MCP clients (agents)                    Owner's browser (connect flow only)
        │ HTTPS, Bearer client token              │ HTTPS
        ▼                                         ▼
 ┌──────────────────────── reverse proxy (TLS) ──────────────────────────┐
 │  /mcp            /oauth/google/callback            /healthz           │
 └───────┬──────────────────────┬────────────────────────────────────────┘
         ▼ 127.0.0.1            ▼
 ┌──────────────────────── Dove process ─────────────────────────────┐
 │ MCP transport ─► Client auth ─► Policy ─► Tool handlers               │
 │                                              │                        │
 │ OAuth connect handler        Provider layer (Google) ─► Outbound      │
 │                                   │            gateway (allowlist)    │
 │ Token manager (refresh, cache) ◄──┘                  │                │
 │ Vault (envelope encryption)                          │                │
 │ State store   Audit log   Rate limiter   Notifier    │                │
 │ Admin socket (local CLI)                             │                │
 └──────────────────────────────────────────────────────┼────────────────┘
                                                        ▼
                                  oauth2.googleapis.com, gmail.googleapis.com
```

- **MCP transport:** Streamable HTTP per the current MCP specification. Stateless mode is enough: no tool needs
  server-to-client requests or sessions. It negotiates protocol versions and supports older ones the main clients
  still use.
- **Client auth:** reads `Authorization: Bearer`, hashes the token, loads the client, checks expiry, revocation and IP
  allowlist. It runs before any MCP processing. Without a valid token it returns HTTP 401 with the OAuth discovery challenge (§5.6) and no account details.
- **Policy:** `authorize(client, capability, account?)` → allow or deny. It is the single place that decides. Every
  tool handler calls it before touching the provider. Denials are audited.
- **Tool handlers:** validate input against the tool's input schema, resolve the account alias within the project,
  call the provider, shape output, apply 6.5.
- **Gmail module:** concrete typed operations in the Rust service (7.8).
- **Outbound gateway:** the single HTTP client to Google with the method and path allowlist (6.3, 7.5), timeouts,
  retries with backoff, and quota handling.
- **Token manager:** per account, returns a valid access token. It refreshes ahead of expiry with single-flight per
  account (one refresh at a time, other callers wait for it). On `invalid_grant` it marks the account
  `reauth_required` and notifies the owner.
- **Vault:** encrypts and decrypts grants (6.4).
- **State store:** an embedded transactional database (for example SQLite in WAL mode) in a data directory owned by
  the service user, `0700`. One process writes it.
- **Notifier:** sends owner notifications for `reauth_required`, repeated upstream errors, a burst of denied calls or
  a client used from a new IP. Channel configurable (for example an HTTP webhook to ntfy, Slack or e-mail). Messages
  carry no mail content.
- **Admin socket:** Unix domain socket for the CLI (FR-C1).

### 7.2 Data model

```text
accounts(id PK, alias UNIQUE, email UNIQUE, display_name, status, granted_scopes, google_sub,
         connected_at, last_used_at, last_error_code, last_error_at)
grants(account_id PK FK, dek_wrapped, kek_version, refresh_token_ciphertext, nonce, created_at, rotated_at)
projects(id PK, name UNIQUE, created_at)
project_accounts(project_id FK, account_id FK, PRIMARY KEY(project_id, account_id))
clients(id PK, name UNIQUE, project_id FK, token_hash UNIQUE, allowed_cidrs,
        expires_at, revoked_at, created_at, last_used_at, last_ip)
client_mailboxes(client_id FK, account_id FK, actions, PRIMARY KEY(client_id, account_id))
pending_connects(state_hash PK, account_alias, expected_email, pkce_verifier_ciphertext, mode(connect|reconnect),
                 created_at, expires_at, used_at)
own_drafts(account_id FK, draft_id, message_id, thread_id, project_id FK, client_id FK, created_at, updated_at,
           state, sent_message_id, PRIMARY KEY(account_id, draft_id))
-- Cursor state is bounded and in memory only.
-- Derived search storage and synchronization checkpoints are specified in §7.9.
audit(seq PK, ts, prev_hash, hash, request_id, actor, project, tool_or_action, account_alias,
      object_ids, result_code, duration_ms, result_count, source_ip)
create_operations(client_id FK, account_id FK, request_key, input_hash, state, result_ids,
                  PRIMARY KEY(client_id, account_id, request_key))
meta(key PK, value)   -- schema version, KEK version, pepper version
```

`google_sub` (the stable Google user id from the ID token) protects against an email address later pointing to a
different Google identity. A reconnect MUST match the stored `google_sub`.

### 7.3 Flow: connecting an account

1. The owner runs `dove accounts connect --alias work-info --email info@example.com`.
2. The CLI asks the service to create a pending connect: a random `state` (stored only as a hash), a PKCE verifier
   (stored encrypted), the expected email, an expiry of 10 minutes.
3. The CLI prints the Google authorization URL:
   `response_type=code`, `client_id`, `redirect_uri=https://<public-host>/oauth/google/callback`,
   `scope=openid email https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.compose`,
   `access_type=offline`, `prompt=consent` (so Google returns a refresh token), `login_hint=<email>`, `state`,
   `code_challenge`, `code_challenge_method=S256`. No `include_granted_scopes`.
4. The owner opens it, signs in, sees Google's warning for an unverified app (section 9), and approves.
5. Callback: the service looks up the pending connect by the hash of `state`, rejects it if missing, expired or used,
   and marks it used before anything else (single use even on failure). It handles `error=access_denied` with a plain
   page.
6. It exchanges the code with the PKCE verifier and the client secret.
7. It validates the ID token (signature against Google's keys, `iss`, `aud` = client id, `exp`), requires
   `email_verified = true` and `email` equal to the expected email (case-insensitive), and for a reconnect `sub` equal
   to the stored `google_sub`.
8. It checks the granted scopes in the token response. Google lets users untick individual scopes. If `gmail.readonly`
   or `gmail.compose` is missing, discard the candidate credentials locally and report the missing scope. Do not invoke revocation as cleanup.
9. Require a usable offline refresh token, exercise one refresh, and check the Gmail profile with the refreshed access token.
10. It encrypts and stores the refresh token, sets the account `active` and shows a page that names the account and
    tells the owner to close the tab. The page contains no token. The callback response sets
    `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
11. On reconnect, commit the verified grant and status together, evict old cached access tokens and discard old credentials locally. A late refresh for the prior grant generation must not change the new account state. Reserve Google revocation for explicit removal; it can invalidate other tokens for that user and Google Cloud project.

### 7.4 Flow: a tool call

1. Proxy → service. Client auth (7.1). Rate limit check per client.
2. MCP request parsing and input schema validation.
3. Resolve explicit accounts against project membership and client mailbox grants. Unknown or outside the intersection → `not_found`.
4. `authorize(client, capability, account)`.
5. Token manager → access token. Provider call through the outbound gateway.
6. Output shaping, untrusted envelope, size limits.
7. Audit record, response.

### 7.5 Google API usage and allowlist

Use the Gmail REST API, not IMAP. IMAP would need the full `https://mail.google.com/` scope, which also allows
permanent deletion and everything else. The REST API works with the narrower `gmail.readonly` and `gmail.compose`,
has native drafts tied to threads, Gmail's own search syntax and stable ids, and needs no long-lived connections.

Outbound allowlist (method, path pattern under `https://gmail.googleapis.com/gmail/v1/users/me/`):

| Method | Path | Used by |
| --- | --- | --- |
| GET | `profile` | connect, `accounts check` |
| GET | `messages` | initial enumeration and live Gmail search |
| GET | `messages/{id}` | index sync, live search hydration and detail reads |
| GET | `history` | paged incremental index sync |
| GET | `threads/{id}` | `get_thread` |
| GET | `labels` | `list_labels` |
| GET | `drafts`, `drafts/{id}` | `list_drafts`, `get_draft` |
| POST | `drafts` | `create_draft` |
| PUT | `drafts/{id}` | `update_draft` |
| POST | `drafts/send` | Only through the separately gated `send_draft` operation (§6.3). |
| GET | `settings/sendAs` | Validate `from_address`; `gmail.readonly` is accepted. |
| POST | `messages/{id}/modify` | `update_messages`, `move_messages` (labels, archive, inbox, spam); needs `gmail.modify` |
| POST | `messages/batchModify` | Allowlisted for bulk label changes (the tools currently send per-message `modify`) |
| POST | `messages/{id}/trash` | `move_messages` to `trash` (needs `delete`), `delete_draft` |
| POST | `messages/{id}/untrash` | `move_messages` out of Trash |
| POST | `threads/{id}/modify` | Allowlisted for thread-level label changes (not used by the tools yet) |

There is no `DELETE` and no `batchDelete`: Dove cannot delete permanently. Since 0.2, connects request `gmail.modify`
as well (optional at the consent screen; without it organize/delete answer `account_unavailable` with
`reason: reauth_required` until `dove accounts reconnect`).

Plus `POST https://oauth2.googleapis.com/token` (code exchange, refresh) and
`POST https://oauth2.googleapis.com/revoke`, and Google's public keys for ID token validation.

The only other outbound destination is `POST` to the exact URLs (scheme, host, port, path) of the operator's webhook
sinks (`dove sinks add`, watch push delivery, design 0.2 section 3). The gateway's sink allowlist is rebuilt from the
state store whenever a sink is added or removed; agents name sinks but never supply URLs.

Explicitly denied: every other send route, `messages` with POST, `messages/import`,
`messages/{id}/trash`, `messages/{id}/modify`, `messages/batchModify`, `messages/batchDelete`, DELETE on messages or
threads, `threads/{id}/modify`, `threads/{id}/trash`, anything under `settings/` except the one GET above, `watch`,
`stop`.

MCP batching (§5.3) combines independent agent reads. V1 executes authorized upstream reads through the existing pooled client with bounded concurrency. No multipart Gmail batch route is needed; Gmail charges the enclosed calls individually.

### 7.6 Draft construction

- Build an RFC 5322 message with a maintained MIME library: `From` (account address, or a validated send-as address),
  `To`, `Cc`, `Bcc`, `Subject`, `Date`, a new `Message-ID` on the account's domain, `MIME-Version`, and for replies
  `In-Reply-To` and `References`.
- Agent-authored drafts use `text/plain; charset=utf-8`. Reading HTML mail remains supported (§6.5).
- Encode as base64url in the `raw` field. Pass `threadId` for replies.
- Limits: at most 50 recipients in total, subject at most 998 bytes encoded, body at most 500 KB, at most 10
  attachments and `limits.draft_attachment_bytes` (default 10 MiB, at most 16 MiB) decoded attachment bytes. With
  attachments the draft is `multipart/mixed`: the text/plain body, then one base64 leaf per attachment with
  `Content-Disposition: attachment` and an RFC 2231 filename. No HTML authoring.
- Request bodies: `limits.body_bytes` (default 1 MiB) for every request, except `/mcp` requests of an authenticated
  client with `draft` on some mailbox, which get `draft_attachment_bytes` × 4/3 + 2 MiB for inline attachments. The
  `/mcp` body is read only after authentication.
- Gmail does not add the account's signature to drafts created through the API. Version 1 leaves the signature to the
  agent's text. Phase 2 MAY append the send-as signature when it can be read with the granted scopes.

### 7.7 Rate limits, quotas, retries

- Pool one asynchronous HTTP client across requests. Default starting bounds: 16 total in-flight Gmail requests per instance, 4 per mailbox, 8 mailbox searches concurrently. These are tunables; list and detail calls share the same budgets. Reserve capacity for interactive draft and read operations so a broad search cannot occupy every slot.
- Failed bearer authentication on `/mcp` is limited per client address (IPv6 by /64, `limits.auth_failures_per_minute`, default 60): an address that used up its budget gets 429 with `Retry-After` before any token lookup. Successful requests and requests without a token are not counted, so hosts that share egress addresses are not starved by normal use; while an address is over its budget, valid tokens from it get 429 too (the check runs before the lookup). Loopback and unresolved addresses are not limited, since they stand for every caller behind Tailscale Serve or in local mode.
- Apply per-client request limits and a separate upstream call/quota budget per search. Charge actual upstream work, including retries. Honour rate limits and Retry-After; retry transient idempotent reads with jitter within the time budget. Bound both queue depth and deadline. Cancel unused work on client disconnect; finish recording any dispatched writes.
- Indexed search, sort, projection and pagination execute locally. Coalesce live Gmail reads by mailbox and message, and use fresh reads for draft mutations. Background backfill yields to foreground traffic and obeys shared per-mailbox and instance quotas.
- Default time budgets for live calls: 10 s per upstream request, 30 s hard limit per tool call. Bound local SQL execution by query deadline and cancellation. Never hold a cursor transaction open between MCP calls.
- No automatic replay of a dispatched create, update or send. A timeout or uncertain persistence after Google success returns `outcome_unknown`. On create, inspect the mailbox's server Drafts in Apple Mail or Gmail. The default owned-draft list can miss an orphan. On update reread the server draft; on send follow §6.3.

### 7.8 Rust implementation

One Cargo package and one `dove` binary with service and local CLI subcommands. Use Tokio, `rmcp` (Streamable HTTP), a shared HTTP client and SQLite in WAL mode. Keep authorization, Gmail operations, draft construction, search scheduling and storage in small internal modules. SQLite transactions finish before awaiting network I/O. Keep synchronous database work off Tokio's executor threads. Introduce a cross-provider trait when a second provider has a concrete implementation.

### 7.9 Search index and sync

**Storage and lifecycle.** One rebuildable SQLCipher database with FTS5, hosted in the same Rust process. Keep the durable grants and admin state in their existing store. At startup verify SQLCipher, the correct independent index key, FTS5 and memory-only temp storage; refuse plaintext fallback. Restrict files to the service identity. Indexing is an explicit local operator choice per mailbox: `dove index enable|disable|status|rebuild <alias>`. Disabled is the default until enabled; the live Gmail mode works immediately. The initial policy is full mailbox history on enabled accounts, including spam/trash for opted-in queries. Give recent mail a bounded priority pass, then enumerate all pages. Until full coverage is established, expose partial results.

**Data.** Store mailbox ID + provider message ID as a unique key, thread ID, Gmail internalDate, size estimate, normalized visible address roles and domains, subject, sanitized searchable body, label IDs and attachment names/types. Use ordinary compound B-tree indexes for mailbox/date, participant/domain, labels and common filter/order pairs. FTS5 indexes the subject, the normalized body and the extracted attachment text (three columns; generations created before 0.2 keep two and serve until their mailbox rebuilds) using unicode61. Each message also stores its category (§5.3a) and whether every supported attachment was read. Keep one text source for FTS, with FTS and metadata updates in the same transaction. No raw MIME or attachment binaries in the persistent index. Attachment text is extracted while the message is ingested, from bytes already in memory: PDF (lopdf, no heavy features), DOCX and ODT (a hand-written bounded ZIP and XML reader), text and CSV. Extraction is bounded by `index.attachment_text_max_bytes` per attachment, `attachment_text_max_chars` of text per message, a wall-clock budget, a decompression cap that does not trust the archive's declared sizes, no entity expansion, page and stream limits for PDF, and panic containment. Failure of any kind leaves the message indexed with its attachments marked unread. MIME parsing has per-message byte, nesting and text limits. If body text exceeds limits or is unavailable, record incomplete content coverage so a body query cannot claim exact absence. MIME metadata that could not be extracted is marked unknown. Missing optional headers alone do not imply incomplete indexing.

**Full and incremental sync.**
1. Capture the account's current Gmail history ID before enumeration. Backfill into a fresh generation in bounded pages, with durable progress and idempotent upserts. Restart or replay safely; restart enumeration if its page token is invalid. Reconcile arrivals, label changes and deletions since the starting ID with history.list before publishing complete. A GET returning 404 for a vanished message removes that candidate. Record skipped/transiently failed messages for retry.
2. Poll history.list from the committed checkpoint (initial default 60 s with jitter, adaptive backoff on quota limits). Coalesce repeated IDs and fetch canonical state for changed messages as necessary. Advance the mailbox checkpoint only after all pages through that history ID and their derived writes have committed; a crash can repeat work without losing changes. History IDs are opaque progress markers; do not increment them. Record last successful check even when nothing changed.
3. If history.list returns 404 for an expired history ID, mark rebuilding, invalidate cursors and start full reconciliation. Do not serve the prior generation as complete. Keep partial/generation state explicit and delete retired generations after cutover. On revocation or admin disable, block reads immediately on known status; index disable also cancels and fences ongoing jobs, purges that mailbox's derived rows/FTS postings and invalidates cursors. Account removal does the same even if network revocation is delayed. A stale job cannot repopulate a removed account. Rights changes take effect without rebuilding.
4. The mailbox is authoritative. Draft update/send always use fresh Gmail data. A successful Dove write wakes incremental sync; callers needing immediate read-after-write use the returned draft ref and live get_draft. Bound sync concurrency, bytes, disk and CPU. Disk-full pauses sync and reports stale status; it must not prevent live reads, drafts or admin revocation.

**Query planning.** Compile the typed request into parameterized SQL. Derive eligible mailbox IDs before evaluating predicates, counts, ranking or paging. Intersect with current grants on every source including batch/cursor paths. Use keyset seeks and bounded projections. Avoid FTS on date/address-only paths or opening body text to answer a subjects-only metadata query. A search holding a SQL read transaction sees one committed index state; between pages it follows the live-cursor contract (§5.3). Use representative fixtures and EXPLAIN QUERY PLAN to verify hot paths. No second search process is required.


## 8. Non-functional requirements

### 8.1 Performance

- Warm indexed structured top-20 across 25 mailboxes: initial p95 target ≤100 ms at the service; FTS + filters + date order: ≤250 ms. Measure end-to-end MCP latency separately. Zero Gmail calls per indexed search on a ready index, including first page, count and projection. Full recounts and wide-prefix FTS have bounded runtime and may return `query_too_broad`. These targets are unverified until measured on declared reference hardware.
- Use 1, 5 and 25 accounts, at least 250k messages total, varied body lengths, skewed senders, large label sets and frequent and rare search terms. Measure cold/warm results, during backfill, during steady polling and under concurrent foreground reads. Report p50/p95, exact input/output bytes, tool calls, disk size, RSS and CPU, index build time, sync lag and provider quota units. Measure coverage and response bytes of subject-only vs default vs detail.
- Live Gmail escape hatch retains a target of ≤2 s to first useful partial result and ≤5 s to full mailbox participation on the defined fixture (25 responding accounts, 20 hits under normal upstream latency). Indexed and live timings are reported separately. Warm single-message live read target ≤1.5 s. Baseline RSS target <256 MiB under a documented steady workload; report peak backfill RSS separately.

### 8.1a Memory budget

Reference deployment starts with a 512 MiB service/container limit. The <256 MiB steady RSS goal is provisional and must be verified with SQLCipher, realistic messages, active clients and sync. Allow a 1 GiB deployment profile for larger workloads or aggressive backfill. The index is disk-backed and must not be copied into RAM.

- Index connection pool: 1 writer plus at most 3 readers. Start each with an 8 MiB suggested SQLite page-cache budget (32 MiB aggregate suggestions). Account separately for the small durable-state pool. Page-cache settings are not a cap on SQL temporaries, Rust buffers or the whole process.
- Admit at most 2 body-fetch/parse jobs concurrently by default. Reserve up to 32 MiB per job across encoded input, decoded text, parser structures and SQL staging. Stream and count input before allocating; reject/defer oversized or over-complex messages with explicit incomplete coverage. Do not multiply parser jobs by the 25 mailboxes. Byte-bound ingest queues before fetching the next page.
- All cursor payloads together are capped at 8 MiB and 1,000 live cursors. Eviction returns cursor_invalid. Read batches and outgoing detail buffers share a bounded allocation budget (initial 16 MiB). Response byte budgets apply to standalone tools too, including both structured and textual encodings.
- Memory-only SQL temporary storage preserves plaintext privacy but needs bounded query concurrency and a verified SQL allocator limit (initial 96 MiB total for the index library, including its page caches). Abort on SQL memory exhaustion as budget_exceeded, pause backfill and retain admin/foreground headroom. This limit does not cover Rust or system allocations. FTS merge and rebuild work share the admission budget. Tune only after peak-RSS and container-memory measurements.
- Record RSS and total container memory during backfill, broad FTS sorts, stalled consumers and concurrent batches. Container memory can include filesystem cache beyond process RSS. A query deadline alone does not bound its peak allocations.

### 8.2 Reliability

- Survives restarts with no loss of grants, projects, clients or own-draft records.
- Google outages or one broken account degrade only the affected calls (`account_errors`).
- Graceful shutdown: finish in-flight requests up to 10 seconds.

### 8.3 Observability

- Structured JSON logs with request id, client name, tool, account alias, duration, result code, upstream status. No
  content (6.2).
- Metrics endpoint MAY exist but only on localhost: request counts and latency by tool and result, token refreshes,
  upstream errors by code, accounts by status.

### 8.4 Configuration

Non-secret settings in one configuration file: public base URL, listen address, allowed origins, rate limits, body
limits, `allow_send` (default false), search deadlines, audit retention, notifier settings and paths to secret files. Secrets only as file paths (6.4). The service
refuses to start when a secret file is readable by group or others, when the public URL is not HTTPS, or when the KEK
is missing.

## 9. Google Cloud setup (owner, once)

1. Create a Google Cloud project, for example `dove-<owner>`, under the owner's own Google account.
2. Enable the Gmail API.
3. Google Auth Platform → Branding: app name, support email, no logo (a logo triggers brand verification).
4. Audience: user type **External** (needed for personal `@gmail.com` accounts and for Workspace domains other than
   the one owning the project). Set the publishing status to **In production**. While the app is in Testing, Google
   expires refresh tokens after 7 days, which would break the service every week.
5. Data access: add the scopes `openid`, `email`, `gmail.readonly`, `gmail.compose`. Both Gmail scopes are
   restricted. Do not submit the app for verification. A personal-use app stays unverified: users see a "Google
   hasn't verified this app" warning and continue through "Advanced". An unverified app is limited to 100 users over
   the project's lifetime, which is enough for about 25 mailboxes.
6. Clients: create an OAuth client of type **Web application** with exactly one authorised redirect URI,
   `https://<public-host>/oauth/google/callback`. Store the client secret in the secret file (6.4).
7. For mailboxes in a Google Workspace domain: the domain's admin may block unverified third-party apps. In the Admin
   console → Security → API controls → App access control, mark the OAuth client id as trusted for that domain.
8. Confirm during implementation, with one real account, that an unverified production app can obtain a long-lived
   refresh token for the restricted scopes, and record the result. If Google refuses, the fallbacks are:
   (a) one Google Cloud project per Workspace domain with user type Internal (no verification and no warning, but only
   for that domain's users), or (b) for personal Gmail accounts, an IMAP provider with an app password in phase 3.

Domain-wide delegation with a service account (Workspace only) was considered and rejected for version 1: one key
could read every mailbox in the domain, not only the connected ones.

Refresh tokens can still stop working: unused for 6 months, the user changes their password (Gmail scopes are
revoked), the user removes access in their Google account, a Workspace admin policy, or too many tokens for one user
and client (the oldest is revoked). All of these end as `invalid_grant` → `reauth_required` → notification.

## 10. Deployment

- One container or one systemd service, single instance. It runs as a dedicated non-root user and holds no Linux
  capabilities. The root filesystem is read-only except the data directory and the socket directory, and
  `no-new-privileges` is set. Memory and CPU limits are set.
- Reverse proxy (Caddy or nginx) with automatic TLS on a dedicated hostname such as `dove.<owner-domain>`. It
  forwards only the explicitly allowed routes from 6.6 and 5.6.
- Back up durable state daily, encrypted. Keep KEK and pepper backups separately and offline. Exclude the rebuildable search database, WAL and temp data from backups and deployment artifacts. Restore starts a fresh index before claiming coverage. Keep the index key in a service credential separate from the index files. Document physical page/WAL reclamation separately from logical removal; no claim of immediate secure erasure from filesystem snapshots.
- Upgrades: schema migrations are versioned and run at startup inside a transaction. A failed migration stops startup
  and leaves the store untouched.
- Clients connect with, for example,
  `claude mcp add --transport http dove https://dove.<owner-domain>/mcp --header "Authorization: Bearer dove_…"`.

## 11. Verification

Unit and integration tests run against a fake Google server that implements the allowlisted endpoints and records
every request. The fake server MUST fail the test on any request outside the allowlist. One manual end-to-end check
runs against a real test Google account before release.

Acceptance criteria:

1. **Intersected grants.** A token with `info=read,draft` and `billing=read` can search both, draft only in info, and cannot discover a third project account by ID, cursor, cache, errors or default lists. Newly added accounts are invisible until granted. Remove/re-add revokes old access. Recheck before returning resumed search results.
2. **Capabilities.** Reject direct tool calls that the token cannot perform even when discovery is bypassed.
3. **Send gates.** Test every combination of instance flag, mailbox grant, project membership and ownership. Only the fully allowed case may hit the typed drafts.send route. On duplicate or concurrent requests, lost response or process death there is at most one Dove submission of the draft. Use fake upstream for all sends in automated tests.
4. **Draft iterations.** Create, revise twice, confirm one draft remains and recipient, untouched fields and reply headers survive. Reject stale revisions, other projects' drafts, unsupported MIME, and draft ID replacement. Concurrent Dove edits from the same revision yield one winner.
5. **Apple Mail release check.** With an operator-controlled Google test mailbox configured for server drafts on macOS, create and revise a threaded reply via MCP; verify subject, recipients and latest text in Apple Mail. Edit and save there, wait for server sync, then request a stale agent edit: expect conflict or not_found and preservation of the human edit. Manually send to a controlled recipient and verify the received content, threading, and subsequent missing draft in Dove. Record versions, server draft mapping and observed ID behavior. Treat this as a release gate.
6. **Header injection.** CR or LF in `subject`, display names or addresses is rejected with `invalid_argument`.
7. **OAuth callback.** These are each rejected without storing anything: unknown state, reused state, expired state,
   mismatched email, unverified email, a different `sub` on reconnect, a missing scope or wrong audience. A successful reconnect survives token refresh and restart. Neither successful reconnect nor rejected scope triggers revocation.
8. **Encryption at rest.** After connecting a fake account with a known refresh token, a byte search of the state
   store file and its WAL does not find the token. Moving a grant row to another account makes decryption fail.
9. **Log hygiene.** A test run with canary values in bodies, subjects, tokens and codes finds none of them in the logs
   or the audit log.
10. **Token lifecycle.** A refresh returning `invalid_grant` sets `reauth_required`, sends a notification once (not
    once per call) and makes tools return `account_unavailable`. A reconnect restores `active`.
11. **Client tokens.** A revoked, rotated-away, expired or wrong-IP token gets 401. A rotated token works immediately.
12. **Untrusted content.** A message with hidden HTML text, a fake closing delimiter and bidirectional override
    characters comes back without the hidden text, with the delimiter escaped and without the override characters.
13. **Transport.** A request with a disallowed `Origin` or a wrong `Host` is refused. The service does not listen on
    any non-loopback address.
14. **Partial failure.** A search across three accounts where one is `reauth_required` returns the other two
    accounts' results plus one `account_errors` entry.
15. **Startup checks.** The service refuses to start with a world-readable secret file, a missing KEK or an HTTP
    public URL.
16. **Audit.** Every tool call and admin action creates exactly one record. `audit verify` detects an edited record.
17. **Search contract.** Across partially overlapping authorized accounts, check AND/OR/NOT precedence, time zone boundaries, exact domain vs subdomain, phrases, suffixes, hidden Bcc, stable timestamp ties, newest/oldest ordering, opt-in counts, unknown fields, and partial results. Match results against a reference fixture including duplicate subjects. A subject-only query returns no IDs, snippets or bodies. On stable data, pages have no duplicates or gaps. Changed, revoked and expired cursors follow §5.3.
18. **Unknown write.** Force a response loss after each upstream mutation and a crash before local commit. Verify the caller's recovery path; no automatic duplicate creation, submission or unacknowledged recreation of a missing draft.
19. **Agent shell.** Using the actual runtime UID for an agent with a draft-only token, attempt the supported admin command to add send, change the instance flag or mint a stronger token. Verify all fail without changing state. Repeat with a local copy of the CLI and through MCP. Run a positive operator-UID test separately. Verify the agent cannot access production service credentials, deployment files or admin socket through shared mounts.
20. **Index integrity and privacy.** Fixtures include arrival during backfill, label removal, deletion, concurrent generation change, history expiration, restart before checkpoint, revoked access and disk-full. Check sanitized body & metadata canaries in query results, their absence in plaintext DB/WAL/temp files and logs, and disappearance from filtered rows/counts after purge. A remote history gap cannot produce a complete negative answer. Missing body/MIME coverage affects only queries that use that field in filters or projections; metadata-only queries can still be complete. Test negated text predicates against truncated bodies, not just positive matches.
21. **Batching.** Mix a permitted read, denied reference, duplicate read, oversized body and a timeout. Assert input ordering, per-item stable outcomes, authorization, bounded bytes, and no repeated upstream work for duplicate reads. Verify stale cursors and unsupported fields fail explicitly.


22. **Client onboarding.** On clean supported computers, install the release binary, redeem an invite, perform a successful read, configure Claude Code/Codex and invoke the same read through MCP. Time active setup against the 60 s target. No extra runtime dependency. Preserve existing MCP entries and project secret hygiene. Try expired/reused invites, concurrent redemption and scope escalation. Confirm all-mail expands once and later additions remain inaccessible.
23. **Web OAuth compatibility.** In real ChatGPT and Claude hosts, connect, approve only the prepared grants, read a mailbox, create and revise a draft with a draft-enabled connection, renew access after expiry, revoke and verify both token types cease working. Repeat with read-only permissions and two isolated projects. Verify DCR alone creates no access and guessed project/mailbox identifiers disclose nothing. Keep failed, unsupported or plan-blocked checks visible.

## 12. Phases

1. **Version 1:** Rust/Gmail, token-scoped access, encrypted opt-in FTS5 index, typed search, read batching, iterative drafts, Apple Mail handoff and owner-controlled optional sending. Implementation order: first the OS/grant boundary and draft flow, then scoped client onboarding/CLI/OAuth, then mailbox sync and index, then query/batch contracts and measured tuning.
2. **Phase 2:** attachment text for safe types (text, CSV, PDF text extracted in a sandboxed process with size and
   time limits) and signatures.
3. **Phase 3:** a Microsoft Graph provider (Microsoft 365 and Outlook.com, OAuth via Entra ID, scopes `Mail.Read`
   and `Mail.ReadWrite` for drafts) and a generic IMAP provider (app passwords, drafts via APPEND to the `\Drafts`
   special-use folder). Design the shared interface at that point. An `organize` capability (label, archive) MAY come here, behind
   its own scope review.


## 13. Decisions left to the owner

1. Public hostname for Dove.
2. Which accounts are personal `@gmail.com` and which are Workspace, and for each Workspace domain whether the owner
   can mark the client id as trusted (9.7).
3. Initial projects and which accounts each contains.
4. Notification channel.
5. Default audit retention (proposed 180 days).
6. Initial ChatGPT/Claude compatibility test accounts and the host settings required to connect.
7. Licence for the public repository: Apache-2.0 (decided 2026-11-13, `LICENSE`).
8. Names: the project is called Dove. The repository is `github.com/dominik-lenhart/dove` and the container image
   `ghcr.io/dominik-lenhart/dove` (decided 2026-11-13); the Rust package stays `dove-mcp`, and `dove-mcp` remains the
   name for npm or PyPI packages should there ever be any (plain `dove` is taken on npm). The binary, the CLI and the MCP server name are `dove`. Client tokens
   start with `dove_`. The name nods to the messenger dove and to Dovecot; Dove has no relation to the Dovecot project,
   and the README says so.

## 13a. Open-source hygiene

- A `SECURITY.md` with a private reporting channel, and a threat-model section in the README that repeats section 6
  in short form, including what Dove does not protect against (a compromised host, 6.2).
- Document Google's compose scope, both send gates, the implications of giving a token standing send permission, and Apple Mail's sequential editing contract.
- No telemetry. The service (`dove serve`) never checks for updates or calls anything but the mail providers and
  the configured webhook (7.5). The CLI may check for a new release (amended 2026-11-13, owner decision): at most once
  per day, only from an interactive terminal, one unauthenticated GET to the GitHub releases API that carries nothing
  but the CLI version in its User-Agent, off with `DOVE_NO_UPDATE_CHECK=1` and under `CI`. Its result is a one-line
  hint on stderr; it never changes a command's output or exit code.
- Signed releases with build provenance: minisign signatures over `SHA256SUMS` (public key in
  `deploy/release/minisign.pub` and built into the binary) and GitHub artifact attestations. `dove upgrade` installs a
  release only after verifying that signature, and replaces the binary atomically. The container image runs as
  non-root by default.
- Example configuration with no real hostnames, ids or secrets. CI scans for secrets.

## 14. References

- Gmail API scopes and their classification: https://developers.google.com/workspace/gmail/api/auth/scopes
- Google OAuth 2.0 for web server applications: https://developers.google.com/identity/protocols/oauth2/web-server
- Unverified apps and the user cap: https://support.google.com/cloud/answer/7454865
- Google refresh token expiry: https://developers.google.com/identity/protocols/oauth2#expiration
- MCP specification (transports, authorization, tools): https://modelcontextprotocol.io/specification
- OAuth 2.0 Security Best Current Practice: RFC 9700. PKCE: RFC 7636.
- Gmail draft lifecycle and threading: https://developers.google.com/workspace/gmail/api/guides/drafts and https://developers.google.com/workspace/gmail/api/guides/threads
- Gmail search results, quotas and send endpoint: https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/list, https://developers.google.com/workspace/gmail/api/reference/quota and https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.drafts/send
- Apple Mail server drafts: https://support.apple.com/de-de/guide/mail/cpmlprefacctmbox/mac
- Gmail sync, native filtering and batch semantics: https://developers.google.com/workspace/gmail/api/guides/sync, https://developers.google.com/workspace/gmail/api/guides/filtering and https://developers.google.com/workspace/gmail/api/guides/batch
- Search and index encryption: https://www.sqlite.org/fts5.html and https://www.zetetic.net/sqlcipher/design/
- Unix peer credentials on Linux: https://man7.org/linux/man-pages/man7/unix.7.html
- Rust MCP SDK: https://github.com/modelcontextprotocol/rust-sdk
- Prior art reviewed: EmailEngine MCP (https://learn.emailengine.app/docs/mcp), Annseraf/mcp-mail (per-client
  presets and account scope), codefuturist/email-mcp.
- Downstream OAuth compatibility references: https://developers.openai.com/apps-sdk/build/auth, https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp and https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
