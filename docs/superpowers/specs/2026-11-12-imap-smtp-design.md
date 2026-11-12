# IMAP/SMTP provider and attachment reads: design

Status: draft for owner review, 2026-11-12. Amends `docs/spec.md` (draft 0.5) where noted.

## Intent

Most of the owner's mail (about 80 %) lives in ordinary IMAP/SMTP mailboxes with password login (Strato, iCloud with an
app-specific password, and similar), not in Gmail. Dove is useless for those today: v1 speaks only the Gmail API, and
the spec defers IMAP to phase 3 (spec 12, N8). This change makes a generic IMAP/SMTP provider a core provider on equal
footing with Gmail, so an agent can work with these mailboxes the way a mail client does, over the same MCP tools.

The owner's typical requests, which define success:

- "Read through all my mail and tell me what is new." (search over all connected mailboxes by date and unread state)
- "Read the new message from Daniel." (search, then a detail read)
- "Import the files from the last mail here." (attachment bytes delivered to the agent)
- "Draft a message from my iCloud address to my teacher." (draft in that account's Drafts folder, visible in Apple Mail)
- Filtering and searching in general. Drafts and search matter most.
- Sending stays possible behind the existing two gates (instance `allow_send`, per-token `send` grant), both off by
  default. Drafts are the normal path; the human presses send in their mail client.

## Goals

1. Connect an IMAP/SMTP mailbox with a password, verified before anything is stored.
2. The existing tools work for IMAP accounts with the same contract and the same security invariants: `get_message`,
   `get_thread`, `list_labels`, `list_drafts`, `get_draft`, `create_draft`, `update_draft`, `send_draft`,
   `batch_read`, `search_messages`.
3. Search over IMAP accounts uses the existing encrypted index (generations, fencing, cursors unchanged).
4. A new read tool returns attachment bytes, for Gmail and IMAP accounts alike.
5. One mixed project can hold Gmail and IMAP mailboxes; an agent does not need to know which is which beyond
   provider-specific options.

## Non-goals

- OAuth/XOAUTH2 login for IMAP (Microsoft 365, Yahoo). Password and app-password login only.
- POP3, Exchange/EWS, JMAP.
- IMAP IDLE push. Polling is enough for now.
- Moving, deleting, flagging or marking messages read, folder management. Dove still never changes a human's mail.
- Attachments in outgoing drafts. (Reversed on owner request 2026-11-12, see the addendum at the end.)
- Attachment text extraction for search (still spec phase 2).
- Autodiscovery over the network (DNS SRV, Mozilla ISPDB lookups). Presets are compiled in.

## Anti-goals (a failure even if everything else works)

- The mailbox password reaches an agent, a log line, the audit log, a process argument list, an environment
  variable, or the plaintext state store.
- An agent can cause any mailbox change other than creating, replacing, and (after send) removing Dove's own drafts,
  and submitting a send it was allowed to send.
- A send is retried after an unknown outcome, or a draft is sent twice.
- A connection without verified TLS, a STARTTLS downgrade, or a password sent before TLS is up.
- Attachment bytes become trusted input: executed, rendered, or written anywhere by Dove itself.

## Constraints and spec amendments

- **G5 / N8 / 7.5 / phase 3:** reversed. Dove now stores mailbox passwords (encrypted) and supports a second provider.
  Spec 7.8 already says to introduce the cross-provider interface once a second provider exists; this is that point.
- **N4 / 5.2 "attachment content is not returned in v1":** reversed for reading. Attachment bytes may be returned by
  the new tool under the limits below. Dove still never opens, renders or extracts attachments.
- **N2 (no deleting):** restated: Dove deletes only messages it can prove are its own drafts (the `own_drafts` record
  and a fresh content check), in the Drafts folder, as part of replacing or sending that draft. Nothing else.
- All existing invariants in AGENTS.md hold unchanged: one authorization point, one audit record per tool call,
  identical `not_found`, no content in logs or audit, no SQLite transaction across network I/O, secrets from files or
  the vault only.
- The outbound allowlist (spec 6.6) is extended, not weakened: Gmail keeps its HTTP allowlist; IMAP/SMTP traffic goes
  only to the host and port stored for that account, and only with the command set listed below.
- TLS: rustls 0.23 via tokio-rustls, the stack reqwest already uses. No native-tls, no second OpenSSL TLS path.
  Certificates are verified against the platform roots. No option to disable verification in release builds.

## Decided

### Account model and connect

- `accounts` gains a `provider` column (`gmail` | `imap`) and, for IMAP, `imap_host`, `imap_port`, `imap_tls`
  (`implicit` | `starttls`), `smtp_host`, `smtp_port`, `smtp_tls`, `username`, and the resolved special folders
  (Drafts, Sent, Junk, Trash). Existing rows become `gmail`. New migration, append-only.
- The password is sealed with the existing vault envelope (per-account DEK, KEK-wrapped), with its own AAD kind
  (`imap_password`) so a Gmail refresh-token blob can never be opened as a password or vice versa.
- New admin verb: `dove accounts connect-imap <alias> --email <address> [--username ..] [--imap-host ..
  --imap-port .. --imap-tls ..] [--smtp-host .. --smtp-port .. --smtp-tls ..]`. The password is read from a TTY
  prompt or stdin, never from argv. It travels over the admin socket like other admin input and is never logged.
- Presets by email domain fill in hosts and ports when flags are omitted (decided: Strato `imap.strato.de:993`
  implicit, `smtp.strato.de:465` implicit; iCloud `icloud.com`/`me.com`/`mac.com` `imap.mail.me.com:993` implicit,
  `smtp.mail.me.com:587` STARTTLS). Other presets (GMX, web.de, posteo, mailbox.org, Outlook.com is excluded since it
  needs OAuth) are the builder's call. Unknown domains require the host flags.
- Connect verification, all before anything is stored: TLS handshake with verified certificate on both servers, IMAP
  `LOGIN` (or `AUTHENTICATE PLAIN`) succeeds, required capabilities are present (below), the special-use Drafts and
  Sent folders resolve, SMTP `AUTH` succeeds. Any failure stores nothing and reports which step failed (never the
  password, never the server's full response text if it could echo input).
- `accounts reconnect <alias>` for IMAP asks for a new password and replaces the sealed one only after the same
  verification. `accounts check` logs in and runs `NOOP`. `accounts remove` deletes the sealed password, the key and
  the index data (nothing to revoke upstream). `disable`/`enable` unchanged.
- An authentication failure during normal use (`NO [AUTHENTICATIONFAILED]`, SMTP 535) marks the account
  `reauth_required` with the same single notification and generation fencing Gmail uses today.

### Server requirements

Required IMAP capabilities: `IMAP4rev1`, `UIDPLUS` (for `APPENDUID` and `UID EXPUNGE`), `SPECIAL-USE` or a Drafts
folder found by name (fallback names: Drafts, Entwürfe, Draft; the operator can override with `--drafts-folder`).
`CONDSTORE`/`QRESYNC` are used when present. A server without `UIDPLUS` is refused at connect. Strato and iCloud are
expected to satisfy this; that is unverified until the first real connect.

### Command allowlist (IMAP and SMTP)

Dove's IMAP client may issue only: `CAPABILITY`, `LOGIN`/`AUTHENTICATE PLAIN`, `STARTTLS`, `ID` (optional), `LIST`/
`LSUB` (with special-use), `STATUS`, `SELECT`/`EXAMINE`, `UID SEARCH`, `UID FETCH` (with `BODY.PEEK[...]` only, so
`\Seen` is never set), `APPEND` (Drafts folder and Sent folder only), `UID STORE +FLAGS.SILENT (\Deleted)` and
`UID EXPUNGE` (only on a UID that is the current UID of a Dove-owned draft in the Drafts folder), `NOOP`, `LOGOUT`,
`ENABLE QRESYNC`. SMTP: `EHLO`, `STARTTLS`, `AUTH PLAIN`/`LOGIN`, `MAIL FROM`, `RCPT TO`, `DATA`, `QUIT`, `RSET`.
The allowlist is enforced in one module, the IMAP/SMTP counterpart of `gmail::gateway`, with typed operations; a
test proves no other command can be produced.

### Identifiers

- Folders get a small integer id per account in the state store (`folder_id` ↔ name). Agent-visible message ids are
  `<folder_id>.<uidvalidity>.<uid>` encoded to satisfy the existing id rule (`[A-Za-z0-9_-]{1,128}`), for example
  `f3-1700000000-4211`. A UIDVALIDITY change makes old ids resolve to `not_found`, which is honest.
- Thread ids for IMAP are derived, not provider-native: the root of the `References`/`In-Reply-To` chain (or the
  message's own `Message-ID`), hashed and encoded. `get_thread` on an IMAP account resolves members from the index; if
  the account is not indexed it returns the single message with an explicit `thread_incomplete` marker.
- Flags map to the existing filter booleans: unread = no `\Seen`, starred = `\Flagged`, draft = `\Draft` or in the
  Drafts folder. `list_labels` returns the account's folders (and keywords, if any) as labels with a type field.
  Spam/trash exclusion uses the special-use `\Junk` and `\Trash` folders.

### Search and index

- IMAP accounts are indexed by default on connect (decided, because `get_thread` and "what is new across all my
  mail" depend on it). The operator can still disable it.
- Sync per folder: checkpoint = (UIDVALIDITY, UIDNEXT, HIGHESTMODSEQ when CONDSTORE). Backfill newest first, as for
  Gmail. Flag changes via CONDSTORE `CHANGEDSINCE`; deletions via QRESYNC `VANISHED`, or a periodic `UID SEARCH ALL`
  diff when QRESYNC is missing. A UIDVALIDITY change rebuilds that folder inside a new generation. The checkpoint
  column becomes a per-folder record; generations, fencing, bounded drops and cursors stay as they are.
- Folders synced: all selectable folders, Trash and Junk included but excluded from results by default exactly like
  Gmail spam/trash. A copy of a message in two folders is two index rows (two ids).
- The live Gmail search source (`source: "gmail"`, `gmail_query`) stays Gmail-only; for an IMAP account it returns
  `invalid_argument`. No live IMAP `SEARCH` source in this change.
- Poll interval: the existing `index.poll_interval_secs`.

### Drafts

- Create: build MIME with the existing builder (From = the account address), `APPEND` to Drafts with flags
  `(\Draft \Seen)`, take the new UID from `APPENDUID`. `own_drafts` stores the folder, UIDVALIDITY, UID, the
  `Message-ID` Dove generated and a SHA-256 of the appended bytes. The agent-visible draft id is Dove's own stable id;
  the revision is the current UID.
- Fresh check before update or send: `UID FETCH` that UID's full bytes from Drafts and compare the hash. Missing UID
  or different hash means a human (or Apple Mail) changed it: `draft_conflict`, the draft is human-owned from then on,
  exactly like the Gmail rule today. Apple Mail re-saves drafts under a new UID, so any human edit ends Dove's
  ownership; this is the intended behaviour.
- Update: `APPEND` the replacement, then `UID STORE \Deleted` + `UID EXPUNGE` on the old UID. If the append succeeds
  and the delete fails, the record moves to the new UID and the stale copy is reported once to the operator (not
  retried blindly). Unknown outcome of the `APPEND` maps to the existing `update_unknown` state.
- `request_key` idempotency, per-draft locks and the rate limit work unchanged.

### Send

- Same state machine (`active` → `sending` → `sent` | `send_unknown`), same gates, same hourly limit charged at claim.
- Sequence: fresh check of the draft bytes; persist `sending`; SMTP submission of exactly those bytes with the `Bcc`
  header removed and the envelope recipients taken from To/Cc/Bcc; on `250` after `DATA` mark `sent`; then `APPEND`
  the sent bytes to the Sent folder and delete the draft (best effort, failures recorded for the operator, never
  re-sending). A connection lost after the final `.` of `DATA` is `send_unknown`; nothing is retried.
- Envelope sender is the account address. No send-as aliases for IMAP in this change.
- Providers that store a Sent copy themselves on SMTP submission would get two copies. iCloud is suspected to do
  this; a per-account `save_sent_copy` flag (default true, preset false where known) handles it.

### Attachment reads (all providers)

- New tool `get_attachment` (action `read`): input `account` + `message_id` (or `ref`) + `attachment_id` (the
  existing `part-<n>` ids from `get_message`). Output: filename (sanitized: no path separators, control characters
  or leading dots), declared MIME type, size, and the bytes as an MCP embedded resource (base64 blob), wrapped in the
  untrusted-content envelope.
- Limit: `limits.attachment_bytes`, default 10 MiB per call; larger attachments return `too_large` with the size.
  Gmail fetches the raw message (already allowlisted) and extracts the part; IMAP fetches the message with
  `BODY.PEEK[]` (fetching a single part via `BODY.PEEK[<section>]` is an optimisation left to the builder).
- Audit records the tool call, account and size class, never the filename.
- The remote CLI gets `dove message attachment save <ref> <attachment_id> [--out DIR]`, which writes the file with mode
  0600, refuses to overwrite, and never opens it. This is how "import the files here" works from Claude Code or a
  shell agent.

### Connections and limits

- A small per-account IMAP connection pool (default at most 2 connections per account, idle timeout 60 s), inside the
  existing global upstream semaphore. SMTP connects per send.
- Timeouts per command (existing `upstream_request_timeout_secs`), whole-call deadline unchanged.
- Response size caps mirror the Gmail ones: a message larger than `index.max_message_bytes` is indexed from metadata
  only and `get_message` truncates as today.

### Testing

- A fake IMAP+SMTP server in `tests/support/` (tokio TCP, plaintext in tests only via a test-only upstream override,
  as `Upstream::single_origin` does for Gmail) with the same fault injection as fake Google (`Delay`, error replies,
  drop after apply) and a recorded command log asserting the allowlist.
- The existing tool e2e suites run against both providers where the behaviour is shared (one parametrised harness),
  plus IMAP-specific tests: UIDVALIDITY change, missing UIDPLUS refused at connect, Apple-Mail-style draft resave
  becomes `draft_conflict`, send unknown after `DATA`, Sent copy, `\Seen` never set.
- One run against a real Dovecot container (`dove-t-*` name) for protocol realism.
- Real Strato and iCloud checks are manual and stay marked unverified until the owner runs them.

## Settled after the builder review (author's calls, owner to check)

- **Duplicates across folders:** no collapsing. Each (folder, UID) is one index row and one id. Trash and Junk rows
  are excluded by default; real copies elsewhere (for example a message to yourself in Inbox and Sent) both show.
  Index rows key on an opaque provider message id string; whether the existing `gmail_id` column is reused or renamed
  in an index migration is the builder's call.
- **Labels for IMAP:** the agent-visible label is the full folder path (for example `INBOX/Rechnungen`). A server-side
  rename is a new folder: the old folder's rows are dropped and the new one is synced. Keywords appear as labels with
  type `keyword`.
- **Re-authorization:** one password serves IMAP and SMTP by default (`--smtp-username` is optional for providers that
  differ). An explicit auth failure on either side marks the account `reauth_required`; TLS or network failures do not,
  they return `upstream_unavailable`.
- **Draft hashing:** after `APPEND`, Dove fetches the stored message by its new UID and hashes the bytes the server
  returns. Later fresh checks compare server bytes with server bytes, so a server that normalises line endings or adds
  headers does not cause false conflicts. A UIDVALIDITY change on Drafts ends Dove's ownership (`draft_conflict`).
- **After `send_unknown`:** Dove never resends. `dove operations` may show a read-only check whether a message with
  the draft's `Message-ID` is in Sent, for the operator to decide.
- **Deleting a replaced draft:** Dove expunges only the UID of its own draft, with `UID EXPUNGE` (UIDPLUS is
  required), regardless of how the human's client handles deletion.
- **Login:** `AUTHENTICATE PLAIN` when advertised, otherwise `LOGIN` with the password sent as an IMAP literal. The
  password field of the admin request is zeroized after use and excluded from admin audit and logging; the admin
  audit records only the verb and alias. TTY prompting without echo may add a small dependency.
- **Attachment responses:** `get_attachment` uses the existing `read` grant. Its response can reach about 14 MiB of
  JSON for a 10 MiB attachment; the response path (not `limits.body_bytes`, which caps requests) and the stdio bridge
  must allow that, and the call deadline applies. Audit size classes: `<1MiB`, `<10MiB`, `too_large`.
- **Tests:** a Dovecot container runs locally under `heavy` with a `dove-t-*` name, image pinned by digest; it may join
  CI later. Test-only plaintext and the fake server's address go through the same mechanism as
  `Upstream::single_origin` today (a public constructor used by the harness), never a config switch.
- **Client crate:** if an existing crate is used, it sits behind the typed allowlist module and only that module
  builds command strings (for example always `BODY.PEEK`). A hand-written minimal client is acceptable if it is
  smaller and simpler to prove.

## Left to the builder

- IMAP and SMTP client crates (for example `async-imap` and `lettre` with tokio-rustls) or a minimal hand-written
  client, as long as the allowlist is enforced in one typed module and the TLS stack is the shared rustls.
- The shape of the provider abstraction (trait or enum dispatch), keeping `policy::authorize` and the audit write in
  the tool layer, not in providers.
- Exact schema of the folder table and per-folder checkpoint.
- Further presets, and the exact operator-facing error texts at connect.
- Plan order, as long as connect + read + search ship before drafts and send, and attachments can land independently.

## Addendum 2026-11-12: attachments, forwards and quoting in drafts

Attachments in outgoing drafts were a non-goal; reversed on owner request 2026-11-12, for Gmail and IMAP alike,
through the existing `create_draft` / `update_draft` tools and the remote CLI (`dove draft create --attach FILE`,
`--forward REF`).

- **Sources.** By reference to an attachment of a message the caller may read (`{ref | account + message_id,
  attachment_id}`), fetched server-side so the bytes never pass through the agent; or inline from the agent
  (`{filename, mime_type, content_base64}`). A reference to a mailbox without a `read` grant is the identical
  `not_found`, decided before any upstream call. Grants already enforce `draft` ⇒ `read`.
- **Forward.** `forward_message_id` (in `account`) or `forward_ref` (any readable mailbox): subject `Fwd: ...`, a
  standard forwarded-message block (From, Date, Subject, To, Cc) and the original plain text below the agent's text,
  the original's attachments by default (`include_attachments`). Over a limit is an error that names
  `include_attachments: false`, never a silent drop.
- **Reply quoting.** `reply_to_message_id` quotes the original below the body (`On <date>, <sender> wrote:` and `> `
  lines), `quote_original` default true, at most 100 KiB of original text and never beyond the 500 KB body limit.
- **Limits.** At most 10 attachments and `limits.draft_attachment_bytes` (default 10 MiB, at most 16 MiB) decoded
  bytes per draft. `/mcp` reads the request body only after authentication; a client with `draft` on some mailbox gets
  room for that much base64 (`× 4/3 + 2 MiB`), everyone else keeps `limits.body_bytes`.
- **Shape.** Drafts stay a text/plain body; with attachments the message is `multipart/mixed` with the body first and
  one base64 leaf per attachment (`Content-Disposition: attachment`, RFC 2231 filename). Filenames are sanitized like
  `get_attachment`'s; MIME types must be a plain `type/subtype` (no parameters, no `multipart/*` or `message/*`; a
  referenced attachment with such a type is attached as `application/octet-stream`). Dove rebuilds only this shape;
  anything else (HTML, inline parts, nested messages) is `draft_conflict` on update, as before.
- **Unchanged.** Own-draft revision and content-hash checks, the send state machine and the exact submission of the
  stored bytes; one audit record per call, which gets the forwarded message id, `attachments:<n>` and a size class but
  never filenames or content. Quote and forward text are untrusted content in the body; only the original subject
  reaches a header, reduced to one clean line.
