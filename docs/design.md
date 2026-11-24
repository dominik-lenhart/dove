# Design decisions

Dove gives a language model access to mailboxes, and the mail it reads is written by strangers. The model can be
steered by that mail, the token it holds can leak, and the machine it runs on may let it run shell commands. Most
choices below come from taking those three cases as the normal case rather than the exception. Each section names
what Dove does, what it does not do, and why. The full requirements and threat model are in [`spec.md`](spec.md);
the reasoning behind individual changes is in [`PLAN.md`](PLAN.md) and the design documents under
[`superpowers/specs/`](superpowers/specs/).

## One token per agent, scoped per mailbox and action

The simple alternative is a mail connector that holds one account's credentials and gives every client the same
access. Dove instead issues each agent its own token with its own list of mailboxes, and per mailbox its own actions
(`read`, `draft`, `organize`, `delete`, `send`, `signatures`). Presets are expanded when the token is created, so a
later change to a preset never widens an existing token. Every tool call passes one authorization function
(`src/policy.rs`) and writes exactly one audit record.

Why: a prompt-injected agent can do anything its token allows, so the useful question is how little that is. A
reading agent cannot draft, a drafting agent cannot send, and an agent for the work mailbox does not see the private
one. Unknown and out-of-scope mailboxes and ids return the identical `not_found`, so a token cannot even learn what
else exists. Spec 5.2, 6.2; [v0.2 design](superpowers/specs/2026-11-13-v0.2-design.md), section 1.

## Drafts in your own Drafts folder; sending is off by default

Dove writes drafts into the mailbox's real Drafts folder (or as Gmail drafts), so the owner reviews them in the mail
client they already use. Sending needs two separate switches: `allow_send = true` in the server configuration and a
`send` grant on one named mailbox. Even then Dove only sends a draft it created and nobody changed since, never with
recipients or text of its own, and never a second time after an outcome it could not confirm (a lost reply after the
final SMTP `.` blocks the draft until the owner checks Sent).

Rejected: a send tool that takes recipients and a body. It would turn every successful injection into outgoing mail.
With drafts the injection's worst case is a draft the owner deletes. Spec 6.3.

## Ask instead of holding standing rights

When an agent needs more than its grants, for example to send 20 reviewed drafts spread over Tuesday or to read
another mailbox for an hour, it files a request (`request_send`, `request_access`). Nothing happens until the owner
approves exactly that request with a passkey in the admin UI. Approved access is a temporary grant with an expiry;
an approved send goes out through the same send path as above, with its revision pinned and an optional "unless
someone replied" condition.

Rejected: granting `send` or a wider scope "for now". Standing rights outlive the task they were given for.
[Requests and admin UI design](superpowers/specs/2026-11-14-requests-and-admin-ui-design.md); spec 6.3a, 6.3b.

## Administration is out of the agents' reach

Admin verbs never accept an agent token. They run over a local Unix socket (a named pipe on Windows) after an OS
peer-identity check, or in the `/admin` web UI after passkey sign-in, with a fresh passkey assertion for sensitive
verbs. The admin UI is served on its own host and is meant for the tailnet only.

Why: agents often have a shell. If the admin interface were an HTTP endpoint guarded by a token, an agent that found
or was handed that token could grant itself everything. With the socket the boundary is the OS user, which a token
cannot cross (this requires the agent to run as a different OS user than the operator; see AGENTS.md). Spec 5.5, 6.2.

## Mail is untrusted input, marked as such

Every tool result that can contain mail carries a fixed `untrusted_content_notice`, and the text rendering wraps mail
in an `<untrusted_email_content>` envelope with the closing delimiter escaped. HTML is parsed with a real parser;
hidden elements, scripts, styles and invisible Unicode (bidirectional overrides, tag and zero-width characters) are
removed. Dove never follows links, loads remote images or runs attachments. Attachment text extraction (PDF, DOCX,
ODT, CSV) runs under CPU and memory budgets with a hand-written ZIP reader that never trusts declared sizes.

Dove cannot make prompt injection impossible, and the spec says so. What it can do is make content easy to treat as
data and keep hidden instructions from reaching the model unseen. Spec 6.5.

## Secrets and the index are encrypted with keys kept elsewhere

Refresh tokens and IMAP passwords are sealed with envelope encryption: a per-account key wrapped by a key-encryption
key that lives in a secret file, not in the database and not in an environment variable. Each ciphertext is bound to
its account and record type, so a copied row does not decrypt in another place. Client tokens are stored only as
keyed hashes. The full-text index is a SQLCipher database (FTS pages and WAL included) with its own key, and every
query is checked against the token's current grants rather than trusting what the index contains.

Rejected: a plain SQLite index next to the state file. A copied backup would then be a readable copy of every
mailbox. Spec 6.4.

## Outbound traffic only through a fixed allowlist

All HTTP to Google goes through one gateway (`src/gmail/gateway.rs`) that allows exact method and path pairs and no
redirects. The IMAP client is Dove's own (`src/imap/`), with one module that builds every command string from an
allowlist. There is no permanent delete anywhere: outside Dove's own drafts, IMAP `\Deleted` is only set on messages
whose copy the server confirmed (`COPYUID`), and the `delete` action only ever moves to Trash or Spam, where the mail stays recoverable.

Why hand-written: a generic client makes it hard to say what was sent when a connection drops. Dove classifies every
write as definitely failed (safe to retry) or `outcome_unknown` (never retried automatically), and that needs to know
exactly where a command stopped. Spec 7.5; [IMAP/SMTP design](superpowers/specs/2026-11-12-imap-smtp-design.md).

## An audit trail without mail in it

One record per tool call and admin action: time, client, tool, mailbox alias, message ids, result code, duration,
source address. No subjects, bodies, addresses or query text. Records are hash-chained (`dove audit verify`), and the
admin UI aggregates them into an activity view.

Why: the owner needs to see what agents did, but an audit log full of mail would be a second copy of the mailbox
with weaker protection. Spec 6.7; [dashboard and audit design](superpowers/specs/2026-11-17-dashboard-audit-design.md).

## Self-hosted, one binary

Dove is one Rust binary with no hosted component and no telemetry. It runs as a system service behind Caddy, nginx
or Tailscale, or as a local service on the owner's own computer. Releases are signed with minisign and verified by
`dove upgrade` against a key built into the binary.

Why: a mail proxy that agents trust holds credentials to every mailbox. Running it as a third-party service would add
one more party that can read all of them. [Local mode and packaging design](superpowers/specs/2026-11-13-local-mode-and-packaging-design.md).

## What this does not cover

A compromised host can use the credentials in memory. A steered agent can still use every permission its token
holds. What the model provider does with mail an agent reads is outside Dove. The README's
[security model](../README.md#security-model) lists these limits next to what is covered.
