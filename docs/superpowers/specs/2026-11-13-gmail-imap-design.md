# Gmail over IMAP (app password) design

Status: approved by the owner on 2026-11-13. Target: v0.3.0. Why: the Gmail API path needs every self-hoster to
create their own Google Cloud project (restricted scopes would need a CASA audit for a shared client). Gmail's IMAP
with an app password needs only 2-Step Verification and an app password, like iCloud.

## Problem

Gmail exposes labels as IMAP folders. One message shows up in `INBOX`, `[Gmail]/All Mail`, `[Gmail]/Important`,
`[Gmail]/Starred` and every label folder, each with its own UID. Dove's IMAP sync indexes every selectable folder, so
a Gmail mailbox would show each message several times. Gmail also has non-standard semantics: copying to a label
folder adds a label, and `\Deleted` + `EXPUNGE` in some folders can delete a message for good, depending on account
settings.

## Decisions

1. **Detection.** At connect, a server that advertises `X-GM-EXT-1` puts the account in Gmail mode:
   `ImapSettings.gmail = true` (serde default `false`, so existing accounts are unchanged). The mode is fixed at
   connect time; `reconnect` keeps it. Gmail mode also requires a `\All` special-use folder; without one, connect
   fails with a clear message.
2. **Preset** `gmail` for `gmail.com` and `googlemail.com`: `imap.gmail.com:993` implicit TLS, `smtp.gmail.com:465`
   implicit TLS, `save_sent_copy = false` (Gmail files submitted mail in Sent itself). `--preset gmail` covers
   Workspace domains.
3. **One row per message.** In Gmail mode the sync scans only the `\All` folder plus `\Junk` and `\Trash` (those are
   not in All Mail). The other folders are still listed and stored in `imap_folders` (for `list_labels`, label names
   and move targets) but get no checkpoints and no rows. Message ids stay `f<folder>-<uidvalidity>-<uid>`, so most
   messages have an All Mail id.
4. **Labels from `X-GM-LABELS`.** Body and flag fetches in Gmail mode also fetch `X-GM-LABELS` (CONDSTORE flag
   refreshes too: Gmail bumps MODSEQ on label changes). Mapping to index labels: `\Inbox` → `INBOX`, `\Sent` →
   `SENT`, `\Draft` → `DRAFT`, `\Important` → `IMPORTANT`, `\Starred` → `STARRED`, user labels → their decoded name
   through `mail::label_text` (modified UTF-7 decode via `utf7::display_name`). Flags map as before (`UNREAD`,
   `STARRED`). So `folders: ["INBOX"]` and the digest's default inbox filter work as on other providers. Messages in
   Trash/Spam keep the existing folder mapping (`TRASH`, `SPAM`).
5. **IDLE and the quick pass** use the `\All` folder instead of `INBOX` in Gmail mode (new inbox mail lands there too).
6. **Organize in Gmail mode** (source message in All Mail):
   - flags: `UID STORE +/-FLAGS (\Seen \Flagged)` as today;
   - `add_labels`/`remove_labels`: `UID STORE +/-X-GM-LABELS (<label>)`; the label must be a known non-special folder
     from `imap_folders` (Dove creates no labels); its wire name is sent as an astring. New `ImapOp` variant, built only
     in `ops.rs`;
   - `move_messages`: `archive` = `-X-GM-LABELS (\Inbox)`; `inbox` = `+X-GM-LABELS (\Inbox)`; a label = `+label`
     then `-\Inbox`. These keep the message id;
   - `trash`/`spam` (needs `delete`): `UID MOVE` to the `\Trash`/`\Junk` folder only. Without `MOVE`, refuse with
     `upstream`/`invalid_argument`; **never** the COPY + `\Deleted` + `EXPUNGE` fallback in Gmail mode, and never
     `\Deleted` on anything but Dove's own drafts;
   - from Trash/Spam: `UID MOVE` to `INBOX` (inbox), to the label folder (a label) or to All Mail (archive).
7. **Drafts and send** work as for other IMAP accounts (APPEND to `\Drafts`, own-draft deletion there). With
   `save_sent_copy = false` Dove files no Sent copy.
8. **Threads** keep the derived id (PLAN A47); `X-GM-THRID` is not used (changing the formula would need an index
   rebuild migration).

## Tests

- Fake IMAP gets a Gmail mode: `X-GM-EXT-1`, `[Gmail]/All Mail` (`\All`), `[Gmail]/Trash`, `[Gmail]/Spam`,
  `[Gmail]/Drafts`, `[Gmail]/Sent Mail`, label folders; one message is visible in several folders with separate UIDs;
  `X-GM-LABELS` in FETCH and STORE; MODSEQ bumps on label changes.
- Index: a message in INBOX + label + All Mail is indexed once with labels `INBOX` and the label; folder filters and
  digest work; archive removes `INBOX` after the next sync; a label change made on the server shows up through the
  CONDSTORE path.
- Organize: the command log never holds `\Deleted` outside Drafts in Gmail mode, and never `EXPUNGE` outside Drafts;
  trash without MOVE is refused; unknown labels are refused before any command.
- Connect: preset, detection, missing `\All` folder.
- Real check against `testdove051@gmail.com` with an app password once built (owner provides it).
