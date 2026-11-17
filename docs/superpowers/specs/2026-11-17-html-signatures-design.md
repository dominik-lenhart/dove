# Named HTML signatures with inline images (design 2026-11-17)

Owner request 2026-11-17 (relayed from the keyset session): a municipality would not click a link because our mail
came "without a complete signature". Drafts from `create_draft` carry at most a plain-text signature today, one per
mailbox or alias, set by the operator only.

## Goals

- Several named signatures per mailbox, for example `behoerden` (quiet, small logo) and `gastgeber` (with a banner) on
  `keyset-cloud`, one of them the default (per mailbox, and optionally per send-as alias).
- A signature has HTML and a text form. The text form is given or derived from the HTML (one line per break, paragraph or cell; images left out).
- Images ship inside the mail as `multipart/related` parts with a `Content-ID`, referenced as `cid:<name>`, so they
  show when a client blocks remote images.
- `create_draft` takes `signature: true | false | "<name>"` (default true = the default signature). Replies put the
  signature above the quote. `update_draft` keeps the draft's signature and quote and can switch or drop it.
- Agents can list signatures (with `draft`), and create, change and delete them only with a new grant action
  `signatures` that the owner grants explicitly (it is in no preset, like `send`). The owner gets an alert when an
  agent changes one.
- The operator has the same through `dove accounts signatures ...` and the admin UI's mailbox page.

## Non-goals

- No remote images other than `https:` (`cid:` is the point), no scripts, forms, iframes or event attributes.
- No rich-text editing of the agent's body: the body stays plain text and is rendered into HTML by Dove.
- Gmail's own signature settings are not read or written.

## Approaches

1. **Chosen: signatures as owner-granted data with a new action.** Fits the grant model (`send` precedent): the owner
   decides per connection and mailbox, `request_access` can ask for it, and every change is audited and alerted.
2. Operator only (CLI and admin UI). Rejected: the agents that write the mail could not maintain their signatures, and
   this host's agents have no admin access.
3. A new request kind for each change, approved with a passkey. Rejected for now: heavy for something the owner can
   grant once, and the alert plus audit already make changes visible.

## Design

### Storage (state store migration)

- `signatures(id, account_id → accounts ON DELETE CASCADE, name, text, html NULL, created_at, updated_at, updated_by)`,
  `UNIQUE(account_id, name)`; name `[a-z0-9][a-z0-9-]{0,39}`.
- `signature_images(signature_id → signatures ON DELETE CASCADE, cid, mime_type, bytes)`, PK `(signature_id, cid)`;
  PNG, JPEG or GIF (checked by magic bytes), at most 6 images and 512 KiB in total per signature; cid
  `[A-Za-z0-9._-]{1,64}`.
- `signature_defaults(account_id, address, signature_id → signatures ON DELETE CASCADE)`, PK `(account_id, address)`;
  address `''` is the mailbox default, else an alias address.
- Legacy `account_signatures` rows move over: the mailbox's text becomes signature `default`, an alias's becomes
  `alias-<n>`, each the default for its address. The old admin verbs keep working on top of the new tables.

### HTML rules

The HTML is parsed (html5ever via `scraper`) and re-serialized from an allowlist: layout and text tags (`table`,
`tbody`, `tr`, `td`, `th`, `div`, `p`, `span`, `br`, `hr`, `b`, `strong`, `i`, `em`, `u`, `small`, `a`, `img`, `font`),
attributes `style`, `width`, `height`, `align`, `valign`, `border`, `cellpadding`, `cellspacing`, `role`, `alt`,
`title`, `color`, `href` (https, http, mailto, tel), `src` (`cid:` of an image of this signature, or https). `style`
values with `url(`, `expression`, `@import`, `javascript:` or backslashes are dropped. Everything else is removed,
its text kept. At most 32 KiB of HTML after cleaning. A `cid:` without a matching image is an error.

### Draft structure

```
multipart/mixed                (only with attachments)
└ multipart/related            (only with images)
  ├ multipart/alternative
  │ ├ text/plain               body + "-- " + text signature + quote/forward block
  │ └ text/html                body (escaped, <br>) + signature HTML + quote as <blockquote>
  └ image/png  Content-ID: <keyset-logo>  Content-Disposition: inline
└ attachments
```

A draft without an HTML signature stays text/plain as before. Dove records how its own draft was composed in
`own_drafts.composition` (signature name, byte lengths of body and signature block; no content), so `get_draft`
reports `composition: {signature, has_html, quote_or_forward_below}` for its own unchanged drafts, and `update_draft`
replaces only the body, re-rendering the signature from its current definition and keeping the quote. If the record
no longer fits the draft's text, the update is a `draft_conflict`; if the signature was deleted, a body change asks for
`changes.signature`.

### Tools

- `list_signatures {account}` (draft): names, default flags, text, whether HTML exists, image cids and sizes;
  `include_html: true` adds the HTML.
- `set_signature {account, name, html?, text?, images?: [{cid, data_base64, mime_type?}], make_default?, for_address?}`
  (signatures): creates or changes (omitted fields keep their value, `images` replaces all, `html: ""` makes it text
  only); `make_default: true` makes it the default for the mailbox or `for_address`.
- `delete_signature {account, name}` (signatures).
