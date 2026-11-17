# Activity dashboard and audit search (design 2026-11-17)

Step 3 of four (owner's order 2026-11-16). Owner's go: "gerne" (2026-11-17).

## Why

The overview says what waits for a decision, but not what the agents have been doing. The audit page can search
already, but only with exact values the owner has to know (`keyset-claude-code`, `requests.approve`), 200 rows at most,
and in production 70 % of all records are one connection's watch polls (`list_watch_events`), which bury the rest.

## Goals

- Overview, new "Activity" section:
  - agent tool calls per day for 14 days (UTC), succeeded vs. failed or refused, as an inline SVG bar chart (the CSP
    forbids inline styles, SVG attributes are fine);
  - per connection for 7 days: calls, failed, writes (tools that are not read-only), watch polls separately, last call;
    each name links to the audit page filtered to it.
- Audit page:
  - suggestions (`<datalist>`) for actor, action and mailbox from the values in the log;
  - result as a select: any, ok, "failed or refused" (`result_code <> 'ok'`), or one code;
  - an object id field (request, draft, message id; exact element of `object_ids`);
  - watch polls hidden unless "Include watch polls" is ticked or the action filter names them;
  - "Older records" paging by `seq`;
  - actor, action and mailbox in each row link to the filtered search.

## Non-goals

No free-text search over content (the audit holds none), no charts beyond the one bar chart, no JS.

## Approaches

1. **Chosen: one new read verb `AuditStats` plus optional fields on `SearchFilter`.** Aggregates are SQL over `audit`
   (indexed on `ts`); agent calls are records whose action is a tool in `tools::registry()`, so admin and system
   records drop out without guessing at actor names.
2. Count in the page from `AuditSearch` rows. Rejected: needs every row of 14 days in memory.
3. A counters table updated on every call. Rejected: a second write per tool call for a page the owner opens rarely.

## Design

- `audit::SearchFilter` gains `failed`, `object`, `before`, `hide_polls` (all optional, serde default, skipped when
  unset, so an older service still parses a newer CLI's request).
- `audit::stats(conn, now, tools) -> Stats { days, clients, values }`; `AdminRequest::AuditStats` (read-only, no
  step-up, covered by `/admin`).
- `list_watch_events` is the one poll tool (`audit::POLL_TOOL`).
