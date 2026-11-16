# Admin UI as an installable app with Web Push (design 2026-11-16)

## Why

Agents ask the owner for things (scheduled sends, access requests), but today the owner only learns about a request
through `[requests] notify_sink`, a webhook that is not set up in production. In practice requests wait until someone
happens to open `/admin`. The owner wants a phone notification and a tap that opens the request, as rootnod already
does on this host.

This is step 1 of four (owner's order 2026-11-16): push, then health and owner alerts over the same channel, then a
dashboard and audit search, then search performance.

## Goals

- `/admin` is installable as a home-screen app (manifest, service worker, icon), on iOS from Safari and on Android
  and desktop.
- On the settings page the owner turns on push for the current device, names it, sends a test notification and
  removes devices.
- A new pending request (send or access) pushes to every device. The notification shows the connection name and the
  kind, for example "claude-code wants to schedule 2 sends" or "claude-code asks for access to strato". It shows no
  addresses, subjects or notes (owner's choice 2026-11-16). Tapping it opens `/admin/requests/<id>`. Approval stays
  there, behind the existing passkey step-up.
- The outbox is generic (kind + reference), so step 2 can push health alerts without a new table.

## Non-goals

- No approval from the notification itself, since iOS has no action buttons and approval needs a passkey.
- No public admin UI. It stays tailnet only (port 43395); the phone is on the tailnet (owner, 2026-11-16).
  Delivery does not need that, because push goes out through Apple and Google.
- No push to agents. Agents keep `dove watch listen` and webhooks.

## Approaches

1. **Recommended, chosen: port rootnod's own Web Push.** RFC 8291 `aes128gcm` and the RFC 8292 VAPID JWT, both
   built on aws-lc-rs, which Dove already depends on. No new crypto crate, and no `crypto-bigint`, which would add a
   third advisory ignore. rootnod's `ece.rs` is checked against RFC 8291 Appendix A.
2. `web-push` crate. Rejected: it pulls in OpenSSL and libcurl, and rootnod rejected it for the same reason (its
   ADR-0006).
3. Only document `notify_sink` with ntfy or a similar relay. Rejected: it needs a third-party app and service, and
   the notification would not open the admin UI.

## Design

- **Store migration.**
  - `push_devices`: id, name, endpoint sealed by the vault (it is a capability URL), p256dh, auth, created_at,
    last_ok_at, failures.
  - `push_outbox`: id, device, kind, ref, title, body, url, state, attempts, next_attempt_at, created_at.
  - At most 16 devices.
- **VAPID key.** P-256, generated on first use and sealed with the vault in the state store (aux kind `vapid_key`).
  `keys rotate` rewraps it like the other sealed values.
- **Endpoints.** Accepted only on known push services: `web.push.apple.com`, `fcm.googleapis.com`,
  `push.services.mozilla.com`, `notify.windows.com`, each matched exactly or as a subdomain. https only.
- **Outbound HTTP.** Through a new `gateway::post_push`: allowlisted host, POST only, no redirects, Background
  priority, 10 s. This is an amendment to spec 7.5, recorded in the PLAN.
- **Queueing.** In the transaction that creates a request, `requests::queue_notice` also writes one outbox row per
  device. `notify_sink` stays as it is.
- **Delivery.** Runs in the existing sink delivery loop. The payload is
  `{"title","body","url","tag"}`, padded to 512 bytes, sent with TTL 24 h and `Urgency: high`. Retries use the sink
  backoff. 404 or 410 removes the device. Log lines carry the device id and status only.
- **Routes.**
  - `/admin/manifest.webmanifest`, `/admin/sw.js` and `/admin/static/icon-*.png`, all public without a session, like
    the other static assets.
  - `/admin/settings/push/key` (GET), `/admin/settings/push/subscribe` (POST), `/admin/settings/push/{id}/test` and
    `/admin/settings/push/{id}/remove`, all with session, CSRF and Origin.
  - Adding a device needs no step-up: the payload carries no secret, and an attacker with a session could already
    read the requests.
  - New admin verbs are classified in `needs_step_up` and listed in `COVERAGE`.
  - The CSP gains `worker-src 'self'` and `manifest-src 'self'`.
- **Service worker.** Minimal: `push` shows the notification, and `notificationclick` focuses or opens the URL. No
  offline cache for HTML.
- **Admin socket and CLI.** `dove admin push list|remove|test`, so the owner can clean up without the UI.

## Tests

- RFC 8291 Appendix A vector.
- A fake push service on loopback, reached through a test-only gateway switch like `allow_plain_http_sinks_for_tests`,
  that decrypts with the receiver keys and checks the payload. It also checks that the body holds no address,
  subject or note.
- A 410 removes the device, and 503 is retried.
- A foreign endpoint host is refused.
- The 16-device limit.
- Routes go through the existing drift and coverage tests.
- In the browser: the demo with the soft authenticator, a real service worker registration in Chromium, and a push to
  the real FCM endpoint from the T3 browser if that is possible.

## Left to the builder

The icon (a simple dove glyph on the theme colour), the exact notification copy per request kind, and the device
naming default (from the User-Agent, editable).
