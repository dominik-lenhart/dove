// Dove admin UI: passkey sign-in, enrolment and confirmations. The only script of the UI (CSP script-src 'self').
// The server creates every challenge and decides everything; this file only moves bytes between the page, the
// browser's WebAuthn API and the server. It never builds HTML from data: messages go in with textContent.
(function () {
  "use strict";

  function b64uEncode(buf) {
    var bytes = new Uint8Array(buf), s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function b64uDecode(str) {
    var s = str.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function csrf() {
    var m = document.querySelector('meta[name="dove-csrf"]');
    return m ? m.getAttribute("content") : "";
  }

  function say(el, msg, kind) {
    if (!el) return;
    el.textContent = msg || "";
    el.className = "status" + (kind ? " " + kind : "");
  }

  function supported() {
    return !!(window.PublicKeyCredential && navigator.credentials && window.fetch);
  }

  async function post(url, body, form) {
    var headers = { "X-Dove-CSRF": csrf() };
    headers["Content-Type"] = form ? "application/x-www-form-urlencoded" : "application/json";
    var r = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: headers,
      body: form ? body : JSON.stringify(body),
    });
    var data = {};
    try { data = await r.json(); } catch (e) { data = { error: "Unexpected answer (" + r.status + "). Reload the page." }; }
    return { ok: r.ok, data: data };
  }

  function requestOptions(pk) {
    var o = {
      challenge: b64uDecode(pk.challenge),
      rpId: pk.rpId,
      userVerification: pk.userVerification,
      timeout: pk.timeout,
    };
    if (pk.allowCredentials) {
      o.allowCredentials = pk.allowCredentials.map(function (c) { return { type: c.type, id: b64uDecode(c.id) }; });
    }
    return o;
  }

  function creationOptions(pk) {
    return {
      rp: pk.rp,
      user: { id: b64uDecode(pk.user.id), name: pk.user.name, displayName: pk.user.displayName },
      challenge: b64uDecode(pk.challenge),
      pubKeyCredParams: pk.pubKeyCredParams,
      authenticatorSelection: pk.authenticatorSelection,
      attestation: pk.attestation,
      timeout: pk.timeout,
    };
  }

  function assertionJSON(cred) {
    var r = cred.response;
    return {
      id: b64uEncode(cred.rawId),
      clientDataJSON: b64uEncode(r.clientDataJSON),
      authenticatorData: b64uEncode(r.authenticatorData),
      signature: b64uEncode(r.signature),
      userHandle: r.userHandle ? b64uEncode(r.userHandle) : null,
    };
  }

  function cancelled(e) {
    return e && (e.name === "NotAllowedError" || e.name === "AbortError");
  }

  // Where to go after signing in (`?next=`, set by the server for a page that needed a session, such as a request a
  // notification opened). Only plain admin paths, the same rule as the server's.
  function nextPath() {
    var n = new URLSearchParams(window.location.search).get("next");
    return n && /^\/admin(\/[A-Za-z0-9_-]+)*$/.test(n) ? n : null;
  }

  // ---------------------------------------------------------------- notifications (Web Push)

  function pushSupported() {
    return "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
  }

  function registerWorker() {
    return navigator.serviceWorker.register("/admin/sw.js", { scope: "/admin" });
  }

  function deviceGuess() {
    var ua = navigator.userAgent;
    if (/iPhone/.test(ua)) return "iphone";
    if (/iPad/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) return "ipad";
    if (/Android/.test(ua)) return "android";
    if (/Macintosh/.test(ua)) return "mac";
    if (/Windows/.test(ua)) return "windows";
    if (/Linux/.test(ua)) return "linux";
    return "browser";
  }

  function sameKey(sub, key) {
    var have = sub.options && sub.options.applicationServerKey;
    if (!have) return false;
    var a = new Uint8Array(have), b = new Uint8Array(key);
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }

  async function pushOn(form) {
    var st = form.querySelector(".status");
    var buttons = form.querySelectorAll("button");
    buttons.forEach(function (b) { b.disabled = true; });
    say(st, "Asking for permission…");
    try {
      if ((await Notification.requestPermission()) !== "granted") {
        throw new Error("Notifications are blocked for Dove on this device. Allow them in the settings, then try again.");
      }
      say(st, "Subscribing…");
      await registerWorker();
      var reg = await Promise.race([
        navigator.serviceWorker.ready,
        new Promise(function (_, reject) {
          setTimeout(function () { reject(new Error("The service worker did not start. Reload the page and try again.")); }, 10000);
        }),
      ]);
      var key = b64uDecode(form.getAttribute("data-push-key"));
      var sub = await reg.pushManager.getSubscription();
      if (sub && !sameKey(sub, key)) { await sub.unsubscribe(); sub = null; }
      if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
      var j = sub.toJSON();
      var name = form.querySelector('input[name="name"]').value;
      var r = await post("/admin/settings/push", {
        name: name,
        subscription: { endpoint: j.endpoint, keys: { p256dh: j.keys.p256dh, auth: j.keys.auth } },
      });
      if (!r.ok) throw new Error(r.data.error || "Dove did not accept the subscription.");
      // A new device learns of every request, so adding one needs the passkey.
      say(st, "Confirm with your passkey…");
      window.location.assign(await finishStepup(r.data, st) || "/admin/settings");
    } catch (e) {
      say(st, e.message || "Notifications could not be turned on.", "error");
      buttons.forEach(function (b) { b.disabled = false; });
    }
  }

  async function login(btn) {
    var st = btn.parentNode.querySelector(".status");
    if (!supported()) return say(st, "This browser cannot use passkeys.", "error");
    btn.disabled = true;
    say(st, "Waiting for your passkey…");
    try {
      var o = await post("/admin/login/options", {});
      if (!o.ok) throw new Error(o.data.error || "Sign-in is not available.");
      var cred = await navigator.credentials.get({ publicKey: requestOptions(o.data.publicKey) });
      var body = { id: o.data.id, credential: assertionJSON(cred) };
      // The page the browser came for: when it is a request from a notification, approving it right after this
      // sign-in needs no second passkey prompt.
      if (nextPath()) body.next = nextPath();
      var f = await post("/admin/login/finish", body);
      if (!f.ok) throw new Error(f.data.error || "Sign-in failed.");
      say(st, "Signed in.", "ok");
      window.location.assign(nextPath() || f.data.redirect || "/admin");
    } catch (e) {
      say(st, cancelled(e) ? "Sign-in was cancelled." : e.message, "error");
      btn.disabled = false;
    }
  }

  async function enrol(btn) {
    var st = btn.parentNode.querySelector(".status");
    var token = btn.getAttribute("data-token") || "";
    if (!token) return say(st, "This link is incomplete. Copy the whole link the command printed.", "error");
    if (!supported()) return say(st, "This browser cannot create passkeys.", "error");
    btn.disabled = true;
    say(st, "Waiting for your device…");
    try {
      var o = await post("/admin/enroll/options", { token: token });
      if (!o.ok) throw new Error(o.data.error || "Enrolment is not available.");
      var cred = await navigator.credentials.create({ publicKey: creationOptions(o.data.publicKey) });
      var body = {
        id: o.data.id,
        credential: {
          id: b64uEncode(cred.rawId),
          clientDataJSON: b64uEncode(cred.response.clientDataJSON),
          attestationObject: b64uEncode(cred.response.attestationObject),
        },
      };
      var f = await post("/admin/enroll/finish", body);
      if (!f.ok) throw new Error(f.data.error || "Enrolment failed.");
      say(st, "Passkey added.", "ok");
      window.location.assign(f.data.redirect || "/admin");
    } catch (e) {
      say(st, cancelled(e) ? "Cancelled. The link still works until it expires." : e.message, "error");
      btn.disabled = false;
    }
  }

  // Finishes a confirmation the server started (`{stepup}`): the passkey signs the challenge and the server runs the
  // stored action. Returns where to go next. An answer that is already `{redirect}` needed no prompt (the sign-in a
  // notification led to counts for its request once).
  async function finishStepup(data, st) {
    if (data.redirect && !data.stepup) return data.redirect;
    if (!data.stepup) throw new Error(data.error || "This action is not available.");
    var cred = await navigator.credentials.get({ publicKey: requestOptions(data.stepup.publicKey) });
    say(st, "Checking…");
    var f = await post("/admin/stepup", { id: data.stepup.id, credential: assertionJSON(cred) });
    if (!f.ok) throw new Error(f.data.error || "The confirmation failed. Nothing was changed.");
    return f.data.redirect;
  }

  // The first 12 bytes of SHA-256(endpoint), base64url: how the server lists a device without its endpoint.
  async function fingerprint(endpoint) {
    var d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(endpoint));
    return b64uEncode(d.slice(0, 12));
  }

  // Marks this browser's device in the settings list and warns when notifications were allowed here but the server
  // no longer has this browser's subscription (iOS drops subscriptions; the push service then answers 410).
  async function checkPush() {
    var lost = document.querySelector("[data-push-lost]");
    var rows = document.querySelectorAll("[data-fingerprint]");
    if (!lost && !rows.length) return;
    if (!pushSupported() || Notification.permission !== "granted" || !window.crypto || !crypto.subtle) return;
    var reg = await navigator.serviceWorker.getRegistration("/admin");
    var sub = reg && (await reg.pushManager.getSubscription());
    var mine = sub ? await fingerprint(sub.endpoint) : null;
    var listed = lost ? (lost.getAttribute("data-fingerprints") || "").split(" ").filter(Boolean) : [];
    rows.forEach(function (r) {
      if (r.getAttribute("data-fingerprint") === mine) {
        listed.push(mine);
        var chip = r.querySelector("[data-this-device]");
        if (chip) chip.hidden = false;
      }
    });
    if (lost && (!mine || listed.indexOf(mine) < 0)) lost.hidden = false;
    var btn = document.querySelector("[data-push-button]");
    if (btn && mine && listed.indexOf(mine) >= 0) btn.textContent = "Renew on this device";
  }

  // The app badge shows the waiting requests (installed app; Badging API where the browser has it).
  function updateBadge() {
    var el = document.querySelector("[data-pending-count]");
    if (!el || !("setAppBadge" in navigator)) return;
    var n = parseInt(el.getAttribute("data-pending-count"), 10) || 0;
    (n > 0 ? navigator.setAppBadge(n) : navigator.clearAppBadge()).catch(function () {});
  }

  // Forms that need a passkey confirmation: the server stores the exact action and answers with a challenge; the
  // passkey signs it; the server runs the stored action.
  async function stepup(form, submitter) {
    var st = form.querySelector(".status");
    if (!supported()) return say(st, "This browser cannot use passkeys.", "error");
    var buttons = form.querySelectorAll("button");
    buttons.forEach(function (b) { b.disabled = true; });
    say(st, "Confirm with your passkey…");
    try {
      var data = new URLSearchParams(new FormData(form, submitter));
      var begin = await post(form.getAttribute("action"), data.toString(), true);
      if (!begin.ok) throw new Error(begin.data.error || "This action is not available.");
      window.location.assign(await finishStepup(begin.data, st) || window.location.pathname);
    } catch (e) {
      say(st, cancelled(e) ? "Cancelled. Nothing was changed." : e.message, "error");
      buttons.forEach(function (b) { b.disabled = false; });
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    var loginBtn = document.querySelector('[data-action="login"]');
    if (loginBtn) loginBtn.addEventListener("click", function () { login(loginBtn); });

    var enrolBtn = document.querySelector('[data-action="enrol"]');
    if (enrolBtn) {
      // The token travels in the fragment, which never reaches a server log; drop it from the address bar.
      enrolBtn.setAttribute("data-token", window.location.hash.replace(/^#/, ""));
      if (window.location.hash) history.replaceState(null, "", window.location.pathname);
      enrolBtn.addEventListener("click", function () { enrol(enrolBtn); });
    }

    document.querySelectorAll("form").forEach(function (form) {
      form.addEventListener("submit", function (ev) {
        var msg = form.getAttribute("data-confirm");
        if (msg && !window.confirm(msg)) { ev.preventDefault(); return; }
        if (form.hasAttribute("data-stepup")) {
          ev.preventDefault();
          stepup(form, ev.submitter);
        }
      });
    });

    // The service worker makes the admin installable and shows notifications. Registering it is harmless where
    // push is unsupported.
    if ("serviceWorker" in navigator) registerWorker().catch(function () {});

    updateBadge();
    checkPush().catch(function () {});

    var pushForm = document.querySelector("[data-push-form]");
    if (pushForm && pushSupported()) {
      var hint = document.querySelector("[data-push-hint]");
      if (hint) hint.hidden = true;
      pushForm.hidden = false;
      var nameField = pushForm.querySelector('input[name="name"]');
      if (nameField && !nameField.value) nameField.value = deviceGuess();
      pushForm.addEventListener("submit", function (ev) {
        ev.preventDefault();
        pushOn(pushForm);
      });
    }

    // Shown-once secrets: copy to the clipboard, falling back to selecting the text.
    document.querySelectorAll("[data-copy]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var field = document.getElementById(btn.getAttribute("data-copy"));
        if (!field) return;
        field.select();
        var done = function () { btn.textContent = "Copied"; };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(field.value).then(done, function () { btn.textContent = "Select and copy"; });
        } else {
          btn.textContent = "Select and copy";
        }
      });
    });

    // Times are rendered in UTC by the server; show them in the reader's time zone when the browser can.
    document.querySelectorAll("time[datetime]").forEach(function (t) {
      var d = new Date(t.getAttribute("datetime"));
      if (isNaN(d)) return;
      t.title = t.textContent;
      t.textContent = d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
    });
  });
})();
