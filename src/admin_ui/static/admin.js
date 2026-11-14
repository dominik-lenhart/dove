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

  async function login(btn) {
    var st = btn.parentNode.querySelector(".status");
    if (!supported()) return say(st, "This browser cannot use passkeys.", "error");
    btn.disabled = true;
    say(st, "Waiting for your passkey…");
    try {
      var o = await post("/admin/login/options", {});
      if (!o.ok) throw new Error(o.data.error || "Sign-in is not available.");
      var cred = await navigator.credentials.get({ publicKey: requestOptions(o.data.publicKey) });
      var f = await post("/admin/login/finish", { id: o.data.id, credential: assertionJSON(cred) });
      if (!f.ok) throw new Error(f.data.error || "Sign-in failed.");
      say(st, "Signed in.", "ok");
      window.location.assign(f.data.redirect || "/admin");
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
      if (!begin.ok || !begin.data.stepup) throw new Error(begin.data.error || "This action is not available.");
      var cred = await navigator.credentials.get({ publicKey: requestOptions(begin.data.stepup.publicKey) });
      say(st, "Checking…");
      var f = await post("/admin/stepup", { id: begin.data.stepup.id, credential: assertionJSON(cred) });
      if (!f.ok) throw new Error(f.data.error || "The confirmation failed. Nothing was changed.");
      window.location.assign(f.data.redirect || window.location.pathname);
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

    // Times are rendered in UTC by the server; show them in the reader's time zone when the browser can.
    document.querySelectorAll("time[datetime]").forEach(function (t) {
      var d = new Date(t.getAttribute("datetime"));
      if (isNaN(d)) return;
      t.title = t.textContent;
      t.textContent = d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
    });
  });
})();
