// Dove admin service worker (design 2026-11-16, PLAN A83): shows a notification for each push, opens its page on a
// tap, keeps the app badge at the number of waiting requests, and shows a static offline page when the server cannot
// be reached. It caches nothing but that page and the files it loads (the list below, filled in by the server): every
// other page still comes from the server, with its session check, and is never stored on the device.
"use strict";

var VERSION = "__VERSION__";
var OFFLINE = ["__OFFLINE__"];
var CACHE = "dove-offline-" + VERSION;
var FALLBACK = "/admin/requests";

// Only plain admin paths: a push payload never makes the app open anything else.
function safeUrl(u) {
  return typeof u === "string" && /^\/admin(\/[A-Za-z0-9_-]+)*$/.test(u) ? u : FALLBACK;
}

function setBadge(n) {
  var nav = self.navigator;
  if (!nav || !("setAppBadge" in nav)) return Promise.resolve();
  var p = n > 0 ? nav.setAppBadge(n) : nav.clearAppBadge();
  return p.catch(function () {});
}

self.addEventListener("install", function (e) {
  e.waitUntil(
    caches
      .open(CACHE)
      .then(function (c) { return c.addAll(OFFLINE); })
      .catch(function () {})
      .then(function () { return self.skipWaiting(); }),
  );
});

self.addEventListener("activate", function (e) {
  e.waitUntil(
    caches
      .keys()
      .then(function (keys) {
        return Promise.all(
          keys.filter(function (k) { return k !== CACHE; }).map(function (k) { return caches.delete(k); }),
        );
      })
      .then(function () { return self.clients.claim(); }),
  );
});

// Network first, always. Only when the network fails: a page navigation gets the offline page, and one of the
// offline page's own files gets its cached copy. Nothing that comes from the network is stored.
self.addEventListener("fetch", function (e) {
  var req = e.request;
  if (req.method !== "GET") return;
  var url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (req.mode === "navigate") {
    e.respondWith(
      fetch(req).catch(function () {
        return caches.match("/admin/offline").then(function (r) { return r || Response.error(); });
      }),
    );
  } else if (OFFLINE.indexOf(url.pathname + url.search) >= 0) {
    e.respondWith(
      fetch(req).catch(function () {
        return caches.match(req).then(function (r) { return r || Response.error(); });
      }),
    );
  }
});

self.addEventListener("push", function (e) {
  var d = {};
  try {
    d = e.data ? e.data.json() : {};
  } catch (err) {
    d = {};
  }
  var title = typeof d.title === "string" && d.title ? d.title : "Dove";
  var options = {
    body: typeof d.body === "string" ? d.body : "Something needs your attention.",
    data: { url: safeUrl(d.url) },
    icon: "/admin/static/icon-192.png",
  };
  // Same tag: a repeated push for one request replaces its notification instead of adding another.
  if (typeof d.tag === "string" && d.tag) options.tag = d.tag;
  var work = [self.registration.showNotification(title, options)];
  if (typeof d.badge === "number" && d.badge >= 0) work.push(setBadge(Math.floor(d.badge)));
  e.waitUntil(Promise.all(work));
});

self.addEventListener("notificationclick", function (e) {
  e.notification.close();
  var url = safeUrl(e.notification.data && e.notification.data.url);
  e.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(function (open) {
      for (var i = 0; i < open.length; i++) {
        var c = open[i];
        if ("focus" in c && "navigate" in c) {
          return c.navigate(url).then(function (n) { return (n || c).focus(); }, function () { return self.clients.openWindow(url); });
        }
      }
      return self.clients.openWindow(url);
    }),
  );
});
