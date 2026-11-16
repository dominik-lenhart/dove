// Dove admin service worker (design 2026-11-16): shows a notification for each push and opens its page on a tap.
// No caching and no fetch handler: every page still comes from the server, with its session check.
"use strict";

var FALLBACK = "/admin/requests";

// Only plain admin paths: a push payload never makes the app open anything else.
function safeUrl(u) {
  return typeof u === "string" && /^\/admin(\/[A-Za-z0-9_-]+)*$/.test(u) ? u : FALLBACK;
}

self.addEventListener("install", function () {
  self.skipWaiting();
});

self.addEventListener("activate", function (e) {
  e.waitUntil(self.clients.claim());
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
  e.waitUntil(self.registration.showNotification(title, options));
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
