"use strict";

const serverless = require("serverless-http");
const { app } = require("../../server");

const expressHandler = serverless(app, {
  binary: ["image/*", "video/*", "application/pdf", "application/octet-stream"]
});

exports.handler = async (event, context) => {
  // Netlify rewrite paths include /.netlify/functions/api as a prefix.
  // Restore the public route before passing the event to Express.
  const prefix = "/.netlify/functions/api";
  const rawUrl = event.rawUrl || event.rawURL || "";
  let pathname = event.path || "/";
  let search = "";
  if (rawUrl) {
    try {
      const parsed = new URL(rawUrl);
      pathname = parsed.pathname || pathname;
      search = parsed.search || "";
    } catch {}
  }
  if (pathname.startsWith(prefix)) pathname = pathname.slice(prefix.length) || "/";
  if (!pathname.startsWith("/")) pathname = `/${pathname}`;
  const host = event.headers?.host || event.headers?.Host || "localhost";
  const proto = event.headers?.["x-forwarded-proto"] || "https";
  const cleanEvent = {
    ...event,
    path: pathname,
    rawPath: pathname,
    rawUrl: `${proto}://${host}${pathname}${search}`,
    rawQuery: search.replace(/^\?/, "")
  };
  return expressHandler(cleanEvent, context);
};
