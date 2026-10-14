"use strict";

// Resolve the real client address behind a trusted reverse proxy. Only the
// entry appended by our own proxy is trusted; anything further left in the
// header was supplied by the client and may be forged.

function normalizeAddress(address) {
  if (typeof address !== "string") return "unknown";
  const trimmed = address.trim();
  if (trimmed.startsWith("::ffff:")) return trimmed.slice(7);
  return trimmed || "unknown";
}

function resolveClientIP(req, { trustProxy = false, hops = 1, header = "x-forwarded-for" } = {}) {
  const socketAddress = normalizeAddress(req.socket && req.socket.remoteAddress);
  if (!trustProxy) return socketAddress;

  const raw = req.headers && req.headers[header];
  if (!raw) return socketAddress;
  const value = Array.isArray(raw) ? raw.join(",") : String(raw);
  const entries = value.split(",").map((entry) => entry.trim()).filter(Boolean);
  if (entries.length === 0) return socketAddress;
  const index = entries.length - hops;
  return normalizeAddress(entries[index >= 0 ? index : 0]);
}

module.exports = { normalizeAddress, resolveClientIP };
