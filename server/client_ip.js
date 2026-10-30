"use strict";

// Resolve the real client address behind a trusted reverse proxy. Only the
// entry appended by our own proxy is trusted; anything further left in the
// header was supplied by the client and may be forged.
//
// When the service is also reachable without going through that proxy (for
// example the platform hostname next to a CDN in front), a client can send
// the header itself. `trustedProxies` closes that gap: the header is used
// only when the immediate peer is inside one of those ranges. The peer is the
// socket address, or `peerHeader` when the platform's own edge reports it
// (Fly.io sets Fly-Client-IP and overwrites any client-supplied value).

const net = require("node:net");

function normalizeAddress(address) {
  if (typeof address !== "string") return "unknown";
  const trimmed = address.trim();
  if (trimmed.startsWith("::ffff:")) return trimmed.slice(7);
  return trimmed || "unknown";
}

function validAddress(address) {
  return net.isIP(address) !== 0 ? address : null;
}

// "1.2.3.0/24,2400:cb00::/32" -> net.BlockList, or null when empty.
function parseProxyRanges(list) {
  const entries = (Array.isArray(list) ? list : String(list || "").split(","))
    .map((entry) => entry.trim())
    .filter(Boolean);
  if (entries.length === 0) return null;
  const blockList = new net.BlockList();
  for (const entry of entries) {
    const [address, bits] = entry.split("/");
    const family = net.isIP(address);
    if (!family) throw new RangeError(`invalid proxy range "${entry}"`);
    const type = family === 6 ? "ipv6" : "ipv4";
    const prefix = bits === undefined ? (family === 6 ? 128 : 32) : Number(bits);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > (family === 6 ? 128 : 32)) {
      throw new RangeError(`invalid prefix in proxy range "${entry}"`);
    }
    blockList.addSubnet(address, prefix, type);
  }
  return blockList;
}

function inRanges(blockList, address) {
  const family = net.isIP(address);
  return family !== 0 && blockList.check(address, family === 6 ? "ipv6" : "ipv4");
}

function firstHeader(req, name) {
  const raw = req.headers && req.headers[name];
  if (!raw) return null;
  return Array.isArray(raw) ? raw.join(",") : String(raw);
}

function resolveClientIP(req, {
  trustProxy = false,
  hops = 1,
  header = "x-forwarded-for",
  peerHeader = null,
  trustedProxies = null,
} = {}) {
  const socketAddress = normalizeAddress(req.socket && req.socket.remoteAddress);
  if (!trustProxy) return socketAddress;

  let peer = socketAddress;
  if (peerHeader) {
    const reported = firstHeader(req, peerHeader);
    const candidate = reported ? validAddress(normalizeAddress(reported.split(",")[0])) : null;
    if (candidate) peer = candidate;
  }
  if (trustedProxies && !inRanges(trustedProxies, peer)) return peer;

  const value = firstHeader(req, header);
  if (!value) return peer;
  const entries = value.split(",").map((entry) => entry.trim()).filter(Boolean);
  if (entries.length === 0) return peer;
  const index = entries.length - hops;
  return validAddress(normalizeAddress(entries[index >= 0 ? index : 0])) || peer;
}

// The rate-limit key for an address: IPv4 as is, IPv6 by its /64 (one
// subscriber usually holds a whole /64, so per-address keys are free to
// rotate).
function rateKey(ip) {
  const address = String(ip).split("%")[0];
  if (!address.includes(":")) return address;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  if (mapped) return mapped[1];
  const [head, tail] = address.split("::");
  const front = head ? head.split(":") : [];
  const back = tail ? tail.split(":") : [];
  const groups = tail === undefined ? front : [...front, ...Array(Math.max(0, 8 - front.length - back.length)).fill("0"), ...back];
  return `${groups.slice(0, 4).map((g) => parseInt(g || "0", 16).toString(16)).join(":")}::/64`;
}

module.exports = { normalizeAddress, parseProxyRanges, rateKey, resolveClientIP };
