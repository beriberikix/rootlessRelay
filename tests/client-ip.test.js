"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { normalizeAddress, resolveClientIP } = require("../server/client_ip");

function req(remoteAddress, headers = {}) {
  return { socket: { remoteAddress }, headers };
}

test("without trust proxy the socket address wins", () => {
  assert.equal(
    resolveClientIP(req("::ffff:203.0.113.9", { "x-forwarded-for": "1.1.1.1" })),
    "203.0.113.9",
  );
  assert.equal(resolveClientIP(req(undefined)), "unknown");
});

test("with trust proxy the entry appended by our proxy is used", () => {
  const options = { trustProxy: true, hops: 1, header: "x-forwarded-for" };
  assert.equal(
    resolveClientIP(req("10.0.0.5", { "x-forwarded-for": "9.9.9.9, 203.0.113.4" }), options),
    "203.0.113.4",
  );
  assert.equal(
    resolveClientIP(req("10.0.0.5", { "x-forwarded-for": "9.9.9.9, 203.0.113.4, 10.0.0.9" }), {
      ...options,
      hops: 2,
    }),
    "203.0.113.4",
  );
  assert.equal(resolveClientIP(req("10.0.0.5", {}), options), "10.0.0.5");
  assert.equal(
    resolveClientIP(req("10.0.0.5", { "x-forwarded-for": "8.8.8.8" }), { ...options, hops: 3 }),
    "8.8.8.8",
  );
});

test("custom header and array header values", () => {
  assert.equal(
    resolveClientIP(req("10.0.0.5", { "cf-connecting-ip": "198.51.100.7" }), {
      trustProxy: true,
      hops: 1,
      header: "cf-connecting-ip",
    }),
    "198.51.100.7",
  );
  assert.equal(
    resolveClientIP(req("10.0.0.5", { "x-forwarded-for": ["1.1.1.1", "2.2.2.2"] }), {
      trustProxy: true,
      hops: 1,
      header: "x-forwarded-for",
    }),
    "2.2.2.2",
  );
  assert.equal(normalizeAddress("  ::ffff:1.2.3.4 "), "1.2.3.4");
});

test("the forwarded header is believed only from trusted proxy ranges", () => {
  const { parseProxyRanges } = require("../server/client_ip");
  const cloudflare = parseProxyRanges("173.245.48.0/20, 2606:4700::/32");
  const opts = { trustProxy: true, header: "cf-connecting-ip", peerHeader: "fly-client-ip", trustedProxies: cloudflare };
  const req = (headers, remoteAddress = "172.16.0.2") => ({ headers, socket: { remoteAddress } });

  // Through Cloudflare: Fly reports a Cloudflare edge as the peer.
  assert.equal(resolveClientIP(req({ "fly-client-ip": "173.245.49.10", "cf-connecting-ip": "203.0.113.9" }), opts), "203.0.113.9");
  assert.equal(resolveClientIP(req({ "fly-client-ip": "2606:4700::1", "cf-connecting-ip": "2001:db8::5" }), opts), "2001:db8::5");
  // Straight to the platform hostname: a forged header is ignored.
  assert.equal(resolveClientIP(req({ "fly-client-ip": "198.51.100.7", "cf-connecting-ip": "203.0.113.9" }), opts), "198.51.100.7");
  // Garbage in the trusted header falls back to the peer.
  assert.equal(resolveClientIP(req({ "fly-client-ip": "173.245.49.10", "cf-connecting-ip": "not-an-ip" }), opts), "173.245.49.10");
  // No peer header: the socket address is the peer.
  assert.equal(resolveClientIP(req({ "cf-connecting-ip": "203.0.113.9" }, "::ffff:173.245.48.1"), { ...opts, peerHeader: null }), "203.0.113.9");
  assert.throws(() => parseProxyRanges("10.0.0.0/33"), RangeError);
  assert.throws(() => parseProxyRanges("nope/8"), RangeError);
  assert.equal(parseProxyRanges(""), null);
});
