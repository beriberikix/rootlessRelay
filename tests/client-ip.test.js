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
