"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  HOSTED_DENY_CIDRS,
  createEgressPolicy,
  inCidr,
  ipv4ToInt,
  parseCidr,
} = require("../policy/egress");

test("ipv4ToInt and CIDR math", () => {
  assert.equal(ipv4ToInt("10.0.2.15"), (10 << 24 >>> 0) + (2 << 8) + 15);
  assert.equal(ipv4ToInt("256.1.1.1"), null);
  assert.equal(ipv4ToInt("1.2.3"), null);
  const range = parseCidr("172.16.0.0/12");
  assert.equal(inCidr(ipv4ToInt("172.31.255.255"), range), true);
  assert.equal(inCidr(ipv4ToInt("172.32.0.0"), range), false);
  assert.equal(inCidr(ipv4ToInt("8.8.8.8"), parseCidr("0.0.0.0/0")), true);
  assert.equal(inCidr(ipv4ToInt("1.1.1.1"), parseCidr("1.1.1.1")), true);
  assert.throws(() => parseCidr("10.0.0.0/33"), RangeError);
  assert.throws(() => parseCidr("bogus"), RangeError);
  assert.ok(HOSTED_DENY_CIDRS.includes("169.254.0.0/16"));
});

function hostedPolicy(overrides = {}) {
  return createEgressPolicy({
    mode: "hosted",
    localAddresses: () => new Set(["203.0.113.200", "34.1.2.3"]),
    denyPorts: [25],
    ...overrides,
  });
}

test("hosted mode denies metadata, loopback, private, CGNAT, multicast and local addresses", () => {
  const policy = hostedPolicy();
  for (const ip of [
    "169.254.169.254",
    "127.0.0.1",
    "10.0.2.2",
    "10.255.255.255",
    "172.16.5.5",
    "192.168.1.1",
    "100.64.0.1",
    "224.0.0.251",
    "255.255.255.255",
    "0.0.0.0",
  ]) {
    const verdict = policy.check(ip, 80, "tcp");
    assert.equal(verdict.allow, false, `${ip} should be denied`);
    assert.match(verdict.reason, /denied-range/);
  }
  assert.deepEqual(policy.check("34.1.2.3", 8001, "tcp"), {
    allow: false,
    reason: "local-address",
  });
  assert.equal(policy.check("1.1.1.1", 443, "tcp").allow, true);
  assert.equal(policy.check("8.8.8.8", 53, "udp").allow, true);
});

test("denied ports apply before allow lists and in every mode", () => {
  const hosted = hostedPolicy({ allowCidrs: ["0.0.0.0/0"] });
  assert.deepEqual(hosted.check("1.2.3.4", 25, "tcp"), {
    allow: false,
    reason: "denied-port",
  });
  const open = createEgressPolicy({ mode: "open", denyPorts: [25] });
  assert.equal(open.check("1.2.3.4", 25, "tcp").allow, false);
  assert.equal(open.check("127.0.0.1", 8080, "tcp").allow, true);
});

test("allow list carves exceptions out of the deny list", () => {
  const policy = hostedPolicy({ allowCidrs: ["127.0.0.0/8", "10.1.0.0/16"] });
  assert.deepEqual(policy.check("127.0.0.1", 9000, "tcp"), {
    allow: true,
    reason: "allow-list",
  });
  assert.equal(policy.check("10.1.4.4", 22, "tcp").allow, true);
  assert.equal(policy.check("10.2.4.4", 22, "tcp").allow, false);
});

test("extra deny CIDRs extend the open policy and invalid addresses are rejected", () => {
  const policy = createEgressPolicy({ mode: "open", denyCidrs: ["198.41.0.0/24"] });
  assert.equal(policy.check("198.41.0.4", 443, "tcp").allow, false);
  assert.equal(policy.check("198.41.1.4", 443, "tcp").allow, true);
  assert.deepEqual(policy.check("not-an-ip", 443, "tcp"), {
    allow: false,
    reason: "invalid-address",
  });
  assert.throws(() => createEgressPolicy({ mode: "strict" }), RangeError);
});
