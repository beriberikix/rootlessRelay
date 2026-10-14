"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { resolveTiers, validateTier } = require("../policy/tiers");

const CONTEXT = {
  rateLimitBps: 1024 * 1024,
  dnsServerIp: "8.8.8.8",
  maxUdpFlows: 256,
  maxConnectionsPerIp: 4,
  enableVmToVm: true,
};

test("default tiers are complete and frozen", () => {
  const tiers = resolveTiers(null, CONTEXT);
  assert.deepEqual(Object.keys(tiers), ["local", "anon", "user", "operator"]);
  assert.equal(tiers.local.uploadBps, null);
  assert.equal(tiers.local.downloadBps, CONTEXT.rateLimitBps);
  assert.equal(tiers.local.vmToVm, true);
  assert.deepEqual(tiers.anon.allowedTcpPorts, [80, 443]);
  assert.deepEqual(tiers.anon.dnsServers, ["8.8.8.8"]);
  assert.equal(tiers.anon.vmToVm, false);
  assert.equal(tiers.user.quotaPeriod, "month");
  assert.ok(Object.isFrozen(tiers.anon));
  for (const tier of Object.values(tiers)) validateTier("x", tier);
});

test("TIERS_JSON deep-merges and can add tiers based on user", () => {
  const tiers = resolveTiers(
    { anon: { maxSessionMs: 60000, allowedTcpPorts: [22, 443] }, pro: { uploadBps: null } },
    CONTEXT,
  );
  assert.equal(tiers.anon.maxSessionMs, 60000);
  assert.deepEqual(tiers.anon.allowedTcpPorts, [22, 443]);
  assert.equal(tiers.anon.synPerSec, 10);
  assert.equal(tiers.pro.uploadBps, null);
  assert.equal(tiers.pro.maxTcpConnections, 256);
});

test("invalid tier overrides are rejected", () => {
  assert.throws(() => resolveTiers({ anon: { bogus: 1 } }, CONTEXT), /unknown field/);
  assert.throws(() => resolveTiers({ anon: { synPerSec: -1 } }, CONTEXT), /non-negative/);
  assert.throws(() => resolveTiers({ anon: { allowedTcpPorts: [70000] } }, CONTEXT), /ports/);
  assert.throws(() => resolveTiers({ anon: { vmToVm: "yes" } }, CONTEXT), /boolean/);
  assert.throws(() => resolveTiers({ anon: { quotaPeriod: "week" } }, CONTEXT), /day/);
  assert.throws(() => resolveTiers([], CONTEXT), /object/);
  assert.throws(() => validateTier("t", { uploadBps: 1 }), /missing/);
});
