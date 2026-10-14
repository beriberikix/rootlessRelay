"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { createSessionRegistry } = require("../server/connection");

test("admission reserves slots, so parallel upgrades cannot overshoot the caps", () => {
  const ctx = { DHCP_START: 15, DHCP_END: 20, usedIPs: new Set([2]) };
  const tiers = { user: { maxSessionsPerOwner: 2, maxSessionsPerIP: 3 } };
  const registry = createSessionRegistry({ ctx, tiers });
  const who = { identity: { owner: "user:1", tier: "user" }, clientIP: "1.1.1.1" };

  const first = registry.admit(who);
  const second = registry.admit(who);
  const third = registry.admit(who);
  assert.equal(first.ok, true);
  assert.equal(second.ok, true);
  assert.equal(third.ok, false, "two reservations already fill the per-account cap");
  assert.equal(third.status, 429);

  // A failed upgrade gives its slot back; releasing twice is harmless.
  second.release();
  second.release();
  const retry = registry.admit(who);
  assert.equal(retry.ok, true);

  // Registering a session turns the reservation into a real slot.
  registry.add({ sessionId: "a", identity: who.identity, clientIP: who.clientIP });
  first.release();
  assert.equal(registry.countFor("user:1"), 2);
  assert.equal(registry.admit(who).ok, false);

  // The pool counts reservations too: 6 addresses in 15..20.
  const many = [];
  for (let i = 0; i < 10; i += 1) {
    many.push(registry.admit({ identity: { owner: `user:x${i}`, tier: "user" }, clientIP: `9.9.9.${i}` }));
  }
  assert.equal(many.filter((v) => v.ok).length, 6 - 2, "two slots are held by user:1");
  assert.equal(many.find((v) => !v.ok).status, 503);
});
