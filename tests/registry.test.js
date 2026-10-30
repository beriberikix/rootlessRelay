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

test("refusals carry close codes, and a paused budget is checked first", () => {
  const ctx = { DHCP_START: 15, DHCP_END: 16, usedIPs: new Set([2]) };
  const tiers = { anon: { maxSessionsPerOwner: 1, maxSessionsPerIP: 1 }, user: { maxSessionsPerOwner: 5, maxSessionsPerIP: 5 } };
  let state = "open";
  const registry = createSessionRegistry({
    ctx,
    tiers,
    budget: { appliesTo: (tier) => tier === "anon" },
    budgetStatus: () => ({ state, pausedUntil: state === "paused" ? "2026-12-01" : null }),
  });
  const anon = { identity: { owner: "anon:1", tier: "anon" }, clientIP: "1.1.1.1" };
  const first = registry.admit(anon);
  assert.equal(first.ok, true);
  assert.deepEqual(
    (({ ok, status, close, reason }) => ({ ok, status, close, reason }))(registry.admit({ identity: { owner: "anon:2", tier: "anon" }, clientIP: "1.1.1.1" })),
    { ok: false, status: 429, close: 1013, reason: "connection limit reached for this address" },
  );
  assert.equal(registry.admit({ identity: anon.identity, clientIP: "2.2.2.2" }).reason, "session limit reached for this account");
  registry.admit({ identity: { owner: "user:9", tier: "user" }, clientIP: "3.3.3.3" });
  assert.equal(registry.poolFull(), true);
  const full = registry.admit({ identity: { owner: "user:8", tier: "user" }, clientIP: "4.4.4.4" });
  assert.deepEqual([full.status, full.close, full.reason], [503, 1013, "relay full"]);

  // Paused: budget tiers get the paused reason before any other check;
  // other tiers are unaffected by the budget.
  state = "paused";
  const paused = registry.admit(anon);
  assert.deepEqual([paused.ok, paused.close, paused.reason], [false, 1008, "free tier paused until 2026-12-01"]);
  assert.equal(registry.admit({ identity: { owner: "user:8", tier: "user" }, clientIP: "4.4.4.4" }).reason, "relay full");
});

test("per-address limits count an IPv6 /64 as one address", () => {
  const ctx = { DHCP_START: 15, DHCP_END: 30, usedIPs: new Set([2]) };
  const tiers = { anon: { maxSessionsPerOwner: 5, maxSessionsPerIP: 2 } };
  const registry = createSessionRegistry({ ctx, tiers });
  const admit = (owner, clientIP) => registry.admit({ identity: { owner, tier: "anon" }, clientIP });
  assert.equal(admit("anon:1", "2001:db8:0:1::1").ok, true);
  assert.equal(admit("anon:2", "2001:db8:0:1::2").ok, true);
  assert.equal(admit("anon:3", "2001:db8:0:1:ffff::3").ok, false, "same /64");
  assert.equal(admit("anon:4", "2001:db8:0:2::1").ok, true, "another /64");
  // Registered sessions are counted under the same key.
  registry.add({ sessionId: "s", identity: { owner: "anon:5", tier: "anon" }, clientIP: "2001:db8:0:3::1", clientKey: "2001:db8:0:3::/64" });
  assert.equal(registry.countForIP("2001:db8:0:3::/64"), 1);
});

test("closeTier closes only the listed tiers", () => {
  const ctx = { DHCP_START: 15, DHCP_END: 30, usedIPs: new Set([2]) };
  const registry = createSessionRegistry({ ctx, tiers: {} });
  const closed = [];
  const session = (id, tier) => ({
    sessionId: id,
    identity: { owner: `${tier}:${id}`, tier },
    clientIP: "1.1.1.1",
    ws: { close: (code, reason) => closed.push([id, code, reason]) },
  });
  registry.add(session("a", "anon"));
  registry.add(session("f", "free"));
  registry.add(session("u", "user"));
  assert.equal(registry.closeTier(["anon", "free"], 1008, "free tier paused until 2026-12-01"), 2);
  assert.deepEqual(closed.map(([id]) => id).sort(), ["a", "f"]);
  assert.deepEqual(closed[0].slice(1), [1008, "free tier paused until 2026-12-01"]);
});
