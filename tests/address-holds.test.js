"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { createAddressHolds } = require("../policy/address_holds");

function makeCtx() {
  return {
    poolPrefix: "10.0.2.",
    macToIP: new Map(),
    ipToSession: new Map(),
    usedIPs: new Set([2]),
  };
}

function fakeTimers() {
  const pending = new Set();
  return {
    pending,
    setTimer(fn, ms) {
      const timer = { fn, ms };
      pending.add(timer);
      return timer;
    },
    clearTimer(timer) {
      pending.delete(timer);
    },
    fireAll() {
      for (const timer of [...pending]) {
        pending.delete(timer);
        timer.fn();
      }
    },
  };
}

// A session that holds 10.0.2.<octet> with a MAC, as relay.js leaves it.
function liveSession(ctx, { octet = 15, mac = "52:54:00:00:00:01" } = {}) {
  const ip = `10.0.2.${octet}`;
  const session = { vmIP: ip, vmMAC: mac };
  ctx.usedIPs.add(octet);
  ctx.macToIP.set(mac, ip);
  ctx.ipToSession.set(ip, session);
  return session;
}

function makeHolds(ctx, timers, holdMs = 60000) {
  let t = 1000;
  return createAddressHolds({
    ctx,
    holdMs,
    now: () => t++,
    setTimer: timers.setTimer,
    clearTimer: timers.clearTimer,
  });
}

test("a closed session's address stays reserved until the hold expires", () => {
  const ctx = makeCtx();
  const timers = fakeTimers();
  const holds = makeHolds(ctx, timers);
  const session = liveSession(ctx);

  assert.equal(holds.hold(session, "user:1"), true);
  assert.equal(ctx.ipToSession.has("10.0.2.15"), false, "no longer routable");
  assert.equal(ctx.macToIP.has("52:54:00:00:00:01"), false, "MAC binding dropped");
  assert.ok(ctx.usedIPs.has(15), "DHCP still skips it");
  assert.equal(holds.size, 1);

  timers.fireAll();
  assert.equal(ctx.usedIPs.has(15), false, "returned to the pool");
  assert.equal(holds.size, 0);
});

test("no hold when disabled, without an address, or for a session that lost its address", () => {
  const ctx = makeCtx();
  const timers = fakeTimers();
  assert.equal(makeHolds(ctx, timers, 0).hold(liveSession(ctx), "user:1"), false);

  const holds = makeHolds(ctx, timers);
  assert.equal(holds.hold({ vmIP: null, vmMAC: "x" }, "user:1"), false);

  const stale = liveSession(ctx, { octet: 16, mac: "52:54:00:00:00:02" });
  ctx.ipToSession.set("10.0.2.16", { other: true });
  assert.equal(holds.hold(stale, "user:1"), false);
  assert.equal(holds.size, 0);
});

test("DHCP with the same owner and MAC gets the held address back", () => {
  const ctx = makeCtx();
  const timers = fakeTimers();
  const holds = makeHolds(ctx, timers);
  holds.hold(liveSession(ctx), "user:1");

  assert.equal(holds.reclaimForMac("user:1", "52:54:00:00:00:01"), "10.0.2.15");
  assert.equal(ctx.macToIP.get("52:54:00:00:00:01"), "10.0.2.15", "allocateIP will return it");
  assert.equal(holds.size, 0);
  assert.equal(timers.pending.size, 0, "expiry cancelled");
});

test("another owner with the same MAC does not get the held address", () => {
  const ctx = makeCtx();
  const holds = makeHolds(ctx, fakeTimers());
  holds.hold(liveSession(ctx), "user:1");

  assert.equal(holds.reclaimForMac("user:2", "52:54:00:00:00:01"), null);
  assert.equal(ctx.macToIP.has("52:54:00:00:00:01"), false);
  assert.equal(holds.size, 1);
});

test("a static claim is refused for another owner and takes the hold for the same owner", () => {
  const ctx = makeCtx();
  const holds = makeHolds(ctx, fakeTimers());
  holds.hold(liveSession(ctx), "user:1");

  assert.equal(holds.mayClaim("user:2", "10.0.2.15"), false);
  assert.equal(holds.isHeldFor("user:2", "10.0.2.15"), false);
  assert.equal(holds.isHeldFor("user:1", "10.0.2.15"), true);
  assert.equal(holds.mayClaim("user:1", "10.0.2.15"), true);
  assert.equal(holds.size, 0);
  assert.equal(holds.mayClaim("user:2", "10.0.2.99"), true, "unheld addresses are free");
});

test("expiry keeps an address that a session took in the meantime", () => {
  const ctx = makeCtx();
  const timers = fakeTimers();
  const holds = makeHolds(ctx, timers);
  holds.hold(liveSession(ctx), "user:1");
  const expiry = [...timers.pending][0];

  ctx.ipToSession.set("10.0.2.15", { identity: { owner: "user:1" } });
  expiry.fn();
  assert.ok(ctx.usedIPs.has(15));
});

test("eviction frees the hold closest to expiring", () => {
  const ctx = makeCtx();
  const holds = makeHolds(ctx, fakeTimers());
  holds.hold(liveSession(ctx, { octet: 15, mac: "a" }), "user:1");
  holds.hold(liveSession(ctx, { octet: 16, mac: "b" }), "user:1");

  assert.equal(holds.evictOldest(), true);
  assert.equal(ctx.usedIPs.has(15), false);
  assert.ok(ctx.usedIPs.has(16));
  assert.equal(holds.evictOldest(), true);
  assert.equal(holds.evictOldest(), false);
});
