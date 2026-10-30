"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { openDatabase } = require("../auth/db");
const { resolveTiers } = require("../policy/tiers");
const { createBudget, createDisabledBudget, nextMonthStart } = require("../metering/budget");
const { createUsageMeter, monthKey } = require("../metering/usage");
const { createMetrics } = require("../metrics");

const quietLog = { info() {}, warn() {}, error() {} };
const TIERS = resolveTiers(null, {
  rateLimitBps: 1024 * 1024, dnsServerIp: "8.8.8.8", maxUdpFlows: 8, maxConnectionsPerIp: 2, enableVmToVm: false,
});

async function db() {
  const database = openDatabase(":memory:");
  await database.migrate();
  return database;
}

function anonSession(id, clientIP = "9.9.9.9") {
  return { sessionId: id, identity: { kind: "anon", owner: `anon:${id}`, tier: "anon" }, clientIP, clientKey: clientIP, bytesSent: 0, bytesReceived: 0 };
}

test("budget states at, below and above each threshold", () => {
  const budget = createBudget({ throttleBytes: 100, pauseBytes: 200, tiers: ["anon", "free"] });
  const at = (bytes) => budget.evaluate({ bytes, now: Date.UTC(2026, 10, 15) }).state;
  assert.equal(at(0), "open");
  assert.equal(at(99), "open");
  assert.equal(at(100), "throttled");
  assert.equal(at(199), "throttled");
  assert.equal(at(200), "paused");
  assert.equal(budget.evaluate({ bytes: 200, now: Date.UTC(2026, 10, 15) }).pausedUntil, "2026-12-01");
  assert.equal(budget.evaluate({ bytes: 150, now: Date.UTC(2026, 10, 15) }).pausedUntil, null);
  assert.equal(budget.appliesTo("anon"), true);
  assert.equal(budget.appliesTo("user"), false);
});

test("the override wins when the budget is on and is ignored when it is off", () => {
  const budget = createBudget({ throttleBytes: 100, pauseBytes: 200, tiers: ["anon"] });
  assert.equal(budget.evaluate({ bytes: 500, forced: "open" }).state, "open");
  assert.equal(budget.evaluate({ bytes: 0, forced: "paused" }).state, "paused");
  const off = createDisabledBudget();
  assert.equal(off.enabled, false);
  assert.equal(off.evaluate({ bytes: 1e15, forced: "paused" }).state, "open");
  assert.equal(off.appliesTo("anon"), false);
});

test("pausedUntil is the next UTC month, including 31 December (year rollover)", () => {
  assert.equal(nextMonthStart(Date.UTC(2026, 9, 31, 23, 59)), "2026-11-01");
  assert.equal(nextMonthStart(Date.UTC(2026, 11, 31, 23, 59)), "2027-01-01");
  assert.equal(nextMonthStart(Date.UTC(2027, 1, 28)), "2027-03-01");
});

test("throttled rates never raise a tier's rate", () => {
  const low = createBudget({ throttleBytes: 1, pauseBytes: 2, throttleBps: 64 * 1024 });
  assert.deepEqual(low.throttledRates(TIERS.anon), { uploadBps: 64 * 1024, downloadBps: 64 * 1024 });
  const high = createBudget({ throttleBytes: 1, pauseBytes: 2, throttleBps: 1024 * 1024 });
  assert.deepEqual(high.throttledRates(TIERS.anon), { uploadBps: 256 * 1024, downloadBps: 512 * 1024 });
  assert.deepEqual(high.throttledRates({ uploadBps: null, downloadBps: null }), { uploadBps: 1024 * 1024, downloadBps: 1024 * 1024 });
});

test("with only anonymous traffic, the bytes are still written to relay_egress_monthly", async () => {
  const database = await db();
  const clock = Date.UTC(2026, 10, 3);
  const usage = createUsageMeter({ db: database, tiers: TIERS, now: () => clock, flushIntervalMs: 1e9, log: quietLog });
  const session = anonSession("a1");
  usage.track(session);
  session.bytesSent = 700;
  session.bytesReceived = 300;
  await usage.flush();
  assert.deepEqual(await database.get("SELECT bytes FROM relay_egress_monthly WHERE month = ?", [monthKey(clock)]), { bytes: 1000 });
  assert.equal(usage.budgetStatus().bytes, 1000);
  usage.close();
  await database.close();
});

test("a failed write still closes over-quota sessions and still pauses; the bytes are written later", async () => {
  const database = await db();
  const clock = Date.UTC(2026, 10, 3);
  const tiers = resolveTiers({ anon: { quotaBytes: 50 } }, {
    rateLimitBps: 1024, dnsServerIp: "8.8.8.8", maxUdpFlows: 8, maxConnectionsPerIp: 2, enableVmToVm: false,
  });
  const exceeded = [];
  const changes = [];
  const usage = createUsageMeter({
    db: database, tiers, now: () => clock, flushIntervalMs: 1e9, log: quietLog,
    budget: createBudget({ throttleBytes: 10, pauseBytes: 40, tiers: ["anon"] }),
    onQuotaExceeded: (session) => exceeded.push(session.sessionId),
    onBudgetChange: (prev, next) => changes.push(`${prev.state}->${next.state}`),
  });
  const session = anonSession("a1");
  usage.track(session);
  session.bytesSent = 60;

  const transaction = database.transaction;
  database.transaction = async () => {
    throw new Error("SQLITE_FULL: database or disk is full");
  };
  await assert.rejects(usage.flush(), /SQLITE_FULL/);
  assert.deepEqual(exceeded, ["a1"], "the over-quota session is closed although the write failed");
  assert.deepEqual(changes, ["open->paused"], "the budget is evaluated although the write failed");
  assert.equal(await database.get("SELECT bytes FROM relay_egress_monthly"), undefined);

  database.transaction = transaction;
  await usage.flush();
  assert.deepEqual(await database.get("SELECT bytes FROM relay_egress_monthly WHERE month = ?", [monthKey(clock)]), { bytes: 60 });
  usage.close();
  await database.close();
});

test("loadBudget adds the stored bytes and restores the override", async () => {
  const database = await db();
  const clock = Date.UTC(2026, 10, 10);
  await database.run("INSERT INTO relay_egress_monthly (month, bytes, forced) VALUES (?, 500, 'paused')", [monthKey(clock)]);
  const usage = createUsageMeter({
    db: database, tiers: TIERS, now: () => clock, flushIntervalMs: 1e9, log: quietLog,
    budget: createBudget({ throttleBytes: 1000, pauseBytes: 2000, tiers: ["anon"] }),
  });
  const session = anonSession("a1");
  usage.track(session);
  session.bytesSent = 20;
  await usage.flush();
  usage.close();

  const fresh = createUsageMeter({
    db: database, tiers: TIERS, now: () => clock, flushIntervalMs: 1e9, log: quietLog,
    budget: createBudget({ throttleBytes: 1000, pauseBytes: 2000, tiers: ["anon"] }),
  });
  await fresh.loadBudget();
  assert.deepEqual(
    { bytes: fresh.budgetStatus().bytes, forced: fresh.budgetStatus().forced, state: fresh.budgetStatus().state },
    { bytes: 520, forced: "paused", state: "paused" },
  );
  fresh.close();
  await database.close();
});

test("month rollover with no traffic: last month's pending bytes go to last month, then the budget resets", async () => {
  const database = await db();
  let clock = Date.UTC(2026, 10, 30, 23, 59);
  const changes = [];
  const usage = createUsageMeter({
    db: database, tiers: TIERS, now: () => clock, flushIntervalMs: 1e9, log: quietLog,
    budget: createBudget({ throttleBytes: 10, pauseBytes: 20, tiers: ["anon"] }),
    onBudgetChange: (prev, next) => changes.push(`${prev.state}->${next.state}`),
  });
  const session = anonSession("a1");
  usage.track(session);
  session.bytesSent = 30;
  // Counted in November, but the flush that stores it runs in December.
  usage.untrack(session);
  usage.evaluateBudget();
  assert.equal(usage.budgetStatus().state, "paused");
  await usage.setForced("paused", "op");

  clock = Date.UTC(2026, 11, 1, 0, 1);
  usage.evaluateBudget();
  assert.deepEqual(changes, ["open->paused", "paused->open"]);
  assert.deepEqual(
    { month: usage.budgetStatus().month, bytes: usage.budgetStatus().bytes, forced: usage.budgetStatus().forced },
    { month: "2026-12", bytes: 0, forced: null },
  );
  await usage.flush();
  assert.deepEqual(
    await database.all("SELECT month, bytes FROM relay_egress_monthly ORDER BY month"),
    [{ month: "2026-11", bytes: 30 }],
  );
  usage.close();
  await database.close();
});

test("setForced is stored and rejects other values", async () => {
  const database = await db();
  const clock = Date.UTC(2026, 10, 3);
  const usage = createUsageMeter({
    db: database, tiers: TIERS, now: () => clock, flushIntervalMs: 1e9, log: quietLog,
    budget: createBudget({ throttleBytes: 10, pauseBytes: 20, tiers: ["anon"] }),
  });
  const status = await usage.setForced("paused", "op");
  assert.equal(status.state, "paused");
  assert.deepEqual(await database.get("SELECT forced FROM relay_egress_monthly WHERE month = ?", [monthKey(clock)]), { forced: "paused" });
  assert.equal((await usage.setForced(null, "op")).state, "open");
  await assert.rejects(usage.setForced("closed", "op"), RangeError);
  usage.close();
  await database.close();
});

test("anonymous quotas group IPv6 addresses by /64", async () => {
  const tiers = resolveTiers({ anon: { quotaBytes: 50 } }, {
    rateLimitBps: 1024, dnsServerIp: "8.8.8.8", maxUdpFlows: 8, maxConnectionsPerIp: 2, enableVmToVm: false,
  });
  const usage = createUsageMeter({ db: null, tiers, flushIntervalMs: 1e9, log: quietLog });
  const session = { ...anonSession("a1", "2001:db8:0:1::5"), clientKey: "2001:db8:0:1::/64" };
  usage.track(session);
  session.bytesSent = 60;
  await usage.flush();
  const identity = { kind: "anon", owner: "anon:other", tier: "anon" };
  assert.equal(await usage.isOverQuota({ identity, clientIP: "2001:db8:0:1::9", clientKey: "2001:db8:0:1::/64" }), true);
  assert.equal(await usage.isOverQuota({ identity, clientIP: "2001:db8:0:2::9", clientKey: "2001:db8:0:2::/64" }), false);
  usage.close();
});

test("budget gauges: bytes, thresholds, one current state, override series", async () => {
  const metrics = createMetrics({ enabled: true });
  const clock = Date.UTC(2026, 10, 3);
  const usage = createUsageMeter({
    db: null, tiers: TIERS, now: () => clock, flushIntervalMs: 1e9, metrics, log: quietLog,
    budget: createBudget({ throttleBytes: 10, pauseBytes: 20, tiers: ["anon"] }),
  });
  const session = anonSession("a1");
  usage.track(session);
  session.bytesSent = 15;
  await usage.flush();
  let text = await metrics.render();
  assert.match(text, /rootlessrelay_budget_bytes 15/);
  assert.match(text, /rootlessrelay_budget_threshold_bytes\{threshold="pause"\} 20/);
  assert.match(text, /rootlessrelay_budget_state\{state="throttled"\} 1/);
  assert.match(text, /rootlessrelay_budget_state\{state="open"\} 0/);
  assert.match(text, /rootlessrelay_budget_forced\{state="open"\} 0/);
  assert.match(text, /rootlessrelay_budget_forced\{state="paused"\} 0/);
  await usage.setForced("open", "op");
  text = await metrics.render();
  assert.match(text, /rootlessrelay_budget_forced\{state="open"\} 1/);
  assert.match(text, /rootlessrelay_budget_state\{state="open"\} 1/);
  usage.close();
});
