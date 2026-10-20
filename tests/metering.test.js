"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { openDatabase } = require("../auth/db");
const { resolveTiers } = require("../policy/tiers");
const { createAuditLog, noopAudit } = require("../metering/audit");
const { createUsageMeter, dayKey, monthKey } = require("../metering/usage");
const { createMetrics } = require("../metrics");

const quietLog = { info() {}, warn() {}, error() {} };

async function db() {
  const database = openDatabase(":memory:");
  await database.migrate();
  return database;
}

test("audit log batches inserts, updates rows on finish, queries and prunes", async () => {
  const database = await db();
  let clock = 1_000_000;
  const audit = createAuditLog({ db: database, retentionDays: 1, now: () => clock, log: quietLog, batchMs: 1e9, pruneIntervalMs: 1e9 });
  audit.record({ key: "s1:a", owner: "user:1", sessionId: "s1", proto: "tcp", dstIP: "1.1.1.1", dstPort: 443, verdict: "allow", startedAt: clock });
  audit.record({ key: "s1:b", owner: "user:1", sessionId: "s1", proto: "tcp", dstIP: "1.1.1.2", dstPort: 80, verdict: "allow", startedAt: clock });
  audit.record({ owner: "user:1", sessionId: "s1", proto: "udp", dstIP: "10.0.0.1", dstPort: 53, verdict: "deny:denied-range:10.0.0.0/8", startedAt: clock, endedAt: clock });
  // Finish before flush merges into the pending row.
  audit.finish("s1:a", { endedAt: clock + 10, bytesIn: 100, bytesOut: 200 });
  assert.equal(audit.pendingCount(), 3);
  await audit.flush();
  assert.equal(audit.pendingCount(), 0);
  // Finish after flush becomes an update.
  audit.finish("s1:b", { endedAt: clock + 20, bytesIn: 5, bytesOut: 6, error: "reset" });
  assert.equal(audit.pendingCount(), 1);
  await audit.flush();

  const rows = await audit.query({ owner: "user:1" });
  assert.equal(rows.length, 3);
  const a = rows.find((row) => row.dstIP === "1.1.1.1");
  assert.deepEqual({ bytesIn: a.bytesIn, bytesOut: a.bytesOut, endedAt: a.endedAt }, { bytesIn: 100, bytesOut: 200, endedAt: clock + 10 });
  const b = rows.find((row) => row.dstIP === "1.1.1.2");
  assert.deepEqual({ bytesIn: b.bytesIn, bytesOut: b.bytesOut, endedAt: b.endedAt }, { bytesIn: 5, bytesOut: 6, endedAt: clock + 20 });
  assert.equal((await audit.query({ verdict: "deny" })).length, 1);
  assert.equal((await audit.query({ verdict: "allow" })).length, 2);
  assert.equal((await audit.query({ owner: "user:2" })).length, 0);
  assert.equal((await audit.query({ since: clock + 1 })).length, 0);

  // Abuse lookup: destination plus a moment, matching connections open then.
  audit.record({ key: "s2:c", owner: "user:2", sessionId: "s2", proto: "tcp", dstIP: "1.1.1.1", dstPort: 443, verdict: "allow", startedAt: clock + 1000 });
  await audit.flush();
  const at = (t, windowMs = 0) => audit.query({ dstIP: "1.1.1.1", at: t, windowMs }).then((r) => r.map((row) => row.owner).sort());
  assert.deepEqual(await at(clock + 5), ["user:1"]);
  assert.deepEqual(await at(clock + 500), [], "s1:a ended at +10 and s2:c starts at +1000");
  assert.deepEqual(await at(clock + 500, 600), ["user:1", "user:2"]);
  assert.deepEqual(await at(clock + 10_000), ["user:2"], "a still-open connection matches any later moment");
  assert.equal((await audit.query({ dstIP: "1.1.1.1", dstPort: 80 })).length, 0);
  assert.equal((await audit.query({ dstIP: "1.1.1.2", dstPort: 80 })).length, 1);

  clock += 2 * 24 * 60 * 60 * 1000;
  assert.equal(await audit.prune(), 4);
  audit.close();
  const disabled = noopAudit();
  disabled.record({});
  assert.deepEqual(await disabled.query({}), []);
  await database.close();
});

test("usage meter accumulates per-org months in SQLite and anon days in memory, and enforces quotas", async () => {
  const database = await db();
  const tiers = resolveTiers({ user: { quotaBytes: 1000 }, anon: { quotaBytes: 50 } }, {
    rateLimitBps: 1, dnsServerIp: "8.8.8.8", maxUdpFlows: 8, maxConnectionsPerIp: 2, enableVmToVm: false,
  });
  let clock = Date.UTC(2026, 9, 14, 12);
  const exceeded = [];
  const metrics = createMetrics({ enabled: true });
  const usage = createUsageMeter({
    db: database, tiers, now: () => clock, flushIntervalMs: 1e9, metrics, log: quietLog,
    onQuotaExceeded: (session) => exceeded.push(session.sessionId),
  });

  const userSession = { sessionId: "u1", identity: { kind: "user", owner: "org:7", orgId: 7, userId: 7, tier: "user" }, clientIP: "1.1.1.1", bytesSent: 0, bytesReceived: 0 };
  const anonSession = { sessionId: "a1", identity: { kind: "anon", owner: "anon:x", tier: "anon" }, clientIP: "9.9.9.9", bytesSent: 0, bytesReceived: 0 };
  usage.track(userSession);
  usage.track(anonSession);
  userSession.bytesSent = 300;
  userSession.bytesReceived = 100;
  anonSession.bytesSent = 30;
  await usage.flush();
  assert.deepEqual(exceeded, []);
  assert.equal(await usage.periodUsage(userSession), 400);
  assert.equal(await usage.periodUsage(anonSession), 30);
  const month = monthKey(clock);
  assert.deepEqual(await usage.monthly(7), [{ month, bytesIn: 100, bytesOut: 300, sessions: 0 }]);

  anonSession.bytesSent = 60;
  userSession.bytesSent = 950;
  await usage.flush();
  assert.deepEqual(exceeded.sort(), ["a1", "u1"]);
  assert.equal(await usage.isOverQuota({ identity: userSession.identity, clientIP: "1.1.1.1" }), true);
  assert.equal(await usage.isOverQuota({ identity: anonSession.identity, clientIP: "9.9.9.9" }), true);
  assert.equal(await usage.isOverQuota({ identity: { kind: "anon", owner: "anon:y", tier: "anon" }, clientIP: "9.9.9.10" }), false);
  assert.equal(await usage.isOverQuota({ identity: { kind: "operator", owner: "org:1", orgId: 1, userId: 1, tier: "operator" }, clientIP: "1.1.1.1" }), false);

  // Untrack records the final delta and session count; a new day resets anon usage.
  userSession.bytesSent = 960;
  usage.untrack(userSession);
  await usage.flush();
  assert.deepEqual(await usage.monthly(7), [{ month, bytesIn: 100, bytesOut: 960, sessions: 1 }]);

  // A session whose bytes were all flushed before it closed still counts.
  const quiet = { sessionId: "u2", identity: userSession.identity, clientIP: "1.1.1.1", bytesSent: 0, bytesReceived: 0 };
  usage.track(quiet);
  quiet.bytesSent = 40;
  await usage.flush();
  usage.untrack(quiet);
  usage.untrack(quiet);
  await usage.flush();
  assert.deepEqual(await usage.monthly(7), [{ month, bytesIn: 100, bytesOut: 1000, sessions: 2 }]);
  clock += 24 * 60 * 60 * 1000;
  assert.notEqual(dayKey(clock), dayKey(clock - 24 * 60 * 60 * 1000));
  assert.equal(await usage.isOverQuota({ identity: anonSession.identity, clientIP: "9.9.9.9" }), false);

  // A fresh meter reads existing monthly totals from the database.
  const fresh = createUsageMeter({ db: database, tiers, now: () => clock, flushIntervalMs: 1e9, log: quietLog });
  assert.equal(await fresh.isOverQuota({ identity: userSession.identity, clientIP: "1.1.1.1" }), true);
  const rendered = await metrics.render();
  assert.match(rendered, /rootlessrelay_bytes_total\{direction="to_vm",tier="user"\} 1000/);
  usage.close();
  fresh.close();
  await database.close();
});

test("metrics can be disabled with no-op instruments", async () => {
  const metrics = createMetrics({ enabled: false });
  metrics.sessionsGauge.inc({ tier: "anon" });
  metrics.bytesCounter.inc({ direction: "to_vm", tier: "anon" }, 5);
  assert.equal(await metrics.render(), "");
  const enabled = createMetrics({ enabled: true });
  enabled.sessionsGauge.inc({ tier: "anon" });
  enabled.egressDenied.inc({ proto: "tcp" });
  const text = await enabled.render();
  assert.match(text, /rootlessrelay_sessions\{tier="anon"\} 1/);
  assert.match(text, /rootlessrelay_egress_denied_total\{proto="tcp"\} 1/);
  assert.match(text, /nodejs_eventloop_lag/);
});
