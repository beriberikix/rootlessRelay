"use strict";

// Per-owner byte metering and quotas. Account usage is accumulated per
// calendar month in SQLite (org_usage_monthly); anonymous usage is kept in memory
// per client address per day. Sessions are sampled on a timer and on close,
// so a crash loses at most one flush interval.

function monthKey(ts) {
  const date = new Date(ts);
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, "0")}`;
}

function dayKey(ts) {
  return new Date(ts).toISOString().slice(0, 10);
}

function noopUsage() {
  return {
    enabled: false,
    track() {},
    untrack() {},
    async flush() {},
    async isOverQuota() {
      return false;
    },
    async periodUsage() {
      return null;
    },
    async monthly() {
      return [];
    },
    close() {},
  };
}

function createUsageMeter({
  db = null,
  enabled = true,
  tiers,
  flushIntervalMs = 30000,
  now = Date.now,
  onQuotaExceeded = null,
  metrics = null,
  log = null,
}) {
  if (!enabled) return noopUsage();

  const tracked = new Map(); // session -> { lastSent, lastReceived }
  const memoryTotals = new Map(); // "day:<key>:<id>" -> bytes (anon / in-memory quotas)
  const dbTotals = new Map(); // "month:<key>:<orgId>" -> bytes (cache of org_usage_monthly + unflushed)
  let flushing = null;

  function tierFor(session) {
    const identity = session.identity || {};
    return tiers[identity.tier] || tiers.user;
  }

  // Quota accounting key: accounts by user id and month, anonymous demo
  // sessions by client address and day.
  function quotaKey(session, ts = now()) {
    const identity = session.identity || {};
    const tier = tierFor(session);
    if (identity.orgId) {
      return { store: "db", key: `month:${monthKey(ts)}:${identity.orgId}`, orgId: identity.orgId, month: monthKey(ts) };
    }
    const period = tier.quotaPeriod === "day" ? dayKey(ts) : monthKey(ts);
    return { store: "memory", key: `${tier.quotaPeriod}:${period}:${session.clientIP}` };
  }

  const loading = new Map(); // key -> in-flight load, so deltas applied meanwhile are kept

  async function loadDbTotal(orgId, month) {
    const key = `month:${month}:${orgId}`;
    if (loading.has(key)) return loading.get(key);
    if (dbTotals.has(key)) return dbTotals.get(key);
    // A failed read is not remembered: the next caller reads again. The
    // deltas counted meanwhile are dropped from the cache with it (they are
    // still flushed), since a cache without the persisted total would let
    // the org past its quota; this cache only gates admission.
    const pending = (async () => {
      try {
        const row = db
          ? await db.get("SELECT bytes_in + bytes_out AS total FROM org_usage_monthly WHERE org_id = ? AND month = ?", [orgId, month])
          : null;
        const persisted = row ? row.total : 0;
        dbTotals.set(key, (dbTotals.get(key) || 0) + persisted);
        return dbTotals.get(key);
      } catch (error) {
        dbTotals.delete(key);
        throw error;
      } finally {
        loading.delete(key);
      }
    })();
    loading.set(key, pending);
    return pending;
  }

  async function periodUsage(session) {
    const q = quotaKey(session);
    if (q.store === "db") return loadDbTotal(q.orgId, q.month);
    return memoryTotals.get(q.key) || 0;
  }

  async function isOverQuota({ identity, clientIP }) {
    const tier = tiers[identity.tier] || tiers.user;
    if (tier.quotaBytes === null) return false;
    const fake = { identity, clientIP };
    return (await periodUsage(fake)) >= tier.quotaBytes;
  }

  function track(session) {
    tracked.set(session, { lastSent: session.bytesSent || 0, lastReceived: session.bytesReceived || 0 });
    const q = quotaKey(session);
    if (q.store === "db") loadDbTotal(q.orgId, q.month).catch((error) => log?.warn("usage load failed", { error }));
  }

  // Every tracked session counts once at close, including one whose bytes
  // were all flushed already (takeDelta then returns null).
  function untrack(session) {
    if (!tracked.has(session)) return;
    const delta = takeDelta(session) || { in: 0, out: 0 };
    tracked.delete(session);
    applyDelta(session, delta, true);
  }

  function takeDelta(session) {
    const state = tracked.get(session);
    if (!state) return null;
    const sent = session.bytesSent || 0;
    const received = session.bytesReceived || 0;
    const delta = { out: Math.max(0, sent - state.lastSent), in: Math.max(0, received - state.lastReceived) };
    state.lastSent = sent;
    state.lastReceived = received;
    if (delta.in === 0 && delta.out === 0) return null;
    return delta;
  }

  const pendingDb = new Map(); // "orgId|month" -> { orgId, month, in, out, sessions }

  function applyDelta(session, delta, closing = false) {
    const tier = tierFor(session);
    metrics?.bytesCounter?.inc({ direction: "to_vm", tier: session.identity?.tier || "local" }, delta.out);
    metrics?.bytesCounter?.inc({ direction: "from_vm", tier: session.identity?.tier || "local" }, delta.in);
    const q = quotaKey(session);
    const total = delta.in + delta.out;
    if (q.store === "db") {
      const pendingKey = `${q.orgId}|${q.month}`;
      const pending = pendingDb.get(pendingKey) || { orgId: q.orgId, month: q.month, in: 0, out: 0, sessions: 0 };
      pending.in += delta.in;
      pending.out += delta.out;
      if (closing) pending.sessions += 1;
      pendingDb.set(pendingKey, pending);
      dbTotals.set(q.key, (dbTotals.get(q.key) || 0) + total);
      return (dbTotals.get(q.key) || 0) >= (tier.quotaBytes ?? Infinity);
    }
    memoryTotals.set(q.key, (memoryTotals.get(q.key) || 0) + total);
    return (memoryTotals.get(q.key) || 0) >= (tier.quotaBytes ?? Infinity);
  }

  async function flush() {
    if (flushing) return flushing;
    flushing = (async () => {
      const exceeded = [];
      for (const session of tracked.keys()) {
        const delta = takeDelta(session);
        if (!delta) continue;
        if (applyDelta(session, delta)) exceeded.push(session);
      }
      if (db && pendingDb.size > 0) {
        const rows = [...pendingDb.values()];
        pendingDb.clear();
        try {
          await db.transaction(async () => {
            for (const row of rows) {
              await db.run(
                "INSERT INTO org_usage_monthly (org_id, month, bytes_in, bytes_out, sessions) VALUES (?, ?, ?, ?, ?) " +
                "ON CONFLICT(org_id, month) DO UPDATE SET bytes_in = bytes_in + excluded.bytes_in, " +
                "bytes_out = bytes_out + excluded.bytes_out, sessions = sessions + excluded.sessions",
                [row.orgId, row.month, row.in, row.out, row.sessions],
              );
            }
          });
        } catch (error) {
          // The transaction rolled back: put the rows back for the next flush.
          for (const row of rows) {
            const key = `${row.orgId}|${row.month}`;
            const pending = pendingDb.get(key) || { orgId: row.orgId, month: row.month, in: 0, out: 0, sessions: 0 };
            pending.in += row.in;
            pending.out += row.out;
            pending.sessions += row.sessions;
            pendingDb.set(key, pending);
          }
          throw error;
        }
      }
      // Drop stale in-memory periods (older than two days).
      const today = dayKey(now());
      const yesterday = dayKey(now() - 24 * 60 * 60 * 1000);
      for (const key of memoryTotals.keys()) {
        if (key.startsWith("day:") && !key.includes(`:${today}:`) && !key.includes(`:${yesterday}:`)) {
          memoryTotals.delete(key);
        }
      }
      for (const session of exceeded) {
        log?.info("quota exceeded", { owner: session.identity?.owner, sessionId: session.sessionId });
        onQuotaExceeded?.(session);
      }
    })().finally(() => {
      flushing = null;
    });
    return flushing;
  }

  async function monthly(orgId, { months = 12 } = {}) {
    if (!db) return [];
    const rows = await db.all(
      "SELECT month, bytes_in AS bytesIn, bytes_out AS bytesOut, sessions FROM org_usage_monthly WHERE org_id = ? ORDER BY month DESC LIMIT ?",
      [orgId, months],
    );
    return rows;
  }

  const timer = setInterval(() => {
    flush().catch((error) => log?.error("usage flush failed", { error }));
  }, flushIntervalMs);
  timer.unref();

  return {
    enabled: true,
    track,
    untrack,
    flush,
    isOverQuota,
    periodUsage,
    monthly,
    close() {
      clearInterval(timer);
    },
  };
}

module.exports = { createUsageMeter, dayKey, monthKey, noopUsage };
