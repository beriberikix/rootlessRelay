"use strict";

// Connection audit log: who connected where, when, and how much. Rows are
// batched into SQLite and pruned after a retention window so abuse reports
// can be answered without keeping data forever.

const DAY_MS = 24 * 60 * 60 * 1000;

function noopAudit() {
  return {
    enabled: false,
    record() {},
    finish() {},
    async flush() {},
    async prune() {
      return 0;
    },
    async query() {
      return [];
    },
    close() {},
    pendingCount: () => 0,
  };
}

function createAuditLog({
  db,
  enabled = true,
  batchMs = 2000,
  maxBatch = 200,
  maxPending = 10000,
  retentionDays = 30,
  pruneIntervalMs = 60 * 60 * 1000,
  now = Date.now,
  log = null,
}) {
  if (!enabled || !db) return noopAudit();

  const pendingInserts = []; // rows not yet in the database
  const pendingByKey = new Map(); // key -> pending row (so finish can merge)
  const insertedIds = new Map(); // key -> database id
  const pendingUpdates = new Map(); // id -> { ended_at, bytes_in, bytes_out }
  let flushing = null;
  let dropped = 0;

  function record(row) {
    if (pendingInserts.length >= maxPending) {
      dropped += 1;
      return;
    }
    const entry = {
      key: row.key || null,
      owner: row.owner,
      session_id: row.sessionId,
      proto: row.proto,
      dst_ip: row.dstIP,
      dst_port: row.dstPort,
      verdict: row.verdict,
      bytes_in: row.bytesIn === undefined ? null : row.bytesIn,
      bytes_out: row.bytesOut === undefined ? null : row.bytesOut,
      started_at: row.startedAt,
      ended_at: row.endedAt === undefined ? null : row.endedAt,
    };
    pendingInserts.push(entry);
    if (entry.key) pendingByKey.set(entry.key, entry);
    if (pendingInserts.length >= maxBatch) scheduleFlush(0);
  }

  function finish(key, { endedAt, bytesIn = null, bytesOut = null, error = null }) {
    const pending = pendingByKey.get(key);
    if (pending) {
      pending.ended_at = endedAt;
      pending.bytes_in = bytesIn;
      pending.bytes_out = bytesOut;
      if (error) pending.verdict = `${pending.verdict}:${error}`.slice(0, 120);
      pendingByKey.delete(key);
      return;
    }
    const id = insertedIds.get(key);
    if (id === undefined) return;
    insertedIds.delete(key);
    pendingUpdates.set(id, { ended_at: endedAt, bytes_in: bytesIn, bytes_out: bytesOut });
  }

  let timer = null;
  function scheduleFlush(delayMs) {
    if (timer) return;
    timer = setTimeout(() => {
      timer = null;
      flush().catch((error) => log?.error("audit flush failed", { error }));
    }, delayMs);
    timer.unref();
  }

  async function flush() {
    if (flushing) return flushing;
    flushing = (async () => {
      const inserts = pendingInserts.splice(0, pendingInserts.length);
      const updates = [...pendingUpdates.entries()];
      pendingUpdates.clear();
      if (inserts.length === 0 && updates.length === 0) return;
      const inserted = new Map(); // row -> id, applied only after commit
      try {
        await db.transaction(async () => {
        for (const row of inserts) {
          const result = await db.run(
            "INSERT INTO connections_audit (owner, session_id, proto, dst_ip, dst_port, verdict, bytes_in, bytes_out, started_at, ended_at) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [row.owner, row.session_id, row.proto, row.dst_ip, row.dst_port, row.verdict,
              row.bytes_in, row.bytes_out, row.started_at, row.ended_at],
          );
          if (row.key) inserted.set(row, { id: result.lastID, endedAt: row.ended_at });
        }
        for (const [id, update] of updates) {
          await db.run(
            "UPDATE connections_audit SET ended_at = ?, bytes_in = ?, bytes_out = ? WHERE id = ?",
            [update.ended_at, update.bytes_in, update.bytes_out, id],
          );
        }
        });
      } catch (error) {
        // Rolled back: requeue so the rows are retried, not lost.
        pendingInserts.unshift(...inserts);
        for (const [id, update] of updates) if (!pendingUpdates.has(id)) pendingUpdates.set(id, update);
        throw error;
      }
      for (const [row, { id, endedAt }] of inserted) {
        if (pendingByKey.get(row.key) === row) {
          // Still open: remember the id so finish() can update it later.
          insertedIds.set(row.key, id);
          pendingByKey.delete(row.key);
        } else if (row.ended_at !== endedAt) {
          // finish() merged into the row while its insert was in flight.
          pendingUpdates.set(id, { ended_at: row.ended_at, bytes_in: row.bytes_in, bytes_out: row.bytes_out });
        }
      }
      if (dropped > 0) {
        log?.warn("audit rows dropped under backpressure", { dropped });
        dropped = 0;
      }
    })().finally(() => {
      flushing = null;
    });
    return flushing;
  }

  async function prune() {
    const cutoff = now() - retentionDays * DAY_MS;
    const result = await db.run("DELETE FROM connections_audit WHERE started_at < ?", [cutoff]);
    return result.changes;
  }

  // `at` (ms) with `windowMs` finds connections open at that moment, which is
  // what an abuse report gives: a destination and a time.
  async function query({
    owner = null, sessionId = null, since = null, until = null, verdict = null, limit = 200,
    dstIP = null, dstPort = null, at = null, windowMs = 5 * 60 * 1000,
  } = {}) {
    const where = [];
    const params = [];
    if (dstIP) {
      where.push("dst_ip = ?");
      params.push(dstIP);
    }
    if (dstPort !== null) {
      where.push("dst_port = ?");
      params.push(dstPort);
    }
    if (at !== null) {
      where.push("started_at <= ? AND (ended_at IS NULL OR ended_at >= ?)");
      params.push(at + windowMs, at - windowMs);
    }
    const orgMatch = owner && /^org:(\d+)$/.exec(owner);
    if (orgMatch) {
      // Rows written before orgs existed are keyed "user:<id>"; a personal
      // org also owns its user's earlier rows.
      where.push(
        "(owner = ? OR owner IN (SELECT 'user:' || m.user_id FROM memberships m JOIN orgs o ON o.id = m.org_id " +
          "WHERE o.id = ? AND o.personal = 1))",
      );
      params.push(owner, Number(orgMatch[1]));
    } else if (owner) {
      where.push("owner = ?");
      params.push(owner);
    }
    if (sessionId) {
      where.push("session_id = ?");
      params.push(sessionId);
    }
    if (since !== null) {
      where.push("started_at >= ?");
      params.push(since);
    }
    if (until !== null) {
      where.push("started_at <= ?");
      params.push(until);
    }
    if (verdict === "deny") where.push("verdict LIKE 'deny%'");
    else if (verdict === "allow") where.push("verdict LIKE 'allow%'");
    const sql = "SELECT id, owner, session_id AS sessionId, proto, dst_ip AS dstIP, dst_port AS dstPort, verdict, " +
      "bytes_in AS bytesIn, bytes_out AS bytesOut, started_at AS startedAt, ended_at AS endedAt FROM connections_audit" +
      (where.length ? ` WHERE ${where.join(" AND ")}` : "") +
      " ORDER BY started_at DESC, id DESC LIMIT ?";
    params.push(Math.max(1, Math.min(Number(limit) || 200, 1000)));
    return db.all(sql, params);
  }

  const interval = setInterval(() => {
    scheduleFlush(0);
  }, batchMs);
  interval.unref();
  const pruneTimer = setInterval(() => {
    prune().catch((error) => log?.error("audit prune failed", { error }));
  }, pruneIntervalMs);
  pruneTimer.unref();

  return {
    enabled: true,
    record,
    finish,
    flush,
    prune,
    query,
    pendingCount: () => pendingInserts.length + pendingUpdates.size,
    close() {
      clearInterval(interval);
      clearInterval(pruneTimer);
      if (timer) clearTimeout(timer);
    },
  };
}

module.exports = { createAuditLog, noopAudit };
