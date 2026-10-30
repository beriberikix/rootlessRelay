"use strict";

// WebSocket connection handling: session registry (per-IP / per-owner
// admission), policy attachment, heartbeat, idle and lifetime timers, and
// cleanup. This replaces the wss.on("connection") block from relay.js.

const crypto = require("crypto");
const { LOCAL_IDENTITY } = require("./public");
const { rateKey, resolveClientIP } = require("./client_ip");

const WS_OPEN = 1;
const SWEEP_INTERVAL_MS = 5000;
const MISSED_PONGS_LIMIT = 2;

// Per-address limits key on the address group (rateKey: IPv6 by /64), so one
// subscriber's many IPv6 addresses count as one. `budget` and `budgetStatus`
// (metering/budget.js, metering/usage.js) let admission refuse budget tiers
// while the relay-wide budget is paused.
function createSessionRegistry({ ctx, tiers, budget = null, budgetStatus = null }) {
  const sessions = new Map();
  const byOwner = new Map();
  const perIP = new Map();

  function poolCapacity() {
    return ctx.DHCP_END - ctx.DHCP_START + 1;
  }

  function poolInUse() {
    // usedIPs always contains the gateway's last octet. Sessions that have
    // not taken an address yet (before DHCP) will, so they count too.
    // Addresses held for a reconnect are evicted when the pool runs out.
    let waiting = 0;
    for (const session of sessions.values()) if (!session.vmIP) waiting += 1;
    const held = ctx.addressHolds ? ctx.addressHolds.size : 0;
    return Math.max(0, ctx.usedIPs.size - 1 - held) + waiting;
  }

  // Slots held between admission and registration. Admission awaits the quota
  // check and the WebSocket handshake before the session exists, so without
  // these, parallel upgrades would all pass the same caps.
  const reservedByOwner = new Map();
  const reservedByIP = new Map();
  let reservedTotal = 0;
  const bump = (map, key, delta) => {
    const next = (map.get(key) || 0) + delta;
    if (next <= 0) map.delete(key);
    else map.set(key, next);
  };

  return {
    sessions,
    byOwner,
    perIP,
    get size() {
      return sessions.size;
    },
    countFor(owner) {
      const set = byOwner.get(owner);
      return (set ? set.size : 0) + (reservedByOwner.get(owner) || 0);
    },
    countForIP(key) {
      return (perIP.get(key) || 0) + (reservedByIP.get(key) || 0);
    },
    poolFull() {
      return poolInUse() + reservedTotal >= poolCapacity();
    },
    // On success the caller holds a reservation and must call release()
    // once: after registering the session, or when the upgrade fails.
    // Refusals carry `close`, the WebSocket close code a browser can read.
    admit({ identity, clientIP, clientKey = rateKey(clientIP) }) {
      const tier = tiers[identity.tier] || tiers.user;
      if (budget && budgetStatus && budget.appliesTo(identity.tier)) {
        const status = budgetStatus();
        if (status.state === "paused") {
          return { ok: false, status: 503, close: 1008, reason: `free tier paused until ${status.pausedUntil}` };
        }
      }
      if (tier.maxSessionsPerIP !== null && this.countForIP(clientKey) >= tier.maxSessionsPerIP) {
        return { ok: false, status: 429, close: 1013, reason: "connection limit reached for this address" };
      }
      if (tier.maxSessionsPerOwner !== null && this.countFor(identity.owner) >= tier.maxSessionsPerOwner) {
        return { ok: false, status: 429, close: 1013, reason: "session limit reached for this account" };
      }
      if (this.poolFull()) {
        return { ok: false, status: 503, close: 1013, reason: "relay full" };
      }
      bump(reservedByOwner, identity.owner, 1);
      bump(reservedByIP, clientKey, 1);
      reservedTotal += 1;
      let released = false;
      const release = () => {
        if (released) return;
        released = true;
        bump(reservedByOwner, identity.owner, -1);
        bump(reservedByIP, clientKey, -1);
        reservedTotal -= 1;
      };
      return { ok: true, release };
    },
    add(session) {
      sessions.set(session.sessionId, session);
      const owner = session.identity.owner;
      if (!byOwner.has(owner)) byOwner.set(owner, new Set());
      byOwner.get(owner).add(session);
      const key = session.clientKey || rateKey(session.clientIP);
      perIP.set(key, (perIP.get(key) || 0) + 1);
    },
    remove(session) {
      if (!sessions.delete(session.sessionId)) return;
      const set = byOwner.get(session.identity.owner);
      if (set) {
        set.delete(session);
        if (set.size === 0) byOwner.delete(session.identity.owner);
      }
      const key = session.clientKey || rateKey(session.clientIP);
      const count = (perIP.get(key) || 1) - 1;
      if (count <= 0) perIP.delete(key);
      else perIP.set(key, count);
    },
    kill(sessionId, code = 1008, reason = "terminated by operator") {
      const session = sessions.get(sessionId);
      if (!session) return false;
      session.ws.close(code, reason);
      return true;
    },
    // Closes the sessions that authenticated with one API token.
    killToken(tokenId, code = 1008, reason = "token revoked") {
      let count = 0;
      for (const session of sessions.values()) {
        if (session.identity && session.identity.tokenId === tokenId) {
          session.ws.close(code, reason);
          count += 1;
        }
      }
      return count;
    },
    // Closes every session a user opened, whichever org it ran in.
    killUser(userId, code = 1008, reason = "account suspended") {
      let count = 0;
      for (const session of sessions.values()) {
        if (session.identity && session.identity.userId === userId) {
          session.ws.close(code, reason);
          count += 1;
        }
      }
      return count;
    },
    // Closes one member's sessions in one org (membership ended or role changed).
    killMember(owner, userId, code = 1008, reason = "removed from organization") {
      const set = byOwner.get(owner);
      if (!set) return 0;
      let count = 0;
      for (const session of [...set]) {
        if (session.identity && session.identity.userId === userId) {
          session.ws.close(code, reason);
          count += 1;
        }
      }
      return count;
    },
    // Closes every session in the given tiers (the budget pausing them).
    closeTier(tierNames, code = 1008, reason = "free tier paused") {
      const names = new Set(tierNames);
      let count = 0;
      for (const session of sessions.values()) {
        if (session.identity && names.has(session.identity.tier)) {
          session.ws.close(code, reason);
          count += 1;
        }
      }
      return count;
    },
    killOwner(owner, code = 1008, reason = "account suspended") {
      const set = byOwner.get(owner);
      if (!set) return 0;
      let count = 0;
      for (const session of [...set]) {
        session.ws.close(code, reason);
        count += 1;
      }
      return count;
    },
  };
}

function attachConnectionHandler(wss, {
  VMSession,
  ctx,
  config,
  tiers,
  policyFactory,
  registry,
  log,
  metrics = null,
  usage = null,
  now = Date.now,
  randomUUID = () => crypto.randomUUID(),
}) {
  wss.on("connection", (ws, req, extra = {}) => {
    const identity = extra.identity || LOCAL_IDENTITY;
    const clientIP = extra.clientIP || resolveClientIP(req, config.clientIpOptions || {});
    const clientKey = extra.clientKey || rateKey(clientIP);
    const tier = tiers[identity.tier] || tiers.user;

    try {
      if (ws._socket && typeof ws._socket.setNoDelay === "function") {
        ws._socket.setNoDelay(true);
        ws._socket.setKeepAlive(true, 30000);
      }
    } catch (error) {
      log?.debug("failed to tune transport socket", { error });
    }

    ctx.connectionsPerIP.set(clientKey, (ctx.connectionsPerIP.get(clientKey) || 0) + 1);

    const session = new VMSession(ws, clientIP, req.socket);
    session.clientKey = clientKey;
    const sessionId = randomUUID();
    session.sessionId = sessionId;
    session.identity = identity;
    session.startedAt = now();
    session.lastActivityAt = session.startedAt;
    session.policy = policyFactory.forSession(identity);
    session.policy.applyToSession(session);
    ctx.activeSessions.set(sessionId, session);
    registry.add(session);
    extra.release?.();
    usage?.track(session);
    metrics?.sessionsGauge?.inc({ tier: identity.tier });
    log?.info("session opened", {
      sessionId,
      clientIP,
      owner: identity.owner,
      tier: identity.tier,
      username: identity.username,
    });

    const timers = [];
    let missedPongs = 0;
    let closed = false;

    function closeWith(code, reason) {
      if (closed || ws.readyState !== WS_OPEN) return;
      log?.info("closing session", { sessionId, code, reason });
      ws.close(code, reason);
    }

    if (config.wsHeartbeatMs > 0) {
      ws.on("pong", () => {
        missedPongs = 0;
      });
      const heartbeat = setInterval(() => {
        if (ws.readyState !== WS_OPEN) return;
        if (missedPongs >= MISSED_PONGS_LIMIT) {
          log?.warn("terminating unresponsive session", { sessionId });
          ws.terminate();
          return;
        }
        missedPongs += 1;
        try {
          ws.ping();
        } catch (_error) {
          // The socket is already gone; the close handler cleans up.
        }
      }, config.wsHeartbeatMs);
      heartbeat.unref();
      timers.push(heartbeat);
    }

    const idleMs = config.sessionIdleTimeoutMs > 0 ? config.sessionIdleTimeoutMs : tier.idleMs;
    let idleTimer = null;
    function resetIdle() {
      if (!idleMs) return;
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(() => closeWith(1000, "idle timeout"), idleMs);
      idleTimer.unref();
    }
    resetIdle();

    if (tier.maxSessionMs) {
      const lifetime = setTimeout(() => closeWith(1000, "session expired"), tier.maxSessionMs);
      lifetime.unref();
      timers.push(lifetime);
    }

    const sweep = setInterval(() => {
      try {
        session.policy.sweep(session);
      } catch (error) {
        log?.error("policy sweep failed", { sessionId, error });
      }
    }, SWEEP_INTERVAL_MS);
    sweep.unref();
    timers.push(sweep);

    ws.on("message", (data, isBinary) => {
      session.lastActivityAt = now();
      // Only frames count as activity: a client's ping: heartbeat must not
      // keep a forgotten session open.
      if (idleMs && isBinary) resetIdle();
      if (!isBinary) {
        const str = data.toString();
        if (str.startsWith("ping:")) {
          ws.send("pong:" + str.substring(5), () => session.resumeTCPTransportWaiters());
        }
        return;
      }
      session.handleEthernetFrame(data);
    });

    // Releases what the session holds and records its end, once: from the
    // socket's close event, or earlier from a shutdown that has to finish
    // this bookkeeping before the final flush (the close event would come
    // after the process exits).
    let finished = false;
    function finish(code, reason) {
      if (finished) return;
      finished = true;
      closed = true;
      for (const timer of timers) clearInterval(timer);
      if (idleTimer) clearTimeout(idleTimer);
      const remaining = (ctx.connectionsPerIP.get(clientKey) || 1) - 1;
      if (remaining <= 0) ctx.connectionsPerIP.delete(clientKey);
      else ctx.connectionsPerIP.set(clientKey, remaining);

      try {
        session.policy.onSessionClose(session);
      } catch (error) {
        log?.error("policy close failed", { sessionId, error });
      }
      usage?.untrack(session);
      session.close();
      ctx.activeSessions.delete(sessionId);
      registry.remove(session);
      metrics?.sessionsGauge?.dec({ tier: identity.tier });
      log?.info("session closed", {
        sessionId,
        clientIP,
        owner: identity.owner,
        tier: identity.tier,
        code,
        reason,
        bytesSent: session.bytesSent,
        bytesReceived: session.bytesReceived,
        durationMs: now() - session.startedAt,
      });
    }
    session.finish = finish;

    ws.on("close", (code, reasonBuffer) => finish(code, reasonBuffer ? reasonBuffer.toString() : ""));

    ws.on("error", (error) => {
      log?.warn("websocket error", { sessionId, error });
    });
  });
}

module.exports = { attachConnectionHandler, createSessionRegistry };
