"use strict";

// WebSocket connection handling: session registry (per-IP / per-owner
// admission), policy attachment, heartbeat, idle and lifetime timers, and
// cleanup. This replaces the wss.on("connection") block from relay.js.

const crypto = require("crypto");
const { LOCAL_IDENTITY } = require("./public");
const { resolveClientIP } = require("./client_ip");

const WS_OPEN = 1;
const SWEEP_INTERVAL_MS = 5000;
const MISSED_PONGS_LIMIT = 2;

function createSessionRegistry({ ctx, tiers }) {
  const sessions = new Map();
  const byOwner = new Map();
  const perIP = new Map();

  function poolCapacity() {
    return ctx.DHCP_END - ctx.DHCP_START + 1;
  }

  function poolInUse() {
    // usedIPs always contains the gateway's last octet.
    return Math.max(0, ctx.usedIPs.size - 1);
  }

  return {
    sessions,
    byOwner,
    perIP,
    get size() {
      return sessions.size;
    },
    countFor(owner) {
      const set = byOwner.get(owner);
      return set ? set.size : 0;
    },
    countForIP(ip) {
      return perIP.get(ip) || 0;
    },
    admit({ identity, clientIP }) {
      const tier = tiers[identity.tier] || tiers.user;
      if (tier.maxSessionsPerIP !== null && this.countForIP(clientIP) >= tier.maxSessionsPerIP) {
        return { ok: false, status: 429, reason: "connection limit reached for this address" };
      }
      if (tier.maxSessionsPerOwner !== null && this.countFor(identity.owner) >= tier.maxSessionsPerOwner) {
        return { ok: false, status: 429, reason: "session limit reached for this account" };
      }
      if (poolInUse() >= poolCapacity()) {
        return { ok: false, status: 503, reason: "address pool exhausted" };
      }
      return { ok: true };
    },
    add(session) {
      sessions.set(session.sessionId, session);
      const owner = session.identity.owner;
      if (!byOwner.has(owner)) byOwner.set(owner, new Set());
      byOwner.get(owner).add(session);
      perIP.set(session.clientIP, (perIP.get(session.clientIP) || 0) + 1);
    },
    remove(session) {
      if (!sessions.delete(session.sessionId)) return;
      const set = byOwner.get(session.identity.owner);
      if (set) {
        set.delete(session);
        if (set.size === 0) byOwner.delete(session.identity.owner);
      }
      const count = (perIP.get(session.clientIP) || 1) - 1;
      if (count <= 0) perIP.delete(session.clientIP);
      else perIP.set(session.clientIP, count);
    },
    kill(sessionId, code = 1008, reason = "terminated by operator") {
      const session = sessions.get(sessionId);
      if (!session) return false;
      session.ws.close(code, reason);
      return true;
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
    const clientIP = extra.clientIP || resolveClientIP(req, {
      trustProxy: config.trustProxy,
      hops: config.trustProxyHops,
      header: config.clientIpHeader,
    });
    const tier = tiers[identity.tier] || tiers.user;

    try {
      if (ws._socket && typeof ws._socket.setNoDelay === "function") {
        ws._socket.setNoDelay(true);
        ws._socket.setKeepAlive(true, 30000);
      }
    } catch (error) {
      log?.debug("failed to tune transport socket", { error });
    }

    ctx.connectionsPerIP.set(clientIP, (ctx.connectionsPerIP.get(clientIP) || 0) + 1);

    const session = new VMSession(ws, clientIP, req.socket);
    const sessionId = randomUUID();
    session.sessionId = sessionId;
    session.identity = identity;
    session.startedAt = now();
    session.lastActivityAt = session.startedAt;
    session.policy = policyFactory.forSession(identity);
    session.policy.applyToSession(session);
    ctx.activeSessions.set(sessionId, session);
    registry.add(session);
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
      if (idleMs) resetIdle();
      if (!isBinary) {
        const str = data.toString();
        if (str.startsWith("ping:")) {
          ws.send("pong:" + str.substring(5), () => session.resumeTCPTransportWaiters());
        }
        return;
      }
      session.handleEthernetFrame(data);
    });

    ws.on("close", (code, reasonBuffer) => {
      closed = true;
      for (const timer of timers) clearInterval(timer);
      if (idleTimer) clearTimeout(idleTimer);
      const remaining = (ctx.connectionsPerIP.get(clientIP) || 1) - 1;
      if (remaining <= 0) ctx.connectionsPerIP.delete(clientIP);
      else ctx.connectionsPerIP.set(clientIP, remaining);

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
        code,
        reason: reasonBuffer ? reasonBuffer.toString() : "",
        bytesSent: session.bytesSent,
        bytesReceived: session.bytesReceived,
        durationMs: now() - session.startedAt,
      });
    });

    ws.on("error", (error) => {
      log?.warn("websocket error", { sessionId, error });
    });
  });
}

module.exports = { attachConnectionHandler, createSessionRegistry };
