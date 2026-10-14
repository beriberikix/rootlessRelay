"use strict";

// Account-scoped API served on the public listener under /api/me. Lets a
// signed-in user (external JWT or API token as a bearer) see their own
// account, usage, live sessions and API tokens, and manage the latter two.
// Everything is scoped to the caller's identity; anonymous identities are
// refused. The operator panel remains the only place to see other accounts.

const { AuthError, extractCredential, readJsonBody, writeJson } = require("./public");

const PREFIX = "/api/me";
const MAX_ACTIVE_TOKENS = 20;
const MAX_TOKEN_DAYS = 365;

// Tier fields a user may see about their own limits.
const PUBLIC_TIER_FIELDS = [
  "uploadBps",
  "downloadBps",
  "maxTcpConnections",
  "maxUdpFlows",
  "allowedTcpPorts",
  "allowedUdpPorts",
  "vmToVm",
  "maxSessionMs",
  "idleMs",
  "maxSessionsPerOwner",
  "quotaBytes",
  "quotaPeriod",
];

function publicTier(name, tiers) {
  const tier = tiers && tiers[name];
  if (!tier) return { name };
  const out = { name };
  for (const field of PUBLIC_TIER_FIELDS) out[field] = tier[field] === undefined ? null : tier[field];
  return out;
}

function sessionSummary(sessionId, session) {
  return {
    sessionId,
    clientIP: session.clientIP,
    vmIP: session.vmIP || null,
    bytesSent: session.bytesSent || 0,
    bytesReceived: session.bytesReceived || 0,
    tcpConnections: session.tcpConnections ? session.tcpConnections.size : 0,
    udpFlows: session.udpFlows ? session.udpFlows.size : 0,
    nickname: session.nickname || null,
    startedAt: session.startedAt ? new Date(session.startedAt).toISOString() : null,
  };
}

function parseId(value) {
  const id = Number.parseInt(value, 10);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function createUserApi({
  authenticate,
  users,
  apiTokens,
  usage,
  registry,
  activeSessions,
  tiers,
  log = null,
  now = Date.now,
}) {
  // `users` and `apiTokens` may be getters when the stores open after the
  // listener starts (hosted.js), or plain objects (tests).
  const store = (ref) => (typeof ref === "function" ? ref() : ref);

  async function requireAccount(req, clientIP) {
    const credential = extractCredential(req);
    if (!credential || credential.source !== "header") {
      throw new AuthError(401, "authentication-required");
    }
    const identity = await authenticate(credential.token, { clientIP, req });
    if (!identity || !identity.userId) throw new AuthError(403, "account-required");
    return identity;
  }

  function ownSessions(identity) {
    const list = [];
    if (!activeSessions) return list;
    activeSessions.forEach((session, sessionId) => {
      if (session.identity && session.identity.owner === identity.owner) {
        list.push(sessionSummary(sessionId, session));
      }
    });
    return list;
  }

  async function currentUsage(identity) {
    const bytes = usage ? await usage.periodUsage({ identity, clientIP: null }) : 0;
    const tier = tiers && tiers[identity.tier];
    return {
      period: tier && tier.quotaPeriod ? tier.quotaPeriod : "month",
      bytes,
      quotaBytes: tier && tier.quotaBytes !== undefined ? tier.quotaBytes : null,
    };
  }

  const routes = [
    {
      method: "GET",
      match: (path) => path === PREFIX,
      async handle({ identity }) {
        const userStore = store(users);
        const user = userStore ? userStore.publicUser(await userStore.findById(identity.userId)) : null;
        return [200, {
          user: user ? {
            id: user.id,
            username: user.username,
            role: user.role,
            tier: user.tier,
            status: user.status,
            createdAt: user.createdAt,
            lastLoginAt: user.lastLoginAt,
          } : { id: identity.userId, username: identity.username, tier: identity.tier },
          tier: publicTier(identity.tier, tiers),
          usage: await currentUsage(identity),
          activeSessions: ownSessions(identity).length,
        }];
      },
    },
    {
      method: "GET",
      match: (path) => path === `${PREFIX}/usage`,
      async handle({ identity }) {
        const months = usage ? await usage.monthly(identity.userId, { months: 12 }) : [];
        return [200, { current: await currentUsage(identity), months }];
      },
    },
    {
      method: "GET",
      match: (path) => path === `${PREFIX}/sessions`,
      async handle({ identity }) {
        return [200, ownSessions(identity)];
      },
    },
    {
      method: "DELETE",
      match: (path) => path.startsWith(`${PREFIX}/sessions/`),
      async handle({ identity, path }) {
        const sessionId = decodeURIComponent(path.slice(`${PREFIX}/sessions/`.length));
        const session = activeSessions ? activeSessions.get(sessionId) : null;
        if (!session || !session.identity || session.identity.owner !== identity.owner) {
          return [404, { error: "session not found" }];
        }
        registry.kill(sessionId, 1008, "terminated by account owner");
        log?.info("session killed by owner", { sessionId, owner: identity.owner });
        return [204, null];
      },
    },
    {
      method: "GET",
      match: (path) => path === `${PREFIX}/tokens`,
      async handle({ identity }) {
        return [200, await store(apiTokens).listForUser(identity.userId)];
      },
    },
    {
      method: "POST",
      match: (path) => path === `${PREFIX}/tokens`,
      async handle({ identity, req }) {
        const body = await readJsonBody(req);
        const name = typeof body.name === "string" && body.name.trim() ? body.name.trim().slice(0, 64) : "default";
        let expiresAt = null;
        if (body.expiresInDays !== undefined && body.expiresInDays !== null) {
          const days = Number(body.expiresInDays);
          if (!Number.isFinite(days) || days <= 0 || days > MAX_TOKEN_DAYS) {
            return [400, { error: `expiresInDays must be between 1 and ${MAX_TOKEN_DAYS}` }];
          }
          expiresAt = new Date(now() + days * 24 * 60 * 60 * 1000).toISOString();
        }
        const tokenStore = store(apiTokens);
        const existing = await tokenStore.listForUser(identity.userId);
        const active = existing.filter((t) => !t.revokedAt && (!t.expiresAt || new Date(t.expiresAt).getTime() > now()));
        if (active.length >= MAX_ACTIVE_TOKENS) {
          return [409, { error: `at most ${MAX_ACTIVE_TOKENS} active tokens per account` }];
        }
        const created = await tokenStore.create({ userId: identity.userId, name, expiresAt });
        log?.info("api token created by owner", { userId: identity.userId, tokenId: created.id });
        return [201, created];
      },
    },
    {
      method: "DELETE",
      match: (path) => path.startsWith(`${PREFIX}/tokens/`),
      async handle({ identity, path }) {
        const id = parseId(path.slice(`${PREFIX}/tokens/`.length));
        const tokenStore = store(apiTokens);
        const mine = id ? (await tokenStore.listForUser(identity.userId)).some((t) => t.id === id) : false;
        if (!mine || !(await tokenStore.revoke(id))) return [404, { error: "token not found" }];
        log?.info("api token revoked by owner", { userId: identity.userId, tokenId: id });
        return [204, null];
      },
    },
  ];

  function matches(path) {
    return path === PREFIX || path.startsWith(`${PREFIX}/`);
  }

  // Returns true when the request was handled (always, for matching paths).
  async function handle(req, res, { path, clientIP, corsHeaders = {} }) {
    if (!matches(path)) return false;
    const candidates = routes.filter((r) => r.match(path));
    const route = candidates.find((r) => r.method === req.method);
    try {
      if (candidates.length === 0) {
        writeJson(res, 404, { error: "not found" }, corsHeaders);
        return true;
      }
      if (!route) {
        writeJson(res, 405, { error: "method not allowed" }, corsHeaders);
        return true;
      }
      const identity = await requireAccount(req, clientIP);
      const [status, body] = await route.handle({ identity, req, path });
      if (status === 204) {
        res.writeHead(204, { "Cache-Control": "no-store", ...corsHeaders });
        res.end();
      } else {
        writeJson(res, status, body, corsHeaders);
      }
    } catch (error) {
      const status = error.status || 500;
      if (status >= 500) log?.error("user api error", { error, stack: error && error.stack, path });
      writeJson(res, status, { error: error.code || error.message || "error" }, corsHeaders);
    }
    return true;
  }

  return { handle, matches, PREFIX };
}

module.exports = { MAX_ACTIVE_TOKENS, PREFIX, createUserApi, publicTier, sessionSummary };
