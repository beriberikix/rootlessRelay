"use strict";

// Account-scoped API served on the public listener under /api/me. Lets a
// signed-in user (external JWT or API token as a bearer) see their own
// account, usage, live sessions and API tokens, and manage the latter two.
// Everything is scoped to the caller's identity; anonymous identities are
// refused. The operator panel remains the only place to see other accounts.
//
// Pending accounts (SIGNUP_MODE=invite, invite not yet redeemed) can read
// their account, redeem an invite and delete themselves; everything that
// leads to relay access is refused with 403 account-pending.

const { AuthError, extractCredential, readJsonBody, writeJson } = require("./public");

const PREFIX = "/api/me";
const MAX_ACTIVE_TOKENS = 20;
const MAX_TOKEN_DAYS = 365;
const REDEEM_FAILURES_PER_HOUR = 10;

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
  invites = null,
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
    const identity = await authenticate(credential.token, { clientIP, req, allowPending: true });
    if (!identity || !identity.userId) throw new AuthError(403, "account-required");
    return identity;
  }

  function requireActive(identity) {
    if (identity.status === "pending") throw new AuthError(403, "account-pending");
  }

  // Managing credentials needs a sign-in. An API token alone must not mint or
  // revoke tokens, or a leaked token could outlive its own revocation.
  function requireSignIn(identity) {
    if (identity.via !== "jwt") throw new AuthError(403, "sign-in-required");
  }

  // Failed redemptions per user in the last hour, to slow down guessing.
  const redeemFailures = new Map(); // userId -> [timestamps]
  function recentFailures(userId) {
    const cutoff = now() - 60 * 60 * 1000;
    const list = (redeemFailures.get(userId) || []).filter((t) => t > cutoff);
    if (list.length) redeemFailures.set(userId, list);
    else redeemFailures.delete(userId);
    return list;
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
          } : { id: identity.userId, username: identity.username, tier: identity.tier, status: identity.status },
          tier: publicTier(identity.tier, tiers),
          usage: await currentUsage(identity),
          activeSessions: ownSessions(identity).length,
        }];
      },
    },
    {
      method: "DELETE",
      match: (path) => path === PREFIX,
      async handle({ identity, req }) {
        // Deleting an account needs a sign-in, not just an API token, and the
        // username typed back as confirmation.
        requireSignIn(identity);
        if (identity.kind === "operator") return [403, { error: "operators are deleted from the admin panel" }];
        const body = await readJsonBody(req);
        if (!body || body.confirm !== identity.username) {
          return [400, { error: "confirm must equal your username" }];
        }
        const killed = registry ? registry.killOwner(identity.owner, 1008, "account deleted") : 0;
        await store(users).remove(identity.userId);
        log?.info("account deleted by owner", { userId: identity.userId, killedSessions: killed });
        return [204, null];
      },
    },
    {
      method: "POST",
      match: (path) => path === `${PREFIX}/redeem`,
      async handle({ identity, req }) {
        if (identity.status !== "pending") return [409, { error: "account is already active" }];
        const inviteStore = store(invites);
        if (!inviteStore) return [404, { error: "invites are not enabled" }];
        if (recentFailures(identity.userId).length >= REDEEM_FAILURES_PER_HOUR) {
          return [429, { error: "too many attempts; try again later" }];
        }
        const body = await readJsonBody(req);
        if (!(await inviteStore.redeem(body && body.code, identity.userId))) {
          redeemFailures.set(identity.userId, [...recentFailures(identity.userId), now()]);
          log?.warn("invite redemption failed", { userId: identity.userId });
          return [400, { error: "invalid, used or expired invite code" }];
        }
        await store(users).activatePending(identity.userId);
        redeemFailures.delete(identity.userId);
        log?.info("invite redeemed", { userId: identity.userId });
        return [200, { status: "active" }];
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
        let sessionId;
        try {
          sessionId = decodeURIComponent(path.slice(`${PREFIX}/sessions/`.length));
        } catch (_error) {
          return [404, { error: "session not found" }];
        }
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
        requireActive(identity);
        requireSignIn(identity);
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
        requireSignIn(identity);
        const id = parseId(path.slice(`${PREFIX}/tokens/`.length));
        const tokenStore = store(apiTokens);
        const mine = id ? (await tokenStore.listForUser(identity.userId)).some((t) => t.id === id) : false;
        if (!mine || !(await tokenStore.revoke(id))) return [404, { error: "token not found" }];
        const killed = registry && registry.killToken ? registry.killToken(id, 1008, "token revoked") : 0;
        log?.info("api token revoked by owner", { userId: identity.userId, tokenId: id, killedSessions: killed });
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
