"use strict";

// Account-scoped API served on the public listener under /api/me. Lets a
// signed-in user (external JWT or API token as a bearer) see their own
// account, usage, live sessions and API tokens, and manage the latter two.
// Everything is scoped to the caller's identity; anonymous identities are
// refused. The operator panel remains the only place to see other accounts.
//
// Pending accounts (SIGNUP_MODE=invite, invite not yet redeemed) can read
// their account, redeem an invite and delete themselves; every other change
// is refused with 403 account-pending.

const { AuthError, extractCredential, extractOrg, readJsonBody, writeJson } = require("./public");
const { ROLES, publicOrg, roleAllows } = require("../auth/orgs");
const { INVITABLE_ROLES } = require("../auth/org_invites");

const PREFIX = "/api/me";
const ORGS_PREFIX = "/api/orgs";
const INVITE_ACCEPT_PATH = "/api/invites/accept";
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
  orgs = null,
  orgInvites = null,
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
    const identity = await authenticate(credential.token, { clientIP, req, allowPending: true, orgId: extractOrg(req) });
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

  // Failed guesses per user in the last hour, to slow down guessing of
  // signup codes and org invitation tokens.
  function failureTracker() {
    const failures = new Map(); // userId -> [timestamps]
    const recent = (userId) => {
      const cutoff = now() - 60 * 60 * 1000;
      const list = (failures.get(userId) || []).filter((t) => t > cutoff);
      if (list.length) failures.set(userId, list);
      else failures.delete(userId);
      return list;
    };
    return {
      tooMany: (userId) => recent(userId).length >= REDEEM_FAILURES_PER_HOUR,
      add: (userId) => failures.set(userId, [...recent(userId), now()]),
      clear: (userId) => failures.delete(userId),
    };
  }
  const redeemFailures = failureTracker();
  const acceptFailures = failureTracker();

  // Members close their own sessions; owners and admins close any in the org.
  // The list and the DELETE route both ask this, so the list never offers
  // what the route would refuse.
  function canCloseSession(identity, session) {
    if (roleAllows(identity.orgRole, "session.close.any")) return true;
    return session.identity.userId === identity.userId && roleAllows(identity.orgRole, "session.close.own");
  }

  // The org's live sessions, each saying who opened it and whether the caller
  // may close it. Usernames go only to roles that may list the org's members
  // (session.list and member.list are the same roles), so nothing new is shown.
  function ownSessions(identity) {
    const list = [];
    if (!activeSessions) return list;
    activeSessions.forEach((session, sessionId) => {
      if (session.identity && session.identity.owner === identity.owner) {
        list.push({
          ...sessionSummary(sessionId, session),
          username: session.identity.username || null,
          own: session.identity.userId === identity.userId,
          canClose: canCloseSession(identity, session),
        });
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

  const ORG_PATH = /^\/api\/orgs\/([0-9]+)$/;
  const MEMBERS_PATH = /^\/api\/orgs\/([0-9]+)\/members$/;
  const MEMBER_PATH = /^\/api\/orgs\/([0-9]+)\/members\/([0-9]+)$/;
  const INVITES_PATH = /^\/api\/orgs\/([0-9]+)\/invites$/;
  const INVITE_PATH = /^\/api\/orgs\/([0-9]+)\/invites\/([0-9]+)$/;

  // Who is acting, as the org store wants it. Operators pass every check,
  // but only when signed in: an operator's API token is a credential for
  // VMs and acts like any member's.
  function principal(identity) {
    return { userId: identity.userId, operator: identity.kind === "operator" && identity.via === "jwt" };
  }

  // 404 for an org the caller has no role in, so ids cannot be probed.
  async function requireMember(identity, orgId) {
    if (!orgId) throw new AuthError(404, "not-found");
    const known = principal(identity).operator
      ? await store(orgs).findById(orgId)
      : await store(orgs).getMembership(orgId, identity.userId);
    if (!known) throw new AuthError(404, "not-found");
  }

  // Checks `action` on the org named in the path and returns its id: 404 when
  // the caller is not a member, 403 when their role does not allow it.
  async function authorizeOrg(identity, action, path) {
    const orgId = parseId(/\/api\/orgs\/([0-9]+)/.exec(path)[1]);
    await requireMember(identity, orgId);
    if (!(await store(orgs).authorize(principal(identity), action, orgId))) throw new AuthError(403, "forbidden");
    return orgId;
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
          org: { id: identity.orgId, role: identity.orgRole },
          usage: await currentUsage(identity),
          activeSessions: ownSessions(identity).length,
        }];
      },
    },
    {
      method: "DELETE",
      match: (path) => path === PREFIX,
      allowPending: true,
      async handle({ identity, req }) {
        // Deleting an account needs a sign-in, not just an API token, and the
        // username typed back as confirmation.
        requireSignIn(identity);
        if (identity.kind === "operator") return [403, { error: "operators are deleted from the admin panel" }];
        const body = await readJsonBody(req);
        if (!body || body.confirm !== identity.username) {
          return [400, { error: "confirm must equal your username" }];
        }
        // Refused (409 sole-owner) while the account solely owns an org that
        // has other members; nothing is closed in that case.
        // Orgs deleted with the account had no other member, so every session
        // in them belongs to this user.
        await store(users).removeAccount(identity.userId);
        const killed = registry && registry.killUser ? registry.killUser(identity.userId, 1008, "account deleted") : 0;
        log?.info("account deleted by owner", { userId: identity.userId, killedSessions: killed });
        return [204, null];
      },
    },
    {
      method: "POST",
      match: (path) => path === `${PREFIX}/redeem`,
      allowPending: true,
      async handle({ identity, req }) {
        if (identity.status !== "pending") return [409, { error: "account is already active" }];
        const inviteStore = store(invites);
        if (!inviteStore) return [404, { error: "invites are not enabled" }];
        if (redeemFailures.tooMany(identity.userId)) {
          return [429, { error: "too many attempts; try again later" }];
        }
        const body = await readJsonBody(req);
        if (!(await inviteStore.redeem(body && body.code, identity.userId))) {
          redeemFailures.add(identity.userId);
          log?.warn("invite redemption failed", { userId: identity.userId });
          return [400, { error: "invalid, used or expired invite code" }];
        }
        await store(users).activatePending(identity.userId);
        redeemFailures.clear(identity.userId);
        log?.info("invite redeemed", { userId: identity.userId });
        return [200, { status: "active" }];
      },
    },
    {
      method: "GET",
      match: (path) => path === `${PREFIX}/usage`,
      async handle({ identity }) {
        const months = usage ? await usage.monthly(identity.orgId, { months: 12 }) : [];
        return [200, { current: await currentUsage(identity), months }];
      },
    },
    {
      method: "GET",
      match: (path) => path === `${PREFIX}/sessions`,
      async handle({ identity }) {
        if (!roleAllows(identity.orgRole, "session.list")) return [403, { error: "forbidden" }];
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
        if (!canCloseSession(identity, session)) return [403, { error: "forbidden" }];
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
        if (!roleAllows(identity.orgRole, "token.create")) return [403, { error: "forbidden" }];
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
        const created = await tokenStore.create({ userId: identity.userId, orgId: identity.orgId, name, expiresAt });
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

    // ---- organizations ----
    {
      method: "GET",
      match: (path) => path === `${PREFIX}/orgs`,
      async handle({ identity }) {
        return [200, await store(orgs).listForUser(identity.userId)];
      },
    },
    {
      method: "POST",
      match: (path) => path === ORGS_PREFIX,
      async handle({ identity, req }) {
        requireSignIn(identity);
        // Beta: only operators create shared orgs.
        if (identity.kind !== "operator") return [403, { error: "forbidden" }];
        const body = await readJsonBody(req);
        const name = typeof body.name === "string" ? body.name.trim() : "";
        if (!name) return [400, { error: "name is required" }];
        const ownerUserId = body.ownerUserId === undefined ? identity.userId : parseId(body.ownerUserId);
        const owner = ownerUserId ? await store(users).findById(ownerUserId) : null;
        if (!owner) return [400, { error: "ownerUserId must be an existing user" }];
        const org = await store(orgs).create({ name, ownerUserId: owner.id, tier: typeof body.tier === "string" ? body.tier : "user" });
        log?.info("org created", { orgId: org.id, ownerUserId: owner.id, by: identity.userId });
        return [201, publicOrg(org)];
      },
    },
    {
      method: "GET",
      match: (path) => ORG_PATH.test(path),
      async handle({ identity, path }) {
        const orgId = await authorizeOrg(identity, "org.view", path);
        const org = await store(orgs).findById(orgId);
        const membership = await store(orgs).getMembership(orgId, identity.userId);
        return [200, { ...publicOrg(org), role: membership ? membership.role : null }];
      },
    },
    {
      method: "PATCH",
      match: (path) => ORG_PATH.test(path),
      async handle({ identity, req, path }) {
        requireSignIn(identity);
        const orgId = await authorizeOrg(identity, "org.rename", path);
        const body = await readJsonBody(req);
        if (typeof body.name !== "string" || !body.name.trim()) return [400, { error: "name is required" }];
        await store(orgs).rename(orgId, body.name);
        return [200, publicOrg(await store(orgs).findById(orgId))];
      },
    },
    {
      method: "DELETE",
      match: (path) => ORG_PATH.test(path),
      async handle({ identity, path }) {
        requireSignIn(identity);
        const orgId = await authorizeOrg(identity, "org.delete", path);
        await store(orgs).remove(orgId);
        const killed = registry ? registry.killOwner(`org:${orgId}`, 1008, "organization deleted") : 0;
        log?.info("org deleted", { orgId, killedSessions: killed, by: identity.userId });
        return [204, null];
      },
    },
    {
      method: "GET",
      match: (path) => MEMBERS_PATH.test(path),
      async handle({ identity, path }) {
        const orgId = await authorizeOrg(identity, "member.list", path);
        return [200, await store(orgs).listMembers(orgId)];
      },
    },
    {
      method: "PATCH",
      match: (path) => MEMBER_PATH.test(path),
      async handle({ identity, req, path }) {
        requireSignIn(identity);
        const [, orgPart, userPart] = MEMBER_PATH.exec(path);
        const orgId = parseId(orgPart);
        const userId = parseId(userPart);
        const body = await readJsonBody(req);
        if (!ROLES.includes(body.role)) return [400, { error: `role must be one of ${ROLES.join(", ")}` }];
        await requireMember(identity, orgId);
        const result = await store(orgs).setMemberRole({ orgId, actor: principal(identity), userId, role: body.role });
        // A role that cannot open sessions ends the member's live ones.
        if (!roleAllows(result.role, "session.open") && registry && registry.killMember) {
          registry.killMember(`org:${orgId}`, userId, 1008, "role changed");
        }
        log?.info("org role changed", { orgId, userId, role: result.role, by: identity.userId });
        return [200, result];
      },
    },
    {
      method: "GET",
      match: (path) => INVITES_PATH.test(path),
      async handle({ identity, path }) {
        const orgId = await authorizeOrg(identity, "member.invite", path);
        return [200, await store(orgInvites).list(orgId)];
      },
    },
    {
      method: "POST",
      match: (path) => INVITES_PATH.test(path),
      async handle({ identity, req, path }) {
        requireSignIn(identity);
        const orgId = await authorizeOrg(identity, "member.invite", path);
        const body = await readJsonBody(req);
        if (!INVITABLE_ROLES.includes(body.role)) {
          return [400, { error: `role must be one of ${INVITABLE_ROLES.join(", ")}` }];
        }
        let created;
        try {
          created = await store(orgInvites).create({ orgId, email: body.email, role: body.role, createdBy: identity.userId });
        } catch (error) {
          if (error instanceof RangeError) return [400, { error: error.message }];
          throw error;
        }
        // The token is not logged: it is the credential.
        log?.info("org invite created", { orgId, inviteId: created.id, role: created.role, by: identity.userId });
        return [201, created];
      },
    },
    {
      method: "DELETE",
      match: (path) => INVITE_PATH.test(path),
      async handle({ identity, path }) {
        requireSignIn(identity);
        const orgId = await authorizeOrg(identity, "member.invite", path);
        const inviteId = parseId(INVITE_PATH.exec(path)[2]);
        if (!inviteId || !(await store(orgInvites).revoke(orgId, inviteId))) return [404, { error: "invite not found" }];
        log?.info("org invite revoked", { orgId, inviteId, by: identity.userId });
        return [204, null];
      },
    },
    {
      method: "POST",
      match: (path) => path === INVITE_ACCEPT_PATH,
      async handle({ identity, req }) {
        // Joining an org needs a sign-in (the token alone proves nothing about
        // who is accepting) and an account that is already active: an org
        // invitation never admits a pending sign-up.
        requireSignIn(identity);
        requireActive(identity);
        if (acceptFailures.tooMany(identity.userId)) return [429, { error: "too many attempts; try again later" }];
        const body = await readJsonBody(req);
        try {
          const joined = await store(orgInvites).accept(body && body.token, {
            id: identity.userId,
            email: identity.email,
            emailVerified: identity.emailVerified,
          });
          acceptFailures.clear(identity.userId);
          log?.info("org invite accepted", { orgId: joined.orgId, userId: identity.userId, role: joined.role });
          return [200, joined];
        } catch (error) {
          if (error.status === 404 || error.status === 403) acceptFailures.add(identity.userId);
          throw error;
        }
      },
    },
    {
      method: "DELETE",
      match: (path) => MEMBER_PATH.test(path),
      async handle({ identity, path }) {
        requireSignIn(identity);
        const [, orgPart, userPart] = MEMBER_PATH.exec(path);
        const orgId = parseId(orgPart);
        const userId = parseId(userPart);
        await requireMember(identity, orgId);
        await store(orgs).removeMember({ orgId, actor: principal(identity), userId });
        const killed = registry && registry.killMember ? registry.killMember(`org:${orgId}`, userId, 1008, "removed from organization") : 0;
        log?.info("org member removed", { orgId, userId, killedSessions: killed, by: identity.userId });
        return [204, null];
      },
    },
  ];

  function matches(path) {
    return path === PREFIX || path.startsWith(`${PREFIX}/`) || path === ORGS_PREFIX || path.startsWith(`${ORGS_PREFIX}/`) || path === INVITE_ACCEPT_PATH;
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
      if (req.method !== "GET" && !route.allowPending) requireActive(identity);
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
      // Internal errors (a TypeError, a SQLite message) stay in the log.
      const message = status >= 500 ? "internal-error" : error.code || error.message || "error";
      writeJson(res, status, { error: message }, corsHeaders);
    }
    return true;
  }

  return { handle, matches, PREFIX };
}

module.exports = { MAX_ACTIVE_TOKENS, PREFIX, createUserApi, publicTier, sessionSummary };
