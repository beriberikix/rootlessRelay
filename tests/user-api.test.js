"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { resolveConfig } = require("../config");
const { AuthError, createPublicServer } = require("../server/public");
const { MAX_ACTIVE_TOKENS, createUserApi, publicTier } = require("../server/user_api");
const { openDatabase } = require("../auth/db");
const { createUserStore } = require("../auth/users");
const { createApiTokenStore, createAuthenticator } = require("../auth/tokens");
const { createOrgStore } = require("../auth/orgs");
const { createInviteStore } = require("../auth/invites");
const { resolveTiers } = require("../policy/tiers");

const quietLog = { debug() {}, info() {}, warn() {}, error() {} };

function request(port, { method = "GET", path = "/", headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    // Node sends DELETE bodies without framing unless Content-Length is set.
    const framed = body ? { "Content-Length": Buffer.byteLength(body), ...headers } : headers;
    const req = http.request({ host: "127.0.0.1", port, method, path, headers: framed }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        data += chunk;
      });
      res.on("end", () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: data,
        json: () => (data ? JSON.parse(data) : null),
      }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

function fakeSession({ owner, userId = null, clientIP = "10.1.1.1", bytesSent = 0 }) {
  const closed = [];
  return {
    identity: { owner, userId },
    clientIP,
    vmIP: "10.0.2.15",
    bytesSent,
    bytesReceived: 0,
    tcpConnections: new Map(),
    udpFlows: new Map(),
    startedAt: 1000,
    ws: { close: (code, reason) => closed.push({ code, reason }) },
    closed,
  };
}

// Bearers prefixed "jwt:" stand in for a signed-in (external JWT) session of
// the account that owns the API token after the prefix.
const signedIn = (fn) => async (token, ctx) => {
  if (token.startsWith("jwt:")) return { ...(await fn(token.slice(4), ctx)), via: "jwt" };
  return fn(token, ctx);
};

async function startServer({ env = {}, usage = null, wrapAuthenticate = signedIn } = {}) {
  const config = resolveConfig({
    RELAY_MODE: "hosted",
    ADMIN_SESSION_SECRET: "s",
    ANON_TOKEN_SECRET: "a",
    LOG_LEVEL: "0",
    ...env,
  });
  const db = openDatabase(":memory:");
  await db.migrate();
  const users = createUserStore(db, { bcryptRounds: 4 });
  const apiTokens = createApiTokenStore(db);
  const invites = createInviteStore(db);
  const orgs = createOrgStore(db);
  const authenticate = wrapAuthenticate(createAuthenticator({ config, users, apiTokens, orgs, log: quietLog }));

  const activeSessions = new Map();
  const registry = {
    kill(sessionId, code, reason) {
      const session = activeSessions.get(sessionId);
      if (!session) return false;
      session.ws.close(code, reason);
      return true;
    },
    killToken(tokenId, code, reason) {
      let killed = 0;
      activeSessions.forEach((session) => {
        if (session.identity.tokenId === tokenId) {
          session.ws.close(code, reason);
          killed += 1;
        }
      });
      return killed;
    },
    killUser(userId, code, reason) {
      let killed = 0;
      activeSessions.forEach((session) => {
        if (session.identity.userId === userId) {
          session.ws.close(code, reason);
          killed += 1;
        }
      });
      return killed;
    },
    killOwner(owner, code, reason) {
      let killed = 0;
      activeSessions.forEach((session) => {
        if (session.identity.owner === owner) {
          session.ws.close(code, reason);
          killed += 1;
        }
      });
      return killed;
    },
  };
  const tiers = resolveTiers(null, { rateLimitBps: 1000, dnsServerIp: "8.8.8.8", maxUdpFlows: 10, maxConnectionsPerIp: 5, enableVmToVm: false });
  const userApi = createUserApi({
    authenticate,
    users: () => users,
    apiTokens,
    invites,
    usage,
    registry,
    activeSessions,
    tiers,
    log: quietLog,
    now: () => 1_700_000_000_000,
  });
  const server = createPublicServer({
    config,
    log: quietLog,
    authenticate,
    lifecycle: { isShuttingDown: () => false },
    userApi,
  });
  const address = await server.listen(0, "127.0.0.1");
  return { server, port: address.port, db, users, orgs, apiTokens, invites, activeSessions, tiers };
}

test("public tier view exposes only user-facing limits", () => {
  const tiers = resolveTiers(null, { rateLimitBps: 1000, dnsServerIp: "8.8.8.8", maxUdpFlows: 10, maxConnectionsPerIp: 5, enableVmToVm: false });
  const view = publicTier("anon", tiers);
  assert.equal(view.name, "anon");
  assert.equal(typeof view.quotaBytes, "number");
  assert.equal(view.synPerSec, undefined);
  assert.equal(view.dnsServers, undefined);
  assert.deepEqual(publicTier("missing", tiers), { name: "missing" });
});

test("account routes need a bearer that resolves to an account", async () => {
  const { server, port, users, apiTokens } = await startServer();
  try {
    assert.equal((await request(port, { path: "/api/me" })).status, 401);
    assert.equal((await request(port, { path: "/api/me", headers: { Authorization: "Bearer nope" } })).status, 401);
    assert.equal((await request(port, { path: "/api/me/nope", headers: { Authorization: "Bearer x" } })).status, 404);
    assert.equal((await request(port, { method: "POST", path: "/api/me", headers: { Authorization: "Bearer x" } })).status, 405);

    const alice = await users.create({ username: "alice", role: "user" });
    const { token } = await apiTokens.create({ userId: alice.id, name: "cli" });
    const me = await request(port, { path: "/api/me", headers: { Authorization: `Bearer ${token}` } });
    assert.equal(me.status, 200);
    const body = me.json();
    assert.equal(body.user.username, "alice");
    assert.equal(body.user.tier, "user");
    assert.equal(body.tier.name, "user");
    assert.equal(body.activeSessions, 0);
    assert.deepEqual(body.usage, { period: "month", bytes: 0, quotaBytes: body.tier.quotaBytes });

    await users.setStatus(alice.id, "banned");
    assert.equal((await request(port, { path: "/api/me", headers: { Authorization: `Bearer ${token}` } })).status, 403);
  } finally {
    await server.close();
  }
});

test("sessions are scoped to the owner and only the owner can kill them", async () => {
  const { server, port, users, apiTokens, activeSessions } = await startServer();
  try {
    const alice = await users.create({ username: "alice", role: "user" });
    const bob = await users.create({ username: "bob", role: "user" });
    const aliceToken = (await apiTokens.create({ userId: alice.id })).token;
    const bobToken = (await apiTokens.create({ userId: bob.id })).token;
    const mine = fakeSession({ owner: `org:${alice.default_org_id}`, userId: alice.id, bytesSent: 42 });
    const theirs = fakeSession({ owner: `org:${bob.default_org_id}`, userId: bob.id });
    activeSessions.set("s-alice", mine);
    activeSessions.set("s-bob", theirs);

    const auth = (t) => ({ Authorization: `Bearer ${t}` });
    const list = await request(port, { path: "/api/me/sessions", headers: auth(aliceToken) });
    assert.equal(list.status, 200);
    assert.deepEqual(list.json().map((s) => s.sessionId), ["s-alice"]);
    assert.equal(list.json()[0].bytesSent, 42);
    assert.equal(list.json()[0].startedAt, new Date(1000).toISOString());

    assert.equal((await request(port, { method: "DELETE", path: "/api/me/sessions/s-bob", headers: auth(aliceToken) })).status, 404);
    assert.equal((await request(port, { method: "DELETE", path: "/api/me/sessions/%E0", headers: auth(aliceToken) })).status, 404, "malformed id");
    assert.equal(theirs.closed.length, 0);
    assert.equal((await request(port, { method: "DELETE", path: "/api/me/sessions/s-alice", headers: auth(aliceToken) })).status, 204);
    assert.deepEqual(mine.closed, [{ code: 1008, reason: "terminated by account owner" }]);
    assert.equal((await request(port, { method: "DELETE", path: "/api/me/sessions/s-alice", headers: auth(bobToken) })).status, 404);
  } finally {
    await server.close();
  }
});

test("token self-service: create with expiry, list, revoke only your own, cap on active tokens", async () => {
  const { server, port, users, apiTokens, activeSessions } = await startServer();
  try {
    const alice = await users.create({ username: "alice", role: "user" });
    const bob = await users.create({ username: "bob", role: "user" });
    const aliceToken = (await apiTokens.create({ userId: alice.id, name: "seed" })).token;
    const bobOwned = await apiTokens.create({ userId: bob.id, name: "bobs" });
    const auth = { Authorization: `Bearer jwt:${aliceToken}`, "Content-Type": "application/json" };
    const tokenOnly = { Authorization: `Bearer ${aliceToken}`, "Content-Type": "application/json" };
    const minted = await request(port, { method: "POST", path: "/api/me/tokens", headers: tokenOnly, body: "{}" });
    assert.equal(minted.status, 403, "an API token cannot mint tokens");
    assert.equal(minted.json().error, "sign-in-required");
    assert.equal((await request(port, { method: "DELETE", path: `/api/me/tokens/${bobOwned.id}`, headers: tokenOnly })).status, 403);
    assert.equal((await request(port, { path: "/api/me/tokens", headers: tokenOnly })).status, 200, "listing is fine");

    const created = await request(port, {
      method: "POST", path: "/api/me/tokens", headers: auth, body: JSON.stringify({ name: "laptop", expiresInDays: 30 }),
    });
    assert.equal(created.status, 201);
    const token = created.json();
    assert.match(token.token, /^rr_/);
    assert.equal(token.name, "laptop");
    assert.equal(token.expiresAt, new Date(1_700_000_000_000 + 30 * 86400000).toISOString());

    const bad = await request(port, {
      method: "POST", path: "/api/me/tokens", headers: auth, body: JSON.stringify({ expiresInDays: 0 }),
    });
    assert.equal(bad.status, 400);

    const list = await request(port, { path: "/api/me/tokens", headers: auth });
    assert.deepEqual(list.json().map((t) => t.name), ["seed", "laptop"]);
    assert.ok(list.json().every((t) => t.token === undefined), "secrets are never listed");

    assert.equal((await request(port, { method: "DELETE", path: `/api/me/tokens/${bobOwned.id}`, headers: auth })).status, 404);
    const viaLaptop = { ...fakeSession({ owner: `org:${alice.default_org_id}`, userId: alice.id }) };
    viaLaptop.identity = { owner: `org:${alice.default_org_id}`, userId: alice.id, tokenId: token.id };
    activeSessions.set("s-laptop", viaLaptop);
    assert.equal((await request(port, { method: "DELETE", path: `/api/me/tokens/${token.id}`, headers: auth })).status, 204);
    assert.deepEqual(viaLaptop.closed, [{ code: 1008, reason: "token revoked" }], "revoking closes its sessions");
    assert.equal((await request(port, { method: "DELETE", path: `/api/me/tokens/${token.id}`, headers: auth })).status, 404);
    const after = await request(port, { path: "/api/me/tokens", headers: auth });
    assert.ok(after.json().find((t) => t.id === token.id).revokedAt);

    // The cap counts active (unrevoked, unexpired) tokens only.
    for (let i = 1; i < MAX_ACTIVE_TOKENS; i += 1) {
      const r = await request(port, { method: "POST", path: "/api/me/tokens", headers: auth, body: JSON.stringify({ name: `t${i}` }) });
      assert.equal(r.status, 201);
    }
    const over = await request(port, { method: "POST", path: "/api/me/tokens", headers: auth, body: JSON.stringify({ name: "one too many" }) });
    assert.equal(over.status, 409);
  } finally {
    await server.close();
  }
});

test("usage comes from the meter; CORS applies to account routes; anonymous identities are refused", async () => {
  const usage = {
    async periodUsage({ identity }) {
      return identity.userId === 1 ? 12345 : 0;
    },
    async monthly(userId) {
      return [{ month: "2026-10", bytesIn: 100, bytesOut: 200, sessions: 3, userId }];
    },
  };
  const { server, port, users, apiTokens } = await startServer({
    env: { ALLOWED_ORIGINS: "https://app.example.com" },
    usage,
  });
  try {
    const alice = await users.create({ username: "alice", role: "user" });
    const token = (await apiTokens.create({ userId: alice.id })).token;
    const headers = { Authorization: `Bearer ${token}`, Origin: "https://app.example.com" };
    const res = await request(port, { path: "/api/me/usage", headers });
    assert.equal(res.status, 200);
    assert.equal(res.json().current.bytes, 12345);
    assert.equal(res.json().months[0].month, "2026-10");
    assert.equal(res.headers["access-control-allow-origin"], "https://app.example.com");
    assert.match(res.headers["access-control-allow-methods"], /DELETE/);

    const other = await request(port, { path: "/api/me", headers: { ...headers, Origin: "https://evil.example" } });
    assert.equal(other.status, 403);

    const preflight = await request(port, {
      method: "OPTIONS",
      path: "/api/me/tokens",
      headers: { Origin: "https://app.example.com", "Access-Control-Request-Method": "POST" },
    });
    assert.equal(preflight.status, 204);
  } finally {
    await server.close();
  }

  // An authenticator that yields an identity without a user id (anonymous).
  const anonApi = createUserApi({
    authenticate: async () => ({ kind: "anon", owner: "anon:x", tier: "anon" }),
    users: null,
    apiTokens: null,
    usage: null,
    registry: null,
    activeSessions: new Map(),
    tiers: {},
  });
  const captured = [];
  const res = {
    writeHead(status, headers) {
      captured.push({ status, headers });
    },
    end(body) {
      captured.push({ body });
    },
  };
  await anonApi.handle({ method: "GET", headers: { authorization: "Bearer anon" }, url: "/api/me" }, res, { path: "/api/me", clientIP: "1.2.3.4" });
  assert.equal(captured[0].status, 403);
  assert.ok(AuthError);
});

test("pending accounts can read, redeem an invite and nothing else", async () => {
  const { server, port, users, apiTokens, invites } = await startServer();
  try {
    const erin = await users.create({ username: "erin", status: "pending" });
    const token = (await apiTokens.create({ userId: erin.id })).token;
    const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };

    const me = await request(port, { path: "/api/me", headers });
    assert.equal(me.status, 200);
    assert.equal(me.json().user.status, "pending");
    const mint = await request(port, { method: "POST", path: "/api/me/tokens", headers, body: "{}" });
    assert.equal(mint.status, 403);
    assert.equal(mint.json().error, "account-pending");

    const bad = await request(port, { method: "POST", path: "/api/me/redeem", headers, body: JSON.stringify({ code: "RLY-0000-0000-0000" }) });
    assert.equal(bad.status, 400);
    const invite = await invites.create({});
    const good = await request(port, { method: "POST", path: "/api/me/redeem", headers, body: JSON.stringify({ code: invite.code.toLowerCase() }) });
    assert.equal(good.status, 200);
    assert.equal((await users.findById(erin.id)).status, "active");
    assert.equal((await request(port, { method: "POST", path: "/api/me/redeem", headers, body: JSON.stringify({ code: invite.code }) })).status, 409);
    assert.equal((await request(port, { method: "POST", path: "/api/me/tokens", headers, body: "{}" })).status, 403, "API token alone");
    assert.equal((await request(port, { method: "POST", path: "/api/me/tokens", headers: { ...headers, Authorization: `Bearer jwt:${token}` }, body: "{}" })).status, 201);

    // Guessing is throttled per account.
    const frank = await users.create({ username: "frank", status: "pending" });
    const frankHeaders = { Authorization: `Bearer ${(await apiTokens.create({ userId: frank.id })).token}` };
    for (let i = 0; i < 10; i += 1) {
      const r = await request(port, { method: "POST", path: "/api/me/redeem", headers: frankHeaders, body: JSON.stringify({ code: "nope" }) });
      assert.equal(r.status, 400);
    }
    const spare = await invites.create({});
    const throttled = await request(port, { method: "POST", path: "/api/me/redeem", headers: frankHeaders, body: JSON.stringify({ code: spare.code }) });
    assert.equal(throttled.status, 429);
  } finally {
    await server.close();
  }
});

test("account deletion needs a sign-in and the username typed back", async () => {
  const { server, port, users, apiTokens, activeSessions } = await startServer();
  try {
    const gina = await users.create({ username: "gina" });
    const token = (await apiTokens.create({ userId: gina.id })).token;
    const session = fakeSession({ owner: `org:${gina.default_org_id}`, userId: gina.id });
    activeSessions.set("s-gina", session);

    const viaToken = await request(port, { method: "DELETE", path: "/api/me", headers: { Authorization: `Bearer ${token}` }, body: JSON.stringify({ confirm: "gina" }) });
    assert.equal(viaToken.status, 403);
    assert.equal(viaToken.json().error, "sign-in-required");

    const signedIn = { Authorization: `Bearer jwt:${token}`, "Content-Type": "application/json" };
    assert.equal((await request(port, { method: "DELETE", path: "/api/me", headers: signedIn, body: JSON.stringify({ confirm: "Gina" }) })).status, 400);
    assert.equal((await request(port, { method: "DELETE", path: "/api/me", headers: signedIn, body: JSON.stringify({ confirm: "gina" }) })).status, 204);
    assert.deepEqual(session.closed, [{ code: 1008, reason: "account deleted" }]);
    assert.equal(await users.findById(gina.id), undefined);
    assert.equal((await request(port, { path: "/api/me", headers: { Authorization: `Bearer ${token}` } })).status, 401);

    const op = await users.create({ username: "ops", role: "operator" });
    const opToken = (await apiTokens.create({ userId: op.id })).token;
    assert.equal((await request(port, { method: "DELETE", path: "/api/me", headers: { Authorization: `Bearer jwt:${opToken}` }, body: JSON.stringify({ confirm: "ops" }) })).status, 403);
  } finally {
    await server.close();
  }
});

test("roles gate sessions and tokens inside a shared org", async () => {
  const { server, port, users, orgs, apiTokens, activeSessions } = await startServer();
  try {
    const owner = await users.create({ username: "owner" });
    const admin = await users.create({ username: "admin" });
    const member = await users.create({ username: "member" });
    const viewer = await users.create({ username: "viewer" });
    const biller = await users.create({ username: "biller" });
    const team = await orgs.create({ name: "team", ownerUserId: owner.id });
    await orgs.addMember({ orgId: team.id, userId: admin.id, role: "admin" });
    await orgs.addMember({ orgId: team.id, userId: member.id, role: "member" });
    await orgs.addMember({ orgId: team.id, userId: viewer.id, role: "read_only" });
    await orgs.addMember({ orgId: team.id, userId: biller.id, role: "billing" });
    const token = async (user) => (await apiTokens.create({ userId: user.id, orgId: team.id })).token;
    const auth = (t, signedIn = false) => ({ Authorization: `Bearer ${signedIn ? "jwt:" : ""}${t}`, "Content-Type": "application/json" });

    const sessions = {
      owner: fakeSession({ owner: `org:${team.id}`, userId: owner.id }),
      member: fakeSession({ owner: `org:${team.id}`, userId: member.id }),
    };
    activeSessions.set("s-owner", sessions.owner);
    activeSessions.set("s-member", sessions.member);

    // Everyone who may read the org sees all its sessions; billing does not.
    const viewerToken = await token(viewer);
    const billerToken = await token(biller);
    const listed = await request(port, { path: "/api/me/sessions", headers: auth(viewerToken) });
    assert.deepEqual(listed.json().map((s) => s.sessionId).sort(), ["s-member", "s-owner"]);
    assert.equal((await request(port, { path: "/api/me/sessions", headers: auth(billerToken) })).status, 403);
    assert.equal((await request(port, { path: "/api/me", headers: auth(billerToken) })).json().org.role, "billing");
    assert.equal((await request(port, { path: "/api/me/usage", headers: auth(billerToken) })).status, 200);

    // A member closes their own session, not a colleague's; an admin closes any; read-only none.
    const memberToken = await token(member);
    assert.equal((await request(port, { method: "DELETE", path: "/api/me/sessions/s-owner", headers: auth(memberToken) })).status, 403);
    assert.equal(sessions.owner.closed.length, 0);
    assert.equal((await request(port, { method: "DELETE", path: "/api/me/sessions/s-member", headers: auth(viewerToken) })).status, 403);
    assert.equal((await request(port, { method: "DELETE", path: "/api/me/sessions/s-member", headers: auth(memberToken) })).status, 204);
    assert.equal((await request(port, { method: "DELETE", path: "/api/me/sessions/s-owner", headers: auth(await token(admin)) })).status, 204);

    // Only roles that open sessions mint tokens, and the token belongs to the caller's org.
    const create = (user, signedInToken) => request(port, { method: "POST", path: "/api/me/tokens", headers: auth(signedInToken, true), body: JSON.stringify({ name: "ci" }) });
    assert.equal((await create(viewer, viewerToken)).status, 403);
    assert.equal((await create(biller, billerToken)).status, 403);
    const made = await create(member, memberToken);
    assert.equal(made.status, 201);
    const row = await apiTokens.verify(made.json().token);
    assert.equal(row.orgId, team.id);
    assert.equal(row.user.id, member.id);
  } finally {
    await server.close();
  }
});

test("deleting an account that solely owns a shared org is refused", async () => {
  const { server, port, users, orgs, apiTokens, activeSessions } = await startServer();
  try {
    const owner = await users.create({ username: "owner" });
    const member = await users.create({ username: "member" });
    const team = await orgs.create({ name: "team", ownerUserId: owner.id });
    await orgs.addMember({ orgId: team.id, userId: member.id, role: "member" });
    const token = (await apiTokens.create({ userId: owner.id })).token;
    const session = fakeSession({ owner: `org:${owner.default_org_id}`, userId: owner.id });
    activeSessions.set("s-owner", session);
    const headers = { Authorization: `Bearer jwt:${token}`, "Content-Type": "application/json" };
    const refused = await request(port, { method: "DELETE", path: "/api/me", headers, body: JSON.stringify({ confirm: "owner" }) });
    assert.equal(refused.status, 409);
    assert.equal(refused.json().error, "sole-owner");
    assert.equal(session.closed.length, 0, "nothing is closed when the delete is refused");
    assert.ok(await users.findById(owner.id));
  } finally {
    await server.close();
  }
});
