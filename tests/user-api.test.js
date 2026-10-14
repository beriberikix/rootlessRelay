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
const { resolveTiers } = require("../policy/tiers");

const quietLog = { debug() {}, info() {}, warn() {}, error() {} };

function request(port, { method = "GET", path = "/", headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path, headers }, (res) => {
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

function fakeSession({ owner, clientIP = "10.1.1.1", bytesSent = 0 }) {
  const closed = [];
  return {
    identity: { owner },
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

async function startServer({ env = {}, usage = null } = {}) {
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
  const authenticate = createAuthenticator({ config, users, apiTokens, log: quietLog });

  const activeSessions = new Map();
  const registry = {
    kill(sessionId, code, reason) {
      const session = activeSessions.get(sessionId);
      if (!session) return false;
      session.ws.close(code, reason);
      return true;
    },
  };
  const tiers = resolveTiers(null, { rateLimitBps: 1000, dnsServerIp: "8.8.8.8", maxUdpFlows: 10, maxConnectionsPerIp: 5, enableVmToVm: false });
  const userApi = createUserApi({
    authenticate,
    users: () => users,
    apiTokens,
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
  return { server, port: address.port, db, users, apiTokens, activeSessions, tiers };
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
    const mine = fakeSession({ owner: `user:${alice.id}`, bytesSent: 42 });
    const theirs = fakeSession({ owner: `user:${bob.id}` });
    activeSessions.set("s-alice", mine);
    activeSessions.set("s-bob", theirs);

    const auth = (t) => ({ Authorization: `Bearer ${t}` });
    const list = await request(port, { path: "/api/me/sessions", headers: auth(aliceToken) });
    assert.equal(list.status, 200);
    assert.deepEqual(list.json().map((s) => s.sessionId), ["s-alice"]);
    assert.equal(list.json()[0].bytesSent, 42);
    assert.equal(list.json()[0].startedAt, new Date(1000).toISOString());

    assert.equal((await request(port, { method: "DELETE", path: "/api/me/sessions/s-bob", headers: auth(aliceToken) })).status, 404);
    assert.equal(theirs.closed.length, 0);
    assert.equal((await request(port, { method: "DELETE", path: "/api/me/sessions/s-alice", headers: auth(aliceToken) })).status, 204);
    assert.deepEqual(mine.closed, [{ code: 1008, reason: "terminated by account owner" }]);
    assert.equal((await request(port, { method: "DELETE", path: "/api/me/sessions/s-alice", headers: auth(bobToken) })).status, 404);
  } finally {
    await server.close();
  }
});

test("token self-service: create with expiry, list, revoke only your own, cap on active tokens", async () => {
  const { server, port, users, apiTokens } = await startServer();
  try {
    const alice = await users.create({ username: "alice", role: "user" });
    const bob = await users.create({ username: "bob", role: "user" });
    const aliceToken = (await apiTokens.create({ userId: alice.id, name: "seed" })).token;
    const bobOwned = await apiTokens.create({ userId: bob.id, name: "bobs" });
    const auth = { Authorization: `Bearer ${aliceToken}`, "Content-Type": "application/json" };

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
    assert.equal((await request(port, { method: "DELETE", path: `/api/me/tokens/${token.id}`, headers: auth })).status, 204);
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
