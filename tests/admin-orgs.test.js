"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { resolveConfig } = require("../config");
const admin = require("../admin/app");
const { openDatabase } = require("../auth/db");
const { createUserStore } = require("../auth/users");
const { createApiTokenStore } = require("../auth/tokens");
const { createOrgStore } = require("../auth/orgs");
const { createOrgInviteStore } = require("../auth/org_invites");
const { resolveTiers } = require("../policy/tiers");

const quietLog = { debug() {}, info() {}, warn() {}, error() {} };

function call(port, { method = "GET", path = "/", cookie = null, body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : JSON.stringify(body);
    const headers = { ...(cookie ? { Cookie: cookie } : {}), ...(payload ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) } : {}) };
    const req = http.request({ host: "127.0.0.1", port, method, path, headers }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, json: () => (data ? JSON.parse(data) : null) }));
    });
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function start() {
  const config = resolveConfig({ RELAY_MODE: "hosted", ADMIN_SESSION_SECRET: "s", ANON_TOKEN_SECRET: "a", LOG_LEVEL: "0" });
  const db = openDatabase(":memory:");
  await db.migrate();
  const users = createUserStore(db, { bcryptRounds: 4 });
  const apiTokens = createApiTokenStore(db);
  const orgs = createOrgStore(db);
  const orgInvites = createOrgInviteStore(db, { orgs });
  const tiers = resolveTiers(null, { rateLimitBps: 1000, dnsServerIp: "8.8.8.8", maxUdpFlows: 10, maxConnectionsPerIp: 5, enableVmToVm: false });
  await users.create({ username: "ops", password: "password-1", role: "operator" });
  admin.configurePassport({ users });

  const closed = [];
  const activeSessions = new Map();
  const registry = {
    killOwner: (owner, code, reason) => { closed.push({ kind: "owner", owner, reason }); return 1; },
    killMember: (owner, userId, code, reason) => { closed.push({ kind: "member", owner, userId, reason }); return 1; },
    killUser: (userId, code, reason) => { closed.push({ kind: "user", userId, reason }); return 1; },
    killToken: () => 0,
  };
  const app = admin.createAdminApp({
    config, users, apiTokens, orgs, orgInvites, activeSessions, registry, rules: null,
    proxyPort: 0, poolCtx: { poolPrefix: "10.0.2.", dhcpStart: 15, dhcpEnd: 254 }, tiers, log: quietLog,
  });
  const server = await admin.startAdminServer(app, { port: 0, host: "127.0.0.1", log: quietLog });
  const port = server.address().port;
  const login = await call(port, { method: "POST", path: "/api/login", body: { username: "ops", password: "password-1" } });
  assert.equal(login.status, 200);
  const cookie = login.headers["set-cookie"][0].split(";")[0];
  return { port, cookie, users, orgs, apiTokens, orgInvites, activeSessions, closed, close: () => new Promise((r) => server.close(r)), db };
}

test("org routes need an operator session", async () => {
  const ctx = await start();
  try {
    for (const [method, path] of [["GET", "/api/orgs"], ["POST", "/api/orgs"], ["GET", "/api/orgs/1"], ["POST", "/api/orgs/1/suspend"], ["DELETE", "/api/orgs/1"]]) {
      assert.equal((await call(ctx.port, { method, path, body: method === "POST" ? {} : undefined })).status, 401, `${method} ${path}`);
    }
  } finally {
    await ctx.close();
  }
});

test("create, list and inspect orgs", async () => {
  const ctx = await start();
  try {
    const { port, cookie, users, activeSessions, apiTokens } = ctx;
    const alice = await users.create({ username: "alice" });
    const bob = await users.create({ username: "bob" });
    const post = (path, body) => call(port, { method: "POST", path, cookie, body });

    assert.equal((await post("/api/orgs", { name: "team" })).status, 400, "an owner is required");
    assert.equal((await post("/api/orgs", { name: "team", ownerUserId: 9999 })).status, 400);
    assert.equal((await post("/api/orgs", { name: "  ", ownerUserId: alice.id })).status, 400);
    assert.equal((await post("/api/orgs", { name: "team", ownerUserId: alice.id, tier: "nope" })).status, 400);
    const created = await post("/api/orgs", { name: "team", ownerUserId: alice.id, tier: "operator" });
    assert.equal(created.status, 201);
    const org = created.json();
    assert.deepEqual([org.personal, org.tier, org.status], [false, "operator", "active"]);

    await post(`/api/orgs/${org.id}/members`, { userId: bob.id, role: "member" });
    await apiTokens.create({ userId: bob.id, orgId: org.id, name: "ci" });
    activeSessions.set("s1", { identity: { owner: `org:${org.id}`, userId: bob.id } });
    activeSessions.set("s2", { identity: { owner: "org:99999", userId: 1 } });

    const list = (await call(port, { path: "/api/orgs", cookie })).json();
    const row = list.find((o) => o.id === org.id);
    assert.deepEqual([row.memberCount, row.sessions, row.personal], [2, 1, false]);
    assert.equal(list.filter((o) => o.personal).length, 3, "ops, alice and bob each have a personal org");

    const detail = (await call(port, { path: `/api/orgs/${org.id}`, cookie })).json();
    assert.deepEqual(detail.members.map((m) => [m.username, m.role]).sort(), [["alice", "owner"], ["bob", "member"]]);
    assert.deepEqual(detail.tokens.map((t) => [t.name, t.username]), [["ci", "bob"]]);
    assert.equal(JSON.stringify(detail).includes("token_hash"), false);
    assert.deepEqual(detail.invites, []);
    assert.equal((await call(port, { path: "/api/orgs/9999", cookie })).status, 404);
    assert.equal((await call(port, { path: "/api/orgs/abc", cookie })).status, 404);
  } finally {
    await ctx.close();
  }
});

test("tier, suspend and delete", async () => {
  const ctx = await start();
  try {
    const { port, cookie, users, orgs, closed } = ctx;
    const alice = await users.create({ username: "alice" });
    const team = await orgs.create({ name: "team", ownerUserId: alice.id });
    const post = (path, body) => call(port, { method: "POST", path, cookie, body });

    // Tier: validated, applied to the org, and mirrored onto a personal org's owner.
    assert.equal((await post(`/api/orgs/${team.id}/tier`, { tier: "nope" })).status, 400);
    assert.equal((await post(`/api/orgs/${team.id}/tier`, {})).status, 400);
    assert.equal((await post(`/api/orgs/${team.id}/tier`, { tier: "operator" })).json().tier, "operator");
    assert.equal((await post(`/api/orgs/${alice.default_org_id}/tier`, { tier: "operator" })).status, 200);
    assert.equal((await users.findById(alice.id)).tier, "operator", "the owner's account follows its personal org");
    assert.equal((await orgs.findById(team.id)).tier, "operator");

    // Suspending ends the org's live sessions; unsuspending reopens it.
    const suspended = await post(`/api/orgs/${team.id}/suspend`, {});
    assert.deepEqual([suspended.json().status, suspended.json().killedSessions], ["suspended", 1]);
    assert.deepEqual(closed.at(-1), { kind: "owner", owner: `org:${team.id}`, reason: "organization suspended" });
    assert.equal((await orgs.findById(team.id)).status, "suspended");
    assert.equal((await post(`/api/orgs/${team.id}/unsuspend`, {})).json().status, "active");
    assert.equal((await post("/api/orgs/9999/suspend", {})).status, 404);

    // Personal orgs go with their user, not through here.
    const personal = await call(ctx.port, { method: "DELETE", path: `/api/orgs/${alice.default_org_id}`, cookie });
    assert.equal(personal.status, 409);
    assert.equal(personal.json().error, "personal-org");
    assert.equal((await call(ctx.port, { method: "DELETE", path: `/api/orgs/${team.id}`, cookie })).status, 204);
    assert.deepEqual(closed.at(-1), { kind: "owner", owner: `org:${team.id}`, reason: "organization deleted" });
    assert.equal(await orgs.findById(team.id), undefined);
  } finally {
    await ctx.close();
  }
});

test("operators add, re-role and remove members; the last owner stays", async () => {
  const ctx = await start();
  try {
    const { port, cookie, users, orgs, closed } = ctx;
    const alice = await users.create({ username: "alice" });
    const bob = await users.create({ username: "bob" });
    const team = await orgs.create({ name: "team", ownerUserId: alice.id });
    const base = `/api/orgs/${team.id}/members`;
    const post = (path, body) => call(port, { method: "POST", path, cookie, body });

    assert.equal((await post(base, { userId: 9999, role: "member" })).status, 400);
    assert.equal((await post(base, { userId: bob.id, role: "wizard" })).status, 400);
    assert.equal((await post(base, { userId: bob.id, role: "member" })).status, 201);
    assert.equal((await post(base, { userId: bob.id, role: "admin" })).json().error, "already-member");

    // An operator acts as an owner: it can grant owner, and demote when another owner remains.
    assert.equal((await post(`${base}/${bob.id}/role`, { role: "owner" })).status, 200);
    assert.equal((await post(`${base}/${alice.id}/role`, { role: "billing" })).status, 200);
    assert.deepEqual(closed.at(-1), { kind: "member", owner: `org:${team.id}`, userId: alice.id, reason: "role changed" }, "a role that cannot open sessions ends them");
    const last = await post(`${base}/${bob.id}/role`, { role: "member" });
    assert.equal(last.status, 409);
    assert.equal(last.json().error, "last-owner");
    assert.equal((await post(`${base}/${bob.id}/role`, { role: "wizard" })).status, 400);
    assert.equal((await post(`${base}/9999/role`, { role: "member" })).json().error, "not-a-member");

    // Removing a member ends their sessions; the last owner cannot be removed.
    assert.equal((await call(port, { method: "DELETE", path: `${base}/${alice.id}`, cookie })).status, 204);
    assert.deepEqual(closed.at(-1), { kind: "member", owner: `org:${team.id}`, userId: alice.id, reason: "removed from organization" });
    const refused = await call(port, { method: "DELETE", path: `${base}/${bob.id}`, cookie });
    assert.equal(refused.status, 409);
    assert.equal((await call(port, { method: "DELETE", path: `${base}/${alice.id}`, cookie })).status, 404);
    assert.deepEqual((await orgs.listMembers(team.id)).map((m) => m.username), ["bob"]);
  } finally {
    await ctx.close();
  }
});
