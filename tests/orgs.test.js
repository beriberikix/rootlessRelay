"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { MIGRATIONS, openDatabase } = require("../auth/db");
const { createUserStore } = require("../auth/users");
const { OrgError, PERMISSIONS, ROLES, createOrgStore, roleAllows } = require("../auth/orgs");
const { createApiTokenStore, createAuthenticator, generateApiToken } = require("../auth/tokens");

async function setup() {
  const db = openDatabase(":memory:");
  await db.migrate();
  const users = createUserStore(db, { bcryptRounds: 4 });
  const orgs = createOrgStore(db);
  const apiTokens = createApiTokenStore(db);
  const authenticate = createAuthenticator({ config: { authRequired: true, anonEnabled: false }, users, apiTokens, orgs });
  return { db, users, orgs, apiTokens, authenticate };
}

const rejectsWith = (code, status) => (error) => error instanceof OrgError && error.code === code && error.status === status;

// The permission matrix from docs/design/orgs-teams-roles.md, written out
// independently of PERMISSIONS so a change to either shows up here.
const MATRIX = {
  //                        owner  admin  member billing read_only
  "org.view":              [true,  true,  true,  true,  true],
  "usage.view":            [true,  true,  true,  true,  true],
  "member.list":           [true,  true,  true,  false, true],
  "session.list":          [true,  true,  true,  false, true],
  "session.open":          [true,  true,  true,  false, false],
  "session.close.own":     [true,  true,  true,  false, false],
  "session.close.any":     [true,  true,  false, false, false],
  "token.create":          [true,  true,  true,  false, false],
  "token.revoke.own":      [true,  true,  true,  false, false],
  "token.revoke.any":      [true,  true,  false, false, false],
  "member.invite":         [true,  true,  false, false, false],
  "member.remove":         [true,  true,  false, false, false],
  "member.role":           [true,  true,  false, false, false],
  "team.manage":           [true,  true,  false, false, false],
  "org.rename":            [true,  true,  false, false, false],
  "billing.view":          [true,  false, false, true,  false],
  "billing.manage":        [true,  false, false, true,  false],
  "org.delete":            [true,  false, false, false, false],
  "org.transfer":          [true,  false, false, false, false],
};

test("every role/action pair matches the permission matrix", () => {
  assert.deepEqual(Object.keys(MATRIX).sort(), Object.keys(PERMISSIONS).sort(), "matrix covers every action");
  for (const [action, expected] of Object.entries(MATRIX)) {
    ROLES.forEach((role, index) => {
      assert.equal(roleAllows(role, action), expected[index], `${role} ${action}`);
    });
  }
  assert.throws(() => roleAllows("owner", "no.such.action"), RangeError);
});

test("authorize: roles, outsiders and operators", async () => {
  const { users, orgs } = await setup();
  const alice = await users.create({ username: "alice" });
  const bob = await users.create({ username: "bob" });
  const ops = await users.create({ username: "ops", role: "operator" });
  const org = alice.default_org_id;
  await orgs.addMember({ orgId: org, userId: bob.id, role: "read_only" });

  assert.equal(await orgs.authorize({ userId: alice.id }, "org.delete", org), true);
  assert.equal(await orgs.authorize({ userId: bob.id }, "member.list", org), true);
  assert.equal(await orgs.authorize({ userId: bob.id }, "token.create", org), false);
  assert.equal(await orgs.authorize({ userId: bob.id }, "org.view", bob.default_org_id), true, "owner of own personal org");
  assert.equal(await orgs.authorize({ userId: ops.id }, "org.view", org), false, "operators are not implicit members");
  assert.equal(await orgs.authorize({ userId: ops.id, operator: true }, "org.delete", org), true);
  assert.equal(await orgs.authorize({ userId: ops.id, operator: true }, "org.delete", 9999), false, "no such org");
  assert.equal(await orgs.authorize(null, "org.view", org), false);
  await assert.rejects(orgs.authorize({ userId: alice.id }, "no.such.action", org), RangeError);
});

test("every user gets a personal org they own, carrying their tier", async () => {
  const { users, orgs } = await setup();
  const alice = await users.create({ username: "alice", tier: "user" });
  const ops = await users.create({ username: "ops", role: "operator" });
  const org = await orgs.findById(alice.default_org_id);
  assert.equal(org.personal, 1);
  assert.equal(org.name, "alice");
  assert.equal(org.tier, "user");
  assert.deepEqual(await orgs.getMembership(org.id, alice.id), { orgId: org.id, userId: alice.id, role: "owner" });
  assert.equal((await orgs.findById(ops.default_org_id)).tier, "operator");

  const external = await users.upsertExternal({ externalSub: "idp|1", username: "ext@example.com" });
  assert.ok(external.default_org_id);
  assert.equal((await users.upsertExternal({ externalSub: "idp|1" })).default_org_id, external.default_org_id, "idempotent");

  // The operator panel sets the tier on the user; the personal org follows.
  await users.setTier(alice.id, "pro");
  assert.equal((await orgs.findById(alice.default_org_id)).tier, "pro");
});

test("concurrent first sight creates one personal org", async () => {
  const { db, users } = await setup();
  const results = await Promise.all(
    [1, 2, 3, 4].map(() => users.upsertExternal({ externalSub: "idp|race", username: "race@example.com" })),
  );
  assert.equal(new Set(results.map((u) => u.default_org_id)).size, 1);
  assert.equal((await db.get("SELECT COUNT(*) AS n FROM orgs")).n, 1);
});

test("an org always has an owner; admins cannot touch owners; nobody edits their own role", async () => {
  const { users, orgs } = await setup();
  const owner = await users.create({ username: "owner" });
  const admin = await users.create({ username: "admin" });
  const member = await users.create({ username: "member" });
  const other = await orgs.create({ name: "team", ownerUserId: owner.id });
  const ownerP = { userId: owner.id };
  const adminP = { userId: admin.id };
  const memberP = { userId: member.id };
  await orgs.addMember({ orgId: other.id, userId: admin.id, role: "admin" });
  await orgs.addMember({ orgId: other.id, userId: member.id, role: "member" });

  // The last owner cannot be demoted or leave.
  await assert.rejects(orgs.setMemberRole({ orgId: other.id, actor: ownerP, userId: owner.id, role: "admin" }), rejectsWith("cannot-change-own-role", 403));
  await assert.rejects(orgs.removeMember({ orgId: other.id, actor: ownerP, userId: owner.id }), rejectsWith("last-owner", 409));
  await assert.rejects(orgs.setMemberRole({ orgId: other.id, actor: { userId: 0, operator: true }, userId: owner.id, role: "member" }), rejectsWith("last-owner", 409));

  // Admins manage non-owners, but cannot grant owner or change an owner.
  assert.deepEqual(await orgs.setMemberRole({ orgId: other.id, actor: adminP, userId: member.id, role: "read_only" }), { orgId: other.id, userId: member.id, role: "read_only" });
  await assert.rejects(orgs.setMemberRole({ orgId: other.id, actor: adminP, userId: member.id, role: "owner" }), rejectsWith("owner-required", 403));
  await assert.rejects(orgs.setMemberRole({ orgId: other.id, actor: adminP, userId: owner.id, role: "member" }), rejectsWith("owner-required", 403));
  await assert.rejects(orgs.removeMember({ orgId: other.id, actor: adminP, userId: owner.id }), rejectsWith("owner-required", 403));
  await assert.rejects(orgs.setMemberRole({ orgId: other.id, actor: adminP, userId: admin.id, role: "member" }), rejectsWith("cannot-change-own-role", 403));

  // Members cannot manage anyone, but can leave.
  await assert.rejects(orgs.setMemberRole({ orgId: other.id, actor: memberP, userId: admin.id, role: "member" }), rejectsWith("forbidden", 403));
  await assert.rejects(orgs.removeMember({ orgId: other.id, actor: memberP, userId: admin.id }), rejectsWith("forbidden", 403));
  await assert.rejects(orgs.removeMember({ orgId: other.id, actor: { userId: 999 }, userId: member.id }), rejectsWith("forbidden", 403), "outsider");

  // With a second owner, the first can step down.
  await orgs.setMemberRole({ orgId: other.id, actor: ownerP, userId: admin.id, role: "owner" });
  assert.equal((await orgs.getMembership(other.id, admin.id)).role, "owner");
  await orgs.setMemberRole({ orgId: other.id, actor: adminP, userId: owner.id, role: "admin" });
  assert.equal((await orgs.getMembership(other.id, owner.id)).role, "admin");

  assert.equal(await orgs.removeMember({ orgId: other.id, actor: memberP, userId: member.id }), true, "leaving");
  await assert.rejects(orgs.removeMember({ orgId: other.id, actor: adminP, userId: member.id }), rejectsWith("not-a-member", 404));
  await assert.rejects(orgs.addMember({ orgId: other.id, userId: owner.id, role: "member" }), rejectsWith("already-member", 409));
});

test("org identity: shared owner within an org, separate across orgs", async () => {
  const { users, orgs, apiTokens, authenticate } = await setup();
  const alice = await users.create({ username: "alice" });
  const bob = await users.create({ username: "bob" });
  await orgs.addMember({ orgId: alice.default_org_id, userId: bob.id, role: "member" });

  const aliceToken = await apiTokens.create({ userId: alice.id });
  const bobInAlices = await apiTokens.create({ userId: bob.id, orgId: alice.default_org_id });
  const bobOwn = await apiTokens.create({ userId: bob.id });

  const a = await authenticate(aliceToken.token, {});
  const b = await authenticate(bobInAlices.token, {});
  const c = await authenticate(bobOwn.token, {});
  assert.equal(a.owner, `org:${alice.default_org_id}`);
  assert.equal(b.owner, a.owner, "members of one org share a network");
  assert.notEqual(b.userId, a.userId);
  assert.equal(b.orgRole, "member");
  assert.notEqual(c.owner, a.owner, "a user's personal org is a different network");
  assert.equal(c.orgRole, "owner");

  // Leaving the org revokes access through its tokens; the other token still works.
  await orgs.removeMember({ orgId: alice.default_org_id, actor: { userId: bob.id }, userId: bob.id });
  await assert.rejects(authenticate(bobInAlices.token, {}), (error) => error.status === 401 && error.code === "token-revoked");
  assert.equal((await authenticate(bobOwn.token, {})).owner, c.owner);
});

test("session access follows the role and the org's status", async () => {
  const { users, orgs, apiTokens, authenticate } = await setup();
  const alice = await users.create({ username: "alice" });
  const viewer = await users.create({ username: "viewer" });
  const org = alice.default_org_id;
  await orgs.addMember({ orgId: org, userId: viewer.id, role: "member" });
  const token = await apiTokens.create({ userId: viewer.id, orgId: org });

  assert.equal((await authenticate(token.token, {})).orgRole, "member");
  await orgs.setMemberRole({ orgId: org, actor: { userId: alice.id }, userId: viewer.id, role: "read_only" });
  const refused = (code) => (error) => error.status === 403 && error.code === code;
  await assert.rejects(authenticate(token.token, {}), refused("role-cannot-open-sessions"));
  const readOnly = await authenticate(token.token, { allowPending: true });
  assert.equal(readOnly.orgRole, "read_only", "still readable through the account API");

  await orgs.setMemberRole({ orgId: org, actor: { userId: alice.id }, userId: viewer.id, role: "member" });
  await orgs.setStatus(org, "suspended");
  await assert.rejects(authenticate(token.token, {}), refused("org-suspended"));
  assert.equal((await authenticate(token.token, { allowPending: true })).orgId, org);
  await orgs.setStatus(org, "active");
  assert.equal((await authenticate(token.token, {})).orgRole, "member");
});

test("deleting an account: personal org goes with it; a shared org with only this owner blocks", async () => {
  const { db, users, orgs, apiTokens } = await setup();
  const alice = await users.create({ username: "alice" });
  const bob = await users.create({ username: "bob" });
  const shared = await orgs.create({ name: "team", ownerUserId: alice.id });
  await orgs.addMember({ orgId: shared.id, userId: bob.id, role: "member" });
  await apiTokens.create({ userId: alice.id });
  await apiTokens.create({ userId: bob.id, orgId: shared.id });
  await db.run("INSERT INTO org_usage_monthly (org_id, month, bytes_in, bytes_out, sessions) VALUES (?, '2026-10', 1, 1, 1)", [alice.default_org_id]);

  await assert.rejects(users.removeAccount(alice.id), rejectsWith("sole-owner", 409));
  assert.ok(await users.findById(alice.id), "nothing was deleted");

  await orgs.setMemberRole({ orgId: shared.id, actor: { userId: alice.id }, userId: bob.id, role: "owner" });
  const result = await users.removeAccount(alice.id);
  assert.equal(result.removed, true);
  assert.deepEqual(result.deletedOrgIds, [alice.default_org_id]);
  assert.equal(await orgs.findById(alice.default_org_id), undefined);
  assert.equal((await db.get("SELECT COUNT(*) AS n FROM org_usage_monthly")).n, 0);
  assert.equal((await db.get("SELECT COUNT(*) AS n FROM api_tokens WHERE user_id = ?", [alice.id])).n, 0);
  assert.ok(await orgs.findById(shared.id), "the shared org survives");
  assert.equal((await orgs.getMembership(shared.id, bob.id)).role, "owner");

  // A user who is the only member of their shared org goes with it too.
  const solo = await orgs.create({ name: "solo", ownerUserId: bob.id });
  assert.deepEqual((await users.removeAccount(bob.id)).deletedOrgIds.sort(), [bob.default_org_id, shared.id, solo.id].sort());
  assert.equal((await db.get("SELECT COUNT(*) AS n FROM orgs")).n, 0);
  assert.equal(await users.removeAccount(bob.id).then((r) => r.removed), false);
});

test("a removed member falls back to their personal org as default", async () => {
  const { users, orgs } = await setup();
  const alice = await users.create({ username: "alice" });
  const bob = await users.create({ username: "bob" });
  const team = await orgs.create({ name: "team", ownerUserId: alice.id });
  await orgs.addMember({ orgId: team.id, userId: bob.id, role: "member" });
  await orgs.removeMember({ orgId: team.id, actor: { userId: alice.id }, userId: bob.id });
  assert.equal((await users.findById(bob.id)).default_org_id, bob.default_org_id);
  assert.equal(await orgs.remove(bob.default_org_id).catch((e) => e.code), "personal-org");
  assert.equal(await orgs.remove(team.id), true);
  assert.deepEqual((await orgs.listForUser(alice.id)).map((o) => o.personal), [true]);
});

test("migration 4 gives every existing user a personal org and carries tokens, tier and usage", async () => {
  const db = openDatabase(":memory:");
  assert.deepEqual(MIGRATIONS.slice(-2).map((m) => m.version), [4, 5]);
  const later = MIGRATIONS.splice(3);
  const generated = generateApiToken();
  try {
    await db.migrate();
    const at = "2026-01-01T00:00:00.000Z";
    await db.exec(`
      INSERT INTO users (id, username, role, tier, status, created_at) VALUES
        (1, 'ops', 'operator', 'operator', 'active', '${at}'),
        (2, 'alice', 'user', 'user', 'active', '${at}'),
        (3, 'bob', 'user', 'pro', 'banned', '${at}'),
        (4, 'carol', 'user', 'user', 'pending', '${at}');
      INSERT INTO usage_monthly (user_id, month, bytes_in, bytes_out, sessions) VALUES
        (2, '2026-09', 10, 20, 1), (2, '2026-10', 30, 40, 2), (3, '2026-10', 5, 5, 1);
      INSERT INTO connections_audit (owner, session_id, proto, dst_ip, dst_port, verdict, started_at)
        VALUES ('user:2', 's1', 'tcp', '1.1.1.1', 443, 'allow', 1);
    `);
    await db.run(
      "INSERT INTO api_tokens (user_id, name, token_prefix, token_hash, created_at) VALUES (2, 'laptop', ?, ?, ?)",
      [generated.prefix, generated.hash, at],
    );
  } finally {
    MIGRATIONS.push(...later);
  }

  assert.equal(await db.migrate(), 5);
  assert.equal(await db.migrate(), 5, "running again is a no-op");

  const users = createUserStore(db, { bcryptRounds: 4 });
  const orgs = createOrgStore(db);
  for (const id of [1, 2, 3, 4]) {
    const user = await users.findById(id);
    const org = await orgs.findById(user.default_org_id);
    assert.equal(org.personal, 1);
    assert.equal(org.tier, user.tier, `tier carried over for ${user.username}`);
    assert.equal(org.name, user.username);
    assert.equal((await orgs.getMembership(org.id, id)).role, "owner");
  }
  assert.equal((await db.get("SELECT COUNT(*) AS n FROM orgs")).n, 4);

  const alice = await users.findById(2);
  const token = await db.get("SELECT org_id FROM api_tokens");
  assert.equal(token.org_id, alice.default_org_id);
  const apiTokens = createApiTokenStore(db);
  const authenticate = createAuthenticator({ config: { authRequired: true }, users, apiTokens, orgs });
  const identity = await authenticate(generated.token, {});
  assert.equal(identity.owner, `org:${alice.default_org_id}`, "a token from before orgs runs as its owner's personal org");

  const usage = await db.all("SELECT org_id, month, bytes_in, bytes_out, sessions FROM org_usage_monthly ORDER BY org_id, month");
  const bob = await users.findById(3);
  assert.deepEqual(usage, [
    { org_id: alice.default_org_id, month: "2026-09", bytes_in: 10, bytes_out: 20, sessions: 1 },
    { org_id: alice.default_org_id, month: "2026-10", bytes_in: 30, bytes_out: 40, sessions: 2 },
    { org_id: bob.default_org_id, month: "2026-10", bytes_in: 5, bytes_out: 5, sessions: 1 },
  ]);
  assert.equal((await db.get("SELECT COUNT(*) AS n FROM usage_monthly")).n, 3, "the old table is left in place for a rollback");
  const auditRow = await db.get("SELECT owner, user_id FROM connections_audit");
  assert.equal(auditRow.owner, "user:2", "audit rows keep their owner string");
  assert.equal(auditRow.user_id, 2, "and are attributed to the user they name");
  assert.equal((await db.all("PRAGMA foreign_key_check")).length, 0);
  await db.close();
});

test("a rolled-back release leaves users and tokens without orgs; they are repaired on first use", async () => {
  const { db, users, authenticate } = await setup();
  // What the previous release writes: no default_org_id, no org_id.
  await db.run("INSERT INTO users (username, role, tier, status, created_at) VALUES ('late', 'user', 'user', 'active', '2026-10-01')");
  const late = await users.findByUsername("late");
  const generated = generateApiToken();
  await db.run(
    "INSERT INTO api_tokens (user_id, name, token_prefix, token_hash, created_at) VALUES (?, 'x', ?, ?, '2026-10-01')",
    [late.id, generated.prefix, generated.hash],
  );
  assert.equal(late.default_org_id, null);

  const identity = await authenticate(generated.token, {});
  const repaired = await users.findById(late.id);
  assert.ok(repaired.default_org_id);
  assert.equal(identity.orgId, repaired.default_org_id);
  assert.equal(identity.owner, `org:${repaired.default_org_id}`);
});

test("audit lookups by org also find the personal org's rows from before orgs existed", async () => {
  const { db, users, orgs } = await setup();
  const { createAuditLog } = require("../metering/audit");
  const alice = await users.create({ username: "alice" });
  const bob = await users.create({ username: "bob" });
  const team = await orgs.create({ name: "team", ownerUserId: bob.id });
  const quiet = { debug() {}, info() {}, warn() {}, error() {} };
  const audit = createAuditLog({ db, retentionDays: 30, log: quiet, batchMs: 1e9, pruneIntervalMs: 1e9 });
  const row = (key, owner) => audit.record({ key, owner, sessionId: key, proto: "tcp", dstIP: "1.1.1.1", dstPort: 443, verdict: "allow", startedAt: Date.now() });
  row("old", `user:${alice.id}`);
  row("new", `org:${alice.default_org_id}`);
  row("bobs", `org:${bob.default_org_id}`);
  row("team", `org:${team.id}`);
  await audit.flush();

  const owners = async (owner) => (await audit.query({ owner })).map((r) => r.sessionId).sort();
  assert.deepEqual(await owners(`org:${alice.default_org_id}`), ["new", "old"]);
  assert.deepEqual(await owners(`org:${bob.default_org_id}`), ["bobs"], "another user's rows are not pulled in");
  assert.deepEqual(await owners(`org:${team.id}`), ["team"], "a shared org has no legacy rows");
  assert.deepEqual(await owners(`user:${alice.id}`), ["old"], "exact owner strings still match exactly");
  audit.close();
});

test("migration 5 attributes earlier audit rows only where the user is unambiguous", async () => {
  const db = openDatabase(":memory:");
  const later = MIGRATIONS.splice(4);
  assert.equal(later[0].version, 5);
  let alice;
  let team;
  try {
    await db.migrate();
    const users = createUserStore(db, { bcryptRounds: 4 });
    const orgs = createOrgStore(db);
    alice = await users.create({ username: "alice" });
    const bob = await users.create({ username: "bob" });
    team = await orgs.create({ name: "team", ownerUserId: bob.id });
    const insert = (owner, id) => db.run(
      "INSERT INTO connections_audit (owner, session_id, proto, dst_ip, dst_port, verdict, started_at) VALUES (?, ?, 'tcp', '1.1.1.1', 443, 'allow', 1)",
      [owner, id],
    );
    await insert(`user:${alice.id}`, "legacy");
    await insert(`org:${alice.default_org_id}`, "personal");
    await insert(`org:${team.id}`, "shared");
    await insert("anon:x", "anon");
    await insert("user:12x", "malformed");
  } finally {
    MIGRATIONS.push(...later);
  }
  assert.equal(await db.migrate(), 5);
  const byId = Object.fromEntries((await db.all("SELECT session_id, user_id FROM connections_audit")).map((r) => [r.session_id, r.user_id]));
  assert.deepEqual(byId, { legacy: alice.id, personal: alice.id, shared: null, anon: null, malformed: null });
  await db.close();
});

test("audit rows record the acting member and can be filtered by user", async () => {
  const { db, users, orgs } = await setup();
  const { createAuditLog } = require("../metering/audit");
  const alice = await users.create({ username: "alice" });
  const bob = await users.create({ username: "bob" });
  const team = await orgs.create({ name: "team", ownerUserId: alice.id });
  await orgs.addMember({ orgId: team.id, userId: bob.id, role: "member" });
  const quiet = { debug() {}, info() {}, warn() {}, error() {} };
  const audit = createAuditLog({ db, retentionDays: 30, log: quiet, batchMs: 1e9, pruneIntervalMs: 1e9 });
  const row = (key, userId) => audit.record({ key, owner: `org:${team.id}`, userId, sessionId: key, proto: "tcp", dstIP: "9.9.9.9", dstPort: 443, verdict: "allow", startedAt: Date.now() });
  row("a1", alice.id);
  row("b1", bob.id);
  row("b2", bob.id);
  audit.record({ key: "n", owner: "anon:x", sessionId: "n", proto: "tcp", dstIP: "9.9.9.9", dstPort: 443, verdict: "allow", startedAt: Date.now() });
  await audit.flush();

  const ids = async (query) => (await audit.query(query)).map((r) => r.sessionId).sort();
  assert.deepEqual(await ids({ owner: `org:${team.id}` }), ["a1", "b1", "b2"], "the org sees every member");
  assert.deepEqual(await ids({ userId: bob.id }), ["b1", "b2"]);
  assert.deepEqual(await ids({ owner: `org:${team.id}`, userId: alice.id }), ["a1"]);
  assert.deepEqual((await audit.query({ userId: bob.id })).map((r) => r.userId), [bob.id, bob.id]);
  assert.equal((await audit.query({ owner: "anon:x" }))[0].userId, null);
  audit.close();
});
