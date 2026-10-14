"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { MIGRATIONS, openDatabase } = require("../auth/db");
const { createUserStore } = require("../auth/users");
const { createApiTokenStore } = require("../auth/tokens");
const { createInviteStore, generateInviteCode, normalizeInviteCode } = require("../auth/invites");

test("invite codes are readable and normalize loosely", () => {
  const code = generateInviteCode();
  assert.match(code, /^RLY-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
  const body = code.slice(4).replace(/-/g, "");
  assert.equal(normalizeInviteCode(code), body);
  assert.equal(normalizeInviteCode(` ${code.toLowerCase().replace(/-/g, " ")} `), body);
  assert.equal(normalizeInviteCode(body), body);
  assert.equal(normalizeInviteCode("RLY-AAAA-BBBB"), null);
  assert.equal(normalizeInviteCode("RLY-AAAA-BBBB-CCCU"), null, "U is not in the alphabet");
  assert.equal(normalizeInviteCode(42), null);
});

test("invite store: create, list, single-use redeem, revoke, expiry", async () => {
  const db = openDatabase(":memory:");
  await db.migrate();
  let clock = Date.UTC(2026, 9, 14);
  const users = createUserStore(db, { bcryptRounds: 4 });
  const invites = createInviteStore(db, { now: () => clock });
  const op = await users.create({ username: "ops", role: "operator" });
  const alice = await users.create({ username: "alice", status: "pending" });
  const bob = await users.create({ username: "bob", status: "pending" });
  assert.equal(alice.status, "pending");

  const first = await invites.create({ createdBy: op.id, note: "for alice", expiresAt: new Date(clock + 86400000).toISOString() });
  assert.equal(first.state, "open");
  assert.equal(first.hint, first.code.slice(-4));
  assert.equal(first.createdBy, "ops");

  assert.equal(await invites.redeem("RLY-0000-0000-0000", alice.id), false);
  const [one, two] = await Promise.all([invites.redeem(first.code, alice.id), invites.redeem(first.code, bob.id)]);
  assert.deepEqual([one, two], [true, false], "a code is redeemed once");
  const listed = await invites.list();
  assert.equal(listed[0].state, "redeemed");
  assert.equal(listed[0].redeemedBy, "alice");
  assert.equal(listed[0].code, undefined, "codes are never listed");
  assert.equal(await invites.revoke(first.id), false, "redeemed codes cannot be revoked");

  // A user who already redeemed cannot consume a second code.
  const spare = await invites.create({});
  assert.equal(await invites.redeem(spare.code, alice.id), false);
  assert.equal(await invites.redeem(spare.code, bob.id), true);

  const second = await invites.create({ createdBy: op.id });
  assert.equal(await invites.revoke(second.id), true);
  const carol = await users.create({ username: "carol", status: "pending" });
  assert.equal(await invites.redeem(second.code, carol.id), false);

  const third = await invites.create({ expiresAt: new Date(clock + 1000).toISOString() });
  clock += 2000;
  assert.equal((await invites.list()).find((i) => i.id === third.id).state, "expired");
  assert.equal(await invites.redeem(third.code, carol.id), false);

  // Deleting the redeeming user keeps the invite row.
  await users.remove(alice.id);
  assert.equal((await invites.list()).find((i) => i.id === first.id).redeemedBy, null);
  await db.close();
});

test("migration 2 rebuilds users without losing tokens", async () => {
  const db = openDatabase(":memory:");
  await db.exec("PRAGMA foreign_keys = ON");
  await db.exec("CREATE TABLE schema_version (version INTEGER NOT NULL)");
  await MIGRATIONS[0].up(db);
  await db.run("INSERT INTO schema_version (version) VALUES (1)");
  await db.run("INSERT INTO users (username, role, tier, status, created_at) VALUES ('old', 'user', 'user', 'active', '2026-01-01')");
  await assert.rejects(db.run("UPDATE users SET status = 'pending' WHERE id = 1"), /CHECK/);
  const v1Tokens = createApiTokenStore(db);
  const token = await v1Tokens.create({ userId: 1, name: "keep" });

  assert.equal(await db.migrate(), MIGRATIONS[MIGRATIONS.length - 1].version);
  const users = createUserStore(db, { bcryptRounds: 4 });
  assert.equal((await users.findById(1)).username, "old");
  assert.equal((await v1Tokens.verify(token.token)).user.username, "old");
  assert.equal(await users.setStatus(1, "pending"), true);
  assert.equal((await db.get("PRAGMA foreign_keys")).foreign_keys, 1, "foreign keys are back on");
  assert.equal((await db.all("PRAGMA foreign_key_check")).length, 0);
  await users.remove(1);
  assert.equal((await db.get("SELECT COUNT(*) AS n FROM api_tokens")).n, 0, "cascade still works after the rebuild");
  await db.close();
});
