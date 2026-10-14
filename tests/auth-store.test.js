"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { MIGRATIONS, openDatabase } = require("../auth/db");
const { createUserStore } = require("../auth/users");
const { SqliteSessionStore } = require("../auth/session_store");

test("fresh database migrates to the latest version with all tables", async () => {
  const db = openDatabase(":memory:");
  const version = await db.migrate();
  assert.equal(version, MIGRATIONS.at(-1).version);
  const tables = (await db.all("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"))
    .map((row) => row.name);
  for (const name of ["users", "api_tokens", "usage_monthly", "connections_audit", "admin_sessions", "schema_version"]) {
    assert.ok(tables.includes(name), `${name} table exists`);
  }
  assert.equal(await db.migrate(), version, "migrate is idempotent");
  await db.close();
});

test("legacy admin_users rows become operators", async () => {
  const db = openDatabase(":memory:");
  await db.exec(`
    CREATE TABLE admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      last_login_at TEXT
    );
    INSERT INTO admin_users (username, password_hash, created_at, last_login_at)
      VALUES ('root', '$2a$04$hash', '2026-01-01T00:00:00Z', NULL);
  `);
  await db.migrate();
  const users = createUserStore(db, { bcryptRounds: 4 });
  const root = await users.findByUsername("root");
  assert.equal(root.role, "operator");
  assert.equal(root.tier, "operator");
  assert.equal(root.status, "active");
  assert.equal(root.password_hash, "$2a$04$hash");
  assert.equal(await users.countOperators(), 1);
  const legacy = await db.get("SELECT name FROM sqlite_master WHERE name = 'admin_users_legacy'");
  assert.ok(legacy, "legacy table kept for rollback");
  await db.close();
});

test("user store creates, verifies passwords, links external identities, bans", async () => {
  const db = openDatabase(":memory:");
  await db.migrate();
  const users = createUserStore(db, { bcryptRounds: 4, now: () => Date.UTC(2026, 9, 14) });
  const alice = await users.create({ username: "alice", password: "correct horse", role: "user" });
  assert.equal(alice.tier, "user");
  assert.equal(await users.verifyPassword(alice, "correct horse"), true);
  assert.equal(await users.verifyPassword(alice, "wrong"), false);
  await assert.rejects(users.create({ username: "alice", password: "another one" }), /UNIQUE/);
  await assert.rejects(users.create({ username: "bad user", password: "x".repeat(8) }), RangeError);
  await assert.rejects(users.create({ username: "short", password: "short" }), RangeError);
  await assert.rejects(users.create({ username: "r", password: "x".repeat(8), role: "root" }), RangeError);

  const op = await users.create({ username: "ops", password: "operator-pass", role: "operator" });
  assert.equal(op.tier, "operator");
  assert.equal(await users.countOperators(), 1);

  const ext = await users.upsertExternal({ externalSub: "https://idp|sub-1", username: "alice" });
  assert.notEqual(ext.username, "alice", "username collision gets a suffix");
  assert.equal(ext.external_sub, "https://idp|sub-1");
  assert.equal(ext.password_hash, null);
  const again = await users.upsertExternal({ externalSub: "https://idp|sub-1", username: "alice" });
  assert.equal(again.id, ext.id);
  assert.equal(await users.verifyPassword(ext, "anything"), false);

  assert.equal(await users.setStatus(alice.id, "banned"), true);
  assert.equal((await users.findById(alice.id)).status, "banned");
  await assert.rejects(users.setStatus(alice.id, "frozen"), RangeError);
  assert.equal(await users.setTier(alice.id, "pro"), true);
  assert.equal(await users.setPassword(alice.id, "new password!"), true);
  assert.equal(await users.verifyPassword(await users.findById(alice.id), "new password!"), true);
  await users.touchLogin(alice.id);
  assert.equal((await users.findById(alice.id)).last_login_at, "2026-10-14T00:00:00.000Z");
  const listed = await users.list();
  assert.equal(listed.length, 3);
  assert.equal(listed[0].hasPassword, true);
  assert.equal("password_hash" in listed[0], false);
  await db.run("INSERT INTO usage_monthly (user_id, month, bytes_in, bytes_out, sessions) VALUES (?, '2026-10', 1, 2, 3)", [ext.id]);
  assert.equal(await users.remove(ext.id), true);
  assert.equal(await users.findById(ext.id), undefined);
  assert.equal((await db.get("SELECT COUNT(*) AS n FROM usage_monthly WHERE user_id = ?", [ext.id])).n, 0);
  assert.equal(await users.remove(ext.id), false);
  await db.close();
});

function promisify(store, method, ...args) {
  return new Promise((resolve, reject) => {
    store[method](...args, (error, value) => (error ? reject(error) : resolve(value)));
  });
}

test("sqlite session store round-trips, expires, prunes and destroys", async () => {
  const db = openDatabase(":memory:");
  await db.migrate();
  let clock = 1000;
  const store = new SqliteSessionStore({ db, now: () => clock, pruneIntervalMs: 0, ttlMs: 500 });
  await promisify(store, "set", "sid-1", { cookie: { maxAge: 1000 }, passport: { user: 7 } });
  await promisify(store, "set", "sid-2", { cookie: {}, passport: { user: 8 } });
  assert.deepEqual(await promisify(store, "get", "sid-1"), { cookie: { maxAge: 1000 }, passport: { user: 7 } });
  assert.equal(await promisify(store, "length"), 2);
  clock = 1600;
  assert.equal(await promisify(store, "get", "sid-2"), null, "ttl expired");
  assert.deepEqual((await promisify(store, "get", "sid-1")).passport, { user: 7 });
  await promisify(store, "touch", "sid-1", { cookie: { maxAge: 1000 } });
  clock = 2500;
  assert.deepEqual((await promisify(store, "get", "sid-1")).passport, { user: 7 }, "touch extended the session");
  clock = 2700;
  assert.equal(await promisify(store, "get", "sid-1"), null);
  await promisify(store, "set", "sid-3", { cookie: { expires: new Date(9000).toISOString() } });
  assert.equal(await store.prune(), 0);
  await promisify(store, "destroy", "sid-3");
  assert.equal(await promisify(store, "get", "sid-3"), null);
  await promisify(store, "clear");
  store.close();
  await db.close();
});
