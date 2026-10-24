"use strict";

// Hosted mode with nothing configured: secrets are generated once and kept
// beside the database, and the first operator is created with a password
// that is logged once.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { withGeneratedSecrets } = require("../secrets");
const { resolveConfig } = require("../config");
const admin = require("../admin/app");
const { openDatabase } = require("../auth/db");
const { createUserStore } = require("../auth/users");

function tmpdir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "relay-zero-config-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test("missing hosted secrets are generated once, kept beside the database, and reused", (t) => {
  const dir = tmpdir(t);
  const env = { RELAY_MODE: "hosted", ADMIN_AUTH_DB_PATH: path.join(dir, "relay.sqlite") };
  const first = withGeneratedSecrets(env);
  assert.deepEqual(first.generated, ["ADMIN_SESSION_SECRET", "ANON_TOKEN_SECRET"]);
  assert.equal(first.file, path.join(dir, "secrets.json"));
  assert.equal(fs.statSync(first.file).mode & 0o777, 0o600);
  assert.ok(first.env.ADMIN_SESSION_SECRET.length >= 32);
  assert.equal(env.ADMIN_SESSION_SECRET, undefined, "the caller's env is not changed");
  assert.doesNotThrow(() => resolveConfig(first.env), "hosted mode starts with the generated secrets");

  const second = withGeneratedSecrets(env);
  assert.deepEqual(second.generated, []);
  assert.deepEqual(second.loaded, ["ADMIN_SESSION_SECRET", "ANON_TOKEN_SECRET"]);
  assert.equal(second.env.ADMIN_SESSION_SECRET, first.env.ADMIN_SESSION_SECRET);
});

test("set secrets win; anon off needs no anon secret; local mode and opt-out generate nothing", (t) => {
  const dir = tmpdir(t);
  const db = path.join(dir, "relay.sqlite");
  const set = withGeneratedSecrets({ RELAY_MODE: "hosted", ADMIN_AUTH_DB_PATH: db, ADMIN_SESSION_SECRET: "from-env", ANON_ENABLED: "false" });
  assert.deepEqual(set.generated, []);
  assert.equal(set.env.ADMIN_SESSION_SECRET, "from-env");
  assert.equal(fs.existsSync(path.join(dir, "secrets.json")), false);

  const anonOff = withGeneratedSecrets({ RELAY_MODE: "hosted", ADMIN_AUTH_DB_PATH: db, ANON_ENABLED: "false" });
  assert.deepEqual(anonOff.generated, ["ADMIN_SESSION_SECRET"]);

  assert.deepEqual(withGeneratedSecrets({ ADMIN_AUTH_DB_PATH: db }).generated, [], "local mode");
  const optOut = { RELAY_MODE: "hosted", ADMIN_AUTH_DB_PATH: db, GENERATE_SECRETS: "false" };
  assert.deepEqual(withGeneratedSecrets(optOut).generated, []);
  assert.throws(() => resolveConfig(optOut), /ADMIN_SESSION_SECRET/, "without generation, hosted mode still refuses to start");
});

test("first start creates an operator named admin with a logged password; later starts do nothing", async (t) => {
  const db = openDatabase(":memory:");
  await db.migrate();
  t.after(() => db.close());
  const users = createUserStore(db, { bcryptRounds: 4 });
  const config = resolveConfig({ RELAY_MODE: "hosted", ADMIN_SESSION_SECRET: "s", ANON_TOKEN_SECRET: "a" });
  const logged = [];
  const log = { info() {}, warn: (msg, fields) => logged.push({ msg, fields }), error() {} };

  await admin.bootstrapOperator({ users, config, log });
  const created = logged.find((entry) => entry.fields && entry.fields.password);
  assert.ok(created, "the password is logged");
  assert.equal(created.fields.username, "admin");
  const operator = await users.findByUsername("admin");
  assert.equal(operator.role, "operator");
  assert.equal(await users.verifyPassword(operator, created.fields.password), true);

  logged.length = 0;
  await admin.bootstrapOperator({ users, config, log });
  assert.deepEqual(logged, [], "an operator exists, so nothing happens");

  const off = resolveConfig({ RELAY_MODE: "hosted", ADMIN_SESSION_SECRET: "s", ANON_TOKEN_SECRET: "a", ADMIN_GENERATE_OPERATOR: "false" });
  const db2 = openDatabase(":memory:");
  await db2.migrate();
  t.after(() => db2.close());
  const users2 = createUserStore(db2, { bcryptRounds: 4 });
  await admin.bootstrapOperator({ users: users2, config: off, log });
  assert.equal(await users2.countOperators(), 0);
});
