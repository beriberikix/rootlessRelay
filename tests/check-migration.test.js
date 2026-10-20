"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { MIGRATIONS, openDatabase } = require("../auth/db");
const { generateApiToken } = require("../auth/tokens");
const { checkMigration, render } = require("../scripts/check-migration");

// A database as the release before organizations left it (schema v3).
async function productionLikeDatabase(dir) {
  const file = path.join(dir, "prod.sqlite");
  const db = openDatabase(file);
  const later = MIGRATIONS.splice(3);
  try {
    await db.migrate();
  } finally {
    MIGRATIONS.push(...later);
  }
  const at = "2026-10-01T00:00:00.000Z";
  await db.run("INSERT INTO users (id, username, role, tier, status, created_at) VALUES (1, 'ops', 'operator', 'operator', 'active', ?)", [at]);
  for (let id = 2; id <= 40; id += 1) {
    const status = id % 9 === 0 ? "banned" : id % 7 === 0 ? "pending" : "active";
    await db.run("INSERT INTO users (id, username, role, tier, status, created_at) VALUES (?, ?, 'user', ?, ?, ?)", [id, `user${id}`, id % 5 === 0 ? "pro" : "user", status, at]);
    const t = generateApiToken();
    await db.run(
      "INSERT INTO api_tokens (user_id, name, token_prefix, token_hash, created_at, revoked_at) VALUES (?, 't', ?, ?, ?, ?)",
      [id, t.prefix, t.hash, at, id % 4 === 0 ? at : null],
    );
    await db.run("INSERT INTO usage_monthly (user_id, month, bytes_in, bytes_out, sessions) VALUES (?, '2026-09', ?, ?, 1), (?, '2026-10', ?, ?, 2)", [id, id * 10, id * 20, id, id * 30, id * 40]);
    await db.run(
      "INSERT INTO connections_audit (owner, session_id, proto, dst_ip, dst_port, verdict, started_at) VALUES (?, ?, 'tcp', '1.1.1.1', 443, 'allow', ?)",
      [`user:${id}`, `s${id}`, id],
    );
  }
  // Audit rows of an account that no longer exists, and of an anonymous session.
  await db.run("INSERT INTO connections_audit (owner, session_id, proto, dst_ip, dst_port, verdict, started_at) VALUES ('user:999', 'gone', 'tcp', '1.1.1.1', 443, 'allow', 1)");
  await db.run("INSERT INTO connections_audit (owner, session_id, proto, dst_ip, dst_port, verdict, started_at) VALUES ('anon:x', 'anon', 'tcp', '1.1.1.1', 443, 'allow', 1)");
  await db.close();
  return file;
}

const sha = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");

test("a production-like v3 database migrates cleanly and the source file is left alone", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cm-test-"));
  try {
    const file = await productionLikeDatabase(dir);
    const digest = sha(file);
    const result = await checkMigration(file);
    assert.equal(result.ok, true, render(result));
    assert.equal(result.before.version, 3);
    assert.equal(result.after.version, MIGRATIONS[MIGRATIONS.length - 1].version);
    assert.equal(result.before.users, 40);
    assert.ok(result.checks.length >= 12);
    assert.equal(sha(file), digest, "the input database is never modified");
    assert.match(render(result), /All checks passed/);
    assert.ok(!render(result).includes("user2"), "the summary carries counts, not usernames");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a database that is already current passes without re-running the data checks", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cm-test-"));
  try {
    const file = await productionLikeDatabase(dir);
    const db = openDatabase(file);
    await db.migrate();
    await db.close();
    const result = await checkMigration(file);
    assert.equal(result.ok, true, render(result));
    assert.equal(result.before.version, result.after.version);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a database from a newer release fails instead of being touched", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cm-test-"));
  try {
    const file = await productionLikeDatabase(dir);
    const db = openDatabase(file);
    await db.run("UPDATE schema_version SET version = 99");
    await db.close();
    const result = await checkMigration(file);
    assert.equal(result.ok, false);
    assert.match(render(result), /FAILED/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("the checks notice a migration that loses data", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cm-test-"));
  const migration = MIGRATIONS[3];
  const original = migration.up;
  try {
    const file = await productionLikeDatabase(dir);
    // A broken migration 4 that forgets to carry usage over and drops a token.
    migration.up = async (db) => {
      await original(db);
      await db.run("DELETE FROM org_usage_monthly WHERE month = '2026-10'");
      await db.run("DELETE FROM api_tokens WHERE id = 1");
    };
    const result = await checkMigration(file);
    assert.equal(result.ok, false);
    const failed = result.checks.filter((c) => !c.ok).map((c) => c.name);
    assert.ok(failed.includes("usage totals match the old table"), failed.join("; "));
    assert.ok(failed.includes("users, operators and tokens are all still there"), failed.join("; "));
  } finally {
    migration.up = original;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
