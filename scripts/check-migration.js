#!/usr/bin/env node
"use strict";

// Rehearses the schema migrations on a COPY of a database (for example a
// restored production backup) and checks what they should preserve. The
// input file is never modified.
//
//   node scripts/check-migration.js /path/to/restored.sqlite
//
// Prints a summary and exits 1 if any check fails. The summary has counts
// only, no usernames, addresses or tokens, so it is safe in CI logs.

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { MIGRATIONS, openDatabase } = require("../auth/db");

async function scalar(db, sql, params = []) {
  const row = await db.get(sql, params);
  return row ? Object.values(row)[0] : null;
}

async function hasTable(db, name) {
  return Boolean(await db.get("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", [name]));
}

async function snapshot(db) {
  const version = (await hasTable(db, "schema_version")) ? await scalar(db, "SELECT version FROM schema_version LIMIT 1") : 0;
  const count = async (table, where = "1") => ((await hasTable(db, table)) ? scalar(db, `SELECT COUNT(*) FROM ${table} WHERE ${where}`) : 0);
  return {
    version,
    users: await count("users"),
    operators: await count("users", "role = 'operator'"),
    tokens: await count("api_tokens"),
    activeTokens: await count("api_tokens", "revoked_at IS NULL"),
    usageRows: await count("usage_monthly"),
    usageBytes: (await hasTable(db, "usage_monthly")) ? await scalar(db, "SELECT COALESCE(SUM(bytes_in + bytes_out), 0) FROM usage_monthly") : 0,
    usageSessions: (await hasTable(db, "usage_monthly")) ? await scalar(db, "SELECT COALESCE(SUM(sessions), 0) FROM usage_monthly") : 0,
    auditRows: await count("connections_audit"),
    invites: await count("invites"),
  };
}

// Returns { before, after, checks: [{ name, ok, detail }], ok }.
async function checkMigration(file) {
  if (!fs.existsSync(file)) throw new Error(`no such file: ${file}`);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "check-migration-"));
  const copy = path.join(dir, "copy.sqlite");
  fs.copyFileSync(file, copy);
  // A WAL left next to the source holds committed pages the copy needs.
  for (const suffix of ["-wal", "-shm"]) {
    if (fs.existsSync(file + suffix)) fs.copyFileSync(file + suffix, copy + suffix);
  }
  const db = openDatabase(copy);
  const checks = [];
  const check = (name, ok, detail = "") => checks.push({ name, ok: Boolean(ok), detail: String(detail) });
  try {
    const target = MIGRATIONS[MIGRATIONS.length - 1].version;
    const before = await snapshot(db);
    check("database is not newer than this release", before.version <= target, `database v${before.version}, release v${target}`);
    if (before.version > target) return { before, after: before, checks, ok: false };

    const started = Date.now();
    const reached = await db.migrate();
    const ms = Date.now() - started;
    const after = await snapshot(db);
    check("migrated to the latest version", reached === target && after.version === target, `v${before.version} -> v${reached} in ${ms} ms`);
    check("running the migrations again changes nothing", (await db.migrate()) === target);

    check("integrity_check is ok", (await scalar(db, "PRAGMA integrity_check")) === "ok");
    const broken = await db.all("PRAGMA foreign_key_check");
    check("no foreign key violations", broken.length === 0, `${broken.length} violation(s)`);

    check("users, operators and tokens are all still there",
      after.users === before.users && after.operators === before.operators && after.tokens === before.tokens && after.activeTokens === before.activeTokens,
      `users ${before.users}->${after.users}, operators ${before.operators}->${after.operators}, tokens ${before.tokens}->${after.tokens}`);
    check("audit rows and signup invites are untouched", after.auditRows === before.auditRows && after.invites === before.invites,
      `audit ${before.auditRows}->${after.auditRows}, invites ${before.invites}->${after.invites}`);

    if (target >= 4 && before.version < 4) {
      const noOrg = await scalar(db, "SELECT COUNT(*) FROM users WHERE default_org_id IS NULL");
      check("every user has a default org", noOrg === 0, `${noOrg} without`);
      const notOwner = await scalar(
        db,
        "SELECT COUNT(*) FROM users u WHERE NOT EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = u.id AND m.org_id = u.default_org_id AND m.role = 'owner')",
      );
      check("every user owns their default org", notOwner === 0, `${notOwner} not owner`);
      check("one personal org per user and nothing else", (await scalar(db, "SELECT COUNT(*) FROM orgs")) === before.users && (await scalar(db, "SELECT COUNT(*) FROM orgs WHERE personal = 0")) === 0);
      const tierDrift = await scalar(db, "SELECT COUNT(*) FROM users u JOIN orgs o ON o.id = u.default_org_id WHERE o.tier != u.tier");
      check("org tier equals the user's tier", tierDrift === 0, `${tierDrift} differ`);
      const orphanTokens = await scalar(
        db,
        "SELECT COUNT(*) FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.org_id IS NULL OR t.org_id != u.default_org_id",
      );
      check("every token belongs to its creator's personal org", orphanTokens === 0, `${orphanTokens} wrong`);
      const moved = await db.get("SELECT COALESCE(SUM(bytes_in + bytes_out), 0) AS bytes, COALESCE(SUM(sessions), 0) AS sessions, COUNT(*) AS n FROM org_usage_monthly");
      check("usage totals match the old table", moved.bytes === before.usageBytes && moved.sessions === before.usageSessions && moved.n === before.usageRows,
        `bytes ${before.usageBytes}->${moved.bytes}, sessions ${before.usageSessions}->${moved.sessions}, rows ${before.usageRows}->${moved.n}`);
    }
    if (target >= 5 && before.version < 5) {
      const legacy = await scalar(db, "SELECT COUNT(*) FROM connections_audit WHERE owner GLOB 'user:[0-9]*' AND substr(owner, 6) NOT GLOB '*[^0-9]*'");
      const attributed = await scalar(
        db,
        "SELECT COUNT(*) FROM connections_audit WHERE owner GLOB 'user:[0-9]*' AND substr(owner, 6) NOT GLOB '*[^0-9]*' AND user_id = CAST(substr(owner, 6) AS INTEGER)",
      );
      check("legacy audit rows are attributed to the user they name", legacy === attributed, `${attributed}/${legacy}`);
      // Ids are never reused (AUTOINCREMENT) and user_id is not a foreign key, so a
      // row of a deleted account keeps naming it. Rows that name no user stay null.
      const overreach = await scalar(
        db,
        "SELECT COUNT(*) FROM connections_audit WHERE user_id IS NOT NULL AND owner NOT GLOB 'user:[0-9]*' " +
          "AND NOT (owner GLOB 'org:[0-9]*' AND EXISTS (SELECT 1 FROM orgs o WHERE 'org:' || o.id = connections_audit.owner AND o.personal = 1))",
      );
      check("rows that name no user are not attributed", overreach === 0, `${overreach} attributed without a basis`);
    }
    if (target >= 7 && before.version < 7) {
      check("the egress budget table exists and starts empty",
        (await hasTable(db, "relay_egress_monthly")) && (await scalar(db, "SELECT COUNT(*) FROM relay_egress_monthly")) === 0);
    }
    return { before, after, checks, ok: checks.every((c) => c.ok) };
  } finally {
    await db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function render(result) {
  const lines = ["| Check | Result | Detail |", "|---|---|---|"];
  for (const c of result.checks) lines.push(`| ${c.name} | ${c.ok ? "pass" : "**FAIL**"} | ${c.detail} |`);
  return [
    `Schema v${result.before.version} -> v${result.after.version}; ${result.before.users} users, ${result.before.tokens} tokens, ${result.before.auditRows} audit rows.`,
    "",
    ...lines,
    "",
    result.ok ? "All checks passed." : "FAILED: do not deploy this release against this database.",
  ].join("\n");
}

if (require.main === module) {
  const file = process.argv[2];
  if (!file) {
    console.error("usage: node scripts/check-migration.js <database.sqlite>");
    process.exit(2);
  }
  checkMigration(file)
    .then((result) => {
      console.log(render(result));
      process.exit(result.ok ? 0 : 1);
    })
    .catch((error) => {
      console.error(`check-migration: ${error.message}`);
      process.exit(2);
    });
}

module.exports = { checkMigration, render };
