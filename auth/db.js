"use strict";

// SQLite access with promise wrappers and versioned migrations. One database
// file holds operators, end users, API tokens, usage, the connection audit
// log and admin login sessions.

const sqlite3 = require("sqlite3");

const MIGRATIONS = [
  {
    version: 1,
    async up(db) {
      await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE,
          password_hash TEXT,
          role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'operator')),
          tier TEXT NOT NULL DEFAULT 'user',
          status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'banned')),
          external_sub TEXT UNIQUE,
          created_at TEXT NOT NULL,
          last_login_at TEXT
        );
        CREATE TABLE IF NOT EXISTS api_tokens (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          name TEXT NOT NULL,
          token_prefix TEXT NOT NULL,
          token_hash TEXT NOT NULL UNIQUE,
          created_at TEXT NOT NULL,
          last_used_at TEXT,
          expires_at TEXT,
          revoked_at TEXT
        );
        CREATE INDEX IF NOT EXISTS api_tokens_prefix ON api_tokens(token_prefix);
        CREATE TABLE IF NOT EXISTS usage_monthly (
          user_id INTEGER NOT NULL,
          month TEXT NOT NULL,
          bytes_in INTEGER NOT NULL DEFAULT 0,
          bytes_out INTEGER NOT NULL DEFAULT 0,
          sessions INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (user_id, month)
        );
        CREATE TABLE IF NOT EXISTS connections_audit (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          owner TEXT NOT NULL,
          session_id TEXT NOT NULL,
          proto TEXT NOT NULL,
          dst_ip TEXT NOT NULL,
          dst_port INTEGER NOT NULL,
          verdict TEXT NOT NULL,
          bytes_in INTEGER,
          bytes_out INTEGER,
          started_at INTEGER NOT NULL,
          ended_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS connections_audit_owner_started ON connections_audit(owner, started_at);
        CREATE INDEX IF NOT EXISTS connections_audit_started ON connections_audit(started_at);
        CREATE TABLE IF NOT EXISTS admin_sessions (
          sid TEXT PRIMARY KEY,
          data TEXT NOT NULL,
          expires_at INTEGER NOT NULL
        );
      `);

      // Legacy fork schema: admin_users becomes operators in users.
      const legacy = await db.get(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'admin_users'",
      );
      if (legacy) {
        await db.run(`
          INSERT OR IGNORE INTO users (username, password_hash, role, tier, status, created_at, last_login_at)
          SELECT username, password_hash, 'operator', 'operator', 'active', created_at, last_login_at
          FROM admin_users
        `);
        await db.run("ALTER TABLE admin_users RENAME TO admin_users_legacy");
      }
    },
  },
];

function openDatabase(filename = ":memory:") {
  const raw = new sqlite3.Database(filename);

  const db = {
    raw,
    filename,
    run(sql, params = []) {
      return new Promise((resolve, reject) => {
        raw.run(sql, params, function onRun(err) {
          if (err) reject(err);
          else resolve({ lastID: this.lastID, changes: this.changes });
        });
      });
    },
    get(sql, params = []) {
      return new Promise((resolve, reject) => {
        raw.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
      });
    },
    all(sql, params = []) {
      return new Promise((resolve, reject) => {
        raw.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
      });
    },
    exec(sql) {
      return new Promise((resolve, reject) => {
        raw.exec(sql, (err) => (err ? reject(err) : resolve()));
      });
    },
    async transaction(fn) {
      await db.run("BEGIN IMMEDIATE");
      try {
        const result = await fn(db);
        await db.run("COMMIT");
        return result;
      } catch (error) {
        await db.run("ROLLBACK").catch(() => {});
        throw error;
      }
    },
    async version() {
      await db.exec("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)");
      const row = await db.get("SELECT version FROM schema_version LIMIT 1");
      return row ? row.version : 0;
    },
    async migrate() {
      if (filename !== ":memory:") {
        await db.exec("PRAGMA journal_mode = WAL");
      }
      await db.exec("PRAGMA foreign_keys = ON");
      let current = await db.version();
      for (const migration of MIGRATIONS) {
        if (migration.version <= current) continue;
        await db.transaction(async () => {
          await migration.up(db);
          if (current === 0) {
            await db.run("INSERT INTO schema_version (version) VALUES (?)", [migration.version]);
          } else {
            await db.run("UPDATE schema_version SET version = ?", [migration.version]);
          }
          current = migration.version;
        });
      }
      return current;
    },
    close() {
      return new Promise((resolve) => raw.close(() => resolve()));
    },
  };
  return db;
}

module.exports = { MIGRATIONS, openDatabase };
