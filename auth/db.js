"use strict";

// SQLite access with promise wrappers and versioned migrations. One database
// file holds operators, end users, API tokens, usage, the connection audit
// log and admin login sessions.

const { AsyncLocalStorage } = require("node:async_hooks");
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
  {
    // Adds the 'pending' account status (invite-only sign-up) and the
    // invites table. SQLite cannot alter a CHECK constraint, so users is
    // rebuilt; foreign keys are off for the rebuild so dropping the old table
    // does not cascade into api_tokens.
    version: 2,
    foreignKeysOff: true,
    async up(db) {
      await db.exec(`
        CREATE TABLE users_v2 (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE,
          password_hash TEXT,
          role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'operator')),
          tier TEXT NOT NULL DEFAULT 'user',
          status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'pending', 'banned')),
          external_sub TEXT UNIQUE,
          created_at TEXT NOT NULL,
          last_login_at TEXT
        );
        INSERT INTO users_v2 (id, username, password_hash, role, tier, status, external_sub, created_at, last_login_at)
          SELECT id, username, password_hash, role, tier, status, external_sub, created_at, last_login_at FROM users;
        DROP TABLE users;
        ALTER TABLE users_v2 RENAME TO users;
        CREATE TABLE IF NOT EXISTS invites (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          code_hash TEXT NOT NULL UNIQUE,
          code_hint TEXT NOT NULL,
          note TEXT,
          created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
          created_at TEXT NOT NULL,
          expires_at TEXT,
          revoked_at TEXT,
          redeemed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
          redeemed_at TEXT
        );
      `);
    },
  },
  {
    // Abuse lookups search the audit by destination and time.
    version: 3,
    async up(db) {
      await db.exec("CREATE INDEX IF NOT EXISTS connections_audit_dst_started ON connections_audit(dst_ip, started_at)");
    },
  },
  {
    // Organizations own networks, tokens, tier and usage; users belong to them
    // through memberships. Additive: users, api_tokens and usage_monthly keep
    // their shape so the previous release still starts on this database (it
    // ignores the new tables and columns; usage it records lands in the old
    // table). Every existing user gets a personal org, owned by them, that
    // carries their tier, their tokens and their usage history.
    version: 4,
    async up(db) {
      await db.exec(`
        CREATE TABLE orgs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          personal INTEGER NOT NULL DEFAULT 0,
          tier TEXT NOT NULL DEFAULT 'user',
          status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
          created_at TEXT NOT NULL
        );
        CREATE TABLE memberships (
          org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'billing', 'read_only')),
          created_at TEXT NOT NULL,
          PRIMARY KEY (org_id, user_id)
        );
        CREATE INDEX memberships_user ON memberships(user_id);
        CREATE TABLE org_invites (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
          email TEXT NOT NULL,
          role TEXT NOT NULL CHECK (role IN ('admin', 'member', 'billing', 'read_only')),
          token_hash TEXT NOT NULL UNIQUE,
          created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
          created_at TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          accepted_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
          accepted_at TEXT,
          revoked_at TEXT
        );
        CREATE TABLE teams (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
          name TEXT NOT NULL,
          UNIQUE (org_id, name)
        );
        CREATE TABLE team_members (
          team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          PRIMARY KEY (team_id, user_id)
        );
        CREATE TABLE org_usage_monthly (
          org_id INTEGER NOT NULL,
          month TEXT NOT NULL,
          bytes_in INTEGER NOT NULL DEFAULT 0,
          bytes_out INTEGER NOT NULL DEFAULT 0,
          sessions INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (org_id, month)
        );
        ALTER TABLE users ADD COLUMN default_org_id INTEGER REFERENCES orgs(id);
        ALTER TABLE api_tokens ADD COLUMN org_id INTEGER REFERENCES orgs(id);
      `);

      const stamp = new Date().toISOString();
      const rows = await db.all("SELECT id, username, tier FROM users ORDER BY id");
      for (const user of rows) {
        const org = await db.run(
          "INSERT INTO orgs (name, personal, tier, status, created_at) VALUES (?, 1, ?, 'active', ?)",
          [user.username, user.tier, stamp],
        );
        await db.run(
          "INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, 'owner', ?)",
          [org.lastID, user.id, stamp],
        );
        await db.run("UPDATE users SET default_org_id = ? WHERE id = ?", [org.lastID, user.id]);
      }
      await db.run("UPDATE api_tokens SET org_id = (SELECT default_org_id FROM users WHERE users.id = api_tokens.user_id)");
      await db.run(
        "INSERT INTO org_usage_monthly (org_id, month, bytes_in, bytes_out, sessions) " +
          "SELECT u.default_org_id, m.month, m.bytes_in, m.bytes_out, m.sessions " +
          "FROM usage_monthly m JOIN users u ON u.id = m.user_id WHERE u.default_org_id IS NOT NULL",
      );
    },
  },
  {
    // The audit is keyed by owner, which is an org for accounts, so a row no
    // longer says which member made the connection. user_id records that. It is
    // not a foreign key: rows outlive the account for the retention window.
    // Earlier rows are attributed where that is unambiguous: "user:<id>" rows
    // name the user, and "org:<id>" rows of a personal org (the only kind that
    // existed before this migration) name its owner.
    version: 5,
    async up(db) {
      await db.exec(`
        ALTER TABLE connections_audit ADD COLUMN user_id INTEGER;
        CREATE INDEX connections_audit_user_started ON connections_audit(user_id, started_at);
        UPDATE connections_audit SET user_id = CAST(substr(owner, 6) AS INTEGER)
          WHERE owner GLOB 'user:[0-9]*' AND substr(owner, 6) NOT GLOB '*[^0-9]*';
        UPDATE connections_audit SET user_id = (
            SELECT m.user_id FROM memberships m JOIN orgs o ON o.id = m.org_id
            WHERE o.personal = 1 AND m.role = 'owner' AND 'org:' || o.id = connections_audit.owner)
          WHERE owner GLOB 'org:[0-9]*' AND user_id IS NULL;
      `);
    },
  },
  {
    // Dashboard sign-in with a relay account (USER_PASSWORD_LOGIN): opaque
    // bearer tokens, stored hashed like API tokens, with an idle and an
    // absolute expiry.
    version: 6,
    async up(db) {
      await db.exec(`
        CREATE TABLE user_sessions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          token_prefix TEXT NOT NULL,
          token_hash TEXT NOT NULL,
          created_at TEXT NOT NULL,
          last_used_at TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          revoked_at TEXT
        );
        CREATE INDEX user_sessions_prefix ON user_sessions(token_prefix);
        CREATE INDEX user_sessions_user ON user_sessions(user_id);
      `);
    },
  },
];

// All access shares one sqlite3 connection, where a transaction is
// connection-wide: a statement issued by an unrelated caller while another
// caller's BEGIN is open would join (and roll back with) that transaction,
// and a second BEGIN fails. So every statement goes through one FIFO queue,
// and a transaction holds the queue until it commits. Statements issued from
// inside the transaction callback (tracked with AsyncLocalStorage) bypass the
// queue, so callbacks may keep using `db` directly.
function openDatabase(filename = ":memory:") {
  const raw = new sqlite3.Database(filename);
  const inTransaction = new AsyncLocalStorage();
  let tail = Promise.resolve();

  function exclusive(task) {
    if (inTransaction.getStore()) return task();
    const result = tail.then(task, task);
    tail = result.catch(() => {});
    return result;
  }

  const rawOps = {
    run(sql, params) {
      return new Promise((resolve, reject) => {
        raw.run(sql, params, function onRun(err) {
          if (err) reject(err);
          else resolve({ lastID: this.lastID, changes: this.changes });
        });
      });
    },
    get(sql, params) {
      return new Promise((resolve, reject) => {
        raw.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
      });
    },
    all(sql, params) {
      return new Promise((resolve, reject) => {
        raw.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
      });
    },
    exec(sql) {
      return new Promise((resolve, reject) => {
        raw.exec(sql, (err) => (err ? reject(err) : resolve()));
      });
    },
  };

  const db = {
    raw,
    filename,
    run(sql, params = []) {
      return exclusive(() => rawOps.run(sql, params));
    },
    get(sql, params = []) {
      return exclusive(() => rawOps.get(sql, params));
    },
    all(sql, params = []) {
      return exclusive(() => rawOps.all(sql, params));
    },
    exec(sql) {
      return exclusive(() => rawOps.exec(sql));
    },
    transaction(fn) {
      return exclusive(() => inTransaction.run(true, async () => {
        await rawOps.run("BEGIN IMMEDIATE", []);
        try {
          const result = await fn(db);
          await rawOps.run("COMMIT", []);
          return result;
        } catch (error) {
          await rawOps.run("ROLLBACK", []).catch(() => {});
          throw error;
        }
      }));
    },
    async version() {
      await db.exec("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)");
      const row = await db.get("SELECT version FROM schema_version LIMIT 1");
      return row ? row.version : 0;
    },
    async migrate() {
      if (filename !== ":memory:") {
        // WAL plus NORMAL sync is durable across process crashes and is what
        // WAL-shipping backup tools (Litestream) expect. busy_timeout lets
        // writes wait out a backup checkpoint instead of failing SQLITE_BUSY.
        await db.exec("PRAGMA journal_mode = WAL");
        await db.exec("PRAGMA synchronous = NORMAL");
        await db.exec("PRAGMA busy_timeout = 5000");
      }
      await db.exec("PRAGMA foreign_keys = ON");
      let current = await db.version();
      for (const migration of MIGRATIONS) {
        if (migration.version <= current) continue;
        // PRAGMA foreign_keys is a no-op inside a transaction, so it is
        // switched around it; foreign_key_check runs before the commit.
        if (migration.foreignKeysOff) await db.exec("PRAGMA foreign_keys = OFF");
        await db.transaction(async () => {
          await migration.up(db);
          if (migration.foreignKeysOff) {
            const broken = await db.all("PRAGMA foreign_key_check");
            if (broken.length > 0) {
              throw new Error(`migration ${migration.version} broke ${broken.length} foreign key reference(s)`);
            }
          }
          if (current === 0) {
            await db.run("INSERT INTO schema_version (version) VALUES (?)", [migration.version]);
          } else {
            await db.run("UPDATE schema_version SET version = ?", [migration.version]);
          }
          current = migration.version;
        }).finally(async () => {
          if (migration.foreignKeysOff) await db.exec("PRAGMA foreign_keys = ON");
        });
      }
      return current;
    },
    // Waits for queued statements, so a final flush is not cut off.
    close() {
      return exclusive(() => new Promise((resolve) => raw.close(() => resolve())));
    },
  };
  return db;
}

module.exports = { MIGRATIONS, openDatabase };
