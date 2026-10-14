"use strict";

// User accounts: operators (admin UI) and end users (data plane), either
// with a local password or linked to an external identity provider.

const bcrypt = require("bcryptjs");

const ROLES = new Set(["user", "operator"]);
const STATUSES = new Set(["active", "banned"]);
const USERNAME_RE = /^[a-zA-Z0-9._@+-]{1,128}$/;

function nowIso(now) {
  return new Date(now()).toISOString();
}

function publicUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    role: row.role,
    tier: row.tier,
    status: row.status,
    externalSub: row.external_sub || null,
    hasPassword: Boolean(row.password_hash),
    createdAt: row.created_at,
    lastLoginAt: row.last_login_at || null,
  };
}

function createUserStore(db, { bcryptRounds = 12, now = Date.now } = {}) {
  async function findRowByUsername(username) {
    return db.get("SELECT * FROM users WHERE username = ?", [username]);
  }

  return {
    publicUser,

    async findByUsername(username) {
      return findRowByUsername(username);
    },

    async findById(id) {
      return db.get("SELECT * FROM users WHERE id = ?", [id]);
    },

    async findByExternalSub(externalSub) {
      return db.get("SELECT * FROM users WHERE external_sub = ?", [externalSub]);
    },

    async list() {
      const rows = await db.all("SELECT * FROM users ORDER BY id");
      return rows.map(publicUser);
    },

    async countOperators() {
      const row = await db.get("SELECT COUNT(*) AS count FROM users WHERE role = 'operator'");
      return row.count;
    },

    async create({ username, password = null, role = "user", tier = null }) {
      if (typeof username !== "string" || !USERNAME_RE.test(username)) {
        throw new RangeError("username must be 1-128 characters of letters, digits, . _ @ + -");
      }
      if (!ROLES.has(role)) throw new RangeError(`role must be one of ${[...ROLES].join(", ")}`);
      if (password !== null && (typeof password !== "string" || password.length < 8)) {
        throw new RangeError("password must be at least 8 characters");
      }
      const passwordHash = password === null ? null : await bcrypt.hash(password, bcryptRounds);
      const resolvedTier = tier || (role === "operator" ? "operator" : "user");
      const result = await db.run(
        "INSERT INTO users (username, password_hash, role, tier, status, created_at) VALUES (?, ?, ?, ?, 'active', ?)",
        [username, passwordHash, role, resolvedTier, nowIso(now)],
      );
      return this.findById(result.lastID);
    },

    // External identity providers create users on first sight.
    async upsertExternal({ externalSub, username, tier = "user" }) {
      const existing = await this.findByExternalSub(externalSub);
      if (existing) return existing;
      let candidate = username && USERNAME_RE.test(username) ? username : externalSub.slice(0, 120);
      if (await findRowByUsername(candidate)) {
        candidate = `${candidate.slice(0, 100)}#${externalSub.slice(-8)}`;
      }
      const result = await db.run(
        "INSERT INTO users (username, password_hash, role, tier, status, external_sub, created_at) VALUES (?, NULL, 'user', ?, 'active', ?, ?)",
        [candidate, tier, externalSub, nowIso(now)],
      );
      return this.findById(result.lastID);
    },

    async setStatus(id, status) {
      if (!STATUSES.has(status)) throw new RangeError("status must be active or banned");
      const result = await db.run("UPDATE users SET status = ? WHERE id = ?", [status, id]);
      return result.changes > 0;
    },

    async setTier(id, tier) {
      if (typeof tier !== "string" || !tier) throw new RangeError("tier is required");
      const result = await db.run("UPDATE users SET tier = ? WHERE id = ?", [tier, id]);
      return result.changes > 0;
    },

    async setPassword(id, password) {
      if (typeof password !== "string" || password.length < 8) {
        throw new RangeError("password must be at least 8 characters");
      }
      const passwordHash = await bcrypt.hash(password, bcryptRounds);
      const result = await db.run("UPDATE users SET password_hash = ? WHERE id = ?", [passwordHash, id]);
      return result.changes > 0;
    },

    async touchLogin(id) {
      await db.run("UPDATE users SET last_login_at = ? WHERE id = ?", [nowIso(now), id]);
    },

    async verifyPassword(user, password) {
      if (!user || !user.password_hash || typeof password !== "string") return false;
      return bcrypt.compare(password, user.password_hash);
    },

    async remove(id) {
      const result = await db.run("DELETE FROM users WHERE id = ?", [id]);
      return result.changes > 0;
    },
  };
}

module.exports = { ROLES, STATUSES, USERNAME_RE, createUserStore, publicUser };
