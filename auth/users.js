"use strict";

// User accounts: operators (admin UI) and end users (data plane), either
// with a local password or linked to an external identity provider.

const crypto = require("node:crypto");
const bcrypt = require("bcryptjs");
const { ensurePersonalOrg, removeUserAndOrgs } = require("./orgs");

const ROLES = new Set(["user", "operator"]);
const STATUSES = new Set(["active", "pending", "banned"]);
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
    defaultOrgId: row.default_org_id || null,
    hasPassword: Boolean(row.password_hash),
    createdAt: row.created_at,
    lastLoginAt: row.last_login_at || null,
  };
}

function createUserStore(db, { bcryptRounds = 12, now = Date.now } = {}) {
  let dummyHash = null;
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

    async create({ username, password = null, role = "user", tier = null, status = "active" }) {
      if (typeof username !== "string" || !USERNAME_RE.test(username)) {
        throw new RangeError("username must be 1-128 characters of letters, digits, . _ @ + -");
      }
      if (!ROLES.has(role)) throw new RangeError(`role must be one of ${[...ROLES].join(", ")}`);
      if (!STATUSES.has(status)) throw new RangeError(`status must be one of ${[...STATUSES].join(", ")}`);
      if (password !== null && (typeof password !== "string" || password.length < 8)) {
        throw new RangeError("password must be at least 8 characters");
      }
      const passwordHash = password === null ? null : await bcrypt.hash(password, bcryptRounds);
      const resolvedTier = tier || (role === "operator" ? "operator" : "user");
      const result = await db.run(
        "INSERT INTO users (username, password_hash, role, tier, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        [username, passwordHash, role, resolvedTier, status, nowIso(now)],
      );
      await ensurePersonalOrg(db, result.lastID, { now });
      return this.findById(result.lastID);
    },

    // External identity providers create users on first sight.
    async upsertExternal({ externalSub, username, tier = "user", status = "active" }) {
      const existing = await this.findByExternalSub(externalSub);
      const placeholder = externalSub.slice(0, 120);
      if (existing) {
        // Accounts created before orgs existed (or by a rolled-back release)
        // get their personal org on first sight.
        if (!existing.default_org_id) await ensurePersonalOrg(db, existing.id, { now });
        // An account first seen without a usable address is named after its
        // subject; it takes the address once one arrives, if that is free.
        if (username && USERNAME_RE.test(username) && existing.username === placeholder &&
          !(await findRowByUsername(username))) {
          await db.run("UPDATE users SET username = ? WHERE id = ? AND username = ?", [username, existing.id, placeholder])
            .catch((error) => { if (!/UNIQUE/.test(error.message)) throw error; });
          return this.findById(existing.id);
        }
        return existing.default_org_id ? existing : this.findById(existing.id);
      }
      let candidate = username && USERNAME_RE.test(username) ? username : placeholder;
      if (await findRowByUsername(candidate)) {
        candidate = `${candidate.slice(0, 100)}#${externalSub.slice(-8)}`;
      }
      // Concurrent first logins race to insert; the loser reads the winner's row.
      await db.run(
        "INSERT INTO users (username, password_hash, role, tier, status, external_sub, created_at) VALUES (?, NULL, 'user', ?, ?, ?, ?) " +
          "ON CONFLICT(external_sub) DO NOTHING",
        [candidate, tier, status, externalSub, nowIso(now)],
      );
      const user = await this.findByExternalSub(externalSub);
      await ensurePersonalOrg(db, user.id, { now });
      return this.findById(user.id);
    },

    async setStatus(id, status) {
      if (!STATUSES.has(status)) throw new RangeError(`status must be one of ${[...STATUSES].join(", ")}`);
      const result = await db.run("UPDATE users SET status = ? WHERE id = ?", [status, id]);
      return result.changes > 0;
    },

    // Only pending accounts; a ban that lands meanwhile is not undone.
    async activatePending(id) {
      const result = await db.run("UPDATE users SET status = 'active' WHERE id = ? AND status = 'pending'", [id]);
      return result.changes > 0;
    },

    async setRole(id, role) {
      if (!ROLES.has(role)) throw new RangeError(`role must be one of ${[...ROLES].join(", ")}`);
      const result = await db.run("UPDATE users SET role = ? WHERE id = ?", [role, id]);
      return result.changes > 0;
    },

    async setTier(id, tier) {
      if (typeof tier !== "string" || !tier) throw new RangeError("tier is required");
      const result = await db.run("UPDATE users SET tier = ? WHERE id = ?", [tier, id]);
      // The tier lives on the org; the user's personal org follows it.
      await db.run("UPDATE orgs SET tier = ? WHERE id = (SELECT default_org_id FROM users WHERE id = ?)", [tier, id]);
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

    // With no user or no password set, still runs one comparison (against a
    // hash nobody knows) so the time taken does not tell whether the account
    // exists.
    async verifyPassword(user, password) {
      if (typeof password !== "string") return false;
      if (!user || !user.password_hash) {
        dummyHash ??= bcrypt.hash(crypto.randomBytes(16).toString("hex"), bcryptRounds);
        await bcrypt.compare(password, await dummyHash);
        return false;
      }
      return bcrypt.compare(password, user.password_hash);
    },

    // Deletes the account, its API tokens (cascade) and what only it holds:
    // orgs it is the sole member of go with it, with their usage. An org it
    // solely owns but shares with others blocks the deletion (OrgError 409
    // sole-owner). The connection audit is keyed by owner and ages out on its
    // own retention. Returns { removed, deletedOrgIds }.
    async removeAccount(id) {
      return removeUserAndOrgs(db, id);
    },

    async remove(id) {
      return (await this.removeAccount(id)).removed;
    },
  };
}

module.exports = { ROLES, STATUSES, USERNAME_RE, createUserStore, publicUser };
