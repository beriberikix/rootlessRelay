"use strict";

// Dashboard sign-in sessions for relay accounts (USER_PASSWORD_LOGIN). A
// session is an opaque bearer token ("rs_<12 hex>_<secret>"), stored as a
// SHA-256 hash like API tokens. It expires after IDLE_MS without use and
// at most ABSOLUTE_MS after sign-in, and is revoked at sign-out.

const crypto = require("crypto");

const SESSION_TOKEN_PREFIX = "rs_";
const IDLE_MS = 12 * 60 * 60 * 1000;
const ABSOLUTE_MS = 7 * 24 * 60 * 60 * 1000;

function hash(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function parseSessionToken(token) {
  if (typeof token !== "string" || !token.startsWith(SESSION_TOKEN_PREFIX)) return null;
  const rest = token.slice(SESSION_TOKEN_PREFIX.length);
  if (rest.indexOf("_") !== 12) return null;
  return { prefix: rest.slice(0, 12) };
}

function createUserSessionStore(db, { now = Date.now, randomBytes = crypto.randomBytes, idleMs = IDLE_MS, absoluteMs = ABSOLUTE_MS } = {}) {
  const iso = (ms) => new Date(ms).toISOString();

  return {
    async create(userId) {
      const prefix = randomBytes(6).toString("hex");
      const token = `${SESSION_TOKEN_PREFIX}${prefix}_${randomBytes(24).toString("base64url")}`;
      const at = now();
      const expiresAt = iso(Math.min(at + idleMs, at + absoluteMs));
      const result = await db.run(
        "INSERT INTO user_sessions (user_id, token_prefix, token_hash, created_at, last_used_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        [userId, prefix, hash(token), iso(at), iso(at), expiresAt],
      );
      return { id: result.lastID, token, expiresAt };
    },

    // Returns { session, user } for a live session, extending its idle
    // expiry (never past the absolute one), or { reason } / null.
    async verify(token) {
      const parsed = parseSessionToken(token);
      if (!parsed) return null;
      const rows = await db.all(
        "SELECT s.*, u.id AS u_id, u.username AS u_username, u.role AS u_role, u.tier AS u_tier, u.status AS u_status, " +
          "u.default_org_id AS u_default_org_id FROM user_sessions s JOIN users u ON u.id = s.user_id WHERE s.token_prefix = ?",
        [parsed.prefix],
      );
      const expected = Buffer.from(hash(token), "hex");
      for (const row of rows) {
        const actual = Buffer.from(row.token_hash, "hex");
        if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) continue;
        const at = now();
        if (row.revoked_at) return { reason: "session-revoked" };
        if (new Date(row.expires_at).getTime() <= at) return { reason: "session-expired" };
        const expiresAt = iso(Math.min(at + idleMs, new Date(row.created_at).getTime() + absoluteMs));
        await db.run("UPDATE user_sessions SET last_used_at = ?, expires_at = ? WHERE id = ?", [iso(at), expiresAt, row.id]);
        return {
          session: { id: row.id, expiresAt },
          user: {
            id: row.u_id,
            username: row.u_username,
            role: row.u_role,
            tier: row.u_tier,
            status: row.u_status,
            default_org_id: row.u_default_org_id,
          },
        };
      }
      return null;
    },

    async revoke(token) {
      const parsed = parseSessionToken(token);
      if (!parsed) return false;
      const result = await db.run(
        "UPDATE user_sessions SET revoked_at = ? WHERE token_prefix = ? AND token_hash = ? AND revoked_at IS NULL",
        [iso(now()), parsed.prefix, hash(token)],
      );
      return result.changes > 0;
    },

    // Ends every session of a user (password change, ban).
    async revokeForUser(userId) {
      const result = await db.run(
        "UPDATE user_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
        [iso(now()), userId],
      );
      return result.changes;
    },

    // Drops rows that can no longer be used.
    async prune() {
      const result = await db.run(
        "DELETE FROM user_sessions WHERE revoked_at IS NOT NULL OR expires_at <= ?",
        [iso(now())],
      );
      return result.changes;
    },
  };
}

module.exports = { ABSOLUTE_MS, IDLE_MS, SESSION_TOKEN_PREFIX, createUserSessionStore, parseSessionToken };
