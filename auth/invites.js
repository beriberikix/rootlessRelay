"use strict";

// Single-use invite codes for invite-only sign-up (SIGNUP_MODE=invite).
// Operators create codes; a pending account redeems one to become active.
// Only a SHA-256 hash of each code is stored, plus a short hint for the list.

const crypto = require("node:crypto");

// Crockford base32 without I, L, O, U: easy to read aloud and retype.
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_GROUPS = 3;
const GROUP_LENGTH = 4;
const MAX_NOTE_LENGTH = 200;

function generateInviteCode(randomBytes = crypto.randomBytes) {
  const bytes = randomBytes(CODE_GROUPS * GROUP_LENGTH);
  let chars = "";
  for (const byte of bytes) chars += ALPHABET[byte % ALPHABET.length];
  const groups = [];
  for (let i = 0; i < CODE_GROUPS; i += 1) groups.push(chars.slice(i * GROUP_LENGTH, (i + 1) * GROUP_LENGTH));
  return `RLY-${groups.join("-")}`;
}

// Uppercases and drops separators and whitespace, so "rly 7k2m-..." matches.
function normalizeInviteCode(code) {
  if (typeof code !== "string") return null;
  const compact = code.toUpperCase().replace(/[\s-]/g, "");
  const body = compact.startsWith("RLY") ? compact.slice(3) : compact;
  if (body.length !== CODE_GROUPS * GROUP_LENGTH) return null;
  for (const ch of body) if (!ALPHABET.includes(ch)) return null;
  return body;
}

function hashInviteCode(normalized) {
  return crypto.createHash("sha256").update(`invite:${normalized}`).digest("hex");
}

function publicInvite(row, now) {
  const expired = row.expires_at && new Date(row.expires_at).getTime() <= now;
  let state = "open";
  if (row.redeemed_at) state = "redeemed";
  else if (row.revoked_at) state = "revoked";
  else if (expired) state = "expired";
  return {
    id: row.id,
    hint: row.code_hint,
    note: row.note || null,
    state,
    createdBy: row.created_by_username || null,
    createdAt: row.created_at,
    expiresAt: row.expires_at || null,
    revokedAt: row.revoked_at || null,
    redeemedBy: row.redeemed_by_username || null,
    redeemedAt: row.redeemed_at || null,
  };
}

function createInviteStore(db, { now = Date.now, randomBytes = crypto.randomBytes } = {}) {
  const iso = () => new Date(now()).toISOString();

  return {
    async create({ createdBy = null, note = null, expiresAt = null } = {}) {
      const trimmed = typeof note === "string" && note.trim() ? note.trim().slice(0, MAX_NOTE_LENGTH) : null;
      const code = generateInviteCode(randomBytes);
      const normalized = normalizeInviteCode(code);
      const result = await db.run(
        "INSERT INTO invites (code_hash, code_hint, note, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        [hashInviteCode(normalized), code.slice(-4), trimmed, createdBy, iso(), expiresAt],
      );
      const row = await this.findRow(result.lastID);
      return { ...publicInvite(row, now()), code };
    },

    async findRow(id) {
      return db.get(
        "SELECT i.*, c.username AS created_by_username, r.username AS redeemed_by_username FROM invites i " +
          "LEFT JOIN users c ON c.id = i.created_by LEFT JOIN users r ON r.id = i.redeemed_by WHERE i.id = ?",
        [id],
      );
    },

    async list() {
      const rows = await db.all(
        "SELECT i.*, c.username AS created_by_username, r.username AS redeemed_by_username FROM invites i " +
          "LEFT JOIN users c ON c.id = i.created_by LEFT JOIN users r ON r.id = i.redeemed_by ORDER BY i.id DESC",
      );
      const at = now();
      return rows.map((row) => publicInvite(row, at));
    },

    // Revokes an unredeemed code. Returns false if it is unknown or used.
    async revoke(id) {
      const result = await db.run(
        "UPDATE invites SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL AND redeemed_at IS NULL",
        [iso(), id],
      );
      return result.changes > 0;
    },

    // Claims the code for userId. The conditional UPDATE is the claim, so two
    // concurrent redemptions of one code cannot both succeed.
    async redeem(code, userId) {
      const normalized = normalizeInviteCode(code);
      if (!normalized) return false;
      const at = iso();
      // One statement: also refuses if this user already redeemed a code, so
      // concurrent redemptions with two codes cannot consume both.
      const result = await db.run(
        "UPDATE invites SET redeemed_by = ?, redeemed_at = ? WHERE code_hash = ? AND redeemed_at IS NULL " +
          "AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?) " +
          "AND NOT EXISTS (SELECT 1 FROM invites WHERE redeemed_by = ?)",
        [userId, at, hashInviteCode(normalized), at, userId],
      );
      return result.changes > 0;
    },
  };
}

module.exports = {
  createInviteStore,
  generateInviteCode,
  hashInviteCode,
  normalizeInviteCode,
};
