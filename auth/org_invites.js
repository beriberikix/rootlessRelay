"use strict";

// Invitations to join an org: email-bound, single-use, expiring and
// revocable. Distinct from the operator-issued signup codes in invites.js,
// which gate who may use the service at all (SIGNUP_MODE=invite); accepting
// an org invitation adds an already-active account to an org and never
// admits a pending one. Only a SHA-256 hash of each token is stored, so the
// token is shown once, to whoever creates the invitation, and handed on out
// of band (the relay sends no email).

const crypto = require("node:crypto");
const { OrgError } = require("./orgs");

const TOKEN_PREFIX = "oi_";
const INVITABLE_ROLES = ["admin", "member", "billing", "read_only"];
const DEFAULT_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

function hashToken(token) {
  return crypto.createHash("sha256").update(`org-invite:${token}`).digest("hex");
}

function normalizeEmail(value) {
  if (typeof value !== "string") return null;
  const email = value.trim().toLowerCase();
  return email.length <= 254 && EMAIL_RE.test(email) ? email : null;
}

// Who an invitation is for: an email address (accepted by an account whose
// identity provider verified that address), or a username without "@"
// (accepted by the account with that username, for relay accounts, which
// have no verified address). Stored lowercased in org_invites.email.
const USERNAME_TARGET_RE = /^[a-z0-9._+-]{1,128}$/;
function normalizeTarget(value) {
  if (typeof value !== "string") return null;
  const target = value.trim().toLowerCase();
  if (target.includes("@")) return normalizeEmail(target);
  return USERNAME_TARGET_RE.test(target) ? target : null;
}

function publicInvite(row, at) {
  let state = "open";
  if (row.accepted_at) state = "accepted";
  else if (row.revoked_at) state = "revoked";
  else if (new Date(row.expires_at).getTime() <= at) state = "expired";
  return {
    id: row.id,
    orgId: row.org_id,
    email: row.email,
    role: row.role,
    state,
    createdBy: row.created_by_username || null,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    acceptedAt: row.accepted_at || null,
    revokedAt: row.revoked_at || null,
  };
}

function createOrgInviteStore(db, { orgs, now = Date.now, ttlMs = DEFAULT_TTL_MS, randomBytes = crypto.randomBytes } = {}) {
  const iso = (ms = now()) => new Date(ms).toISOString();

  async function findRow(id) {
    return db.get(
      "SELECT i.*, u.username AS created_by_username FROM org_invites i LEFT JOIN users u ON u.id = i.created_by WHERE i.id = ?",
      [id],
    );
  }

  return {
    // Invites `email` to the org with `role`. Inviting an address that already
    // has an open invitation replaces it (the old token stops working), which
    // doubles as "resend". The token is returned once.
    async create({ orgId, email, role, createdBy = null }) {
      const normalized = normalizeTarget(email);
      if (!normalized) throw new RangeError("email must be a valid address or a username");
      if (!INVITABLE_ROLES.includes(role)) throw new RangeError(`role must be one of ${INVITABLE_ROLES.join(", ")}`);
      const token = `${TOKEN_PREFIX}${randomBytes(24).toString("base64url")}`;
      const created = await db.transaction(async () => {
        const at = iso();
        await db.run(
          "UPDATE org_invites SET revoked_at = ? WHERE org_id = ? AND email = ? AND accepted_at IS NULL AND revoked_at IS NULL",
          [at, orgId, normalized],
        );
        const result = await db.run(
          "INSERT INTO org_invites (org_id, email, role, token_hash, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
          [orgId, normalized, role, hashToken(token), createdBy, at, iso(now() + ttlMs)],
        );
        return findRow(result.lastID);
      });
      return { ...publicInvite(created, now()), token };
    },

    async list(orgId) {
      const rows = await db.all(
        "SELECT i.*, u.username AS created_by_username FROM org_invites i LEFT JOIN users u ON u.id = i.created_by " +
          "WHERE i.org_id = ? ORDER BY i.id DESC",
        [orgId],
      );
      const at = now();
      return rows.map((row) => publicInvite(row, at));
    },

    // Revokes an open invitation of this org. False if it is unknown, belongs
    // to another org, or was already accepted or revoked.
    async revoke(orgId, inviteId) {
      const result = await db.run(
        "UPDATE org_invites SET revoked_at = ? WHERE id = ? AND org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL",
        [iso(), inviteId, orgId],
      );
      return result.changes > 0;
    },

    // Accepts for `user` ({ id, username, email, emailVerified }). An unknown, used,
    // revoked or expired token is one answer (404 invite-invalid); a live
    // token needs a verified address that matches the invited one. The claim
    // and the membership are one transaction, so a concurrent second accept
    // or an existing membership leaves the invitation unused.
    async accept(token, user) {
      if (typeof token !== "string" || !token.startsWith(TOKEN_PREFIX) || token.length > 200) {
        throw new OrgError(404, "invite-invalid");
      }
      return db.transaction(async () => {
        const row = await db.get("SELECT * FROM org_invites WHERE token_hash = ?", [hashToken(token)]);
        const live = row && !row.accepted_at && !row.revoked_at && new Date(row.expires_at).getTime() > now();
        if (!live) throw new OrgError(404, "invite-invalid");
        if (!row.email.includes("@")) {
          if (typeof user.username !== "string" || user.username.toLowerCase() !== row.email) {
            throw new OrgError(403, "invite-username-mismatch");
          }
        } else {
          if (!user.emailVerified || !user.email) throw new OrgError(403, "email-not-verified");
          if (user.email.toLowerCase() !== row.email) throw new OrgError(403, "invite-email-mismatch");
        }
        const claimed = await db.run(
          "UPDATE org_invites SET accepted_by = ?, accepted_at = ? WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL",
          [user.id, iso(), row.id],
        );
        if (claimed.changes === 0) throw new OrgError(404, "invite-invalid");
        const org = await db.get("SELECT id FROM orgs WHERE id = ?", [row.org_id]);
        if (!org) throw new OrgError(404, "invite-invalid");
        await orgs.addMember({ orgId: row.org_id, userId: user.id, role: row.role });
        return { orgId: row.org_id, role: row.role };
      });
    },
  };
}

module.exports = { DEFAULT_TTL_MS, INVITABLE_ROLES, TOKEN_PREFIX, createOrgInviteStore, hashToken, normalizeEmail };
