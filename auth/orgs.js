"use strict";

// Organizations: the unit that owns a private network, API tokens, tier and
// usage. Users belong to orgs through memberships that carry a role. Every
// user has a personal org (created on first sight). `authorize` is the one
// place that maps a role to what it may do; the membership mutations here
// enforce the invariants (an org always has an owner, and so on).

const ROLES = ["owner", "admin", "member", "billing", "read_only"];
const ORG_STATUSES = ["active", "suspended"];

const SESSION_ROLES = ["owner", "admin", "member"];
const MANAGER_ROLES = ["owner", "admin"];
const READER_ROLES = ["owner", "admin", "member", "read_only"];

// action -> roles allowed. Operators (global) pass every check.
const PERMISSIONS = {
  "org.view": ROLES,
  "usage.view": ROLES,
  "member.list": READER_ROLES,
  "session.list": READER_ROLES,
  "session.open": SESSION_ROLES,
  "session.close.own": SESSION_ROLES,
  "session.close.any": MANAGER_ROLES,
  "token.create": SESSION_ROLES,
  "token.revoke.own": SESSION_ROLES,
  "token.revoke.any": MANAGER_ROLES,
  "member.invite": MANAGER_ROLES,
  "member.remove": MANAGER_ROLES,
  "member.role": MANAGER_ROLES,
  "team.manage": MANAGER_ROLES,
  "org.rename": MANAGER_ROLES,
  "billing.view": ["owner", "billing"],
  "billing.manage": ["owner", "billing"],
  "org.delete": ["owner"],
  "org.transfer": ["owner"],
};

class OrgError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.status = status;
    this.code = code;
  }
}

function roleAllows(role, action) {
  const allowed = PERMISSIONS[action];
  if (!allowed) throw new RangeError(`unknown action: ${action}`);
  return allowed.includes(role);
}

function nowIso(now) {
  return new Date(now()).toISOString();
}

function publicOrg(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    personal: Boolean(row.personal),
    tier: row.tier,
    status: row.status,
    createdAt: row.created_at,
  };
}

// Creates the user's personal org and makes it their default, unless they
// already have one. Idempotent and safe against concurrent first logins: the
// check and the inserts run in one transaction.
async function ensurePersonalOrg(db, userId, { now = Date.now } = {}) {
  return db.transaction(async () => {
    const user = await db.get("SELECT id, username, tier, default_org_id FROM users WHERE id = ?", [userId]);
    if (!user) return null;
    if (user.default_org_id) return db.get("SELECT * FROM orgs WHERE id = ?", [user.default_org_id]);
    const at = nowIso(now);
    const org = await db.run(
      "INSERT INTO orgs (name, personal, tier, status, created_at) VALUES (?, 1, ?, 'active', ?)",
      [user.username, user.tier, at],
    );
    await db.run("INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, 'owner', ?)", [org.lastID, userId, at]);
    await db.run("UPDATE users SET default_org_id = ? WHERE id = ?", [org.lastID, userId]);
    return db.get("SELECT * FROM orgs WHERE id = ?", [org.lastID]);
  });
}

// Deletes a user and what only they hold: orgs where they are the sole member
// go with them (tokens, usage, memberships); an org they solely own but share
// with others blocks the deletion until ownership moves. Returns the ids of
// the deleted orgs so the caller can close their sessions.
async function removeUserAndOrgs(db, userId) {
  return db.transaction(async () => {
    const user = await db.get("SELECT id FROM users WHERE id = ?", [userId]);
    if (!user) return { removed: false, deletedOrgIds: [] };
    const mine = await db.all(
      "SELECT m.org_id, m.role, " +
        "(SELECT COUNT(*) FROM memberships o WHERE o.org_id = m.org_id) AS members, " +
        "(SELECT COUNT(*) FROM memberships o WHERE o.org_id = m.org_id AND o.role = 'owner') AS owners " +
        "FROM memberships m WHERE m.user_id = ?",
      [userId],
    );
    const deletedOrgIds = [];
    for (const row of mine) {
      if (row.members === 1) deletedOrgIds.push(row.org_id);
      else if (row.role === "owner" && row.owners === 1) {
        throw new OrgError(409, "sole-owner", "transfer ownership or delete the org first");
      }
    }
    for (const orgId of deletedOrgIds) {
      await db.run("DELETE FROM api_tokens WHERE org_id = ?", [orgId]);
      await db.run("DELETE FROM org_usage_monthly WHERE org_id = ?", [orgId]);
      await db.run("UPDATE users SET default_org_id = NULL WHERE default_org_id = ?", [orgId]);
      await db.run("DELETE FROM orgs WHERE id = ?", [orgId]);
    }
    // Tokens this user minted in orgs that outlive them go with them.
    await db.run("DELETE FROM api_tokens WHERE user_id = ?", [userId]);
    const result = await db.run("DELETE FROM users WHERE id = ?", [userId]);
    await db.run("DELETE FROM usage_monthly WHERE user_id = ?", [userId]);
    return { removed: result.changes > 0, deletedOrgIds };
  });
}

function createOrgStore(db, { now = Date.now } = {}) {
  async function roleOf(orgId, userId) {
    const row = await db.get("SELECT role FROM memberships WHERE org_id = ? AND user_id = ?", [orgId, userId]);
    return row ? row.role : null;
  }

  // The actor's effective role for managing members: operators act as owners.
  async function actorRole(orgId, actor) {
    if (actor && actor.operator) return "owner";
    return actor ? roleOf(orgId, actor.userId) : null;
  }

  async function ownerCount(orgId) {
    const row = await db.get("SELECT COUNT(*) AS n FROM memberships WHERE org_id = ? AND role = 'owner'", [orgId]);
    return row.n;
  }

  return {
    ensurePersonalOrg: (userId) => ensurePersonalOrg(db, userId, { now }),

    async findById(id) {
      return db.get("SELECT * FROM orgs WHERE id = ?", [id]);
    },

    async list() {
      return (await db.all("SELECT * FROM orgs ORDER BY id")).map(publicOrg);
    },

    // Every org with its member count, for the operator panel.
    async listWithCounts() {
      const rows = await db.all(
        "SELECT o.*, (SELECT COUNT(*) FROM memberships m WHERE m.org_id = o.id) AS member_count FROM orgs o ORDER BY o.id",
      );
      return rows.map((row) => ({ ...publicOrg(row), memberCount: row.member_count }));
    },

    // Orgs a user belongs to, with their role in each.
    async listForUser(userId) {
      const rows = await db.all(
        "SELECT o.*, m.role AS role FROM orgs o JOIN memberships m ON m.org_id = o.id WHERE m.user_id = ? ORDER BY o.id",
        [userId],
      );
      return rows.map((row) => ({ ...publicOrg(row), role: row.role }));
    },

    getMembership: async (orgId, userId) => {
      const role = await roleOf(orgId, userId);
      return role ? { orgId, userId, role } : null;
    },

    async listMembers(orgId) {
      const rows = await db.all(
        "SELECT m.user_id AS userId, u.username, m.role, m.created_at AS createdAt " +
          "FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.org_id = ? ORDER BY m.created_at, m.user_id",
        [orgId],
      );
      return rows;
    },

    // Creates a shared org with `ownerUserId` as its owner. Who may call this
    // is a route concern (operators only during the beta).
    async create({ name, ownerUserId, tier = "user" }) {
      const trimmed = typeof name === "string" ? name.trim().slice(0, 100) : "";
      if (!trimmed) throw new RangeError("name is required");
      return db.transaction(async () => {
        const at = nowIso(now);
        const org = await db.run(
          "INSERT INTO orgs (name, personal, tier, status, created_at) VALUES (?, 0, ?, 'active', ?)",
          [trimmed, tier, at],
        );
        await db.run("INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, 'owner', ?)", [org.lastID, ownerUserId, at]);
        return db.get("SELECT * FROM orgs WHERE id = ?", [org.lastID]);
      });
    },

    async rename(orgId, name) {
      const trimmed = typeof name === "string" ? name.trim().slice(0, 100) : "";
      if (!trimmed) throw new RangeError("name is required");
      const result = await db.run("UPDATE orgs SET name = ? WHERE id = ?", [trimmed, orgId]);
      return result.changes > 0;
    },

    async setTier(orgId, tier) {
      if (typeof tier !== "string" || !tier) throw new RangeError("tier is required");
      const result = await db.run("UPDATE orgs SET tier = ? WHERE id = ?", [tier, orgId]);
      // A personal org's tier is also shown on its owner's account.
      await db.run(
        "UPDATE users SET tier = ? WHERE id IN (SELECT m.user_id FROM memberships m JOIN orgs o ON o.id = m.org_id " +
          "WHERE o.id = ? AND o.personal = 1 AND m.role = 'owner')",
        [tier, orgId],
      );
      return result.changes > 0;
    },

    async setStatus(orgId, status) {
      if (!ORG_STATUSES.includes(status)) throw new RangeError(`status must be one of ${ORG_STATUSES.join(", ")}`);
      const result = await db.run("UPDATE orgs SET status = ? WHERE id = ?", [status, orgId]);
      return result.changes > 0;
    },

    // True when `principal` ({ userId, operator }) may perform `action` in the
    // org. A user outside the org may do nothing; operators may do anything.
    async authorize(principal, action, orgId) {
      if (!PERMISSIONS[action]) throw new RangeError(`unknown action: ${action}`);
      if (!principal) return false;
      if (principal.operator) return Boolean(await this.findById(orgId));
      const role = await roleOf(orgId, principal.userId);
      return role !== null && roleAllows(role, action);
    },

    // Adds a user without an actor check (used by invitation acceptance and
    // by the operator panel). Re-adding an existing member is refused.
    async addMember({ orgId, userId, role }) {
      if (!ROLES.includes(role)) throw new RangeError(`role must be one of ${ROLES.join(", ")}`);
      const at = nowIso(now);
      const result = await db.run(
        "INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(org_id, user_id) DO NOTHING",
        [orgId, userId, role, at],
      );
      if (result.changes === 0) throw new OrgError(409, "already-member");
      return { orgId, userId, role };
    },

    // Changes a member's role. Rules: the actor needs `member.role`; nobody
    // changes their own role; only an owner (or operator) grants or removes
    // `owner`; the last owner cannot be demoted.
    async setMemberRole({ orgId, actor, userId, role }) {
      if (!ROLES.includes(role)) throw new RangeError(`role must be one of ${ROLES.join(", ")}`);
      return db.transaction(async () => {
        const acting = await actorRole(orgId, actor);
        if (!acting || !roleAllows(acting, "member.role")) throw new OrgError(403, "forbidden");
        if (actor && !actor.operator && actor.userId === userId) throw new OrgError(403, "cannot-change-own-role");
        const current = await roleOf(orgId, userId);
        if (!current) throw new OrgError(404, "not-a-member");
        if ((role === "owner" || current === "owner") && acting !== "owner") throw new OrgError(403, "owner-required");
        if (current === "owner" && role !== "owner" && (await ownerCount(orgId)) <= 1) {
          throw new OrgError(409, "last-owner");
        }
        await db.run("UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?", [role, orgId, userId]);
        return { orgId, userId, role };
      });
    },

    // Removes a member, or lets a member leave (actor === user). Admins cannot
    // remove owners, and the last owner cannot go. Tokens the user minted in
    // this org are revoked with the membership.
    async removeMember({ orgId, actor, userId }) {
      return db.transaction(async () => {
        const leaving = actor && !actor.operator && actor.userId === userId;
        const acting = await actorRole(orgId, actor);
        if (!acting) throw new OrgError(403, "forbidden");
        if (!leaving && !roleAllows(acting, "member.remove")) throw new OrgError(403, "forbidden");
        const current = await roleOf(orgId, userId);
        if (!current) throw new OrgError(404, "not-a-member");
        if (current === "owner") {
          if (!leaving && acting !== "owner") throw new OrgError(403, "owner-required");
          if ((await ownerCount(orgId)) <= 1) throw new OrgError(409, "last-owner");
        }
        await db.run("DELETE FROM memberships WHERE org_id = ? AND user_id = ?", [orgId, userId]);
        await db.run(
          "UPDATE api_tokens SET revoked_at = ? WHERE org_id = ? AND user_id = ? AND revoked_at IS NULL",
          [nowIso(now), orgId, userId],
        );
        // A removed default org falls back to the personal org.
        await db.run(
          "UPDATE users SET default_org_id = (SELECT o.id FROM orgs o JOIN memberships m ON m.org_id = o.id " +
            "WHERE m.user_id = users.id AND o.personal = 1 ORDER BY o.id LIMIT 1) " +
            "WHERE id = ? AND default_org_id = ?",
          [userId, orgId],
        );
        return true;
      });
    },

    // Deletes an org with its memberships, tokens and usage. Personal orgs go
    // with their user, not through here.
    async remove(orgId) {
      return db.transaction(async () => {
        const org = await db.get("SELECT personal FROM orgs WHERE id = ?", [orgId]);
        if (!org) return false;
        if (org.personal) throw new OrgError(409, "personal-org");
        await db.run("DELETE FROM api_tokens WHERE org_id = ?", [orgId]);
        await db.run("DELETE FROM org_usage_monthly WHERE org_id = ?", [orgId]);
        await db.run(
          "UPDATE users SET default_org_id = (SELECT o.id FROM orgs o JOIN memberships m ON m.org_id = o.id " +
            "WHERE m.user_id = users.id AND o.personal = 1 ORDER BY o.id LIMIT 1) WHERE default_org_id = ?",
          [orgId],
        );
        const result = await db.run("DELETE FROM orgs WHERE id = ?", [orgId]);
        return result.changes > 0;
      });
    },
  };
}

module.exports = {
  ORG_STATUSES,
  OrgError,
  PERMISSIONS,
  ROLES,
  createOrgStore,
  ensurePersonalOrg,
  publicOrg,
  removeUserAndOrgs,
  roleAllows,
};
