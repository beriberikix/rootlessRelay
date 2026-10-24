"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { openDatabase } = require("../auth/db");
const { createUserStore } = require("../auth/users");
const { OrgError, createOrgStore } = require("../auth/orgs");
const { INVITABLE_ROLES, TOKEN_PREFIX, createOrgInviteStore, hashToken, normalizeEmail } = require("../auth/org_invites");

async function setup() {
  const db = openDatabase(":memory:");
  await db.migrate();
  const clock = { now: 1_700_000_000_000 };
  const users = createUserStore(db, { bcryptRounds: 4 });
  const orgs = createOrgStore(db, { now: () => clock.now });
  const invites = createOrgInviteStore(db, { orgs, now: () => clock.now });
  const owner = await users.create({ username: "owner" });
  const team = await orgs.create({ name: "team", ownerUserId: owner.id });
  return { db, clock, users, orgs, invites, owner, team };
}

const rejects = (status, code) => (error) => error instanceof OrgError && error.status === status && error.code === code;
const verified = (user, email) => ({ id: user.id, email, emailVerified: true });

test("email normalization and invitable roles", () => {
  assert.equal(normalizeEmail("  Dana@Example.COM "), "dana@example.com");
  for (const bad of ["", "dana", "dana@", "@example.com", "a b@example.com", "dana@example", null, 42, `${"a".repeat(250)}@example.com`]) {
    assert.equal(normalizeEmail(bad), null, String(bad));
  }
  assert.deepEqual(INVITABLE_ROLES, ["admin", "member", "billing", "read_only"], "owner is never granted by invitation");
});

test("create returns the token once and stores only its hash", async () => {
  const { db, invites, owner, team } = await setup();
  const created = await invites.create({ orgId: team.id, email: "Dana@Example.com", role: "member", createdBy: owner.id });
  assert.match(created.token, new RegExp(`^${TOKEN_PREFIX}[A-Za-z0-9_-]{32}$`));
  assert.equal(created.email, "dana@example.com");
  assert.equal(created.state, "open");
  assert.equal(created.createdBy, "owner");
  const row = await db.get("SELECT token_hash FROM org_invites");
  assert.equal(row.token_hash, hashToken(created.token));
  assert.ok(!JSON.stringify(await db.all("SELECT * FROM org_invites")).includes(created.token), "the token itself is not stored");
  const listed = await invites.list(team.id);
  assert.equal(listed.length, 1);
  assert.equal(listed[0].token, undefined, "listings never include tokens");

  await assert.rejects(invites.create({ orgId: team.id, email: "no pe", role: "member" }), RangeError);
  await assert.rejects(invites.create({ orgId: team.id, email: "nope@", role: "member" }), RangeError);
  await assert.rejects(invites.create({ orgId: team.id, email: "a@b.co", role: "owner" }), RangeError);
});

test("accepting adds the member with the invited role, once", async () => {
  const { users, orgs, invites, owner, team } = await setup();
  const dana = await users.create({ username: "dana" });
  const { token } = await invites.create({ orgId: team.id, email: "dana@example.com", role: "billing", createdBy: owner.id });

  assert.deepEqual(await invites.accept(token, verified(dana, "DANA@example.com")), { orgId: team.id, role: "billing" });
  assert.equal((await orgs.getMembership(team.id, dana.id)).role, "billing");
  assert.equal((await invites.list(team.id))[0].state, "accepted");
  await assert.rejects(invites.accept(token, verified(dana, "dana@example.com")), rejects(404, "invite-invalid"));
  assert.equal((await users.findById(dana.id)).default_org_id, dana.default_org_id, "the default org does not change");
});

test("the invited address must match and be verified; a refused attempt does not consume the invite", async () => {
  const { users, invites, owner, team } = await setup();
  const dana = await users.create({ username: "dana" });
  const eve = await users.create({ username: "eve" });
  const { token } = await invites.create({ orgId: team.id, email: "dana@example.com", role: "member", createdBy: owner.id });

  await assert.rejects(invites.accept(token, verified(eve, "eve@example.com")), rejects(403, "invite-email-mismatch"));
  await assert.rejects(invites.accept(token, { id: dana.id, email: "dana@example.com", emailVerified: false }), rejects(403, "email-not-verified"));
  await assert.rejects(invites.accept(token, { id: dana.id, email: null, emailVerified: true }), rejects(403, "email-not-verified"));
  assert.equal((await invites.list(team.id))[0].state, "open");
  assert.deepEqual(await invites.accept(token, verified(dana, "dana@example.com")), { orgId: team.id, role: "member" });
});

test("an invitation to a username is accepted by that account, with no verified address", async () => {
  const { users, orgs, invites, owner, team } = await setup();
  const frank = await users.create({ username: "Frank", password: "frank-password" });
  const eve = await users.create({ username: "eve" });
  const created = await invites.create({ orgId: team.id, email: " Frank ", role: "member", createdBy: owner.id });
  assert.equal(created.email, "frank");

  await assert.rejects(invites.accept(created.token, { id: eve.id, username: "eve", email: null, emailVerified: false }),
    rejects(403, "invite-username-mismatch"));
  // A verified address is no substitute for the named account.
  await assert.rejects(invites.accept(created.token, { id: eve.id, username: "eve", email: "frank@example.com", emailVerified: true }),
    rejects(403, "invite-username-mismatch"));
  assert.deepEqual(await invites.accept(created.token, { id: frank.id, username: "Frank", email: null, emailVerified: false }),
    { orgId: team.id, role: "member" });
  assert.equal((await orgs.getMembership(team.id, frank.id)).role, "member");

  // An address-shaped target still needs that verified address, whatever the username.
  const addressed = await invites.create({ orgId: team.id, email: "grace@example.com", role: "member", createdBy: owner.id });
  const lookalike = await users.create({ username: "grace@example.com", password: "grace-password" });
  await assert.rejects(invites.accept(addressed.token, { id: lookalike.id, username: "grace@example.com", email: null, emailVerified: false }),
    rejects(403, "email-not-verified"));
});

test("unknown, malformed, expired and revoked tokens are all the same answer", async () => {
  const { users, clock, invites, owner, team } = await setup();
  const dana = await users.create({ username: "dana" });
  const me = verified(dana, "dana@example.com");
  for (const bad of [undefined, null, 5, "", "garbage", `${TOKEN_PREFIX}unknown`, `${TOKEN_PREFIX}${"x".repeat(300)}`]) {
    await assert.rejects(invites.accept(bad, me), rejects(404, "invite-invalid"), String(bad));
  }

  const expiring = await invites.create({ orgId: team.id, email: "dana@example.com", role: "member", createdBy: owner.id });
  clock.now += 7 * 24 * 60 * 60 * 1000 + 1;
  assert.equal((await invites.list(team.id))[0].state, "expired");
  await assert.rejects(invites.accept(expiring.token, me), rejects(404, "invite-invalid"));

  const revoked = await invites.create({ orgId: team.id, email: "dana@example.com", role: "member", createdBy: owner.id });
  assert.equal(await invites.revoke(team.id, revoked.id), true);
  assert.equal(await invites.revoke(team.id, revoked.id), false, "already revoked");
  await assert.rejects(invites.accept(revoked.token, me), rejects(404, "invite-invalid"));
});

test("inviting the same address again replaces the open invitation", async () => {
  const { users, invites, owner, team } = await setup();
  const dana = await users.create({ username: "dana" });
  const first = await invites.create({ orgId: team.id, email: "dana@example.com", role: "member", createdBy: owner.id });
  const second = await invites.create({ orgId: team.id, email: "Dana@example.com", role: "admin", createdBy: owner.id });
  assert.deepEqual((await invites.list(team.id)).map((i) => i.state), ["open", "revoked"]);
  await assert.rejects(invites.accept(first.token, verified(dana, "dana@example.com")), rejects(404, "invite-invalid"));
  assert.deepEqual(await invites.accept(second.token, verified(dana, "dana@example.com")), { orgId: team.id, role: "admin" });
});

test("revoking is scoped to the org that issued the invitation", async () => {
  const { orgs, invites, owner, team } = await setup();
  const other = await orgs.create({ name: "other", ownerUserId: owner.id });
  const invite = await invites.create({ orgId: team.id, email: "dana@example.com", role: "member", createdBy: owner.id });
  assert.equal(await invites.revoke(other.id, invite.id), false);
  assert.equal((await invites.list(team.id))[0].state, "open");
});

test("an existing member cannot accept; the invitation stays usable", async () => {
  const { users, orgs, invites, owner, team } = await setup();
  const dana = await users.create({ username: "dana" });
  await orgs.addMember({ orgId: team.id, userId: dana.id, role: "member" });
  const { token } = await invites.create({ orgId: team.id, email: "dana@example.com", role: "admin", createdBy: owner.id });
  await assert.rejects(invites.accept(token, verified(dana, "dana@example.com")), rejects(409, "already-member"));
  assert.equal((await invites.list(team.id))[0].state, "open", "rolled back with the failed membership");
  assert.equal((await orgs.getMembership(team.id, dana.id)).role, "member", "the role is not changed by invitation");
});

test("two simultaneous accepts of one invitation: one wins", async () => {
  const { users, orgs, invites, owner, team } = await setup();
  const dana = await users.create({ username: "dana" });
  const { token } = await invites.create({ orgId: team.id, email: "dana@example.com", role: "member", createdBy: owner.id });
  const results = await Promise.allSettled([
    invites.accept(token, verified(dana, "dana@example.com")),
    invites.accept(token, verified(dana, "dana@example.com")),
  ]);
  assert.deepEqual(results.map((r) => r.status).sort(), ["fulfilled", "rejected"]);
  assert.equal((await orgs.listMembers(team.id)).filter((m) => m.userId === dana.id).length, 1);
});

test("deleting the org or the inviter keeps things consistent", async () => {
  const { db, users, orgs, invites, owner, team } = await setup();
  const admin = await users.create({ username: "admin" });
  await orgs.addMember({ orgId: team.id, userId: admin.id, role: "admin" });
  await invites.create({ orgId: team.id, email: "dana@example.com", role: "member", createdBy: admin.id });
  await orgs.setMemberRole({ orgId: team.id, actor: { userId: owner.id }, userId: admin.id, role: "member" });
  await users.removeAccount(admin.id);
  assert.equal((await invites.list(team.id))[0].createdBy, null, "the inviter's deletion leaves the row");
  await orgs.remove(team.id);
  assert.equal((await db.get("SELECT COUNT(*) AS n FROM org_invites")).n, 0, "invitations go with the org");
});
