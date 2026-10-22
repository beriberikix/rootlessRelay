"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const jose = require("jose");
const { openDatabase } = require("../auth/db");
const { createUserStore } = require("../auth/users");
const { createOrgStore } = require("../auth/orgs");
const { AuthError } = require("../server/public");
const {
  ANON_ISSUER,
  createAnonIssuer,
  rateKey,
  createApiTokenStore,
  createAuthenticator,
  createJwtVerifier,
  generateApiToken,
  hashToken,
  parseApiToken,
  verifyTurnstile,
} = require("../auth/tokens");

async function setup() {
  const db = openDatabase(":memory:");
  await db.migrate();
  const users = createUserStore(db, { bcryptRounds: 4 });
  const clock = { now: 1_700_000_000_000 };
  const apiTokens = createApiTokenStore(db, { now: () => clock.now });
  const orgs = createOrgStore(db);
  return { db, users, apiTokens, orgs, clock };
}

test("API token format, hashing and parsing", () => {
  const generated = generateApiToken();
  assert.match(generated.token, /^rr_[0-9a-f]{12}_[A-Za-z0-9_-]{32}$/);
  assert.equal(generated.hash, hashToken(generated.token));
  assert.deepEqual(parseApiToken(generated.token), { prefix: generated.prefix });
  assert.equal(parseApiToken("rr_short_x"), null);
  assert.equal(parseApiToken("eyJhbGciOi"), null);
});

test("API token store: create, verify, expiry, revoke, list", async () => {
  const { db, users, apiTokens, clock } = await setup();
  const alice = await users.create({ username: "alice", password: "password-1" });
  const created = await apiTokens.create({ userId: alice.id, name: "laptop" });
  const verified = await apiTokens.verify(created.token);
  assert.equal(verified.user.username, "alice");
  assert.equal(verified.user.status, "active");
  assert.equal(await apiTokens.verify(`${created.token.slice(0, -1)}X`), null, "wrong secret, same prefix");
  assert.equal(await apiTokens.verify("rr_000000000000_nope"), null);

  const expiring = await apiTokens.create({
    userId: alice.id,
    name: "temp",
    expiresAt: new Date(clock.now + 1000).toISOString(),
  });
  assert.equal((await apiTokens.verify(expiring.token)).user.username, "alice");
  clock.now += 2000;
  assert.deepEqual(
    (({ user, reason }) => ({ user, reason }))(await apiTokens.verify(expiring.token)),
    { user: null, reason: "token-expired" },
  );

  assert.equal(await apiTokens.revoke(created.id), true);
  assert.equal(await apiTokens.revoke(created.id), false);
  assert.equal((await apiTokens.verify(created.token)).reason, "token-revoked");
  const listed = await apiTokens.listForUser(alice.id);
  assert.equal(listed.length, 2);
  assert.ok(listed[0].revokedAt);
  assert.equal("token_hash" in listed[0], false);
  await db.close();
});

test("anonymous tokens: issue, verify, IP binding, expiry, tampering, per-IP rate limit", async () => {
  const clock = { now: 1_700_000_000_000 };
  const anon = createAnonIssuer({ secret: "anon-secret", ttlMs: 60_000, perIpPerHour: 2, now: () => clock.now });
  const issued = await anon.issue({ ip: "203.0.113.5" });
  assert.equal(jose.decodeJwt(issued.token).iss, ANON_ISSUER);
  const identity = await anon.verify(issued.token, { ip: "203.0.113.5" });
  assert.equal(identity.kind, "anon");
  assert.equal(identity.tier, "anon");
  assert.match(identity.owner, /^anon:[0-9a-f-]{36}$/);
  await assert.rejects(anon.verify(issued.token, { ip: "198.51.100.9" }), (error) =>
    error instanceof AuthError && error.code === "anon-token-ip-mismatch");
  const [header, payload, signature] = issued.token.split(".");
  await assert.rejects(anon.verify(`${header}.${payload}.${signature.slice(0, -2)}AA`, { ip: "203.0.113.5" }), /invalid-anon-token/);
  await anon.issue({ ip: "203.0.113.5" });
  await assert.rejects(anon.issue({ ip: "203.0.113.5" }), (error) => error.status === 429);
  await anon.issue({ ip: "203.0.113.6" });
  clock.now += 61_000;
  await assert.rejects(anon.verify(issued.token, { ip: "203.0.113.5" }), /invalid-anon-token/);

  const unbound = createAnonIssuer({ secret: "s", bindIp: false, now: () => clock.now });
  const token = (await unbound.issue({ ip: "1.1.1.1" })).token;
  assert.equal((await unbound.verify(token, { ip: "2.2.2.2" })).kind, "anon");
});

test("external JWT verification with a local JWKS", async () => {
  const { privateKey, publicKey } = await jose.generateKeyPair("RS256");
  const jwk = await jose.exportJWK(publicKey);
  jwk.kid = "k1";
  const jwks = jose.createLocalJWKSet({ keys: [jwk] });
  const clock = { now: 1_700_000_000_000 };
  const verifier = createJwtVerifier({
    issuer: "https://idp.example",
    audience: "relay",
    jwksUrl: "https://idp.example/jwks",
    jwks,
    now: () => clock.now,
  });
  const sign = (claims, options = {}) =>
    new jose.SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(options.issuer || "https://idp.example")
      .setAudience(options.audience || "relay")
      .setSubject(options.sub || "sub-1")
      .setIssuedAt(Math.floor(clock.now / 1000))
      .setExpirationTime(Math.floor(clock.now / 1000) + 300)
      .sign(privateKey);

  const good = await verifier.verify(await sign({ email: "alice@example.com" }));
  assert.deepEqual({ iss: good.iss, sub: good.sub, username: good.username }, {
    iss: "https://idp.example", sub: "sub-1", username: "alice@example.com",
  });
  const invalidJwt = (error) => error instanceof AuthError && error.status === 401 && error.code === "invalid-jwt";
  await assert.rejects(verifier.verify(await sign({}, { audience: "other" })), invalidJwt);
  await assert.rejects(verifier.verify(await sign({}, { issuer: "https://evil" })), invalidJwt);
  const expiring = await sign({});
  clock.now += 600_000;
  await assert.rejects(verifier.verify(expiring), invalidJwt);
});

test("authenticator dispatches API tokens, anon tokens and external JWTs", async () => {
  const { db, users, apiTokens, orgs, clock } = await setup();
  const { privateKey, publicKey } = await jose.generateKeyPair("RS256");
  const jwk = await jose.exportJWK(publicKey);
  const jwt = createJwtVerifier({
    issuer: "https://idp.example",
    audience: "relay",
    jwksUrl: "https://idp.example/jwks",
    jwks: jose.createLocalJWKSet({ keys: [jwk] }),
    now: () => clock.now,
  });
  const anon = createAnonIssuer({ secret: "anon", now: () => clock.now });
  const config = { authRequired: true, anonEnabled: true, jwt: { defaultTier: "user" } };
  const authenticate = createAuthenticator({ config, users, apiTokens, orgs, anon, jwt });

  await assert.rejects(authenticate(null, {}), (error) => error.status === 401 && error.code === "authentication-required");
  await assert.rejects(authenticate("garbage", {}), /invalid-token/);

  const alice = await users.create({ username: "alice", password: "password-1" });
  const created = await apiTokens.create({ userId: alice.id });
  const viaToken = await authenticate(created.token, { clientIP: "1.1.1.1" });
  assert.deepEqual(viaToken, {
    kind: "user", owner: `org:${alice.default_org_id}`, orgId: alice.default_org_id, orgRole: "owner",
    userId: alice.id, username: "alice", tier: "user", status: "active", via: "api-token", tokenId: created.id,
  });
  await users.setStatus(alice.id, "banned");
  await assert.rejects(authenticate(created.token, {}), (error) => error.status === 403);

  const op = await users.create({ username: "ops", password: "password-2", role: "operator" });
  const opToken = await apiTokens.create({ userId: op.id });
  assert.equal((await authenticate(opToken.token, {})).kind, "operator");

  const anonToken = (await anon.issue({ ip: "9.9.9.9" })).token;
  assert.equal((await authenticate(anonToken, { clientIP: "9.9.9.9" })).kind, "anon");
  const disabled = createAuthenticator({ config: { ...config, anonEnabled: false }, users, apiTokens, orgs, anon, jwt });
  await assert.rejects(disabled(anonToken, { clientIP: "9.9.9.9" }), /anonymous-access-disabled/);

  const external = await new jose.SignJWT({ email: "bob@example.com" })
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer("https://idp.example")
    .setAudience("relay")
    .setSubject("sub-bob")
    .setIssuedAt(Math.floor(clock.now / 1000))
    .setExpirationTime(Math.floor(clock.now / 1000) + 300)
    .sign(privateKey);
  const viaJwt = await authenticate(external, {});
  assert.equal(viaJwt.kind, "user");
  assert.equal(viaJwt.username, "bob@example.com");
  const bob = await users.findByExternalSub("https://idp.example|sub-bob");
  assert.equal(bob.id, viaJwt.userId);
  assert.equal((await authenticate(external, {})).userId, bob.id, "second login reuses the user");

  const foreign = await new jose.SignJWT({})
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer("https://other")
    .setAudience("relay")
    .setSubject("x")
    .setExpirationTime(Math.floor(clock.now / 1000) + 300)
    .sign(privateKey);
  await assert.rejects(authenticate(foreign, {}), /unknown-issuer/);

  const optional = createAuthenticator({ config: { ...config, authRequired: false }, users, apiTokens, orgs, anon, jwt });
  assert.equal((await optional(null, {})).kind, "local");

  // Invite-only sign-up: a first-time external login creates a pending
  // account that may use the account API but not open sessions.
  const invite = createAuthenticator({ config: { ...config, signupMode: "invite" }, users, apiTokens, orgs, anon, jwt });
  const carolJwt = await new jose.SignJWT({ email: "carol@example.com" })
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer("https://idp.example")
    .setAudience("relay")
    .setSubject("sub-carol")
    .setExpirationTime(Math.floor(clock.now / 1000) + 300)
    .sign(privateKey);
  await assert.rejects(invite(carolJwt, {}), (error) => error.status === 403 && error.code === "account-pending");
  const pending = await invite(carolJwt, { allowPending: true });
  assert.equal(pending.status, "pending");
  assert.equal(pending.via, "jwt");
  const carolToken = await apiTokens.create({ userId: pending.userId });
  await assert.rejects(invite(carolToken.token, {}), /account-pending/);
  assert.equal((await invite(carolToken.token, { allowPending: true })).status, "pending");
  assert.equal((await invite(external, {})).status, "active", "existing accounts are unaffected");
  await users.setStatus(pending.userId, "banned");
  await assert.rejects(invite(carolJwt, { allowPending: true }), /account-suspended/);
  await db.close();
});

test("turnstile verification calls the siteverify endpoint", async () => {
  const calls = [];
  const fetchFn = async (url, init) => {
    calls.push({ url, body: init.body.toString() });
    return { ok: true, json: async () => ({ success: init.body.get("response") === "good" }) };
  };
  assert.equal(await verifyTurnstile({ secret: "s", token: "good", ip: "1.1.1.1", fetchFn }), true);
  assert.equal(await verifyTurnstile({ secret: "s", token: "bad", fetchFn }), false);
  assert.equal(await verifyTurnstile({ secret: "s", token: "", fetchFn }), false);
  assert.match(calls[0].url, /turnstile/);
  assert.match(calls[0].body, /remoteip=1\.1\.1\.1/);
});

test("external JWTs: unverified emails are not used as usernames; algorithms are pinned", async () => {
  const { privateKey, publicKey } = await jose.generateKeyPair("RS256");
  const jwk = await jose.exportJWK(publicKey);
  const clock = 1_700_000_000_000;
  const verifier = createJwtVerifier({
    issuer: "https://idp.example",
    audience: "relay",
    jwksUrl: "https://idp.example/jwks",
    usernameClaim: "email",
    verifiedClaim: "email_verified",
    jwks: jose.createLocalJWKSet({ keys: [jwk] }),
    now: () => clock,
  });
  const sign = (claims, alg = "RS256", key = privateKey) => new jose.SignJWT(claims)
    .setProtectedHeader({ alg })
    .setIssuer("https://idp.example")
    .setAudience("relay")
    .setSubject("sub-1")
    .setExpirationTime(Math.floor(clock / 1000) + 300)
    .sign(key);
  assert.equal((await verifier.verify(await sign({ email: "a@example.com", email_verified: true }))).username, "a@example.com");
  assert.equal((await verifier.verify(await sign({ email: "a@example.com", email_verified: false }))).username, null);
  assert.equal((await verifier.verify(await sign({ email: "a@example.com" }))).username, null);
  const ps = await jose.generateKeyPair("PS256");
  const psJwk = { ...(await jose.exportJWK(ps.publicKey)), alg: "PS256" };
  const mixed = createJwtVerifier({
    issuer: "https://idp.example", audience: "relay", jwksUrl: "https://idp.example/jwks",
    jwks: jose.createLocalJWKSet({ keys: [psJwk] }), now: () => clock,
  });
  await assert.rejects(mixed.verify(await sign({}, "PS256", ps.privateKey)), (error) => error.code === "invalid-jwt", "only RS256 by default");
});

test("a signed-in user acts in the org they name, and the verified email is exposed only when the IdP vouches", async () => {
  const { db, users, orgs, apiTokens, clock } = await setup();
  const { privateKey, publicKey } = await jose.generateKeyPair("RS256");
  const jwk = await jose.exportJWK(publicKey);
  const verifier = (verifiedClaim) => createJwtVerifier({
    issuer: "https://idp.example", audience: "relay", jwksUrl: "https://idp.example/jwks",
    jwks: jose.createLocalJWKSet({ keys: [jwk] }), usernameClaim: "email", verifiedClaim, now: () => clock.now,
  });
  const sign = (claims) => new jose.SignJWT(claims)
    .setProtectedHeader({ alg: "RS256" }).setIssuer("https://idp.example").setAudience("relay")
    .setSubject("sub-dana").setIssuedAt(Math.floor(clock.now / 1000)).setExpirationTime(Math.floor(clock.now / 1000) + 300)
    .sign(privateKey);
  const config = { authRequired: true, anonEnabled: false, jwt: { defaultTier: "user" } };
  const authenticateWith = (verifiedClaim) => createAuthenticator({ config, users, apiTokens, orgs, jwt: verifier(verifiedClaim) });

  const vouched = await sign({ email: "Dana@Example.com", email_verified: true });
  const authenticate = authenticateWith("email_verified");
  const first = await authenticate(vouched, {});
  assert.equal(first.email, "dana@example.com", "lower-cased for matching an invite");
  assert.equal(first.emailVerified, true);
  assert.equal(first.orgRole, "owner");

  // Unverified address: not offered, and not used as the username.
  const unverified = await sign({ email: "dana@example.com", email_verified: false });
  const second = await authenticate(unverified, {});
  assert.equal(second.emailVerified, false);
  assert.equal(second.email, null);
  // No verified claim configured: nothing vouches, so no invite matching.
  const unconfigured = await authenticateWith(null)(vouched, {});
  assert.equal(unconfigured.emailVerified, false);
  assert.equal(unconfigured.email, null);

  // Default org unless one is named; naming one needs membership.
  const dana = await users.findByExternalSub("https://idp.example|sub-dana");
  const team = await orgs.create({ name: "team", ownerUserId: (await users.create({ username: "boss" })).id });
  const refused = (error) => error.status === 403 && error.code === "not-a-member";
  assert.equal((await authenticate(vouched, {})).orgId, dana.default_org_id);
  await assert.rejects(authenticate(vouched, { orgId: team.id }), refused);
  await assert.rejects(authenticate(vouched, { orgId: 987654 }), refused, "a missing org answers like a foreign one");
  await orgs.addMember({ orgId: team.id, userId: dana.id, role: "member" });
  const inTeam = await authenticate(vouched, { orgId: team.id });
  assert.equal(inTeam.owner, `org:${team.id}`);
  assert.equal(inTeam.orgRole, "member");
  assert.equal((await authenticate(vouched, { orgId: dana.default_org_id })).orgRole, "owner");
  await db.close();
});

test("anonymous issuer: addresses that never return are swept; IPv6 is limited per /64", async () => {
  const clock = { now: Date.UTC(2026, 9, 22) };
  const anon = createAnonIssuer({ secret: "anon-secret", perIpPerHour: 2, now: () => clock.now });
  for (let i = 0; i < 500; i++) await anon.issue({ ip: `2001:db8:${i.toString(16)}::1` });
  assert.equal(anon.trackedKeys(), 500);
  clock.now += 61 * 60 * 1000;
  await anon.issue({ ip: "203.0.113.5" });
  assert.equal(anon.trackedKeys(), 1, "an hour later, only the new address is held");

  await anon.issue({ ip: "2001:db8:aa:bb::1" });
  await anon.issue({ ip: "2001:db8:aa:bb:ffff:1:2:3" });
  await assert.rejects(anon.issue({ ip: "2001:db8:aa:bb::99" }), (error) =>
    error instanceof AuthError && error.code === "anon-token-rate-limited");
  await anon.issue({ ip: "2001:db8:aa:bc::1" });

  assert.equal(rateKey("203.0.113.5"), "203.0.113.5");
  assert.equal(rateKey("::ffff:203.0.113.5"), "203.0.113.5");
  assert.equal(rateKey("2001:0DB8:0000:00aa:1:2:3:4"), "2001:db8:0:aa::/64");
  assert.equal(rateKey("2001:db8::1"), "2001:db8:0:0::/64");
  assert.equal(rateKey("fe80::1%eth0"), "fe80:0:0:0::/64");
  assert.equal(rateKey("::1"), "0:0:0:0::/64");
});
