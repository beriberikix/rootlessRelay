"use strict";

// Credentials for the data plane: per-user API tokens, short-lived anonymous
// tokens, external OIDC JWTs, and the authenticator that maps any of them to
// an Identity { kind, owner, tier, orgId?, orgRole?, userId?, username? }.
// For accounts, `owner` is the org ("org:<id>"): members of one org share a
// private network, a tier and a usage quota.

const crypto = require("crypto");
const jose = require("jose");
const { AuthError, LOCAL_IDENTITY } = require("../server/public");
const { roleAllows } = require("./orgs");

const API_TOKEN_PREFIX = "rr_";
const ANON_ISSUER = "rootlessrelay-anon";
const TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function generateApiToken(randomBytes = crypto.randomBytes) {
  const prefix = randomBytes(6).toString("hex");
  const secret = randomBytes(24).toString("base64url");
  const token = `${API_TOKEN_PREFIX}${prefix}_${secret}`;
  return { token, prefix, hash: hashToken(token) };
}

function parseApiToken(token) {
  if (typeof token !== "string" || !token.startsWith(API_TOKEN_PREFIX)) return null;
  const rest = token.slice(API_TOKEN_PREFIX.length);
  const index = rest.indexOf("_");
  if (index !== 12) return null;
  return { prefix: rest.slice(0, index) };
}

function createApiTokenStore(db, { now = Date.now, randomBytes = crypto.randomBytes } = {}) {
  return {
    // A token belongs to an org (default: the creator's default org) and is
    // minted by a user; sessions opened with it run as that org.
    async create({ userId, orgId = null, name = "default", expiresAt = null }) {
      const generated = generateApiToken(randomBytes);
      const result = await db.run(
        "INSERT INTO api_tokens (user_id, org_id, name, token_prefix, token_hash, created_at, expires_at) " +
          "VALUES (?, COALESCE(?, (SELECT default_org_id FROM users WHERE id = ?)), ?, ?, ?, ?, ?)",
        [userId, orgId, userId, String(name).slice(0, 64), generated.prefix, generated.hash, new Date(now()).toISOString(), expiresAt],
      );
      return { id: result.lastID, token: generated.token, prefix: generated.prefix, name, expiresAt };
    },

    // Returns { token, user } or null. Lookup by the public prefix, then a
    // constant-time comparison of the secret's hash.
    async verify(token) {
      const parsed = parseApiToken(token);
      if (!parsed) return null;
      const rows = await db.all(
        "SELECT t.*, u.id AS u_id, u.username AS u_username, u.role AS u_role, u.tier AS u_tier, u.status AS u_status, " +
        "u.default_org_id AS u_default_org_id " +
        "FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.token_prefix = ?",
        [parsed.prefix],
      );
      const expected = Buffer.from(hashToken(token), "hex");
      for (const row of rows) {
        const actual = Buffer.from(row.token_hash, "hex");
        if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) continue;
        if (row.revoked_at) return { token: row, user: null, reason: "token-revoked" };
        if (row.expires_at && new Date(row.expires_at).getTime() <= now()) {
          return { token: row, user: null, reason: "token-expired" };
        }
        await db.run("UPDATE api_tokens SET last_used_at = ? WHERE id = ?", [new Date(now()).toISOString(), row.id]);
        return {
          token: row,
          user: {
            id: row.u_id,
            username: row.u_username,
            role: row.u_role,
            tier: row.u_tier,
            status: row.u_status,
            default_org_id: row.u_default_org_id,
          },
          // Tokens minted before orgs existed (or by a rolled-back release)
          // have no org; they run as the creator's default org.
          orgId: row.org_id || row.u_default_org_id || null,
        };
      }
      return null;
    },

    async revoke(id) {
      const result = await db.run(
        "UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
        [new Date(now()).toISOString(), id],
      );
      return result.changes > 0;
    },

    // Every token that runs as the org, with who minted it (operator panel).
    async listForOrg(orgId) {
      const rows = await db.all(
        "SELECT t.id, t.name, t.token_prefix, t.user_id, u.username, t.created_at, t.last_used_at, t.expires_at, t.revoked_at " +
          "FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.org_id = ? ORDER BY t.id",
        [orgId],
      );
      return rows.map((row) => ({
        id: row.id,
        name: row.name,
        prefix: row.token_prefix,
        userId: row.user_id,
        username: row.username,
        createdAt: row.created_at,
        lastUsedAt: row.last_used_at,
        expiresAt: row.expires_at,
        revokedAt: row.revoked_at,
      }));
    },

    async listForUser(userId) {
      const rows = await db.all(
        "SELECT id, name, token_prefix, created_at, last_used_at, expires_at, revoked_at FROM api_tokens WHERE user_id = ? ORDER BY id",
        [userId],
      );
      return rows.map((row) => ({
        id: row.id,
        name: row.name,
        prefix: row.token_prefix,
        createdAt: row.created_at,
        lastUsedAt: row.last_used_at,
        expiresAt: row.expires_at,
        revokedAt: row.revoked_at,
      }));
    },
  };
}

const HOUR_MS = 60 * 60 * 1000;

function ipHash(ip, secret) {
  return crypto.createHmac("sha256", secret).update(String(ip)).digest("hex").slice(0, 16);
}

// The rate-limit key for an address: IPv4 as is, IPv6 by its /64 (one
// subscriber usually holds a whole /64, so per-address keys are free to
// rotate).
function rateKey(ip) {
  const address = String(ip).split("%")[0];
  if (!address.includes(":")) return address;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  if (mapped) return mapped[1];
  const [head, tail] = address.split("::");
  const front = head ? head.split(":") : [];
  const back = tail ? tail.split(":") : [];
  const groups = tail === undefined ? front : [...front, ...Array(Math.max(0, 8 - front.length - back.length)).fill("0"), ...back];
  return `${groups.slice(0, 4).map((g) => parseInt(g || "0", 16).toString(16)).join(":")}::/64`;
}

// Anonymous demo tokens: HS256 JWTs bound (optionally) to the requesting IP
// and rate-limited per IP (per /64 for IPv6) so a single client cannot mint
// unbounded identities.
function createAnonIssuer({
  secret,
  ttlMs = 15 * 60 * 1000,
  bindIp = true,
  perIpPerHour = 10,
  now = Date.now,
  randomUUID = () => crypto.randomUUID(),
}) {
  if (!secret) throw new RangeError("anon token secret is required");
  const key = new TextEncoder().encode(secret);
  const issued = new Map(); // rate key -> timestamps
  let lastSweepAt = 0;

  function prune(rk, current) {
    const list = (issued.get(rk) || []).filter((ts) => current - ts < HOUR_MS);
    if (list.length === 0) issued.delete(rk);
    else issued.set(rk, list);
    return list;
  }

  // Addresses that never come back would otherwise stay in the map forever.
  function sweep(current) {
    if (current - lastSweepAt < 60 * 1000) return;
    lastSweepAt = current;
    for (const [rk, list] of issued) {
      if (current - list.at(-1) >= HOUR_MS) issued.delete(rk);
    }
  }

  return {
    async issue({ ip }) {
      const current = now();
      sweep(current);
      const rk = rateKey(ip);
      const recent = prune(rk, current);
      if (recent.length >= perIpPerHour) {
        throw new AuthError(429, "anon-token-rate-limited");
      }
      recent.push(current);
      issued.set(rk, recent);
      const jti = randomUUID();
      const expiresAt = current + ttlMs;
      const claims = bindIp ? { iph: ipHash(ip, secret) } : {};
      const token = await new jose.SignJWT(claims)
        .setProtectedHeader({ alg: "HS256" })
        .setIssuer(ANON_ISSUER)
        .setJti(jti)
        .setIssuedAt(Math.floor(current / 1000))
        .setExpirationTime(Math.floor(expiresAt / 1000))
        .sign(key);
      return { token, expiresAt: new Date(expiresAt).toISOString(), ttlMs };
    },

    // How many rate keys are held.
    trackedKeys() {
      return issued.size;
    },

    async verify(token, { ip }) {
      let payload;
      try {
        ({ payload } = await jose.jwtVerify(token, key, {
          issuer: ANON_ISSUER,
          algorithms: ["HS256"],
          currentDate: new Date(now()),
        }));
      } catch (_error) {
        throw new AuthError(401, "invalid-anon-token");
      }
      if (bindIp && payload.iph !== ipHash(ip, secret)) {
        throw new AuthError(401, "anon-token-ip-mismatch");
      }
      return { kind: "anon", owner: `anon:${payload.jti}`, tier: "anon", username: null };
    },
  };
}

// External OIDC provider: verify signature via (remote) JWKS plus issuer and
// audience. `jwks` is injectable so tests can use a local key set.
function createJwtVerifier({
  issuer,
  audience,
  jwksUrl,
  usernameClaim = "email",
  verifiedClaim = null,
  algorithms = ["RS256"],
  jwks = null,
  now = Date.now,
}) {
  const keySet = jwks || jose.createRemoteJWKSet(new URL(jwksUrl));
  return {
    issuer,
    async verify(token) {
      let payload;
      try {
        ({ payload } = await jose.jwtVerify(token, keySet, { issuer, audience, algorithms, currentDate: new Date(now()) }));
      } catch (error) {
        throw new AuthError(401, "invalid-jwt", error.message);
      }
      if (!payload.sub) throw new AuthError(401, "invalid-jwt", "missing sub");
      // With verifiedClaim set, an address the IdP has not verified is not used
      // as the username (it could impersonate someone else's email).
      const verified = verifiedClaim === null || payload[verifiedClaim] === true;
      const username = verified && typeof payload[usernameClaim] === "string" ? payload[usernameClaim] : null;
      // Without a verifiedClaim nothing vouches for the address, so it is not
      // treated as verified (org invites need one).
      const emailVerified = verifiedClaim !== null && verified && username !== null;
      const email = emailVerified ? username.toLowerCase() : null;
      return { iss: payload.iss, sub: payload.sub, username, email, emailVerified, claims: payload };
    },
  };
}

async function verifyTurnstile({ secret, token, ip, fetchFn = globalThis.fetch }) {
  if (!token) return false;
  const body = new URLSearchParams({ secret, response: token });
  if (ip) body.set("remoteip", ip);
  const response = await fetchFn(TURNSTILE_VERIFY_URL, { method: "POST", body });
  if (!response.ok) return false;
  const result = await response.json();
  return Boolean(result && result.success);
}

function identityFor({ user, org, role, via = null }) {
  return {
    kind: user.role === "operator" ? "operator" : "user",
    owner: `org:${org.id}`,
    orgId: org.id,
    orgRole: role,
    userId: user.id,
    username: user.username,
    tier: org.tier || (user.role === "operator" ? "operator" : "user"),
    status: user.status || "active",
    via,
  };
}

// Banned accounts are always refused. Pending accounts (invite-only sign-up,
// not yet redeemed) may reach the account API but not open sessions.
function checkStatus(user, allowPending) {
  if (user.status === "active") return;
  if (user.status === "pending" && allowPending) return;
  if (user.status === "pending") throw new AuthError(403, "account-pending");
  throw new AuthError(403, "account-suspended");
}

// Resolves the org a user acts in and their role there. `allowPending` is the
// account-API context (as opposed to opening a session): it lets pending
// users, suspended orgs and roles that cannot open sessions through, so they
// can still read their account.
// `requested` is an org the client named; it must be one the user belongs to
// (a missing org and a foreign org answer the same, so ids cannot be probed).
async function resolveOrg({ orgs, user, orgId, requested = null, allowPending }) {
  let org = null;
  if (requested) {
    org = await orgs.findById(requested);
    if (!org) throw new AuthError(403, "not-a-member");
  } else {
    if (orgId) org = await orgs.findById(orgId);
    if (!org) org = await orgs.ensurePersonalOrg(user.id);
  }
  if (!org) throw new AuthError(403, "no-organization");
  const role = (await orgs.getMembership(org.id, user.id))?.role || null;
  if (!role) throw new AuthError(403, "not-a-member");
  if (!allowPending) {
    if (org.status !== "active") throw new AuthError(403, "org-suspended");
    if (!roleAllows(role, "session.open")) throw new AuthError(403, "role-cannot-open-sessions");
  }
  return { org, role };
}

function createAuthenticator({ config, users, apiTokens, orgs, anon = null, jwt = null, log = null }) {
  return async function authenticate(token, { clientIP, allowPending = false, orgId: requestedOrg = null } = {}) {
    if (!token) {
      if (config.authRequired) throw new AuthError(401, "authentication-required");
      return LOCAL_IDENTITY;
    }

    if (parseApiToken(token)) {
      const result = await apiTokens.verify(token);
      if (!result) throw new AuthError(401, "invalid-token");
      if (!result.user) throw new AuthError(401, result.reason || "invalid-token");
      checkStatus(result.user, allowPending);
      // A token is bound to its org; naming another one is an error, not a switch.
      if (requestedOrg && requestedOrg !== result.orgId) throw new AuthError(403, "token-org-mismatch");
      const { org, role } = await resolveOrg({ orgs, user: result.user, orgId: result.orgId, allowPending });
      return { ...identityFor({ user: result.user, org, role, via: "api-token" }), tokenId: result.token.id };
    }

    let unverified;
    try {
      unverified = jose.decodeJwt(token);
    } catch (_error) {
      throw new AuthError(401, "invalid-token");
    }

    if (unverified.iss === ANON_ISSUER) {
      if (!anon || !config.anonEnabled) throw new AuthError(401, "anonymous-access-disabled");
      return anon.verify(token, { ip: clientIP });
    }

    if (jwt && unverified.iss === jwt.issuer) {
      const verified = await jwt.verify(token);
      const user = await users.upsertExternal({
        externalSub: `${verified.iss}|${verified.sub}`,
        username: verified.username,
        tier: config.jwt ? config.jwt.defaultTier : "user",
        status: config.signupMode === "invite" ? "pending" : "active",
      });
      checkStatus(user, allowPending);
      await users.touchLogin(user.id);
      const { org, role } = await resolveOrg({ orgs, user, orgId: user.default_org_id, requested: requestedOrg, allowPending });
      // The address is only offered for matching an org invite when the IdP
      // vouches for it (JWT_VERIFIED_CLAIM).
      return { ...identityFor({ user, org, role, via: "jwt" }), email: verified.email, emailVerified: verified.emailVerified };
    }

    log?.warn("token from unknown issuer", { issuer: unverified.iss, clientIP });
    throw new AuthError(401, "unknown-issuer");
  };
}

module.exports = {
  ANON_ISSUER,
  API_TOKEN_PREFIX,
  createAnonIssuer,
  rateKey,
  createApiTokenStore,
  createAuthenticator,
  createJwtVerifier,
  generateApiToken,
  hashToken,
  identityFor,
  parseApiToken,
  verifyTurnstile,
};
