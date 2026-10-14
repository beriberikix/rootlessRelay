"use strict";

// Credentials for the data plane: per-user API tokens, short-lived anonymous
// tokens, external OIDC JWTs, and the authenticator that maps any of them to
// an Identity { kind, owner, tier, userId?, username? }.

const crypto = require("crypto");
const jose = require("jose");
const { AuthError, LOCAL_IDENTITY } = require("../server/public");

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
    async create({ userId, name = "default", expiresAt = null }) {
      const generated = generateApiToken(randomBytes);
      const result = await db.run(
        "INSERT INTO api_tokens (user_id, name, token_prefix, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        [userId, String(name).slice(0, 64), generated.prefix, generated.hash, new Date(now()).toISOString(), expiresAt],
      );
      return { id: result.lastID, token: generated.token, prefix: generated.prefix, name, expiresAt };
    },

    // Returns { token, user } or null. Lookup by the public prefix, then a
    // constant-time comparison of the secret's hash.
    async verify(token) {
      const parsed = parseApiToken(token);
      if (!parsed) return null;
      const rows = await db.all(
        "SELECT t.*, u.id AS u_id, u.username AS u_username, u.role AS u_role, u.tier AS u_tier, u.status AS u_status " +
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
          user: { id: row.u_id, username: row.u_username, role: row.u_role, tier: row.u_tier, status: row.u_status },
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

function ipHash(ip, secret) {
  return crypto.createHmac("sha256", secret).update(String(ip)).digest("hex").slice(0, 16);
}

// Anonymous demo tokens: HS256 JWTs bound (optionally) to the requesting IP
// and rate-limited per IP so a single client cannot mint unbounded identities.
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
  const issued = new Map(); // ip -> timestamps

  function prune(ip, current) {
    const list = (issued.get(ip) || []).filter((ts) => current - ts < 60 * 60 * 1000);
    if (list.length === 0) issued.delete(ip);
    else issued.set(ip, list);
    return list;
  }

  return {
    async issue({ ip }) {
      const current = now();
      const recent = prune(ip, current);
      if (recent.length >= perIpPerHour) {
        throw new AuthError(429, "anon-token-rate-limited");
      }
      recent.push(current);
      issued.set(ip, recent);
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
      return { iss: payload.iss, sub: payload.sub, username, claims: payload };
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

function identityForUser(user, via = null) {
  return {
    kind: user.role === "operator" ? "operator" : "user",
    owner: `user:${user.id}`,
    userId: user.id,
    username: user.username,
    tier: user.tier || (user.role === "operator" ? "operator" : "user"),
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

function createAuthenticator({ config, users, apiTokens, anon = null, jwt = null, log = null }) {
  return async function authenticate(token, { clientIP, allowPending = false } = {}) {
    if (!token) {
      if (config.authRequired) throw new AuthError(401, "authentication-required");
      return LOCAL_IDENTITY;
    }

    if (parseApiToken(token)) {
      const result = await apiTokens.verify(token);
      if (!result) throw new AuthError(401, "invalid-token");
      if (!result.user) throw new AuthError(401, result.reason || "invalid-token");
      checkStatus(result.user, allowPending);
      return { ...identityForUser(result.user, "api-token"), tokenId: result.token.id };
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
      return identityForUser(user, "jwt");
    }

    log?.warn("token from unknown issuer", { issuer: unverified.iss, clientIP });
    throw new AuthError(401, "unknown-issuer");
  };
}

module.exports = {
  ANON_ISSUER,
  API_TOKEN_PREFIX,
  createAnonIssuer,
  createApiTokenStore,
  createAuthenticator,
  createJwtVerifier,
  generateApiToken,
  hashToken,
  identityForUser,
  parseApiToken,
  verifyTurnstile,
};
