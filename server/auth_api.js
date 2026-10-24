"use strict";

// Dashboard sign-in with relay accounts (USER_PASSWORD_LOGIN):
//
//   GET  /api/auth/config   which sign-in methods this relay offers
//   POST /api/auth/login    {username, password} -> {token, expiresAt, user}
//   POST /api/auth/logout   revokes the bearer session token
//   POST /api/auth/signup   {username, password, code?} (USER_SIGNUP)
//
// The token is a session token (auth/user_sessions.js): the dashboard sends
// it as a bearer token to /api/me and /api/orgs, and VMs can use it like any
// other credential, until it expires or the user signs out.

const { AuthError, extractCredential, readJsonBody, writeJson } = require("./public");
const { rateKey } = require("../auth/tokens");

const WINDOW_MS = 15 * 60 * 1000;
const FAILURES_PER_USERNAME = 10;
const FAILURES_PER_ADDRESS = 50;
const SIGNUPS_PER_ADDRESS = 10;
const MAX_TRACKED = 10000;

function createLimiter(limit, now) {
  const hits = new Map(); // key -> [timestamps]
  function recent(key) {
    const cutoff = now() - WINDOW_MS;
    const list = (hits.get(key) || []).filter((t) => t > cutoff);
    if (list.length) hits.set(key, list);
    else hits.delete(key);
    return list;
  }
  return {
    blocked: (key) => recent(key).length >= limit,
    add(key) {
      if (hits.size >= MAX_TRACKED) for (const k of [...hits.keys()]) recent(k);
      hits.set(key, [...recent(key), now()]);
    },
    clear: (key) => hits.delete(key),
  };
}

function createAuthApi({ config, users, userSessions, invites = null, ready = null, log = null, now = Date.now }) {
  const store = (ref) => (typeof ref === "function" ? ref() : ref);
  const byUsername = createLimiter(FAILURES_PER_USERNAME, now);
  const byAddress = createLimiter(FAILURES_PER_ADDRESS, now);
  const signups = createLimiter(SIGNUPS_PER_ADDRESS, now);

  const publicUser = (user) => ({ id: user.id, username: user.username, role: user.role, status: user.status });

  async function startSession(user) {
    const session = await store(userSessions).create(user.id);
    await store(users).touchLogin(user.id);
    return { token: session.token, expiresAt: session.expiresAt, user: publicUser(user) };
  }

  async function login(body, clientIP) {
    const username = typeof body.username === "string" ? body.username.trim() : "";
    const password = body.password;
    const nameKey = username.toLowerCase();
    const addressKey = rateKey(clientIP || "unknown");
    if (byUsername.blocked(nameKey) || byAddress.blocked(addressKey)) {
      return [429, { error: "too-many-attempts" }];
    }
    const userStore = store(users);
    const user = username ? await userStore.findByUsername(username) : null;
    // Operators sign in to the dashboard with a password only where the
    // operator panel allows passwords too (ADMIN_PASSWORD_LOGIN).
    const eligible = Boolean(user && (user.role !== "operator" || config.adminPasswordLogin));
    // Always compare, so timing does not reveal which usernames exist.
    const valid = await userStore.verifyPassword(eligible ? user : null, password);
    if (!eligible || !valid) {
      byUsername.add(nameKey);
      byAddress.add(addressKey);
      log?.warn("password sign-in failed", { clientIP });
      return [401, { error: "invalid-credentials" }];
    }
    if (user.status === "banned") return [403, { error: "account-suspended" }];
    byUsername.clear(nameKey);
    log?.info("password sign-in", { userId: user.id });
    return [200, await startSession(user)];
  }

  async function signup(body, clientIP) {
    if (!config.userSignup) return [404, { error: "sign-up is disabled" }];
    const addressKey = rateKey(clientIP || "unknown");
    if (signups.blocked(addressKey)) return [429, { error: "too-many-attempts" }];
    signups.add(addressKey);
    const username = typeof body.username === "string" ? body.username.trim() : "";
    const invite = config.signupMode === "invite";
    const inviteStore = store(invites);
    if (invite && (!inviteStore || typeof body.code !== "string" || !body.code.trim())) {
      return [400, { error: "invite-code-required" }];
    }
    const userStore = store(users);
    if (await userStore.findByUsername(username)) return [409, { error: "username-taken" }];
    let user;
    try {
      user = await userStore.create({ username, password: body.password, status: invite ? "pending" : "active" });
    } catch (error) {
      if (error instanceof RangeError) return [400, { error: error.message }];
      if (/UNIQUE/.test(String(error && error.message))) return [409, { error: "username-taken" }];
      throw error;
    }
    if (invite) {
      if (!(await inviteStore.redeem(body.code, user.id))) {
        await userStore.removeAccount(user.id);
        return [400, { error: "invalid, used or expired invite code" }];
      }
      await userStore.activatePending(user.id);
      user = await userStore.findById(user.id);
    }
    log?.info("account created by sign-up", { userId: user.id, invite });
    return [201, await startSession(user)];
  }

  function matches(path) {
    return path === "/api/auth" || path.startsWith("/api/auth/");
  }

  async function handle(req, res, { path, clientIP, corsHeaders = {} }) {
    if (!matches(path)) return false;
    try {
      if (ready) await ready;
      if (path === "/api/auth/config" && req.method === "GET") {
        writeJson(res, 200, {
          passwordLogin: config.userPasswordLogin,
          signup: config.userPasswordLogin && config.userSignup ? config.signupMode : null,
          oidc: config.jwt ? { issuer: config.jwt.issuer, audience: config.jwt.audience } : null,
        }, corsHeaders);
        return true;
      }
      if (!config.userPasswordLogin) {
        writeJson(res, 404, { error: "password sign-in is disabled" }, corsHeaders);
        return true;
      }
      if (req.method !== "POST" || !["/api/auth/login", "/api/auth/logout", "/api/auth/signup"].includes(path)) {
        writeJson(res, 404, { error: "not found" }, corsHeaders);
        return true;
      }
      if (path === "/api/auth/logout") {
        const credential = extractCredential(req);
        if (credential && credential.source === "header") await store(userSessions).revoke(credential.token);
        res.writeHead(204, { "Cache-Control": "no-store", ...corsHeaders });
        res.end();
        return true;
      }
      const body = await readJsonBody(req);
      const [status, payload] = path === "/api/auth/login" ? await login(body, clientIP) : await signup(body, clientIP);
      writeJson(res, status, payload, corsHeaders);
    } catch (error) {
      const status = error instanceof AuthError || error.status ? error.status : 500;
      if (status >= 500) log?.error("auth api error", { error, stack: error && error.stack, path });
      writeJson(res, status, { error: status >= 500 ? "internal-error" : error.code || error.message }, corsHeaders);
    }
    return true;
  }

  return { handle, matches };
}

module.exports = { FAILURES_PER_ADDRESS, FAILURES_PER_USERNAME, createAuthApi };
