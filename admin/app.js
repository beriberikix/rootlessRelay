"use strict";

// Operator admin API and UI. Operators log in with username/password via
// Passport; sessions persist in SQLite. End users, API tokens, inbound rules,
// live sessions and configuration are managed here.

const http = require("http");
const path = require("path");
const express = require("express");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const expressSession = require("express-session");
const { validateRule } = require("./rules");
const { createOidcLogin } = require("./oidc");
const { publicUser } = require("../auth/users");
const { OrgError, ROLES, publicOrg } = require("../auth/orgs");

async function bootstrapOperator({ users, config, log }) {
  if ((await users.countOperators()) > 0) return;
  if (config.adminBootstrapUsername && config.adminBootstrapPassword) {
    await users.create({
      username: config.adminBootstrapUsername,
      password: config.adminBootstrapPassword,
      role: "operator",
    });
    log?.info("bootstrapped initial operator", { username: config.adminBootstrapUsername });
    return;
  }
  // Keep the data plane running; admin logins fail until an operator exists.
  log?.warn(
    "no operator accounts found; set ADMIN_BOOTSTRAP_USERNAME and ADMIN_BOOTSTRAP_PASSWORD to create one",
  );
}

function configurePassport({ users }) {
  passport.use(
    new LocalStrategy(async (username, password, done) => {
      try {
        const user = await users.findByUsername(username);
        const eligible = Boolean(user && user.role === "operator" && user.status === "active");
        // Always compare, so the response time does not tell which
        // usernames are operators.
        const valid = await users.verifyPassword(eligible ? user : null, password);
        if (!eligible || !valid) {
          done(null, false, { message: "Invalid username or password" });
          return;
        }
        await users.touchLogin(user.id);
        done(null, { id: user.id, username: user.username, role: user.role });
      } catch (error) {
        done(error);
      }
    }),
  );
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await users.findById(id);
      if (!user || user.role !== "operator" || user.status !== "active") {
        done(null, false);
        return;
      }
      done(null, { id: user.id, username: user.username, role: user.role });
    } catch (error) {
      done(error);
    }
  });
}

function createLoginRateLimiter({ windowMs, maxAttempts, now = Date.now }) {
  const attempts = new Map();
  function key(req, username) {
    return `${req.ip || req.socket.remoteAddress || "unknown"}:${username || "unknown"}`;
  }
  function cleanup(current) {
    for (const [k, attempt] of attempts) {
      if (current - attempt.firstAttemptAt > windowMs) attempts.delete(k);
    }
  }
  return {
    isLimited(req, username) {
      const current = now();
      cleanup(current);
      const attempt = attempts.get(key(req, username));
      return attempt ? attempt.count >= maxAttempts : false;
    },
    registerFailure(req, username) {
      const current = now();
      const k = key(req, username);
      const existing = attempts.get(k);
      if (!existing || current - existing.firstAttemptAt > windowMs) {
        attempts.set(k, { count: 1, firstAttemptAt: current });
      } else {
        existing.count += 1;
      }
    },
    clear(req, username) {
      attempts.delete(key(req, username));
    },
  };
}

function requireAdminAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) {
    next();
    return;
  }
  res.status(401).json({ error: "Unauthorized" });
}

function sessionSummary(sessionId, session) {
  const identity = session.identity || {};
  return {
    sessionId,
    clientIP: session.clientIP,
    vmIP: session.vmIP,
    vmMAC: session.vmMAC,
    bytesSent: session.bytesSent,
    bytesReceived: session.bytesReceived,
    udpFlowCount: session.udpFlows.size,
    udpDroppedPackets: session.udpFlows.droppedPackets,
    udpSendErrors: session.udpFlows.sendErrors,
    tcpConnections: session.tcpConnections.size,
    nickname: session.nickname,
    owner: identity.owner,
    tier: identity.tier,
    kind: identity.kind,
    userId: identity.userId || null,
    orgId: identity.orgId || null,
    username: identity.username || null,
    startedAt: session.startedAt ? new Date(session.startedAt).toISOString() : null,
    policy: session.policy ? session.policy.counters : null,
  };
}

function asyncRoute(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

function parseId(value) {
  const id = Number.parseInt(value, 10);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function createAdminApp({
  config,
  users,
  apiTokens,
  invites = null,
  orgs = null,
  orgInvites = null,
  sessionStore,
  activeSessions,
  registry,
  rules,
  proxyPort,
  poolCtx,
  tiers = null,
  audit = null,
  usage = null,
  metrics = null,
  adminHtmlPath = path.join(__dirname, "..", "admin.html"),
  log,
}) {
  const app = express();

  const loginLimiter = createLoginRateLimiter({
    windowMs: config.adminLoginWindowMs,
    maxAttempts: config.adminLoginMaxAttempts,
  });

  if (config.adminTrustProxy) app.set("trust proxy", 1);

  // CSRF: the panel only sends JSON via fetch, so form-encoded bodies are not
  // parsed, and a state-changing request that carries an Origin must come
  // from this host. (Behind `fly proxy` the operator uses localhost, where a
  // page on another local port is "same-site" and SameSite cookies alone do
  // not stop it.) Requests without Origin (CLI, tests) are not browsers.
  app.use(express.json({ limit: "64kb" }));
  app.use((req, res, next) => {
    if (["GET", "HEAD", "OPTIONS"].includes(req.method) || !req.headers.origin) {
      next();
      return;
    }
    let originHost = null;
    try {
      originHost = new URL(req.headers.origin).host;
    } catch (_error) {
      originHost = null;
    }
    if (originHost !== req.headers.host) {
      res.status(403).json({ error: "cross-origin request refused" });
      return;
    }
    next();
  });
  app.use(
    expressSession({
      name: "admin.sid",
      secret: config.adminSessionSecret,
      store: sessionStore,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        secure: config.adminCookieSecure,
        // Lax, not Strict: the OIDC callback is a top-level redirect from the
        // provider and must carry the session holding the login state.
        // Cross-site POSTs are refused by the Origin check below.
        sameSite: "lax",
        maxAge: 8 * 60 * 60 * 1000,
      },
    }),
  );
  app.use(passport.initialize());
  app.use(passport.session());

  // Prometheus scrape endpoint: operator session or METRICS_TOKEN bearer.
  // METRICS_PUBLIC=true skips auth for scrapers on a private network (e.g. a
  // platform scraper reaching the admin port over its internal network).
  app.get("/metrics", asyncRoute(async (req, res) => {
    if (!metrics || !metrics.enabled) {
      res.status(404).json({ error: "metrics are disabled" });
      return;
    }
    const authorization = req.headers.authorization || "";
    const bearer = /^bearer\s+/i.test(authorization) ? authorization.replace(/^bearer\s+/i, "").trim() : null;
    const tokenOk = config.metricsToken && bearer && bearer.length === config.metricsToken.length &&
      require("crypto").timingSafeEqual(Buffer.from(bearer), Buffer.from(config.metricsToken));
    const sessionOk = req.isAuthenticated && req.isAuthenticated();
    if (!config.metricsPublic && !tokenOk && !sessionOk) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }
    res.set("Content-Type", metrics.contentType);
    res.status(200).send(await metrics.render());
  }));

  app.get("/", (_req, res) => {
    res.sendFile(adminHtmlPath);
  });

  if (config.adminOidc) {
    createOidcLogin({ ...config.adminOidc, users, log }).mount(app);
  }

  app.get("/api/auth/status", (req, res) => {
    const authenticated = req.isAuthenticated && req.isAuthenticated();
    if (!authenticated) {
      res.status(200).json({ authenticated: false, oidc: Boolean(config.adminOidc), passwordLogin: config.adminPasswordLogin });
      return;
    }
    res.status(200).json({ authenticated: true, username: req.user.username });
  });

  app.post("/api/login", (req, res, next) => {
    if (!config.adminPasswordLogin) {
      res.status(403).json({ error: "Password sign-in is disabled; use single sign-on." });
      return;
    }
    const username = typeof req.body.username === "string" ? req.body.username.trim() : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";
    if (!username || !password) {
      res.status(400).json({ error: "Username and password are required" });
      return;
    }
    if (loginLimiter.isLimited(req, username)) {
      res.status(429).json({ error: "Too many failed login attempts. Please try again later." });
      return;
    }
    passport.authenticate("local", (err, user) => {
      if (err) {
        next(err);
        return;
      }
      if (!user) {
        loginLimiter.registerFailure(req, username);
        res.status(401).json({ error: "Invalid username or password" });
        return;
      }
      req.logIn(user, (loginErr) => {
        if (loginErr) {
          next(loginErr);
          return;
        }
        loginLimiter.clear(req, username);
        res.status(200).json({ ok: true, username: user.username });
      });
    })(req, res, next);
  });

  app.post("/api/logout", (req, res, next) => {
    req.logout((logoutErr) => {
      if (logoutErr) {
        next(logoutErr);
        return;
      }
      req.session.destroy((destroyErr) => {
        if (destroyErr) {
          next(destroyErr);
          return;
        }
        res.clearCookie("admin.sid");
        res.status(200).json({ ok: true });
      });
    });
  });

  app.use("/api", requireAdminAuth);

  app.get("/api/config", (_req, res) => {
    res.status(200).json({
      mode: config.mode,
      inboundRulesEnabled: config.inboundRulesEnabled,
      proxyPort,
      authRequired: config.authRequired,
      anonEnabled: config.anonEnabled,
      signupMode: config.signupMode,
      externalJwt: Boolean(config.jwt),
      tiers: tiers ? Object.keys(tiers) : [],
    });
  });

  // --- live sessions -------------------------------------------------------

  app.get("/api/sessions", (_req, res) => {
    const sessions = [];
    activeSessions.forEach((session, sessionId) => {
      sessions.push(sessionSummary(sessionId, session));
    });
    res.status(200).json(sessions);
  });

  app.post("/api/sessions/:sessionId/nickname", (req, res) => {
    const session = activeSessions.get(req.params.sessionId);
    if (!session) {
      res.sendStatus(404);
      return;
    }
    const nickname = typeof req.body.nickname === "string" ? req.body.nickname.trim().slice(0, 64) : "";
    session.nickname = nickname || undefined;
    res.sendStatus(200);
  });

  app.delete("/api/sessions/:sessionId/nickname", (req, res) => {
    const session = activeSessions.get(req.params.sessionId);
    if (!session) {
      res.sendStatus(404);
      return;
    }
    session.nickname = undefined;
    res.sendStatus(204);
  });

  app.delete("/api/sessions/:sessionId", (req, res) => {
    if (!registry || !registry.kill(req.params.sessionId, 1008, "terminated by operator")) {
      res.sendStatus(404);
      return;
    }
    log?.info("session killed by operator", { sessionId: req.params.sessionId, by: req.user.username });
    res.sendStatus(204);
  });

  // --- users and API tokens -------------------------------------------------

  app.get("/api/users", asyncRoute(async (_req, res) => {
    res.status(200).json(await users.list());
  }));

  app.post("/api/users", asyncRoute(async (req, res) => {
    const { username, password, role, tier } = req.body || {};
    if (tier !== undefined && tier !== null && tier !== "" && unknownTier(tier)) {
      res.status(400).json({ error: unknownTier(tier) });
      return;
    }
    try {
      const user = await users.create({
        username,
        password: password === undefined || password === "" ? null : password,
        role: role || "user",
        tier: tier || null,
      });
      log?.info("user created", { userId: user.id, username: user.username, role: user.role, by: req.user.username });
      res.status(201).json(publicUser(user));
    } catch (error) {
      if (error instanceof RangeError) {
        res.status(400).json({ error: error.message });
        return;
      }
      if (/UNIQUE/.test(error.message)) {
        res.status(409).json({ error: "username already exists" });
        return;
      }
      throw error;
    }
  }));

  app.get("/api/users/:id", asyncRoute(async (req, res) => {
    const id = parseId(req.params.id);
    const user = id ? await users.findById(id) : null;
    if (!user) {
      res.sendStatus(404);
      return;
    }
    res.status(200).json({ ...publicUser(user), tokens: await apiTokens.listForUser(id) });
  }));

  app.post("/api/users/:id/tokens", asyncRoute(async (req, res) => {
    const id = parseId(req.params.id);
    const user = id ? await users.findById(id) : null;
    if (!user) {
      res.sendStatus(404);
      return;
    }
    const { name, expiresAt } = req.body || {};
    if (expiresAt !== undefined && expiresAt !== null && Number.isNaN(new Date(expiresAt).getTime())) {
      res.status(400).json({ error: "expiresAt must be an ISO timestamp" });
      return;
    }
    const created = await apiTokens.create({
      userId: id,
      name: typeof name === "string" && name ? name : "default",
      expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
    });
    log?.info("api token created", { userId: id, tokenId: created.id, by: req.user.username });
    res.status(201).json(created);
  }));

  app.delete("/api/tokens/:id", asyncRoute(async (req, res) => {
    const id = parseId(req.params.id);
    if (!id || !(await apiTokens.revoke(id))) {
      res.sendStatus(404);
      return;
    }
    const killed = registry && registry.killToken ? registry.killToken(id, 1008, "token revoked") : 0;
    log?.info("api token revoked", { tokenId: id, killedSessions: killed, by: req.user.username });
    res.sendStatus(204);
  }));

  async function setUserStatus(req, res, status) {
    const id = parseId(req.params.id);
    const user = id ? await users.findById(id) : null;
    if (!user) {
      res.sendStatus(404);
      return;
    }
    if (status === "banned" && user.id === req.user.id) {
      res.status(400).json({ error: "cannot ban yourself" });
      return;
    }
    await users.setStatus(id, status);
    let killed = 0;
    if (status === "banned" && registry) killed = registry.killUser(id, 1008, "account suspended");
    log?.info("user status changed", { userId: id, status, killedSessions: killed, by: req.user.username });
    res.status(200).json({ ...publicUser(await users.findById(id)), killedSessions: killed });
  }

  app.delete("/api/users/:id", asyncRoute(async (req, res) => {
    const id = parseId(req.params.id);
    const user = id ? await users.findById(id) : null;
    if (!user) {
      res.sendStatus(404);
      return;
    }
    if (user.id === req.user.id) {
      res.status(400).json({ error: "cannot delete yourself" });
      return;
    }
    try {
      await users.removeAccount(id);
    } catch (error) {
      if (error.status === 409) {
        res.status(409).json({ error: error.code });
        return;
      }
      throw error;
    }
    const killed = registry ? registry.killUser(id, 1008, "account deleted") : 0;
    log?.info("user deleted", { userId: id, username: user.username, killedSessions: killed, by: req.user.username });
    res.sendStatus(204);
  }));

  app.post("/api/users/:id/ban", asyncRoute((req, res) => setUserStatus(req, res, "banned")));
  app.post("/api/users/:id/unban", asyncRoute((req, res) => setUserStatus(req, res, "active")));
  app.post("/api/users/:id/activate", asyncRoute((req, res) => setUserStatus(req, res, "active")));

  // --- invite codes (SIGNUP_MODE=invite) ---------------------------------------

  app.get("/api/invites", asyncRoute(async (_req, res) => {
    res.status(200).json(invites ? await invites.list() : []);
  }));

  app.post("/api/invites", asyncRoute(async (req, res) => {
    if (!invites) {
      res.sendStatus(404);
      return;
    }
    const { note, expiresInDays } = req.body || {};
    let expiresAt = null;
    if (expiresInDays !== undefined && expiresInDays !== null && expiresInDays !== "") {
      const days = Number(expiresInDays);
      if (!Number.isFinite(days) || days <= 0 || days > 365) {
        res.status(400).json({ error: "expiresInDays must be between 1 and 365" });
        return;
      }
      expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
    }
    const created = await invites.create({ createdBy: req.user.id, note, expiresAt });
    log?.info("invite created", { inviteId: created.id, by: req.user.username });
    res.status(201).json(created);
  }));

  app.delete("/api/invites/:id", asyncRoute(async (req, res) => {
    const id = parseId(req.params.id);
    if (!invites || !id || !(await invites.revoke(id))) {
      res.sendStatus(404);
      return;
    }
    log?.info("invite revoked", { inviteId: id, by: req.user.username });
    res.sendStatus(204);
  }));

  app.post("/api/users/:id/role", asyncRoute(async (req, res) => {
    const id = parseId(req.params.id);
    const role = req.body && req.body.role;
    if (!id || !(await users.findById(id))) {
      res.sendStatus(404);
      return;
    }
    if (id === req.user.id && role !== "operator") {
      res.status(400).json({ error: "cannot remove your own operator role" });
      return;
    }
    try {
      await users.setRole(id, role);
    } catch (error) {
      if (error instanceof RangeError) {
        res.status(400).json({ error: error.message });
        return;
      }
      throw error;
    }
    log?.info("user role changed", { userId: id, role, by: req.user.username });
    res.status(200).json(publicUser(await users.findById(id)));
  }));

  app.post("/api/users/:id/tier", asyncRoute(async (req, res) => {
    const id = parseId(req.params.id);
    const tier = req.body && req.body.tier;
    if (!id || !(await users.findById(id))) {
      res.sendStatus(404);
      return;
    }
    if (tiers && !tiers[tier]) {
      res.status(400).json({ error: `unknown tier; known tiers: ${Object.keys(tiers).join(", ")}` });
      return;
    }
    await users.setTier(id, tier);
    res.status(200).json(publicUser(await users.findById(id)));
  }));

  app.post("/api/users/:id/password", asyncRoute(async (req, res) => {
    const id = parseId(req.params.id);
    if (!id || !(await users.findById(id))) {
      res.sendStatus(404);
      return;
    }
    try {
      await users.setPassword(id, req.body && req.body.password);
    } catch (error) {
      if (error instanceof RangeError) {
        res.status(400).json({ error: error.message });
        return;
      }
      throw error;
    }
    res.sendStatus(204);
  }));

  // --- audit log and usage --------------------------------------------------

  // ---- organizations ------------------------------------------------------
  // Operators act as owners of every org. Shared orgs are created here during
  // the beta; the public API only lets members manage their own org.

  const operatorActor = (req) => ({ userId: req.user.id, operator: true });
  const orgOwner = (id) => `org:${id}`;

  function liveSessionCount(orgId) {
    let count = 0;
    if (activeSessions) {
      activeSessions.forEach((session) => {
        if (session.identity && session.identity.owner === orgOwner(orgId)) count += 1;
      });
    }
    return count;
  }

  // Answers store errors as the HTTP statuses they carry; true when handled.
  function orgFailure(res, error) {
    if (error instanceof OrgError) {
      res.status(error.status).json({ error: error.code });
      return true;
    }
    if (error instanceof RangeError) {
      res.status(400).json({ error: error.message });
      return true;
    }
    return false;
  }

  async function findOrg(req, res) {
    const id = parseId(req.params.id);
    const org = orgs && id ? await orgs.findById(id) : null;
    if (!org) {
      res.sendStatus(404);
      return null;
    }
    return org;
  }

  function unknownTier(tier) {
    return tiers && !tiers[tier] ? `unknown tier; known tiers: ${Object.keys(tiers).join(", ")}` : null;
  }

  app.get("/api/orgs", asyncRoute(async (_req, res) => {
    if (!orgs) {
      res.status(200).json([]);
      return;
    }
    const list = await orgs.listWithCounts();
    res.status(200).json(list.map((org) => ({ ...org, sessions: liveSessionCount(org.id) })));
  }));

  app.post("/api/orgs", asyncRoute(async (req, res) => {
    const { name, ownerUserId, tier } = req.body || {};
    const owner = orgs && parseId(ownerUserId) ? await users.findById(parseId(ownerUserId)) : null;
    if (!owner) {
      res.status(400).json({ error: "ownerUserId must be an existing user" });
      return;
    }
    if (tier !== undefined && unknownTier(tier)) {
      res.status(400).json({ error: unknownTier(tier) });
      return;
    }
    try {
      const org = await orgs.create({ name, ownerUserId: owner.id, tier: tier || "user" });
      log?.info("org created", { orgId: org.id, ownerUserId: owner.id, by: req.user.username });
      res.status(201).json(publicOrg(org));
    } catch (error) {
      if (!orgFailure(res, error)) throw error;
    }
  }));

  app.get("/api/orgs/:id", asyncRoute(async (req, res) => {
    const org = await findOrg(req, res);
    if (!org) return;
    res.status(200).json({
      ...publicOrg(org),
      sessions: liveSessionCount(org.id),
      members: await orgs.listMembers(org.id),
      tokens: await apiTokens.listForOrg(org.id),
      invites: orgInvites ? await orgInvites.list(org.id) : [],
    });
  }));

  app.post("/api/orgs/:id/tier", asyncRoute(async (req, res) => {
    const org = await findOrg(req, res);
    if (!org) return;
    const tier = req.body && req.body.tier;
    if (typeof tier !== "string" || unknownTier(tier)) {
      res.status(400).json({ error: unknownTier(tier) || "tier is required" });
      return;
    }
    await orgs.setTier(org.id, tier);
    log?.info("org tier changed", { orgId: org.id, tier, by: req.user.username });
    res.status(200).json(publicOrg(await orgs.findById(org.id)));
  }));

  async function setOrgStatus(req, res, status) {
    const org = await findOrg(req, res);
    if (!org) return;
    await orgs.setStatus(org.id, status);
    let killed = 0;
    if (status === "suspended" && registry) killed = registry.killOwner(orgOwner(org.id), 1008, "organization suspended");
    log?.info("org status changed", { orgId: org.id, status, killedSessions: killed, by: req.user.username });
    res.status(200).json({ ...publicOrg(await orgs.findById(org.id)), killedSessions: killed });
  }
  app.post("/api/orgs/:id/suspend", asyncRoute((req, res) => setOrgStatus(req, res, "suspended")));
  app.post("/api/orgs/:id/unsuspend", asyncRoute((req, res) => setOrgStatus(req, res, "active")));

  app.delete("/api/orgs/:id", asyncRoute(async (req, res) => {
    const org = await findOrg(req, res);
    if (!org) return;
    try {
      await orgs.remove(org.id);
    } catch (error) {
      if (!orgFailure(res, error)) throw error;
      return;
    }
    const killed = registry ? registry.killOwner(orgOwner(org.id), 1008, "organization deleted") : 0;
    log?.info("org deleted", { orgId: org.id, killedSessions: killed, by: req.user.username });
    res.sendStatus(204);
  }));

  app.post("/api/orgs/:id/members", asyncRoute(async (req, res) => {
    const org = await findOrg(req, res);
    if (!org) return;
    const { userId, role } = req.body || {};
    const user = parseId(userId) ? await users.findById(parseId(userId)) : null;
    if (!user) {
      res.status(400).json({ error: "userId must be an existing user" });
      return;
    }
    if (!ROLES.includes(role)) {
      res.status(400).json({ error: `role must be one of ${ROLES.join(", ")}` });
      return;
    }
    try {
      res.status(201).json(await orgs.addMember({ orgId: org.id, userId: user.id, role }));
    } catch (error) {
      if (!orgFailure(res, error)) throw error;
    }
  }));

  app.post("/api/orgs/:id/members/:userId/role", asyncRoute(async (req, res) => {
    const org = await findOrg(req, res);
    if (!org) return;
    const userId = parseId(req.params.userId);
    const role = req.body && req.body.role;
    if (!ROLES.includes(role)) {
      res.status(400).json({ error: `role must be one of ${ROLES.join(", ")}` });
      return;
    }
    try {
      const result = await orgs.setMemberRole({ orgId: org.id, actor: operatorActor(req), userId, role });
      // Roles that cannot open sessions end the member's live ones.
      if (!["owner", "admin", "member"].includes(role) && registry && registry.killMember) {
        registry.killMember(orgOwner(org.id), userId, 1008, "role changed");
      }
      log?.info("org role changed", { orgId: org.id, userId, role, by: req.user.username });
      res.status(200).json(result);
    } catch (error) {
      if (!orgFailure(res, error)) throw error;
    }
  }));

  app.delete("/api/orgs/:id/members/:userId", asyncRoute(async (req, res) => {
    const org = await findOrg(req, res);
    if (!org) return;
    const userId = parseId(req.params.userId);
    try {
      await orgs.removeMember({ orgId: org.id, actor: operatorActor(req), userId });
    } catch (error) {
      if (!orgFailure(res, error)) throw error;
      return;
    }
    const killed = registry && registry.killMember ? registry.killMember(orgOwner(org.id), userId, 1008, "removed from organization") : 0;
    log?.info("org member removed", { orgId: org.id, userId, killedSessions: killed, by: req.user.username });
    res.sendStatus(204);
  }));

  app.get("/api/audit", asyncRoute(async (req, res) => {
    if (!audit || !audit.enabled) {
      res.status(200).json({ enabled: false, rows: [] });
      return;
    }
    const since = req.query.since ? new Date(req.query.since).getTime() : null;
    const until = req.query.until ? new Date(req.query.until).getTime() : null;
    if ((since !== null && Number.isNaN(since)) || (until !== null && Number.isNaN(until))) {
      res.status(400).json({ error: "since/until must be ISO timestamps" });
      return;
    }
    const at = req.query.at ? new Date(req.query.at).getTime() : null;
    const windowMinutes = req.query.windowMinutes ? Number(req.query.windowMinutes) : 5;
    const dstPort = req.query.dstPort ? Number(req.query.dstPort) : null;
    if ((at !== null && Number.isNaN(at)) || !(windowMinutes >= 0 && windowMinutes <= 1440)
      || (dstPort !== null && !(Number.isInteger(dstPort) && dstPort > 0 && dstPort < 65536))) {
      res.status(400).json({ error: "at must be an ISO timestamp, windowMinutes 0-1440, dstPort 1-65535" });
      return;
    }
    const userId = req.query.userId ? parseId(req.query.userId) : null;
    if (req.query.userId && !userId) {
      res.status(400).json({ error: "userId must be a positive integer" });
      return;
    }
    const rows = await audit.query({
      owner: req.query.owner || null,
      userId,
      sessionId: req.query.sessionId || null,
      verdict: req.query.verdict || null,
      dstIP: req.query.dstIp || null,
      dstPort,
      at,
      windowMs: windowMinutes * 60 * 1000,
      since,
      until,
      limit: req.query.limit ? Number(req.query.limit) : 200,
    });
    res.status(200).json({ enabled: true, rows });
  }));

  app.get("/api/usage/:id", asyncRoute(async (req, res) => {
    const id = parseId(req.params.id);
    const user = id ? await users.findById(id) : null;
    if (!user) {
      res.sendStatus(404);
      return;
    }
    const tier = tiers ? tiers[user.tier] || tiers.user : null;
    res.status(200).json({
      userId: id,
      tier: user.tier,
      quotaBytes: tier ? tier.quotaBytes : null,
      quotaPeriod: tier ? tier.quotaPeriod : null,
      currentPeriodBytes: usage
        ? await usage.periodUsage({ identity: { orgId: user.default_org_id, tier: user.tier, owner: `org:${user.default_org_id}` }, clientIP: null })
        : null,
      months: usage ? await usage.monthly(user.default_org_id) : [],
    });
  }));

  // --- inbound rules --------------------------------------------------------

  function requireRules(_req, res, next) {
    if (!config.inboundRulesEnabled) {
      res.status(403).json({ error: "Inbound rules are disabled on this relay" });
      return;
    }
    next();
  }

  app.get("/api/rules", requireRules, (_req, res) => {
    res.status(200).json(rules.proxyRules);
  });

  let nextRuleId = 1;
  app.post("/api/rules", requireRules, (req, res) => {
    const verdict = validateRule(req.body, { ...poolCtx, existingRules: rules.proxyRules });
    if (!verdict.ok) {
      res.status(400).json({ error: verdict.error });
      return;
    }
    const rule = verdict.rule;
    rule.id = nextRuleId++;
    rules.proxyRules.push(rule);
    if (rule.type === "port") rules.startPortForward(rule);
    log?.info("inbound rule added", { ruleId: rule.id, type: rule.type, by: req.user.username });
    res.status(201).json(rule);
  });

  app.delete("/api/rules/:id", requireRules, (req, res) => {
    const id = Number.parseInt(req.params.id, 10);
    const index = rules.proxyRules.findIndex((rule) => rule.id === id);
    if (index === -1) {
      res.sendStatus(404);
      return;
    }
    const rule = rules.proxyRules[index];
    if (rule.type === "port") {
      rules.stopPortForward(rule);
    } else {
      rules.stopTcpForward(rule.id);
      rules.stopUdpForward(rule.id);
    }
    rules.proxyRules.splice(index, 1);
    log?.info("inbound rule removed", { ruleId: id, by: req.user.username });
    res.sendStatus(204);
  });

  app.use((err, _req, res, _next) => {
    log?.error("admin api error", { error: err });
    res.status(500).json({ error: "Internal server error" });
  });

  return app;
}

function startAdminServer(app, { port, host, log }) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      log?.info("admin ui listening", { url: `http://${host}:${server.address().port}` });
      resolve(server);
    });
  });
}

module.exports = {
  bootstrapOperator,
  configurePassport,
  createAdminApp,
  createLoginRateLimiter,
  requireAdminAuth,
  sessionSummary,
  startAdminServer,
};
