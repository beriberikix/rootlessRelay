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
const { publicUser } = require("../auth/users");

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
        if (!user || user.role !== "operator" || user.status !== "active" ||
          !(await users.verifyPassword(user, password))) {
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

  app.use(express.json({ limit: "64kb" }));
  app.use(express.urlencoded({ extended: false }));
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
        sameSite: "strict",
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

  app.get("/api/auth/status", (req, res) => {
    const authenticated = req.isAuthenticated && req.isAuthenticated();
    if (!authenticated) {
      res.status(200).json({ authenticated: false });
      return;
    }
    res.status(200).json({ authenticated: true, username: req.user.username });
  });

  app.post("/api/login", (req, res, next) => {
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
    log?.info("api token revoked", { tokenId: id, by: req.user.username });
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
    if (status === "banned" && registry) killed = registry.killOwner(`user:${id}`, 1008, "account suspended");
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
    const killed = registry ? registry.killOwner(`user:${id}`, 1008, "account deleted") : 0;
    await users.remove(id);
    log?.info("user deleted", { userId: id, username: user.username, killedSessions: killed, by: req.user.username });
    res.sendStatus(204);
  }));

  app.post("/api/users/:id/ban", asyncRoute((req, res) => setUserStatus(req, res, "banned")));
  app.post("/api/users/:id/unban", asyncRoute((req, res) => setUserStatus(req, res, "active")));

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
    const rows = await audit.query({
      owner: req.query.owner || null,
      sessionId: req.query.sessionId || null,
      verdict: req.query.verdict || null,
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
        ? await usage.periodUsage({ identity: { userId: id, tier: user.tier, owner: `user:${id}` }, clientIP: null })
        : null,
      months: usage ? await usage.monthly(id) : [],
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
