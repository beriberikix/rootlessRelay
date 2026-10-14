"use strict";

// Operator admin API and UI (moved out of relay.js). Local username/password
// auth with Passport and SQLite; sessions, inbound rules and configuration.

const http = require("http");
const path = require("path");
const express = require("express");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const expressSession = require("express-session");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3");
const { validateRule } = require("./rules");

function openDatabase(dbPath) {
  const db = new sqlite3.Database(dbPath);
  return {
    raw: db,
    run(sql, params = []) {
      return new Promise((resolve, reject) => {
        db.run(sql, params, function onRun(err) {
          if (err) reject(err);
          else resolve(this);
        });
      });
    },
    get(sql, params = []) {
      return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
      });
    },
    all(sql, params = []) {
      return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
      });
    },
    close() {
      return new Promise((resolve) => db.close(() => resolve()));
    },
  };
}

async function initializeAdminAuth({ db, config, log }) {
  await db.run(`
    CREATE TABLE IF NOT EXISTS admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      last_login_at TEXT
    )
  `);

  const countRow = await db.get("SELECT COUNT(*) AS count FROM admin_users");
  if (countRow.count === 0) {
    if (config.adminBootstrapUsername && config.adminBootstrapPassword) {
      const passwordHash = await bcrypt.hash(config.adminBootstrapPassword, 12);
      await db.run(
        "INSERT INTO admin_users (username, password_hash, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
        [config.adminBootstrapUsername, passwordHash],
      );
      log?.info("bootstrapped initial admin user", { username: config.adminBootstrapUsername });
    } else {
      // Keep the data plane running; admin logins fail until a user exists.
      log?.warn(
        "no admin users found; set ADMIN_BOOTSTRAP_USERNAME and ADMIN_BOOTSTRAP_PASSWORD to create one",
      );
    }
  }

  passport.use(
    new LocalStrategy(async (username, password, done) => {
      try {
        const user = await db.get(
          "SELECT id, username, password_hash FROM admin_users WHERE username = ?",
          [username],
        );
        if (!user) {
          done(null, false, { message: "Invalid username or password" });
          return;
        }
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
          done(null, false, { message: "Invalid username or password" });
          return;
        }
        await db.run("UPDATE admin_users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", [user.id]);
        done(null, { id: user.id, username: user.username });
      } catch (error) {
        done(error);
      }
    }),
  );

  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await db.get("SELECT id, username FROM admin_users WHERE id = ?", [id]);
      done(null, user || false);
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
    username: identity.username || null,
    startedAt: session.startedAt ? new Date(session.startedAt).toISOString() : null,
    policy: session.policy ? session.policy.counters : null,
  };
}

function createAdminApp({
  config,
  db,
  activeSessions,
  registry,
  rules,
  proxyPort,
  poolCtx,
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
    });
  });

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
  createAdminApp,
  createLoginRateLimiter,
  initializeAdminAuth,
  openDatabase,
  requireAdminAuth,
  sessionSummary,
  startAdminServer,
};
