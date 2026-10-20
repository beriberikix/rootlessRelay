"use strict";

// Composition root for the hosted-mode modules. relay.js calls init() once
// with its configuration constants and shared state, then uses the returned
// helpers at its `// HOSTED:` hook points. In local mode (the default) the
// observable behavior matches upstream rootlessRelay.

const fs = require("fs");
const path = require("path");
const { resolveConfig } = require("./config");
const { createLogger } = require("./log");
const { createEgressPolicy } = require("./policy/egress");
const { resolveTiers } = require("./policy/tiers");
const { createPolicyFactory } = require("./policy/session_policy");
const { createAddressHolds } = require("./policy/address_holds");
const { AuthError, createPublicServer } = require("./server/public");
const { createUserApi } = require("./server/user_api");
const { attachConnectionHandler, createSessionRegistry } = require("./server/connection");
const { installLifecycle } = require("./server/lifecycle");
const { openDatabase } = require("./auth/db");
const { createUserStore } = require("./auth/users");
const { createInviteStore } = require("./auth/invites");
const { createOrgStore } = require("./auth/orgs");
const { SqliteSessionStore } = require("./auth/session_store");
const tokens = require("./auth/tokens");
const { createAuditLog, noopAudit } = require("./metering/audit");
const { createUsageMeter, noopUsage } = require("./metering/usage");
const { createMetrics } = require("./metrics");
const admin = require("./admin/app");

const POOL_PREFIX = "10.0.2.";

// Forwarders let the policy factory and connection handler be built before
// the database is open; the real implementations are swapped in on ready.
function forwarder(ref, methods) {
  const target = {};
  for (const method of methods) {
    target[method] = (...args) => ref.current[method](...args);
  }
  Object.defineProperty(target, "enabled", { get: () => ref.current.enabled });
  return target;
}

function init(ctx) {
  const config = resolveConfig(ctx.env || process.env);
  const log = createLogger({ json: config.logJson, level: "info" });
  for (const warning of config.warnings) log.warn(warning);
  log.info("relay mode", {
    mode: config.mode,
    authRequired: config.authRequired,
    anonEnabled: config.anonEnabled,
    externalJwt: Boolean(config.jwt),
    egressPolicy: config.egressPolicy,
    inboundRules: config.inboundRulesEnabled,
    antiSpoof: config.antiSpoof,
    audit: config.auditEnabled,
    metrics: config.metricsEnabled,
  });

  const egress = createEgressPolicy({
    mode: config.egressPolicy,
    denyCidrs: config.egressDenyCidrs,
    allowCidrs: config.egressAllowCidrs,
    denyPorts: config.egressDenyPorts,
  });

  const tiers = resolveTiers(config.tiersJson, {
    rateLimitBps: ctx.RATE_LIMIT_BPS,
    dnsServerIp: ctx.DNS_SERVER_IP,
    maxUdpFlows: ctx.MAX_UDP_FLOWS_PER_SESSION,
    maxConnectionsPerIp: ctx.MAX_CONNECTIONS_PER_IP,
    enableVmToVm: ctx.ENABLE_VM_TO_VM,
  });

  const policyCtx = {
    GATEWAY_IP: ctx.GATEWAY_IP,
    DHCP_START: ctx.DHCP_START,
    DHCP_END: ctx.DHCP_END,
    poolPrefix: POOL_PREFIX,
    macToIP: ctx.macToIP,
    ipToSession: ctx.ipToSession,
    usedIPs: ctx.usedIPs,
    activeSessions: ctx.activeSessions,
    connectionsPerIP: ctx.connectionsPerIP,
  };
  policyCtx.addressHolds = createAddressHolds({ ctx: policyCtx, holdMs: config.addressHoldMs, log });

  const metrics = createMetrics({ enabled: config.metricsEnabled, mergeUrls: config.metricsMergeUrls });
  const auditRef = { current: noopAudit() };
  const usageRef = { current: noopUsage() };
  const audit = forwarder(auditRef, ["record", "finish", "flush", "prune", "query", "pendingCount", "close"]);
  const usage = forwarder(usageRef, ["track", "untrack", "flush", "isOverQuota", "periodUsage", "monthly", "close"]);

  const registry = createSessionRegistry({ ctx: policyCtx, tiers });
  const policyFactory = createPolicyFactory({ config, tiers, egress, ctx: policyCtx, audit, metrics, log });
  const lifecycle = installLifecycle({
    servers: [],
    getSessions: () => registry.sessions.values(),
    flushers: [],
    timeoutMs: config.shutdownTimeoutMs,
    hardExitMs: config.hardExitMs,
    log,
  });

  // Admission: registry caps first, then the byte quota for the identity.
  const admission = {
    async admit(args) {
      const verdict = registry.admit(args);
      if (!verdict.ok) return verdict;
      try {
        if (await usage.isOverQuota(args)) {
          verdict.release();
          return { ok: false, status: 429, reason: "quota exceeded" };
        }
      } catch (error) {
        verdict.release();
        throw error;
      }
      return verdict;
    },
  };

  // Identity services become available once the database is open; upgrade
  // requests that arrive earlier wait on `ready`.
  const state = {
    db: null,
    users: null,
    apiTokens: null,
    invites: null,
    orgs: null,
    anon: null,
    jwt: null,
    authenticate: null,
    handleAnonToken: null,
    publicServer: null,
    adminServer: null,
  };
  let resolveReady;
  const ready = new Promise((resolve) => {
    resolveReady = resolve;
  });

  async function authenticate(token, context) {
    await ready;
    if (!state.authenticate) throw new AuthError(503, "identity-unavailable");
    return state.authenticate(token, context);
  }

  async function handleAnonToken(request) {
    await ready;
    if (!state.handleAnonToken) throw new AuthError(404, "anonymous-access-disabled");
    return state.handleAnonToken(request);
  }

  function createWebSocketServer({ ENABLE_WSS, WS_PORT, WS_BIND_ADDRESS, maxPayload }) {
    const tls = ENABLE_WSS
      ? { cert: fs.readFileSync("cert.pem"), key: fs.readFileSync("key.pem") }
      : null;
    // Account self-service routes; the stores are read lazily because the
    // database opens after the listener starts.
    const userApi = config.authRequired
      ? createUserApi({
        authenticate,
        users: () => state.users,
        apiTokens: () => state.apiTokens,
        orgs: () => state.orgs,
        invites: () => state.invites,
        usage,
        registry,
        activeSessions: ctx.activeSessions,
        tiers,
        log,
      })
      : null;
    const publicServer = createPublicServer({
      config,
      log,
      tls,
      authenticate,
      admission,
      wssOptions: { maxPayload },
      lifecycle,
      sessionCount: () => registry.size,
      handleAnonToken: config.anonEnabled ? handleAnonToken : null,
      metrics,
      userApi,
    });
    state.publicServer = publicServer;
    lifecycle.addServer(publicServer.server);
    publicServer.listen(WS_PORT, WS_BIND_ADDRESS).then(() => {
      if (ENABLE_WSS) {
        console.log(
          `Secure WebSocket (WSS) VPN server, visit https://${WS_BIND_ADDRESS}:${WS_PORT} and trust your certificate`,
        );
      } else {
        console.log(`WebSocket VPN server listening on ${WS_BIND_ADDRESS}:${WS_PORT}`);
      }
    }).catch((error) => {
      log.error("public server failed to listen", { error });
      lifecycle.shutdown("listen failed", 1);
    });
    return publicServer.wss;
  }

  function attach(wss, VMSession) {
    attachConnectionHandler(wss, {
      VMSession,
      ctx: policyCtx,
      config,
      tiers,
      policyFactory,
      registry,
      log,
      metrics,
      usage,
    });
  }

  async function initializeIdentity() {
    const dbPath = config.adminAuthDbPath || path.join(__dirname, "admin_auth.sqlite");
    const db = openDatabase(dbPath);
    await db.migrate();
    state.db = db;
    state.users = createUserStore(db);
    state.apiTokens = tokens.createApiTokenStore(db);
    state.invites = createInviteStore(db);
    state.orgs = createOrgStore(db);
    if (config.anonEnabled && config.anonTokenSecret) {
      state.anon = tokens.createAnonIssuer({
        secret: config.anonTokenSecret,
        ttlMs: config.anonTokenTtlMs,
        bindIp: config.anonTokenBindIp,
        perIpPerHour: config.anonTokensPerIpPerHour,
      });
    }
    if (config.jwt) {
      state.jwt = tokens.createJwtVerifier({
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        jwksUrl: config.jwt.jwksUrl,
        usernameClaim: config.jwt.usernameClaim,
        verifiedClaim: config.jwt.verifiedClaim,
        algorithms: config.jwt.algorithms,
      });
    }
    state.authenticate = tokens.createAuthenticator({
      config,
      users: state.users,
      apiTokens: state.apiTokens,
      orgs: state.orgs,
      anon: state.anon,
      jwt: state.jwt,
      log,
    });
    if (state.anon) {
      state.handleAnonToken = async ({ body, clientIP }) => {
        if (config.turnstileSecret) {
          const ok = await tokens.verifyTurnstile({
            secret: config.turnstileSecret,
            token: body && body.turnstileToken,
            ip: clientIP,
          });
          if (!ok) throw new AuthError(403, "captcha-failed");
        }
        const issued = await state.anon.issue({ ip: clientIP });
        metrics.anonTokensIssued.inc();
        log.info("anon token issued", { clientIP });
        return { token: issued.token, expiresAt: issued.expiresAt, tier: "anon" };
      };
    }

    auditRef.current = createAuditLog({
      db,
      enabled: config.auditEnabled,
      retentionDays: config.auditRetentionDays,
      log,
    });
    usageRef.current = createUsageMeter({
      db,
      enabled: true,
      tiers,
      flushIntervalMs: config.usageFlushIntervalMs,
      metrics,
      log,
      onQuotaExceeded: (session) => {
        if (session.ws && session.ws.readyState === 1) session.ws.close(1008, "quota exceeded");
      },
    });
    lifecycle.addFlusher(async () => {
      await usage.flush();
      await audit.flush();
      usage.close();
      audit.close();
      await db.close();
    });
    return db;
  }

  function startAdmin(rules) {
    const run = async () => {
      const db = await initializeIdentity();
      await admin.bootstrapOperator({ users: state.users, config, log });
      admin.configurePassport({ users: state.users });
      const sessionStore = new SqliteSessionStore({ db });
      lifecycle.addFlusher(() => sessionStore.close());
      const app = admin.createAdminApp({
        config,
        users: state.users,
        apiTokens: state.apiTokens,
        invites: state.invites,
        sessionStore,
        activeSessions: ctx.activeSessions,
        registry,
        rules,
        proxyPort: ctx.PROXY_PORT,
        poolCtx: { poolPrefix: POOL_PREFIX, dhcpStart: ctx.DHCP_START, dhcpEnd: ctx.DHCP_END },
        tiers,
        audit,
        usage,
        metrics,
        log,
      });
      const server = await admin.startAdminServer(app, {
        port: ctx.ADMIN_PORT,
        host: ctx.ADMIN_BIND_ADDRESS,
        log,
      });
      state.adminServer = server;
      lifecycle.addServer(server);
      console.log(`💡 Admin UI listening on http://${ctx.ADMIN_BIND_ADDRESS}:${ctx.ADMIN_PORT}`);
    };
    run()
      .catch((error) => {
        log.error("failed to start identity/admin services", { error, stack: error && error.stack });
        lifecycle.shutdown("admin start failed", 1);
      })
      .finally(resolveReady);
  }

  return {
    config,
    log,
    tiers,
    egress,
    registry,
    addressHolds: policyCtx.addressHolds,
    policyFactory,
    lifecycle,
    metrics,
    audit,
    usage,
    state,
    ready,
    createWebSocketServer,
    attachConnectionHandler: attach,
    startAdmin,
  };
}

module.exports = { POOL_PREFIX, init };
