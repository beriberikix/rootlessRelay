"use strict";

// Composition root for the hosted-mode modules. relay.js calls init() once
// with its configuration constants and shared state, then uses the returned
// helpers at its `// HOSTED:` hook points. In local mode (the default) the
// observable behavior matches upstream rootlessRelay.

const fs = require("fs");
const { resolveConfig } = require("./config");
const { createLogger } = require("./log");
const { createEgressPolicy } = require("./policy/egress");
const { resolveTiers } = require("./policy/tiers");
const { createPolicyFactory } = require("./policy/session_policy");
const { createPublicServer } = require("./server/public");
const { attachConnectionHandler, createSessionRegistry } = require("./server/connection");
const { installLifecycle } = require("./server/lifecycle");
const admin = require("./admin/app");

const POOL_PREFIX = "10.0.2.";

function init(ctx) {
  const config = resolveConfig(ctx.env || process.env);
  const log = createLogger({ json: config.logJson, level: "info" });
  for (const warning of config.warnings) log.warn(warning);
  log.info("relay mode", {
    mode: config.mode,
    authRequired: config.authRequired,
    egressPolicy: config.egressPolicy,
    inboundRules: config.inboundRulesEnabled,
    antiSpoof: config.antiSpoof,
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

  const registry = createSessionRegistry({ ctx: policyCtx, tiers });
  const policyFactory = createPolicyFactory({ config, tiers, egress, ctx: policyCtx, log });
  const lifecycle = installLifecycle({
    servers: [],
    getSessions: () => registry.sessions.values(),
    flushers: [],
    timeoutMs: config.shutdownTimeoutMs,
    hardExitMs: config.hardExitMs,
    log,
  });

  const state = {
    authenticate: null,
    handleAnonToken: null,
    publicServer: null,
    adminServer: null,
    db: null,
  };

  function createWebSocketServer({ ENABLE_WSS, WS_PORT, WS_BIND_ADDRESS, maxPayload }) {
    const tls = ENABLE_WSS
      ? { cert: fs.readFileSync("cert.pem"), key: fs.readFileSync("key.pem") }
      : null;
    const publicServer = createPublicServer({
      config,
      log,
      tls,
      authenticate: (...args) => (state.authenticate ? state.authenticate(...args) : rejectNoAuth()),
      admission: registry,
      wssOptions: { maxPayload },
      lifecycle,
      sessionCount: () => registry.size,
      handleAnonToken: (...args) => (state.handleAnonToken ? state.handleAnonToken(...args) : rejectNoAnon()),
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

  function rejectNoAuth() {
    const { AuthError } = require("./server/public");
    throw new AuthError(401, "authentication required");
  }

  function rejectNoAnon() {
    const { AuthError } = require("./server/public");
    throw new AuthError(404, "anonymous access is disabled");
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
    });
  }

  function startAdmin(rules) {
    const dbPath = config.adminAuthDbPath || require("path").join(__dirname, "admin_auth.sqlite");
    const db = admin.openDatabase(dbPath);
    state.db = db;
    const app = admin.createAdminApp({
      config,
      db,
      activeSessions: ctx.activeSessions,
      registry,
      rules,
      proxyPort: ctx.PROXY_PORT,
      poolCtx: { poolPrefix: POOL_PREFIX, dhcpStart: ctx.DHCP_START, dhcpEnd: ctx.DHCP_END },
      log,
    });
    admin.initializeAdminAuth({ db, config, log })
      .then(() => admin.startAdminServer(app, { port: ctx.ADMIN_PORT, host: ctx.ADMIN_BIND_ADDRESS, log }))
      .then((server) => {
        state.adminServer = server;
        lifecycle.addServer(server);
        console.log(`💡 Admin UI listening on http://${ctx.ADMIN_BIND_ADDRESS}:${ctx.ADMIN_PORT}`);
      })
      .catch((error) => {
        log.error("failed to start admin server", { error });
        lifecycle.shutdown("admin start failed", 1);
      });
    lifecycle.addFlusher(() => db.close());
    return { app, db };
  }

  return {
    config,
    log,
    tiers,
    egress,
    registry,
    policyFactory,
    lifecycle,
    state,
    createWebSocketServer,
    attachConnectionHandler: attach,
    startAdmin,
  };
}

module.exports = { POOL_PREFIX, init };
