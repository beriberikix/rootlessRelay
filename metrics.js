"use strict";

// Prometheus metrics for the hosted relay. When disabled, every instrument is
// a no-op so call sites never need to branch.

function noopInstrument() {
  return { inc() {}, dec() {}, set() {}, observe() {}, labels() { return this; } };
}

function createMetrics({ enabled = true, promClient = null } = {}) {
  if (!enabled) {
    return {
      enabled: false,
      registry: null,
      contentType: "text/plain",
      async render() {
        return "";
      },
      sessionsGauge: noopInstrument(),
      bytesCounter: noopInstrument(),
      egressDenied: noopInstrument(),
      synRateDrops: noopInstrument(),
      connCapDenied: noopInstrument(),
      authFailures: noopInstrument(),
      anonTokensIssued: noopInstrument(),
      upgradeRejections: noopInstrument(),
    };
  }

  const client = promClient || require("prom-client");
  const registry = new client.Registry();
  client.collectDefaultMetrics({ register: registry, prefix: "rootlessrelay_" });

  const sessionsGauge = new client.Gauge({
    name: "rootlessrelay_sessions",
    help: "Open VM sessions",
    labelNames: ["tier"],
    registers: [registry],
  });
  const bytesCounter = new client.Counter({
    name: "rootlessrelay_bytes_total",
    help: "Bytes relayed, by direction and tier",
    labelNames: ["direction", "tier"],
    registers: [registry],
  });
  const egressDenied = new client.Counter({
    name: "rootlessrelay_egress_denied_total",
    help: "Outbound connections refused by policy",
    labelNames: ["proto"],
    registers: [registry],
  });
  const synRateDrops = new client.Counter({
    name: "rootlessrelay_syn_rate_drops_total",
    help: "SYNs dropped for exceeding the per-session rate",
    registers: [registry],
  });
  const connCapDenied = new client.Counter({
    name: "rootlessrelay_connection_cap_denied_total",
    help: "Connections refused for exceeding the per-session cap",
    registers: [registry],
  });
  const authFailures = new client.Counter({
    name: "rootlessrelay_auth_failures_total",
    help: "Rejected WebSocket upgrades, by reason",
    labelNames: ["code"],
    registers: [registry],
  });
  const anonTokensIssued = new client.Counter({
    name: "rootlessrelay_anon_tokens_issued_total",
    help: "Anonymous demo tokens issued",
    registers: [registry],
  });
  const upgradeRejections = new client.Counter({
    name: "rootlessrelay_upgrade_rejections_total",
    help: "WebSocket upgrades rejected before the handshake, by HTTP status",
    labelNames: ["status"],
    registers: [registry],
  });

  return {
    enabled: true,
    registry,
    contentType: registry.contentType,
    render: () => registry.metrics(),
    sessionsGauge,
    bytesCounter,
    egressDenied,
    synRateDrops,
    connCapDenied,
    authFailures,
    anonTokensIssued,
    upgradeRejections,
  };
}

module.exports = { createMetrics };
