"use strict";

// Prometheus metrics for the hosted relay. When disabled, every instrument is
// a no-op so call sites never need to branch.

function noopInstrument() {
  return { inc() {}, dec() {}, set() {}, observe() {}, labels() { return this; } };
}

// Appends the exposition text served at each of `mergeUrls` (for example a
// sidecar's local metrics endpoint, so a platform that scrapes one endpoint
// per app sees both). Families the relay already exports are skipped, and an
// unreachable URL is left out rather than failing the scrape.
async function fetchMerged(urls, ownText, { fetch, timeoutMs }) {
  const own = new Set(ownText.match(/^# TYPE \S+/gm)?.map((line) => line.slice(7)) || []);
  const parts = await Promise.all(urls.map(async (url) => {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
      return res.ok ? await res.text() : "";
    } catch {
      return "";
    }
  }));
  return parts
    .flatMap((text) => text.split("\n"))
    .filter((line) => {
      const name = line.startsWith("# ") ? line.split(" ")[2] : line.split(/[{\s]/)[0];
      return line && ![...own].some((family) => name === family || name?.startsWith(family + "_"));
    })
    .join("\n");
}

function createMetrics({
  enabled = true,
  promClient = null,
  mergeUrls = [],
  fetch = globalThis.fetch,
  mergeTimeoutMs = 2000,
} = {}) {
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
      budgetBytes: noopInstrument(),
      budgetThresholdBytes: noopInstrument(),
      budgetState: noopInstrument(),
      budgetForced: noopInstrument(),
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
  // Relay-wide monthly egress budget (metering/budget.js).
  const budgetBytes = new client.Gauge({
    name: "rootlessrelay_budget_bytes",
    help: "Bytes relayed this UTC month, all tiers",
    registers: [registry],
  });
  const budgetThresholdBytes = new client.Gauge({
    name: "rootlessrelay_budget_threshold_bytes",
    help: "Budget thresholds in bytes",
    labelNames: ["threshold"],
    registers: [registry],
  });
  const budgetState = new client.Gauge({
    name: "rootlessrelay_budget_state",
    help: "1 for the budget's current state (open, throttled, paused), else 0",
    labelNames: ["state"],
    registers: [registry],
  });
  const budgetForced = new client.Gauge({
    name: "rootlessrelay_budget_forced",
    help: "1 when an operator has forced the budget to this state, else 0",
    labelNames: ["state"],
    registers: [registry],
  });

  return {
    enabled: true,
    registry,
    contentType: registry.contentType,
    async render() {
      const text = await registry.metrics();
      if (mergeUrls.length === 0) return text;
      const merged = await fetchMerged(mergeUrls, text, { fetch, timeoutMs: mergeTimeoutMs });
      return merged ? `${text.trimEnd()}\n${merged}\n` : text;
    },
    sessionsGauge,
    bytesCounter,
    egressDenied,
    synRateDrops,
    connCapDenied,
    authFailures,
    anonTokensIssued,
    upgradeRejections,
    budgetBytes,
    budgetThresholdBytes,
    budgetState,
    budgetForced,
  };
}

module.exports = { createMetrics };
