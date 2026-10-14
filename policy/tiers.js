"use strict";

// Per-identity resource tiers. `null` means unlimited. TIERS_JSON deep-merges
// over these defaults so operators can tune limits without code changes.

const KiB = 1024;
const MiB = 1024 * KiB;
const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;

const TIER_FIELDS = {
  uploadBps: "number",
  downloadBps: "number",
  maxTcpConnections: "number",
  synPerSec: "number",
  dnsQps: "number",
  maxUdpFlows: "number",
  connectTimeoutMs: "number",
  allowedTcpPorts: "ports",
  allowedUdpPorts: "ports",
  dnsServers: "addresses",
  vmToVm: "boolean",
  maxSessionMs: "number",
  idleMs: "number",
  maxSessionsPerOwner: "number",
  maxSessionsPerIP: "number",
  quotaBytes: "number",
  quotaPeriod: "period",
};

function buildDefaultTiers({
  rateLimitBps,
  dnsServerIp,
  maxUdpFlows,
  maxConnectionsPerIp,
  enableVmToVm,
}) {
  return {
    local: {
      uploadBps: null,
      downloadBps: rateLimitBps,
      maxTcpConnections: null,
      synPerSec: null,
      dnsQps: null,
      maxUdpFlows,
      connectTimeoutMs: null,
      allowedTcpPorts: null,
      allowedUdpPorts: null,
      dnsServers: null,
      vmToVm: enableVmToVm,
      maxSessionMs: null,
      idleMs: null,
      maxSessionsPerOwner: null,
      maxSessionsPerIP: maxConnectionsPerIp,
      quotaBytes: null,
      quotaPeriod: "month",
    },
    anon: {
      uploadBps: 256 * KiB,
      downloadBps: 512 * KiB,
      maxTcpConnections: 32,
      synPerSec: 10,
      dnsQps: 20,
      maxUdpFlows: 32,
      connectTimeoutMs: 10000,
      allowedTcpPorts: [80, 443],
      allowedUdpPorts: [443],
      dnsServers: [dnsServerIp],
      vmToVm: false,
      maxSessionMs: 15 * MINUTE,
      idleMs: 3 * MINUTE,
      maxSessionsPerOwner: 1,
      maxSessionsPerIP: 2,
      quotaBytes: 200 * MiB,
      quotaPeriod: "day",
    },
    user: {
      uploadBps: rateLimitBps,
      downloadBps: rateLimitBps,
      maxTcpConnections: 256,
      synPerSec: 50,
      dnsQps: 100,
      maxUdpFlows: 256,
      connectTimeoutMs: 15000,
      allowedTcpPorts: null,
      allowedUdpPorts: null,
      dnsServers: null,
      vmToVm: enableVmToVm,
      maxSessionMs: 12 * HOUR,
      idleMs: 30 * MINUTE,
      maxSessionsPerOwner: 4,
      maxSessionsPerIP: maxConnectionsPerIp,
      quotaBytes: 20 * 1024 * MiB,
      quotaPeriod: "month",
    },
    operator: {
      uploadBps: 4 * MiB,
      downloadBps: 4 * MiB,
      maxTcpConnections: 1024,
      synPerSec: 200,
      dnsQps: 400,
      maxUdpFlows: 1024,
      connectTimeoutMs: 15000,
      allowedTcpPorts: null,
      allowedUdpPorts: null,
      dnsServers: null,
      vmToVm: enableVmToVm,
      maxSessionMs: null,
      idleMs: null,
      maxSessionsPerOwner: 10,
      maxSessionsPerIP: maxConnectionsPerIp,
      quotaBytes: null,
      quotaPeriod: "month",
    },
  };
}

function isPort(value) {
  return Number.isInteger(value) && value >= 1 && value <= 65535;
}

function validateTier(name, tier) {
  if (!tier || typeof tier !== "object" || Array.isArray(tier)) {
    throw new RangeError(`Tier "${name}" must be an object`);
  }
  for (const [field, value] of Object.entries(tier)) {
    const kind = TIER_FIELDS[field];
    if (!kind) throw new RangeError(`Tier "${name}" has unknown field "${field}"`);
    if (value === null && kind !== "boolean" && kind !== "period") continue;
    switch (kind) {
      case "number":
        if (!Number.isFinite(value) || value < 0) {
          throw new RangeError(`Tier "${name}.${field}" must be a non-negative number or null`);
        }
        break;
      case "ports":
        if (!Array.isArray(value) || !value.every(isPort)) {
          throw new RangeError(`Tier "${name}.${field}" must be an array of ports or null`);
        }
        break;
      case "addresses":
        if (!Array.isArray(value) || !value.every((entry) => typeof entry === "string")) {
          throw new RangeError(`Tier "${name}.${field}" must be an array of addresses or null`);
        }
        break;
      case "boolean":
        if (typeof value !== "boolean") {
          throw new RangeError(`Tier "${name}.${field}" must be a boolean`);
        }
        break;
      case "period":
        if (value !== "day" && value !== "month") {
          throw new RangeError(`Tier "${name}.${field}" must be "day" or "month"`);
        }
        break;
      default:
        break;
    }
  }
  for (const field of Object.keys(TIER_FIELDS)) {
    if (!(field in tier)) throw new RangeError(`Tier "${name}" is missing "${field}"`);
  }
  return tier;
}

function resolveTiers(tiersJson, context) {
  const tiers = buildDefaultTiers(context);
  if (tiersJson) {
    if (typeof tiersJson !== "object" || Array.isArray(tiersJson)) {
      throw new RangeError("TIERS_JSON must be an object keyed by tier name");
    }
    for (const [name, overrides] of Object.entries(tiersJson)) {
      if (!overrides || typeof overrides !== "object" || Array.isArray(overrides)) {
        throw new RangeError(`TIERS_JSON.${name} must be an object`);
      }
      tiers[name] = { ...(tiers[name] || tiers.user), ...overrides };
    }
  }
  for (const [name, tier] of Object.entries(tiers)) {
    validateTier(name, tier);
    Object.freeze(tier);
  }
  return tiers;
}

module.exports = { TIER_FIELDS, buildDefaultTiers, resolveTiers, validateTier };
