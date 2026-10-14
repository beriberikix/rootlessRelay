"use strict";

// Validation for inbound rule bodies posted to the admin API. Only known
// fields survive; everything is type- and range-checked so a rule can never
// bind an arbitrary address or target an address outside the VM pool.

const net = require("net");

function isPort(value) {
  return Number.isInteger(value) && value >= 1 && value <= 65535;
}

function toPort(value) {
  if (typeof value === "string" && /^\d+$/.test(value)) return Number(value);
  return value;
}

function validateVmAddress(vm, { poolPrefix, dhcpStart, dhcpEnd }) {
  if (typeof vm !== "string" || !vm.startsWith(poolPrefix)) return false;
  const last = Number(vm.slice(poolPrefix.length));
  return Number.isInteger(last) && last >= dhcpStart && last <= dhcpEnd;
}

function validateRule(body, { poolPrefix = "10.0.2.", dhcpStart = 15, dhcpEnd = 254, existingRules = [] } = {}) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { ok: false, error: "Rule body must be an object" };
  }
  const { type } = body;
  if (type !== "port" && type !== "http") {
    return { ok: false, error: 'Rule type must be "port" or "http"' };
  }
  if (!validateVmAddress(body.vm, { poolPrefix, dhcpStart, dhcpEnd })) {
    return { ok: false, error: "vm must be an address inside the VM pool" };
  }
  const port = toPort(body.port);
  if (!isPort(port)) {
    return { ok: false, error: "port must be an integer between 1 and 65535" };
  }

  if (type === "port") {
    const protocols = Array.isArray(body.protocols) ? body.protocols : [];
    if (protocols.length === 0 || !protocols.every((p) => p === "tcp" || p === "udp")) {
      return { ok: false, error: 'protocols must be a non-empty array of "tcp" and/or "udp"' };
    }
    const hostPort = toPort(body.host_port);
    if (!isPort(hostPort)) {
      return { ok: false, error: "host_port must be an integer between 1 and 65535" };
    }
    const bindAddress = body.bind_address === undefined || body.bind_address === ""
      ? "0.0.0.0"
      : body.bind_address;
    if (typeof bindAddress !== "string" || net.isIPv4(bindAddress) === false) {
      return { ok: false, error: "bind_address must be an IPv4 address" };
    }
    const uniqueProtocols = [...new Set(protocols)];
    for (const existing of existingRules) {
      if (existing.type !== "port" || existing.host_port !== hostPort) continue;
      const overlap = (existing.protocols || []).some((p) => uniqueProtocols.includes(p));
      if (overlap) {
        return { ok: false, error: `host_port ${hostPort} is already in use` };
      }
    }
    return {
      ok: true,
      rule: { type, vm: body.vm, port, protocols: uniqueProtocols, host_port: hostPort, bind_address: bindAddress },
    };
  }

  const path = body.path === undefined || body.path === "" ? "/" : body.path;
  if (typeof path !== "string" || !path.startsWith("/") || /[\s]/.test(path)) {
    return { ok: false, error: "path must start with / and contain no whitespace" };
  }
  const rule = { type, vm: body.vm, port, path };
  if (body.targetPath !== undefined && body.targetPath !== "") {
    if (typeof body.targetPath !== "string" || !body.targetPath.startsWith("/") || /\s/.test(body.targetPath)) {
      return { ok: false, error: "targetPath must start with / and contain no whitespace" };
    }
    rule.targetPath = body.targetPath;
  }
  if (body.vhost !== undefined && body.vhost !== "") {
    if (typeof body.vhost !== "string" || body.vhost.length > 253 || !/^[a-z0-9.-]+(:\d{1,5})?$/i.test(body.vhost)) {
      return { ok: false, error: "vhost must be a hostname" };
    }
    rule.vhost = body.vhost;
  }
  return { ok: true, rule };
}

module.exports = { validateRule, validateVmAddress };
