"use strict";

// Outbound destination policy. Pure functions plus a small factory so the
// decision can be unit-tested without sockets.

const os = require("os");

function ipv4ToInt(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = (value * 256) + octet;
  }
  return value;
}

function parseCidr(cidr) {
  const [ip, bitsText] = cidr.split("/");
  const base = ipv4ToInt(ip);
  const bits = bitsText === undefined ? 32 : Number(bitsText);
  if (base === null || !Number.isInteger(bits) || bits < 0 || bits > 32) {
    throw new RangeError(`Invalid CIDR "${cidr}"`);
  }
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { cidr, base: (base & mask) >>> 0, mask, bits };
}

function inCidr(ipInt, parsed) {
  return ((ipInt & parsed.mask) >>> 0) === parsed.base;
}

// Ranges that a hosted relay must never reach on a tenant's behalf: loopback,
// link-local (cloud metadata), private, CGNAT, documentation, benchmarking,
// multicast and reserved space.
const HOSTED_DENY_CIDRS = [
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "224.0.0.0/4",
  "240.0.0.0/4",
  "255.255.255.255/32",
];

function snapshotLocalAddresses() {
  const addresses = new Set();
  for (const entries of Object.values(os.networkInterfaces())) {
    for (const entry of entries || []) {
      if (entry.family === "IPv4" || entry.family === 4) {
        addresses.add(entry.address);
      }
    }
  }
  return addresses;
}

function createLocalAddressSource({ refreshMs = 60000, now = Date.now } = {}) {
  let cached = null;
  let cachedAt = 0;
  return () => {
    const current = now();
    if (!cached || current - cachedAt >= refreshMs) {
      cached = snapshotLocalAddresses();
      cachedAt = current;
    }
    return cached;
  };
}

// UDP services that answer a small request with a much larger reply, the
// ones reflection attacks and amplifier scans use. A VM has no reason to
// reach them on the internet; probing them from the relay's address draws
// abuse reports. DNS (53) and NTP (123) are left open: VMs need them, and
// DNS queries are rate limited per session.
const HOSTED_DENY_UDP_PORTS = [
  17, // QOTD
  19, // chargen
  111, // portmapper
  137, // NetBIOS name service
  161, // SNMP
  389, // CLDAP
  520, // RIP
  1900, // SSDP
  3283, // Apple Remote Desktop
  3702, // WS-Discovery
  5353, // mDNS
  10001, // Ubiquiti discovery
  11211, // memcached
];

function createEgressPolicy({
  mode = "open",
  denyCidrs = [],
  allowCidrs = [],
  denyPorts = [],
  denyUdpPorts = [],
  localAddresses = createLocalAddressSource(),
} = {}) {
  if (!["open", "hosted"].includes(mode)) {
    throw new RangeError(`Unknown egress mode "${mode}"`);
  }
  const allow = allowCidrs.map(parseCidr);
  const deny = [
    ...(mode === "hosted" ? HOSTED_DENY_CIDRS : []),
    ...denyCidrs,
  ].map(parseCidr);
  const deniedPorts = new Set(denyPorts);
  const deniedUdpPorts = new Set(denyUdpPorts);

  function check(dstIP, dstPort, proto = "tcp") {
    const ipInt = ipv4ToInt(dstIP);
    if (ipInt === null) return { allow: false, reason: "invalid-address" };
    if (deniedPorts.has(dstPort)) return { allow: false, reason: "denied-port" };
    if (proto === "udp" && deniedUdpPorts.has(dstPort)) return { allow: false, reason: "denied-udp-port" };
    for (const range of allow) {
      if (inCidr(ipInt, range)) return { allow: true, reason: "allow-list" };
    }
    for (const range of deny) {
      if (inCidr(ipInt, range)) {
        return { allow: false, reason: `denied-range:${range.cidr}` };
      }
    }
    if (mode === "hosted" && localAddresses().has(dstIP)) {
      return { allow: false, reason: "local-address" };
    }
    return { allow: true, reason: proto === "udp" ? "udp" : "tcp" };
  }

  return { mode, check };
}

module.exports = {
  HOSTED_DENY_CIDRS,
  HOSTED_DENY_UDP_PORTS,
  createEgressPolicy,
  createLocalAddressSource,
  inCidr,
  ipv4ToInt,
  parseCidr,
};
