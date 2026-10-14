"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { buildIPv4Packet, parseIPv4Packet, tcpChecksum } = require("../packet_utils");
const { createEgressPolicy } = require("../policy/egress");
const { resolveTiers } = require("../policy/tiers");
const { SessionPolicy, buildTcpReset, createPolicyFactory } = require("../policy/session_policy");

const GATEWAY_IP = "10.0.2.2";
const TIERS = resolveTiers(null, {
  rateLimitBps: 1024 * 1024,
  dnsServerIp: "8.8.8.8",
  maxUdpFlows: 256,
  maxConnectionsPerIp: 4,
  enableVmToVm: true,
});

function makeCtx() {
  return {
    GATEWAY_IP,
    DHCP_START: 15,
    DHCP_END: 254,
    poolPrefix: "10.0.2.",
    poolBytes: [10, 0, 2],
    macToIP: new Map(),
    ipToSession: new Map(),
    usedIPs: new Set([2]),
  };
}

function fakeSession(id = "s1") {
  return {
    sessionId: id,
    vmIP: null,
    vmMAC: null,
    vmMACBytes: null,
    tcpConnections: new Map(),
    udpFlows: { maxFlows: 256 },
    rateLimiter: null,
    ws: { readyState: 1 },
    sent: [],
    aborted: [],
    sendIPToVM(packet) { this.sent.push(packet); },
    abortTCPConnection(key, conn, error) { this.aborted.push({ key, conn, error }); },
  };
}

function makePolicy({
  tier = "local",
  owner = "local",
  egressMode = "open",
  ctx = makeCtx(),
  now = () => 1000,
  antiSpoof = true,
  audit = null,
  tiers = TIERS,
} = {}) {
  const policy = new SessionPolicy({
    tier: tiers[tier],
    identity: { kind: tier, owner, tier },
    egress: createEgressPolicy({ mode: egressMode, localAddresses: () => new Set(), denyPorts: [25] }),
    ctx,
    antiSpoof,
    audit,
    now,
  });
  return policy;
}

function attach(policy, session) {
  session.policy = policy;
  policy.applyToSession(session);
  return session;
}

function tcpPacket({ srcIP, dstIP, srcPort = 40000, dstPort = 80, payload = Buffer.alloc(0), flags = 0x02 }) {
  const tcp = Buffer.alloc(20 + payload.length);
  tcp.writeUInt16BE(srcPort, 0);
  tcp.writeUInt16BE(dstPort, 2);
  tcp.writeUInt32BE(1000, 4);
  tcp[12] = 5 << 4;
  tcp[13] = flags;
  payload.copy(tcp, 20);
  const packet = buildIPv4Packet(tcp, srcIP, dstIP, 6, 1);
  packet.writeUInt16BE(tcpChecksum(packet), 36);
  return packet;
}

function udpPacket({ srcIP, dstIP, srcPort = 40000, dstPort = 53, payload = Buffer.alloc(10) }) {
  const udp = Buffer.alloc(8 + payload.length);
  udp.writeUInt16BE(srcPort, 0);
  udp.writeUInt16BE(dstPort, 2);
  udp.writeUInt16BE(udp.length, 4);
  payload.copy(udp, 8);
  return buildIPv4Packet(udp, srcIP, dstIP, 17, 1);
}

function admit(policy, session, packet) {
  const parsed = parseIPv4Packet(packet);
  return policy.admitIPv4(session, parsed, parsed.packet);
}

test("learn-then-lock claims the first source IP and registers it in the shared maps", () => {
  const ctx = makeCtx();
  const policy = makePolicy({ ctx });
  const session = attach(policy, fakeSession());
  session.vmMAC = "52:54:00:aa:bb:cc";
  assert.equal(admit(policy, session, tcpPacket({ srcIP: "10.0.2.15", dstIP: "1.1.1.1" })), true);
  assert.equal(session.vmIP, "10.0.2.15");
  assert.equal(ctx.ipToSession.get("10.0.2.15"), session);
  assert.equal(ctx.macToIP.get("52:54:00:aa:bb:cc"), "10.0.2.15");
  assert.ok(ctx.usedIPs.has(15));
  assert.equal(admit(policy, session, tcpPacket({ srcIP: "10.0.2.16", dstIP: "1.1.1.1" })), false);
  assert.equal(policy.counters.spoofDrops, 1);
  assert.equal(admit(policy, session, tcpPacket({ srcIP: "10.0.2.15", dstIP: "1.1.1.1" })), true);
});

test("DHCP from 0.0.0.0 is allowed before and after the IP is known; other 0.0.0.0 traffic is not", () => {
  const policy = makePolicy();
  const session = attach(policy, fakeSession());
  const dhcp = udpPacket({ srcIP: "0.0.0.0", dstIP: "255.255.255.255", srcPort: 68, dstPort: 67 });
  assert.equal(admit(policy, session, dhcp), true);
  assert.equal(session.vmIP, null);
  assert.equal(admit(policy, session, tcpPacket({ srcIP: "0.0.0.0", dstIP: "1.1.1.1" })), false);
  session.vmIP = "10.0.2.20";
  assert.equal(admit(policy, session, dhcp), true);
});

test("claims are refused for held, gateway, broadcast and out-of-pool addresses", () => {
  const ctx = makeCtx();
  const other = fakeSession("s2");
  other.vmIP = "10.0.2.15";
  ctx.ipToSession.set("10.0.2.15", other);
  const policy = makePolicy({ ctx });
  const session = attach(policy, fakeSession());
  assert.equal(admit(policy, session, tcpPacket({ srcIP: "10.0.2.15", dstIP: "1.1.1.1" })), false);
  assert.equal(admit(policy, session, tcpPacket({ srcIP: GATEWAY_IP, dstIP: "1.1.1.1" })), false);
  assert.equal(admit(policy, session, tcpPacket({ srcIP: "10.0.2.255", dstIP: "1.1.1.1" })), false);
  assert.equal(admit(policy, session, tcpPacket({ srcIP: "10.0.2.5", dstIP: "1.1.1.1" })), false);
  assert.equal(admit(policy, session, tcpPacket({ srcIP: "192.168.1.5", dstIP: "1.1.1.1" })), false);
  assert.equal(session.vmIP, null);
  // A dead holder releases its claim.
  other.ws.readyState = 3;
  assert.equal(admit(policy, session, tcpPacket({ srcIP: "10.0.2.15", dstIP: "1.1.1.1" })), true);
  assert.equal(ctx.ipToSession.get("10.0.2.15"), session);
});

test("anti-spoof can be disabled", () => {
  const policy = makePolicy({ antiSpoof: false });
  const session = attach(policy, fakeSession());
  assert.equal(admit(policy, session, tcpPacket({ srcIP: "192.168.1.5", dstIP: "1.1.1.1" })), true);
  assert.equal(session.vmIP, null);
  assert.equal(policy.admitFrame(session, Buffer.alloc(6, 1)), true);
});

test("MAC lock rejects a changed MAC and a MAC bound to another live session", () => {
  const ctx = makeCtx();
  const other = fakeSession("s2");
  ctx.macToIP.set("00:00:00:00:00:02", "10.0.2.16");
  ctx.ipToSession.set("10.0.2.16", other);
  const policy = makePolicy({ ctx });
  const session = attach(policy, fakeSession());
  assert.equal(policy.admitFrame(session, Buffer.from([0, 0, 0, 0, 0, 2])), false);
  assert.equal(policy.admitFrame(session, Buffer.from([0, 0, 0, 0, 0, 1])), true);
  session.vmMACBytes = Buffer.from([0, 0, 0, 0, 0, 1]);
  assert.equal(policy.admitFrame(session, Buffer.from([0, 0, 0, 0, 0, 1])), true);
  assert.equal(policy.admitFrame(session, Buffer.from([0, 0, 0, 0, 0, 3])), false);
  assert.equal(policy.counters.macDrops, 2);
});

test("canReach requires the same owner and a tier that allows VM-to-VM", () => {
  const a = attach(makePolicy({ tier: "user", owner: "user:1" }), fakeSession("a"));
  const b = attach(makePolicy({ tier: "user", owner: "user:1" }), fakeSession("b"));
  const c = attach(makePolicy({ tier: "user", owner: "user:2" }), fakeSession("c"));
  const anon = attach(makePolicy({ tier: "anon", owner: "anon:x" }), fakeSession("d"));
  assert.equal(a.policy.canReach(a, b), true);
  assert.equal(a.policy.canReach(a, c), false);
  assert.equal(a.policy.canReach(a, a), false);
  assert.equal(anon.policy.canReach(anon, a), false);
  assert.equal(a.policy.canReach(a, anon), false);
  assert.equal(a.policy.canReach(a, { policy: null }), false);
});

test("denied TCP egress answers with RST|ACK acknowledging the SYN", () => {
  const policy = makePolicy({ tier: "user", owner: "user:1", egressMode: "hosted" });
  const session = attach(policy, fakeSession());
  session.vmIP = "10.0.2.15";
  const allowed = policy.allowTcpConnect(session, {
    srcIP: "10.0.2.15", srcPort: 40000, dstIP: "169.254.169.254", dstPort: 80, seqNum: 5000,
  });
  assert.equal(allowed, false);
  assert.equal(policy.counters.egressDenied, 1);
  assert.equal(session.sent.length, 1);
  const parsed = parseIPv4Packet(session.sent[0]);
  assert.equal(parsed.srcIP, "169.254.169.254");
  assert.equal(parsed.dstIP, "10.0.2.15");
  const tcp = parsed.packet.subarray(parsed.headerLength);
  assert.equal(tcp.readUInt16BE(0), 80);
  assert.equal(tcp.readUInt16BE(2), 40000);
  assert.equal(tcp[13], 0x14);
  assert.equal(tcp.readUInt32BE(8), 5001);
  assert.equal(tcpChecksum(parsed.packet), parsed.packet.readUInt16BE(parsed.headerLength + 16));
  assert.equal(policy.allowTcpConnect(session, {
    srcIP: "10.0.2.15", srcPort: 40001, dstIP: "1.1.1.1", dstPort: 443, seqNum: 1,
  }), true);
  assert.equal(policy.allowTcpConnect(session, {
    srcIP: "10.0.2.15", srcPort: 40002, dstIP: "1.1.1.1", dstPort: 25, seqNum: 1,
  }), false);
});

test("anon tier allows only its port list and resolver, SYN rate drops silently, conn cap resets", () => {
  let clock = 0;
  const policy = makePolicy({
    tier: "anon", owner: "anon:x", egressMode: "hosted", now: () => clock,
    tiers: resolveTiers({ anon: { synPerSec: 2, maxTcpConnections: 1 } }, {
      rateLimitBps: 1024, dnsServerIp: "8.8.8.8", maxUdpFlows: 8, maxConnectionsPerIp: 2, enableVmToVm: false,
    }),
  });
  const session = attach(policy, fakeSession());
  assert.equal(session.udpFlows.maxFlows, 32);
  const syn = (dstPort, srcPort) => policy.allowTcpConnect(session, {
    srcIP: "10.0.2.15", srcPort, dstIP: "1.1.1.1", dstPort, seqNum: 1,
  });
  assert.equal(syn(22, 1), false);
  assert.equal(session.sent.length, 1, "tier port denial sends RST");
  assert.equal(syn(443, 2), true);
  assert.equal(syn(443, 3), false, "third SYN within a second exceeds synPerSec=2");
  assert.equal(policy.counters.synRateDrops, 1);
  assert.equal(session.sent.length, 1, "rate drop is silent");
  clock = 2000;
  session.tcpConnections.set("2:1.1.1.1:443", { socket: { connecting: false } });
  assert.equal(syn(443, 4), false, "connection cap reached");
  assert.equal(policy.counters.connCapDenied, 1);
  assert.equal(session.sent.length, 2, "cap denial sends RST");

  assert.equal(policy.allowUdpSend(session, "8.8.8.8", 53, true, 40), true);
  assert.equal(policy.allowUdpSend(session, "1.1.1.1", 53, true, 40), false);
  assert.equal(policy.allowUdpSend(session, "1.1.1.1", 443, false, 40), true);
  assert.equal(policy.allowUdpSend(session, "1.1.1.1", 5000, false, 40), false);
  assert.equal(policy.allowUdpSend(session, "10.0.0.1", 443, false, 40), false);
});

test("upload policing exempts control traffic and drops payload over budget", () => {
  const policy = makePolicy({
    tier: "anon", owner: "anon:x", now: () => 0,
    tiers: resolveTiers({ anon: { uploadBps: 100 } }, {
      rateLimitBps: 1024, dnsServerIp: "8.8.8.8", maxUdpFlows: 8, maxConnectionsPerIp: 2, enableVmToVm: false,
    }),
  });
  const session = attach(policy, fakeSession());
  session.vmIP = "10.0.2.15";
  const ack = tcpPacket({ srcIP: "10.0.2.15", dstIP: "1.1.1.1", flags: 0x10 });
  for (let i = 0; i < 20; i += 1) assert.equal(admit(policy, session, ack), true);
  const gatewayData = tcpPacket({ srcIP: "10.0.2.15", dstIP: GATEWAY_IP, payload: Buffer.alloc(500) });
  assert.equal(admit(policy, session, gatewayData), true);
  const data = tcpPacket({ srcIP: "10.0.2.15", dstIP: "1.1.1.1", payload: Buffer.alloc(60), flags: 0x18 });
  assert.equal(admit(policy, session, data), true);
  assert.equal(admit(policy, session, data), false);
  assert.equal(policy.counters.uploadDrops, 1);
  const udp = udpPacket({ srcIP: "10.0.2.15", dstIP: "1.1.1.1", dstPort: 443, payload: Buffer.alloc(100) });
  assert.equal(admit(policy, session, udp), false);
});

test("admitDownload skips internet TCP and DHCP replies but budgets UDP and VM-to-VM", () => {
  const policy = makePolicy({
    tier: "user", owner: "user:1", now: () => 0,
    tiers: resolveTiers({ user: { downloadBps: 100 } }, {
      rateLimitBps: 1024, dnsServerIp: "8.8.8.8", maxUdpFlows: 8, maxConnectionsPerIp: 2, enableVmToVm: true,
    }),
  });
  const session = attach(policy, fakeSession());
  const internetTcp = tcpPacket({ srcIP: "1.1.1.1", dstIP: "10.0.2.15", payload: Buffer.alloc(1000) });
  assert.equal(policy.admitDownload(session, internetTcp), true);
  const dhcpReply = udpPacket({ srcIP: GATEWAY_IP, dstIP: "255.255.255.255", srcPort: 67, dstPort: 68, payload: Buffer.alloc(300) });
  assert.equal(policy.admitDownload(session, dhcpReply), true);
  const udpReply = udpPacket({ srcIP: "8.8.8.8", dstIP: "10.0.2.15", srcPort: 53, dstPort: 40000, payload: Buffer.alloc(50) });
  assert.equal(policy.admitDownload(session, udpReply), true);
  assert.equal(policy.admitDownload(session, udpReply), false);
  assert.equal(policy.counters.downloadDrops, 1);
  const vmToVm = tcpPacket({ srcIP: "10.0.2.16", dstIP: "10.0.2.15", payload: Buffer.alloc(10) });
  assert.equal(policy.admitDownload(session, vmToVm), false);
  // Unlimited tiers install a pass-through limiter.
  const local = attach(makePolicy({ tier: "local", tiers: resolveTiers({ local: { downloadBps: null } }, {
    rateLimitBps: 1024, dnsServerIp: "8.8.8.8", maxUdpFlows: 8, maxConnectionsPerIp: 2, enableVmToVm: true,
  }) }), fakeSession());
  assert.equal(local.policy.admitDownload(local, udpReply), true);
  assert.equal(local.rateLimiter.tryConsume(1e9), true);
});

test("sweep aborts sockets still connecting after the tier timeout", () => {
  let clock = 0;
  const policy = makePolicy({ tier: "user", owner: "user:1", now: () => clock });
  const session = attach(policy, fakeSession());
  assert.equal(policy.allowTcpConnect(session, {
    srcIP: "10.0.2.15", srcPort: 1, dstIP: "1.1.1.1", dstPort: 443, seqNum: 1,
  }), true);
  const conn = { socket: { connecting: true } };
  session.tcpConnections.set("1:1.1.1.1:443", conn);
  clock = 14000;
  policy.sweep(session, clock);
  assert.equal(session.aborted.length, 0);
  clock = 16000;
  policy.sweep(session, clock);
  assert.equal(session.aborted.length, 1);
  assert.equal(session.aborted[0].key, "1:1.1.1.1:443");
  assert.equal(policy.counters.connectTimeouts, 1);
  policy.onTcpClose(session, "1:1.1.1.1:443", conn, new Error("connect timeout"));
  assert.equal(policy.pendingConnects.size, 0);
});

test("audit receives allow rows with bytes on close and rate-limited deny rows", () => {
  const rows = [];
  const finished = [];
  const audit = { record: (row) => rows.push(row), finish: (key, data) => finished.push({ key, ...data }) };
  let clock = 0;
  const policy = makePolicy({ tier: "user", owner: "user:1", egressMode: "hosted", audit, now: () => clock });
  const session = attach(policy, fakeSession("sess"));
  policy.allowTcpConnect(session, { srcIP: "10.0.2.15", srcPort: 1, dstIP: "1.1.1.1", dstPort: 443, seqNum: 1 });
  policy.onTcpClose(session, "1:1.1.1.1:443", { socket: { bytesRead: 10, bytesWritten: 20 } });
  assert.equal(rows[0].verdict, "allow");
  assert.deepEqual(finished[0], { key: "sess:1:1.1.1.1:443", endedAt: 0, bytesIn: 10, bytesOut: 20, error: null });
  policy.allowTcpConnect(session, { srcIP: "10.0.2.15", srcPort: 2, dstIP: "127.0.0.1", dstPort: 8001, seqNum: 1 });
  policy.allowTcpConnect(session, { srcIP: "10.0.2.15", srcPort: 3, dstIP: "127.0.0.1", dstPort: 8001, seqNum: 1 });
  assert.equal(rows.filter((row) => row.verdict.startsWith("deny")).length, 1);
  clock = 20000;
  policy.allowTcpConnect(session, { srcIP: "10.0.2.15", srcPort: 4, dstIP: "127.0.0.1", dstPort: 8001, seqNum: 1 });
  assert.equal(rows.filter((row) => row.verdict.startsWith("deny")).length, 2);
});

test("createPolicyFactory picks the identity tier and falls back to user", () => {
  const factory = createPolicyFactory({
    config: { antiSpoof: true },
    tiers: TIERS,
    egress: createEgressPolicy({ mode: "open" }),
    ctx: makeCtx(),
  });
  assert.equal(factory.forSession({ kind: "anon", owner: "anon:1", tier: "anon" }).tier, TIERS.anon);
  assert.equal(factory.forSession({ kind: "user", owner: "user:1", tier: "gold" }).tier, TIERS.user);
  assert.equal(buildTcpReset({ srcIP: "1.1.1.1", srcPort: 1, dstIP: "2.2.2.2", dstPort: 2 }).length, 40);
});
