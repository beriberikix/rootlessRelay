"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { buildIPv4Packet, parseIPv4Packet, tcpChecksum } = require("../packet_utils");
const { createEgressPolicy } = require("../policy/egress");
const { resolveTiers } = require("../policy/tiers");
const { SessionPolicy, buildTcpReset, createPolicyFactory } = require("../policy/session_policy");
const { createAddressHolds } = require("../policy/address_holds");

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
  userId = undefined,
  egressMode = "open",
  ctx = makeCtx(),
  now = () => 1000,
  antiSpoof = true,
  audit = null,
  tiers = TIERS,
  setTimer,
  clearTimer,
} = {}) {
  const policy = new SessionPolicy({
    tier: tiers[tier],
    identity: { kind: tier, owner, userId, tier },
    egress: createEgressPolicy({ mode: egressMode, localAddresses: () => new Set(), denyPorts: [25] }),
    ctx,
    antiSpoof,
    audit,
    now,
    ...(setTimer ? { setTimer, clearTimer } : {}),
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
  // Over budget, VM-to-VM traffic waits in the peer queue instead.
  const vmToVm = tcpPacket({ srcIP: "10.0.2.16", dstIP: "10.0.2.15", payload: Buffer.alloc(10) });
  assert.equal(policy.admitDownload(session, vmToVm), false);
  assert.equal(policy.peerQueue.length, 1);
  policy.clearPeerQueue();
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
  const policy = makePolicy({ tier: "user", owner: "org:9", userId: 4, egressMode: "hosted", audit, now: () => clock });
  const session = attach(policy, fakeSession("sess"));
  policy.allowTcpConnect(session, { srcIP: "10.0.2.15", srcPort: 1, dstIP: "1.1.1.1", dstPort: 443, seqNum: 1 });
  policy.onTcpClose(session, "1:1.1.1.1:443", { socket: { bytesRead: 10, bytesWritten: 20 } });
  assert.equal(rows[0].verdict, "allow");
  assert.equal(rows[0].owner, "org:9");
  assert.equal(rows[0].userId, 4, "the member who connected is recorded with the org");
  assert.deepEqual(finished[0], { key: "sess:1:1.1.1.1:443", endedAt: 0, bytesIn: 10, bytesOut: 20, error: null });
  policy.allowTcpConnect(session, { srcIP: "10.0.2.15", srcPort: 2, dstIP: "127.0.0.1", dstPort: 8001, seqNum: 1 });
  policy.allowTcpConnect(session, { srcIP: "10.0.2.15", srcPort: 3, dstIP: "127.0.0.1", dstPort: 8001, seqNum: 1 });
  assert.equal(rows.filter((row) => row.verdict.startsWith("deny")).length, 1);
  clock = 20000;
  policy.allowTcpConnect(session, { srcIP: "10.0.2.15", srcPort: 4, dstIP: "127.0.0.1", dstPort: 8001, seqNum: 1 });
  assert.equal(rows.filter((row) => row.verdict.startsWith("deny")).length, 2);
  assert.ok(rows.filter((row) => row.verdict.startsWith("deny")).every((row) => row.userId === 4), "denials name the member too");
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

test("SYN and DNS rates are shared by an owner's sessions, not multiplied by them (DP-4)", () => {
  const clock = 0;
  const tiers = resolveTiers({ user: { synPerSec: 2, dnsQps: 1 } }, {
    rateLimitBps: 1024, dnsServerIp: "8.8.8.8", maxUdpFlows: 8, maxConnectionsPerIp: 2, enableVmToVm: false,
  });
  const factory = createPolicyFactory({
    config: { antiSpoof: true }, tiers, egress: createEgressPolicy({ mode: "open" }), ctx: makeCtx(), now: () => clock,
  });
  const open = (owner, id) => {
    const policy = factory.forSession({ kind: "user", owner, tier: "user" });
    return { policy, session: attach(policy, fakeSession(id)) };
  };
  const syn = ({ policy, session }, srcPort) => policy.allowTcpConnect(session, {
    srcIP: "10.0.2.15", srcPort, dstIP: "1.1.1.1", dstPort: 443, seqNum: 1,
  });
  const a = open("org:1", "a");
  const b = open("org:1", "b");
  const other = open("org:2", "c");
  assert.equal(syn(a, 1), true);
  assert.equal(syn(b, 2), true);
  assert.equal(syn(b, 3), false, "the owner's third SYN in a second is over synPerSec=2, whichever session sends it");
  assert.equal(syn(a, 4), false);
  assert.equal(syn(other, 5), true, "another owner has its own budget");
  assert.equal(a.policy.allowUdpSend(a.session, "8.8.8.8", 53, true, 40), true);
  assert.equal(b.policy.allowUdpSend(b.session, "8.8.8.8", 53, true, 40), false, "dnsQps=1 across both sessions");

  assert.equal(factory.sharedOwnerCount(), 2);
  a.policy.onSessionClose(a.session);
  b.policy.onSessionClose(b.session);
  b.policy.onSessionClose(b.session);
  assert.equal(factory.sharedOwnerCount(), 1, "the owner's entry goes when its last session closes");
  other.policy.onSessionClose(other.session);
  assert.equal(factory.sharedOwnerCount(), 0);
});

test("a flood of denied destinations is summarised, not stored row by row", () => {
  const rows = [];
  const audit = { record: (row) => rows.push(row), finish() {} };
  let clock = 0;
  const policy = makePolicy({ tier: "user", owner: "user:1", egressMode: "hosted", audit, now: () => clock });
  const session = attach(policy, fakeSession("flood"));
  for (let i = 0; i < 50000; i += 1) {
    policy.allowUdpSend(session, `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`, 9, false, 8);
  }
  assert.equal(rows.length, 30, "per-minute budget for deny rows");
  assert.ok(policy.deniedAt.size <= 1024, "denied-key memory is bounded");
  clock = 61000;
  policy.allowUdpSend(session, "10.200.0.1", 9, false, 8);
  const summary = rows.find((row) => row.proto === "summary");
  assert.equal(summary.verdict, "suppressed:deny=49970:allow=0");
  assert.equal(rows.at(-1).verdict.startsWith("deny"), true, "a new window allows rows again");
});

function fakeTimers() {
  const timers = [];
  return {
    timers,
    setTimer(fn, ms) { const t = { fn, ms }; timers.push(t); return t; },
    clearTimer(t) { const i = timers.indexOf(t); if (i >= 0) timers.splice(i, 1); },
    runNext() { const t = timers.shift(); if (t) t.fn(); return t; },
  };
}

const SHAPING_TIERS = resolveTiers({ user: { downloadBps: 10000 } }, {
  rateLimitBps: 1024, dnsServerIp: "8.8.8.8", maxUdpFlows: 8, maxConnectionsPerIp: 2, enableVmToVm: true,
});

function peerPacket(i, size = 1500) {
  const payload = Buffer.alloc(size - 28);
  payload.writeUInt32BE(i, 0);
  return udpPacket({ srcIP: "10.0.2.16", dstIP: "10.0.2.15", srcPort: 5000, dstPort: 6000, payload });
}

test("VM-to-VM traffic over the download budget is queued and released in order", () => {
  let t = 0;
  const timers = fakeTimers();
  const policy = makePolicy({ tier: "user", owner: "user:1", now: () => t, tiers: SHAPING_TIERS, ...timers });
  const session = attach(policy, fakeSession());
  session.sendIPToVM = function (packet) {
    // relay.js runs admitDownload again on the way out; released packets pass.
    assert.equal(policy.admitDownload(this, packet), true);
    this.sent.push(packet.readUInt32BE(28));
  };

  const immediate = [];
  for (let i = 0; i < 20; i += 1) {
    if (policy.admitDownload(session, peerPacket(i))) immediate.push(i);
  }
  assert.deepEqual(immediate, [0, 1, 2, 3, 4, 5]); // 9000 of 10000 bytes per second
  assert.equal(policy.peerQueue.length, 14);
  assert.equal(policy.counters.downloadDrops, 0);
  assert.equal(timers.timers.length, 1);

  // Nothing frees up until the sliding window moves past the first packets.
  t = 500;
  timers.runNext();
  assert.deepEqual(session.sent, []);
  t = 1001;
  while (timers.timers.length && session.sent.length < 6) timers.runNext();
  assert.deepEqual(session.sent, [6, 7, 8, 9, 10, 11]);

  // A new packet queues behind the backlog rather than jumping it.
  t = 2002;
  assert.equal(policy.admitDownload(session, peerPacket(99)), false);
  while (timers.timers.length && session.sent.length < 12) timers.runNext();
  assert.deepEqual(session.sent.slice(6), [12, 13, 14, 15, 16, 17]);
  assert.equal(policy.peerQueue.at(-1).readUInt32BE(28), 99);
});

test("the peer queue is bounded, and cleared when the session closes or goes away", () => {
  const timers = fakeTimers();
  const policy = makePolicy({ tier: "user", owner: "user:1", now: () => 0, tiers: SHAPING_TIERS, ...timers });
  const session = attach(policy, fakeSession());
  let queued = 0;
  for (let i = 0; i < 400; i += 1) if (!policy.admitDownload(session, peerPacket(i))) queued += 1;
  assert.ok(policy.peerQueueBytes <= 256 * 1024);
  assert.equal(policy.counters.downloadDrops, queued - policy.peerQueue.length);
  assert.ok(policy.counters.downloadDrops > 0);

  policy.onSessionClose(session);
  assert.equal(policy.peerQueue.length, 0);
  assert.equal(timers.timers.length, 0);

  for (let i = 0; i < 10; i += 1) policy.admitDownload(session, peerPacket(i));
  session.ws.readyState = 3;
  timers.runNext();
  assert.equal(policy.peerQueue.length, 0);
  assert.deepEqual(session.sent, []);
});

test("gateway traffic and unlimited tiers are not shaped", () => {
  const timers = fakeTimers();
  const policy = makePolicy({ tier: "user", owner: "user:1", now: () => 0, tiers: SHAPING_TIERS, ...timers });
  const session = attach(policy, fakeSession());
  const fromGateway = udpPacket({ srcIP: GATEWAY_IP, dstIP: "10.0.2.15", srcPort: 8080, dstPort: 6000, payload: Buffer.alloc(9000) });
  assert.equal(policy.admitDownload(session, fromGateway), true);
  assert.equal(policy.admitDownload(session, fromGateway), false);
  assert.equal(policy.peerQueue.length, 0);

  const local = makePolicy({ tier: "local", ...timers, tiers: resolveTiers({ local: { downloadBps: null } }, {
    rateLimitBps: 1024, dnsServerIp: "8.8.8.8", maxUdpFlows: 8, maxConnectionsPerIp: 2, enableVmToVm: true,
  }) });
  const localSession = attach(local, fakeSession());
  for (let i = 0; i < 50; i += 1) assert.equal(local.admitDownload(localSession, peerPacket(i)), true);
});

test("upload policing skips traffic to a reachable session of the same owner", () => {
  const ctx = makeCtx();
  const tiers = resolveTiers({ user: { uploadBps: 100 } }, {
    rateLimitBps: 1024, dnsServerIp: "8.8.8.8", maxUdpFlows: 8, maxConnectionsPerIp: 2, enableVmToVm: true,
  });
  const sender = attach(makePolicy({ tier: "user", owner: "user:1", ctx, now: () => 0, tiers }), fakeSession("a"));
  const peer = attach(makePolicy({ tier: "user", owner: "user:1", ctx, now: () => 0, tiers }), fakeSession("b"));
  const stranger = attach(makePolicy({ tier: "user", owner: "user:2", ctx, now: () => 0, tiers }), fakeSession("c"));
  sender.vmIP = "10.0.2.15";
  ctx.ipToSession.set("10.0.2.15", sender);
  ctx.ipToSession.set("10.0.2.16", peer);
  ctx.ipToSession.set("10.0.2.17", stranger);

  const toPeer = udpPacket({ srcIP: "10.0.2.15", dstIP: "10.0.2.16", dstPort: 6000, payload: Buffer.alloc(500) });
  for (let i = 0; i < 5; i += 1) assert.equal(admit(sender.policy, sender, toPeer), true);
  const toStranger = udpPacket({ srcIP: "10.0.2.15", dstIP: "10.0.2.17", dstPort: 6000, payload: Buffer.alloc(500) });
  assert.equal(admit(sender.policy, sender, toStranger), false);
  assert.equal(sender.policy.counters.uploadDrops, 1);
});

function parseReset(packet) {
  const parsed = parseIPv4Packet(packet);
  const tcp = parsed.packet.subarray(parsed.headerLength);
  return {
    srcIP: parsed.srcIP,
    dstIP: parsed.dstIP,
    srcPort: tcp.readUInt16BE(0),
    dstPort: tcp.readUInt16BE(2),
    seq: tcp.readUInt32BE(4),
    ack: tcp.readUInt32BE(8),
    flags: tcp[13],
    checksumOk: tcpChecksum(parsed.packet) === tcp.readUInt16BE(16),
  };
}

test("a segment for an unknown connection is reset as RFC 9293 describes", () => {
  const policy = makePolicy({ tier: "user", owner: "user:1" });
  const session = attach(policy, fakeSession());
  const segment = { srcIP: "10.0.2.15", srcPort: 40000, dstIP: "93.184.216.34", dstPort: 443 };

  // With ACK: a bare RST whose sequence number is the segment's ACK.
  policy.onUnknownTcpSegment(session, { ...segment, seqNum: 100, ackNum: 5000, flags: 0x18, length: 10 });
  let rst = parseReset(session.sent.pop());
  assert.deepEqual(
    [rst.srcIP, rst.srcPort, rst.dstIP, rst.dstPort, rst.seq, rst.flags],
    ["93.184.216.34", 443, "10.0.2.15", 40000, 5000, 0x04],
  );
  assert.equal(rst.checksumOk, true);

  // Without ACK: RST|ACK acknowledging the segment, FIN counting as one.
  policy.onUnknownTcpSegment(session, { ...segment, seqNum: 0xfffffffe, ackNum: 0, flags: 0x01, length: 3 });
  rst = parseReset(session.sent.pop());
  assert.equal(rst.seq, 0);
  assert.equal(rst.ack, 2, "sequence numbers wrap");
  assert.equal(rst.flags, 0x14);

  // A reset is never answered.
  policy.onUnknownTcpSegment(session, { ...segment, seqNum: 1, ackNum: 1, flags: 0x14, length: 0 });
  assert.equal(session.sent.length, 0);
  assert.equal(policy.counters.unknownTcpResets, 2);
});

test("segments toward an address held for the owner are not reset; others are", () => {
  const ctx = makeCtx();
  ctx.addressHolds = createAddressHolds({ ctx, holdMs: 60000, setTimer: () => null, clearTimer: () => {} });
  const gone = { vmIP: "10.0.2.16", vmMAC: "52:54:00:00:00:16" };
  ctx.usedIPs.add(16);
  ctx.ipToSession.set("10.0.2.16", gone);
  assert.equal(ctx.addressHolds.hold(gone, "user:1"), true);

  const segment = { srcIP: "10.0.2.15", srcPort: 40000, dstIP: "10.0.2.16", dstPort: 3240, seqNum: 1, ackNum: 1, flags: 0x10, length: 0 };
  const peer = attach(makePolicy({ tier: "user", owner: "user:1", ctx }), fakeSession("a"));
  peer.policy.onUnknownTcpSegment(peer, segment);
  assert.equal(peer.sent.length, 0, "the peer may come back");

  const stranger = attach(makePolicy({ tier: "user", owner: "user:2", ctx }), fakeSession("b"));
  stranger.policy.onUnknownTcpSegment(stranger, segment);
  assert.equal(stranger.sent.length, 1, "other owners see no difference from an unused address");
});

test("claimIP refuses an address held for another owner and reclaims one held for the same owner", () => {
  const ctx = makeCtx();
  ctx.addressHolds = createAddressHolds({ ctx, holdMs: 60000, setTimer: () => null, clearTimer: () => {} });
  const gone = { vmIP: "10.0.2.20", vmMAC: "52:54:00:00:00:20" };
  ctx.usedIPs.add(20);
  ctx.ipToSession.set("10.0.2.20", gone);
  ctx.addressHolds.hold(gone, "user:1");

  const stranger = attach(makePolicy({ tier: "user", owner: "user:2", ctx }), fakeSession("b"));
  assert.equal(admit(stranger.policy, stranger, tcpPacket({ srcIP: "10.0.2.20", dstIP: "1.1.1.1" })), false);
  assert.equal(stranger.vmIP, null);

  const back = attach(makePolicy({ tier: "user", owner: "user:1", ctx }), fakeSession("a"));
  assert.equal(admit(back.policy, back, tcpPacket({ srcIP: "10.0.2.20", dstIP: "1.1.1.1" })), true);
  assert.equal(back.vmIP, "10.0.2.20");
  assert.equal(ctx.ipToSession.get("10.0.2.20"), back);
  assert.equal(ctx.addressHolds.size, 0);
});

function silentHolder(ctx, { owner = "user:1", lastActivityAt = 0 } = {}) {
  const holder = attach(makePolicy({ tier: "user", owner, ctx }), fakeSession("old"));
  holder.vmIP = "10.0.2.30";
  holder.vmMAC = "52:54:00:00:00:30";
  holder.vmMACBytes = Buffer.from([0x52, 0x54, 0, 0, 0, 0x30]);
  holder.lastActivityAt = lastActivityAt;
  holder.ws = { readyState: 1, terminated: false, terminate() { this.terminated = true; } };
  ctx.usedIPs.add(30);
  ctx.macToIP.set(holder.vmMAC, holder.vmIP);
  ctx.ipToSession.set(holder.vmIP, holder);
  return holder;
}

test("a new session of the same owner takes over the MAC of a silent session", () => {
  const ctx = makeCtx();
  const holder = silentHolder(ctx);
  const session = attach(makePolicy({ tier: "user", owner: "user:1", ctx, now: () => 10000 }), fakeSession("new"));

  assert.equal(session.policy.admitFrame(session, holder.vmMACBytes), true);
  assert.equal(holder.ws.terminated, true);
  assert.equal(ctx.ipToSession.has("10.0.2.30"), false);
  assert.equal(ctx.macToIP.get("52:54:00:00:00:30"), "10.0.2.30", "DHCP returns the same address");
  assert.ok(ctx.usedIPs.has(30));
  assert.equal(holder.vmMAC, null, "the old session's close releases nothing");
  assert.equal(session.policy.counters.takeovers, 1);
});

test("no takeover of a session that is still talking, or of another owner's", () => {
  const ctx = makeCtx();
  const busy = silentHolder(ctx, { lastActivityAt: 8000 });
  const session = attach(makePolicy({ tier: "user", owner: "user:1", ctx, now: () => 10000 }), fakeSession("new"));
  assert.equal(session.policy.admitFrame(session, busy.vmMACBytes), false);
  assert.equal(busy.ws.terminated, false);

  const ctx2 = makeCtx();
  const theirs = silentHolder(ctx2, { owner: "user:2" });
  const stranger = attach(makePolicy({ tier: "user", owner: "user:1", ctx: ctx2, now: () => 10000 }), fakeSession("new"));
  assert.equal(stranger.policy.admitFrame(stranger, theirs.vmMACBytes), false);
  assert.equal(stranger.policy.admitIPv4 && admit(stranger.policy, stranger, tcpPacket({ srcIP: "10.0.2.30", dstIP: "1.1.1.1" })), false);
  assert.equal(theirs.ws.terminated, false);
});

test("claiming a silent session's address with a new MAC takes it over and drops the old binding", () => {
  const ctx = makeCtx();
  const holder = silentHolder(ctx);
  const session = attach(makePolicy({ tier: "user", owner: "user:1", ctx, now: () => 10000 }), fakeSession("new"));
  session.vmMAC = "52:54:00:00:00:31";
  assert.equal(admit(session.policy, session, tcpPacket({ srcIP: "10.0.2.30", dstIP: "1.1.1.1" })), true);
  assert.equal(session.vmIP, "10.0.2.30");
  assert.equal(ctx.ipToSession.get("10.0.2.30"), session);
  assert.equal(ctx.macToIP.has("52:54:00:00:00:30"), false);
  assert.equal(holder.ws.terminated, true);
});
