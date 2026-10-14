"use strict";

// End-to-end checks of hosted mode against a spawned relay: authentication at
// the WebSocket upgrade, anonymous tokens, egress denial with RST, anti-spoof,
// tenant isolation, admission caps, operator tooling and graceful shutdown.

const test = require("node:test");
const assert = require("node:assert/strict");
const net = require("node:net");
const {
  FrameQueue,
  GATEWAY_IP,
  buildARPRequest,
  buildTCPFrame,
  buildUDPFrame,
  delay,
  httpJson,
  listen,
  macFromNumber,
  openWebSocket,
  startRelay,
} = require("./helpers/relay_harness");

const NETWORK = { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 20000 };

function buildDHCPDiscover(vmMAC) {
  const dhcp = Buffer.alloc(244);
  dhcp[0] = 1;
  dhcp[1] = 1;
  dhcp[2] = 6;
  dhcp.writeUInt32BE(0x12345678, 4);
  vmMAC.copy(dhcp, 28);
  dhcp.writeUInt32BE(0x63825363, 236);
  dhcp[240] = 53;
  dhcp[241] = 1;
  dhcp[242] = 1;
  dhcp[243] = 255;
  return buildUDPFrame({
    vmMAC,
    srcIP: "0.0.0.0",
    dstIP: "255.255.255.255",
    srcPort: 68,
    dstPort: 67,
    payload: dhcp,
  });
}

async function anonToken(relay) {
  const response = await httpJson(relay.wsPort, { method: "POST", path: "/api/anon/token", body: {} });
  assert.equal(response.status, 200, response.text);
  return response.body.token;
}

async function sessionsByMac(relay, cookie) {
  const response = await httpJson(relay.adminPort, { path: "/api/sessions", cookie });
  assert.equal(response.status, 200);
  const map = new Map();
  for (const session of response.body) map.set(session.vmMAC, session);
  return map;
}

function macString(mac) {
  return Array.from(mac).map((b) => b.toString(16).padStart(2, "0")).join(":");
}

async function bringUp(relay, ws, vmMAC, cookie, vmIP = null) {
  // ARP for the gateway assigns an IP (learn-then-lock also accepts a
  // consistent source address); read the assignment back from the admin API.
  ws.send(buildARPRequest({ vmMAC, vmIP: vmIP || "0.0.0.0" }));
  await delay(60);
  const sessions = await sessionsByMac(relay, cookie);
  const session = sessions.get(macString(vmMAC));
  assert.ok(session && session.vmIP, "session has a VM IP after ARP");
  return session;
}

test("local mode: plain WebSocket accepted, anon endpoint absent", NETWORK, async () => {
  const relay = await startRelay();
  try {
    const { ws, status } = await openWebSocket(relay.wsPort);
    assert.equal(status, 101);
    ws.close();
    assert.equal((await httpJson(relay.wsPort, { method: "POST", path: "/api/anon/token", body: {} })).status, 404);
  } finally {
    await relay.close();
  }
});

test("hosted mode: upgrade needs a credential; anon token works; DHCP and ARP work; egress denial answers RST", NETWORK, async () => {
  const relay = await startRelay({ hosted: true });
  const sink = net.createServer((socket) => socket.end());
  const sinkPort = await listen(sink);
  try {
    assert.equal((await openWebSocket(relay.wsPort)).status, 401);
    assert.equal((await openWebSocket(relay.wsPort, { bearer: "rr_000000000000_bogus" })).status, 401);

    const token = await anonToken(relay);
    const { ws, status } = await openWebSocket(relay.wsPort, { token });
    assert.equal(status, 101);
    assert.equal(ws.protocol, "relay.v1");
    const frames = new FrameQueue(ws);
    const vmMAC = macFromNumber(1);

    ws.send(buildDHCPDiscover(vmMAC));
    const offer = await frames.waitFor((f) => f.kind === "udp" && f.srcPort === 67);
    assert.equal(offer.srcIP, GATEWAY_IP);

    const cookie = await relay.adminCookie();
    const session = await bringUp(relay, ws, vmMAC, cookie);
    assert.equal(session.tier, "anon");
    assert.match(session.owner, /^anon:/);
    const arpReply = await frames.waitFor((f) => f.kind === "arp" && f.opcode === 2);
    assert.equal(arpReply.senderIP, GATEWAY_IP);

    // Loopback is denied in hosted mode: the VM gets an immediate RST.
    ws.send(buildTCPFrame({
      vmMAC, srcIP: session.vmIP, dstIP: "127.0.0.1", srcPort: 40000, dstPort: sinkPort, seq: 100, flags: { syn: true },
    }));
    const rst = await frames.waitFor((f) => f.kind === "tcp" && f.dstPort === 40000);
    assert.equal(rst.rst, true);
    assert.equal(rst.srcIP, "127.0.0.1");
    assert.equal(rst.ack, 101);

    // Metadata service and a non-allow-listed port are denied the same way.
    ws.send(buildTCPFrame({
      vmMAC, srcIP: session.vmIP, dstIP: "169.254.169.254", srcPort: 40001, dstPort: 80, seq: 7, flags: { syn: true },
    }));
    assert.equal((await frames.waitFor((f) => f.kind === "tcp" && f.dstPort === 40001)).rst, true);

    const after = await sessionsByMac(relay, cookie);
    assert.equal(after.get(macString(vmMAC)).policy.egressDenied, 2);
    assert.equal(after.get(macString(vmMAC)).tcpConnections, 0);
    ws.close();
  } finally {
    sink.close();
    await relay.close();
  }
});

test("hosted mode: allow-listed loopback plus an open port list lets the handshake through", NETWORK, async () => {
  const relay = await startRelay({
    hosted: true,
    env: { EGRESS_ALLOW_CIDRS: "127.0.0.0/8", TIERS_JSON: JSON.stringify({ anon: { allowedTcpPorts: null } }) },
  });
  const sink = net.createServer((socket) => socket.on("data", () => {}));
  const sinkPort = await listen(sink);
  try {
    const { ws } = await openWebSocket(relay.wsPort, { token: await anonToken(relay) });
    const frames = new FrameQueue(ws);
    const vmMAC = macFromNumber(2);
    const session = await bringUp(relay, ws, vmMAC, await relay.adminCookie());
    ws.send(buildTCPFrame({
      vmMAC, srcIP: session.vmIP, dstIP: "127.0.0.1", srcPort: 40100, dstPort: sinkPort, seq: 500, flags: { syn: true },
    }));
    const synAck = await frames.waitFor((f) => f.kind === "tcp" && f.dstPort === 40100);
    assert.equal(synAck.syn && synAck.ackFlag, true);
    assert.equal(synAck.rst, false);
    assert.equal(synAck.ack, 501);
    ws.close();
  } finally {
    sink.close();
    await relay.close();
  }
});

test("anti-spoof: a session may only send from its assigned address", NETWORK, async () => {
  const relay = await startRelay({
    hosted: true,
    env: { EGRESS_ALLOW_CIDRS: "127.0.0.0/8", TIERS_JSON: JSON.stringify({ anon: { allowedTcpPorts: null } }) },
  });
  const sink = net.createServer((socket) => socket.on("data", () => {}));
  const sinkPort = await listen(sink);
  try {
    const { ws } = await openWebSocket(relay.wsPort, { token: await anonToken(relay) });
    const frames = new FrameQueue(ws);
    const vmMAC = macFromNumber(3);
    const cookie = await relay.adminCookie();
    const session = await bringUp(relay, ws, vmMAC, cookie);
    const other = session.vmIP.replace(/\.\d+$/, (m) => `.${Number(m.slice(1)) + 1}`);

    ws.send(buildTCPFrame({
      vmMAC, srcIP: other, dstIP: "127.0.0.1", srcPort: 40200, dstPort: sinkPort, seq: 1, flags: { syn: true },
    }));
    assert.equal(await frames.expectNone((f) => f.kind === "tcp" && f.dstPort === 40200, 300), true, "spoofed SYN is dropped");

    ws.send(buildTCPFrame({
      vmMAC: macFromNumber(99), srcIP: session.vmIP, dstIP: "127.0.0.1", srcPort: 40201, dstPort: sinkPort, seq: 1, flags: { syn: true },
    }));
    assert.equal(await frames.expectNone((f) => f.kind === "tcp" && f.dstPort === 40201, 300), true, "changed MAC is dropped");

    ws.send(buildDHCPDiscover(vmMAC));
    assert.equal((await frames.waitFor((f) => f.kind === "udp" && f.srcPort === 67)).srcIP, GATEWAY_IP, "DHCP still answered");

    const counters = (await sessionsByMac(relay, cookie)).get(macString(vmMAC)).policy;
    assert.equal(counters.spoofDrops, 1);
    assert.equal(counters.macDrops, 1);
    ws.close();
  } finally {
    sink.close();
    await relay.close();
  }
});

test("tenant isolation: anon sessions cannot see each other; one account's sessions can", NETWORK, async () => {
  const relay = await startRelay({ hosted: true, env: { ENABLE_VM_TO_VM: "true" } });
  try {
    const cookie = await relay.adminCookie();
    const a = await openWebSocket(relay.wsPort, { token: await anonToken(relay) });
    const b = await openWebSocket(relay.wsPort, { token: await anonToken(relay) });
    const framesA = new FrameQueue(a.ws);
    const macA = macFromNumber(10);
    const macB = macFromNumber(11);
    const sessionA = await bringUp(relay, a.ws, macA, cookie);
    const sessionB = await bringUp(relay, b.ws, macB, cookie);
    assert.notEqual(sessionA.owner, sessionB.owner);

    a.ws.send(buildARPRequest({ vmMAC: macA, vmIP: sessionA.vmIP, targetIP: sessionB.vmIP }));
    assert.equal(
      await framesA.expectNone((f) => f.kind === "arp" && f.senderIP === sessionB.vmIP, 300),
      true,
      "no ARP reply for another tenant's VM",
    );
    a.ws.send(buildTCPFrame({
      vmMAC: macA, srcIP: sessionA.vmIP, dstIP: sessionB.vmIP, srcPort: 40300, dstPort: 22, seq: 9, flags: { syn: true },
    }));
    const rst = await framesA.waitFor((f) => f.kind === "tcp" && f.dstPort === 40300);
    assert.equal(rst.rst, true, "cross-tenant SYN is refused");
    a.ws.close();
    b.ws.close();
    await delay(50);

    // One account, two sessions: same owner, VM-to-VM allowed.
    const created = await httpJson(relay.adminPort, {
      method: "POST", path: "/api/users", cookie, body: { username: "pair", password: "pair-password" },
    });
    assert.equal(created.status, 201, created.text);
    const tokenRes = await httpJson(relay.adminPort, {
      method: "POST", path: `/api/users/${created.body.id}/tokens`, cookie, body: { name: "t" },
    });
    assert.equal(tokenRes.status, 201);
    const c = await openWebSocket(relay.wsPort, { token: tokenRes.body.token });
    const d = await openWebSocket(relay.wsPort, { bearer: tokenRes.body.token });
    assert.equal(c.status, 101);
    assert.equal(d.status, 101);
    const framesC = new FrameQueue(c.ws);
    const macC = macFromNumber(12);
    const macD = macFromNumber(13);
    const sessionC = await bringUp(relay, c.ws, macC, cookie);
    const sessionD = await bringUp(relay, d.ws, macD, cookie);
    assert.equal(sessionC.owner, `user:${created.body.id}`);
    assert.equal(sessionC.owner, sessionD.owner);
    assert.equal(sessionC.username, "pair");
    c.ws.send(buildARPRequest({ vmMAC: macC, vmIP: sessionC.vmIP, targetIP: sessionD.vmIP }));
    const reply = await framesC.waitFor((f) => f.kind === "arp" && f.opcode === 2 && f.senderIP === sessionD.vmIP);
    assert.ok(reply, "same-owner ARP is answered");
    c.ws.close();
    d.ws.close();
  } finally {
    await relay.close();
  }
});

test("admission caps: anon sessions per token and per address, pool exhaustion reported", NETWORK, async () => {
  const relay = await startRelay({ hosted: true });
  try {
    const token = await anonToken(relay);
    const first = await openWebSocket(relay.wsPort, { token });
    assert.equal(first.status, 101);
    assert.equal((await openWebSocket(relay.wsPort, { token })).status, 429, "one session per anon token");
    const second = await openWebSocket(relay.wsPort, { token: await anonToken(relay) });
    assert.equal(second.status, 101);
    assert.equal((await openWebSocket(relay.wsPort, { token: await anonToken(relay) })).status, 429, "two anon sessions per address");
    first.ws.close();
    second.ws.close();
    await delay(50);
    const third = await openWebSocket(relay.wsPort, { token: await anonToken(relay) });
    assert.equal(third.status, 101, "slots are released on close");
    third.ws.close();
  } finally {
    await relay.close();
  }
});

test("operator flow: users, tokens, sessions list, kill, ban, rules disabled", NETWORK, async () => {
  const relay = await startRelay({ hosted: true });
  try {
    const cookie = await relay.adminCookie();
    assert.equal((await httpJson(relay.adminPort, { path: "/api/users" })).status, 401);
    const config = await httpJson(relay.adminPort, { path: "/api/config", cookie });
    assert.equal(config.body.mode, "hosted");
    assert.equal(config.body.inboundRulesEnabled, false);

    const bad = await httpJson(relay.adminPort, { method: "POST", path: "/api/users", cookie, body: { username: "x y", password: "password-1" } });
    assert.equal(bad.status, 400);
    const created = await httpJson(relay.adminPort, { method: "POST", path: "/api/users", cookie, body: { username: "carol", password: "carol-password" } });
    assert.equal(created.status, 201);
    assert.equal(created.body.role, "user");
    assert.equal((await httpJson(relay.adminPort, { method: "POST", path: "/api/users", cookie, body: { username: "carol", password: "carol-password" } })).status, 409);

    const tokenRes = await httpJson(relay.adminPort, { method: "POST", path: `/api/users/${created.body.id}/tokens`, cookie, body: { name: "cli" } });
    assert.equal(tokenRes.status, 201);
    assert.match(tokenRes.body.token, /^rr_/);

    const conn = await openWebSocket(relay.wsPort, { bearer: tokenRes.body.token });
    assert.equal(conn.status, 101);
    const closed = new Promise((resolve) => conn.ws.once("close", (code, reason) => resolve({ code, reason: reason.toString() })));
    await delay(30);
    const sessions = await httpJson(relay.adminPort, { path: "/api/sessions", cookie });
    assert.equal(sessions.body.length, 1);
    assert.equal(sessions.body[0].owner, `user:${created.body.id}`);
    assert.equal(sessions.body[0].username, "carol");
    assert.equal(sessions.body[0].tier, "user");

    assert.equal((await httpJson(relay.adminPort, { method: "DELETE", path: `/api/sessions/${sessions.body[0].sessionId}`, cookie })).status, 204);
    assert.deepEqual(await closed, { code: 1008, reason: "terminated by operator" });

    const reconnect = await openWebSocket(relay.wsPort, { bearer: tokenRes.body.token });
    assert.equal(reconnect.status, 101);
    const bannedClose = new Promise((resolve) => reconnect.ws.once("close", (code) => resolve(code)));
    const ban = await httpJson(relay.adminPort, { method: "POST", path: `/api/users/${created.body.id}/ban`, cookie });
    assert.equal(ban.status, 200);
    assert.equal(ban.body.killedSessions, 1);
    assert.equal(await bannedClose, 1008);
    assert.equal((await openWebSocket(relay.wsPort, { bearer: tokenRes.body.token })).status, 403);
    assert.equal((await httpJson(relay.adminPort, { method: "POST", path: `/api/users/${created.body.id}/unban`, cookie })).status, 200);

    const userView = await httpJson(relay.adminPort, { path: `/api/users/${created.body.id}`, cookie });
    assert.equal(userView.body.tokens.length, 1);
    assert.equal((await httpJson(relay.adminPort, { method: "DELETE", path: `/api/tokens/${tokenRes.body.id}`, cookie })).status, 204);
    assert.equal((await openWebSocket(relay.wsPort, { bearer: tokenRes.body.token })).status, 401);

    const doomed = await httpJson(relay.adminPort, { method: "POST", path: "/api/users", cookie, body: { username: "dave", role: "user" } });
    const doomedToken = await httpJson(relay.adminPort, { method: "POST", path: `/api/users/${doomed.body.id}/tokens`, cookie, body: {} });
    const doomedConn = await openWebSocket(relay.wsPort, { bearer: doomedToken.body.token });
    assert.equal(doomedConn.status, 101);
    const deletedClose = new Promise((resolve) => doomedConn.ws.once("close", (code) => resolve(code)));
    assert.equal((await httpJson(relay.adminPort, { method: "DELETE", path: `/api/users/${doomed.body.id}`, cookie })).status, 204);
    assert.equal(await deletedClose, 1008);
    assert.equal((await httpJson(relay.adminPort, { path: `/api/users/${doomed.body.id}`, cookie })).status, 404);
    assert.equal((await openWebSocket(relay.wsPort, { bearer: doomedToken.body.token })).status, 401);
    assert.equal((await httpJson(relay.adminPort, { method: "DELETE", path: `/api/users/${doomed.body.id}`, cookie })).status, 404);
    const me = (await httpJson(relay.adminPort, { path: "/api/users", cookie })).body.find((u) => u.role === "operator");
    assert.equal((await httpJson(relay.adminPort, { method: "DELETE", path: `/api/users/${me.id}`, cookie })).status, 400);

    const invite = await httpJson(relay.adminPort, { method: "POST", path: "/api/invites", cookie, body: { note: "beta tester", expiresInDays: 7 } });
    assert.equal(invite.status, 201);
    assert.match(invite.body.code, /^RLY-/);
    assert.equal((await httpJson(relay.adminPort, { method: "POST", path: "/api/invites", cookie, body: { expiresInDays: 0 } })).status, 400);
    const inviteList = await httpJson(relay.adminPort, { path: "/api/invites", cookie });
    assert.deepEqual(inviteList.body.map((i) => [i.note, i.state, i.code]), [["beta tester", "open", undefined]]);
    assert.equal((await httpJson(relay.adminPort, { method: "DELETE", path: `/api/invites/${invite.body.id}`, cookie })).status, 204);
    assert.equal((await httpJson(relay.adminPort, { method: "DELETE", path: `/api/invites/${invite.body.id}`, cookie })).status, 404);
    assert.equal((await httpJson(relay.adminPort, { path: "/api/config", cookie })).body.signupMode, "open");
    assert.equal((await httpJson(relay.adminPort, { path: "/api/audit?dstIp=1.2.3.4&at=2026-10-14T00:00:00Z&windowMinutes=10", cookie })).status, 200);
    assert.equal((await httpJson(relay.adminPort, { path: "/api/audit?at=yesterday", cookie })).status, 400);
    assert.equal((await httpJson(relay.adminPort, { path: "/api/audit?dstPort=70000", cookie })).status, 400);

    assert.equal((await httpJson(relay.adminPort, { path: "/api/rules", cookie })).status, 403);
    assert.equal((await httpJson(relay.adminPort, {
      method: "POST", path: "/api/rules", cookie,
      body: { type: "port", protocols: ["tcp"], host_port: 39000, vm: "10.0.2.15", port: 22 },
    })).status, 403);
  } finally {
    await relay.close();
  }
});

test("account API: a user sees and manages only their own sessions and tokens", NETWORK, async () => {
  const relay = await startRelay({ hosted: true });
  try {
    const cookie = await relay.adminCookie();
    const dave = (await httpJson(relay.adminPort, { method: "POST", path: "/api/users", cookie, body: { username: "dave", password: "dave-password" } })).body;
    const erin = (await httpJson(relay.adminPort, { method: "POST", path: "/api/users", cookie, body: { username: "erin", password: "erin-password" } })).body;
    const daveToken = (await httpJson(relay.adminPort, { method: "POST", path: `/api/users/${dave.id}/tokens`, cookie, body: { name: "seed" } })).body.token;
    const erinToken = (await httpJson(relay.adminPort, { method: "POST", path: `/api/users/${erin.id}/tokens`, cookie, body: { name: "seed" } })).body.token;
    const asDave = { Authorization: `Bearer ${daveToken}` };
    const asErin = { Authorization: `Bearer ${erinToken}` };

    assert.equal((await httpJson(relay.wsPort, { path: "/api/me" })).status, 401);
    const anon = await anonToken(relay);
    assert.equal((await httpJson(relay.wsPort, { path: "/api/me", headers: { Authorization: `Bearer ${anon}` } })).status, 403);

    const me = await httpJson(relay.wsPort, { path: "/api/me", headers: asDave });
    assert.equal(me.status, 200);
    assert.equal(me.body.user.username, "dave");
    assert.equal(me.body.tier.name, "user");
    assert.equal(me.body.activeSessions, 0);

    const conn = await openWebSocket(relay.wsPort, { bearer: daveToken });
    assert.equal(conn.status, 101);
    await delay(30);
    const mine = await httpJson(relay.wsPort, { path: "/api/me/sessions", headers: asDave });
    assert.equal(mine.body.length, 1);
    assert.equal((await httpJson(relay.wsPort, { path: "/api/me/sessions", headers: asErin })).body.length, 0);
    const sessionId = mine.body[0].sessionId;
    assert.equal((await httpJson(relay.wsPort, { method: "DELETE", path: `/api/me/sessions/${sessionId}`, headers: asErin })).status, 404);
    const closed = new Promise((resolve) => conn.ws.once("close", (code, reason) => resolve({ code, reason: reason.toString() })));
    assert.equal((await httpJson(relay.wsPort, { method: "DELETE", path: `/api/me/sessions/${sessionId}`, headers: asDave })).status, 204);
    assert.deepEqual(await closed, { code: 1008, reason: "terminated by account owner" });

    const created = await httpJson(relay.wsPort, { method: "POST", path: "/api/me/tokens", headers: asDave, body: { name: "laptop", expiresInDays: 7 } });
    assert.equal(created.status, 201);
    assert.equal((await openWebSocket(relay.wsPort, { token: created.body.token })).status, 101);
    const list = await httpJson(relay.wsPort, { path: "/api/me/tokens", headers: asDave });
    assert.deepEqual(list.body.map((t) => t.name), ["seed", "laptop"]);
    assert.equal((await httpJson(relay.wsPort, { method: "DELETE", path: `/api/me/tokens/${created.body.id}`, headers: asErin })).status, 404);
    assert.equal((await httpJson(relay.wsPort, { method: "DELETE", path: `/api/me/tokens/${created.body.id}`, headers: asDave })).status, 204);
    assert.equal((await openWebSocket(relay.wsPort, { token: created.body.token })).status, 401);

    const usage = await httpJson(relay.wsPort, { path: "/api/me/usage", headers: asDave });
    assert.equal(usage.status, 200);
    assert.equal(usage.body.current.period, "month");
    assert.ok(Array.isArray(usage.body.months));
  } finally {
    await relay.close();
  }
});

test("audit log, usage, metrics and quota enforcement", NETWORK, async () => {
  const relay = await startRelay({
    hosted: true,
    env: {
      EGRESS_ALLOW_CIDRS: "127.0.0.0/8",
      USAGE_FLUSH_INTERVAL_MS: "150",
      METRICS_TOKEN: "scrape-me",
      TIERS_JSON: JSON.stringify({ user: { quotaBytes: 2000 } }),
    },
  });
  const sink = net.createServer((socket) => {
    socket.on("data", () => {});
    socket.write(Buffer.alloc(1500, 0x41));
  });
  const sinkPort = await listen(sink);
  try {
    const cookie = await relay.adminCookie();
    const created = await httpJson(relay.adminPort, { method: "POST", path: "/api/users", cookie, body: { username: "dave", password: "dave-password" } });
    const tokenRes = await httpJson(relay.adminPort, { method: "POST", path: `/api/users/${created.body.id}/tokens`, cookie, body: {} });
    const { ws } = await openWebSocket(relay.wsPort, { token: tokenRes.body.token });
    const frames = new FrameQueue(ws);
    const closed = new Promise((resolve) => ws.once("close", (code, reason) => resolve({ code, reason: reason.toString() })));
    const vmMAC = macFromNumber(20);
    const session = await bringUp(relay, ws, vmMAC, cookie);

    // One denied and one allowed connection.
    ws.send(buildTCPFrame({ vmMAC, srcIP: session.vmIP, dstIP: "169.254.169.254", srcPort: 41000, dstPort: 80, seq: 1, flags: { syn: true } }));
    await frames.waitFor((f) => f.kind === "tcp" && f.dstPort === 41000 && f.rst);
    ws.send(buildTCPFrame({ vmMAC, srcIP: session.vmIP, dstIP: "127.0.0.1", srcPort: 41001, dstPort: sinkPort, seq: 1, flags: { syn: true } }));
    const synAck = await frames.waitFor((f) => f.kind === "tcp" && f.dstPort === 41001 && f.syn);
    ws.send(buildTCPFrame({ vmMAC, srcIP: session.vmIP, dstIP: "127.0.0.1", srcPort: 41001, dstPort: sinkPort, seq: 2, ack: synAck.seq + 1, flags: { ack: true } }));
    // The sink pushes 1500 bytes toward the VM; acknowledge what arrives so
    // the relay keeps sending and the session's byte counters grow.
    const data = await frames.waitFor((f) => f.kind === "tcp" && f.dstPort === 41001 && f.payload.length > 0, 3000);
    ws.send(buildTCPFrame({ vmMAC, srcIP: session.vmIP, dstIP: "127.0.0.1", srcPort: 41001, dstPort: sinkPort, seq: 2, ack: data.seq + data.payload.length, flags: { ack: true } }));

    // Keep pushing bytes through until the 2000-byte user quota closes the session.
    const quotaClose = await Promise.race([closed, delay(6000).then(() => null)]);
    assert.deepEqual(quotaClose, { code: 1008, reason: "quota exceeded" });

    const usageRes = await httpJson(relay.adminPort, { path: `/api/usage/${created.body.id}`, cookie });
    assert.equal(usageRes.status, 200);
    assert.equal(usageRes.body.quotaBytes, 2000);
    assert.ok(usageRes.body.currentPeriodBytes >= 2000, `usage ${usageRes.body.currentPeriodBytes}`);
    assert.equal(usageRes.body.months.length, 1);
    assert.equal((await openWebSocket(relay.wsPort, { token: tokenRes.body.token })).status, 429, "over quota is refused at upgrade");

    await delay(2500); // audit batch interval
    const auditRes = await httpJson(relay.adminPort, { path: `/api/audit?owner=user:${created.body.id}`, cookie });
    assert.equal(auditRes.status, 200);
    assert.equal(auditRes.body.enabled, true);
    const verdicts = auditRes.body.rows.map((row) => `${row.dstIP}:${row.dstPort}=${row.verdict.split(":")[0]}`).sort();
    assert.deepEqual(verdicts, [`127.0.0.1:${sinkPort}=allow`, "169.254.169.254:80=deny"]);
    const allowed = auditRes.body.rows.find((row) => row.verdict.startsWith("allow"));
    assert.ok(allowed.endedAt, "allowed connection has an end time after the session closed");
    assert.equal((await httpJson(relay.adminPort, { path: "/api/audit?verdict=deny", cookie })).body.rows.length, 1);

    assert.equal((await httpJson(relay.adminPort, { path: "/metrics" })).status, 401);
    const scraped = await httpJson(relay.adminPort, { path: "/metrics", headers: { Authorization: "Bearer scrape-me" } });
    assert.equal(scraped.status, 200);
    assert.match(scraped.text, /rootlessrelay_egress_denied_total\{proto="tcp"\} 1/);
    assert.match(scraped.text, /rootlessrelay_bytes_total\{direction="to_vm",tier="user"\} [1-9]/);
    assert.match(scraped.text, /rootlessrelay_upgrade_rejections_total\{status="429"\} 1/);
    assert.equal((await httpJson(relay.adminPort, { path: "/metrics", cookie })).status, 200);
  } finally {
    sink.close();
    await relay.close();
  }
});

test("healthz and graceful shutdown: clients get 1001 and the process exits 0 within a second", NETWORK, async () => {
  const relay = await startRelay({ hosted: true });
  const token = await anonToken(relay);
  const { ws } = await openWebSocket(relay.wsPort, { token });
  const closed = new Promise((resolve) => ws.once("close", (code, reason) => resolve({ code, reason: reason.toString() })));
  const health = await httpJson(relay.wsPort, { path: "/healthz" });
  assert.equal(health.status, 200);
  assert.deepEqual(health.body, { ok: true, mode: "hosted", sessions: 1 });

  const started = Date.now();
  relay.child.kill("SIGTERM");
  assert.deepEqual(await closed, { code: 1001, reason: "server shutting down" });
  const exit = await relay.exited;
  assert.equal(exit.code, 0);
  assert.ok(Date.now() - started < 1000, "exited within the SIGKILL window");
  await relay.close();
});
