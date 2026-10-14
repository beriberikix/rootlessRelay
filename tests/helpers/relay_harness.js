"use strict";

// Shared helpers for network tests that spawn relay.js as a child process:
// frame builders for a fake VM, a WebSocket connector, an admin API client,
// and a relay launcher with mode/env overrides.

const { spawn } = require("node:child_process");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const WebSocket = require("ws");
const { buildIPv4Packet, parseIPv4Packet, tcpChecksum } = require("../../packet_utils");

const ROOT = path.join(__dirname, "..", "..");
const GATEWAY_IP = "10.0.2.2";
const GATEWAY_MAC = Buffer.from([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

const ADMIN_USER = "test-admin";
const ADMIN_PASSWORD = "test-admin-password";
const ADMIN_SECRET = "test-session-secret";

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function freeTcpPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      server.close((error) => (error ? reject(error) : resolve(port)));
    });
  });
}

function listen(server, port = 0) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve(server.address().port);
    });
  });
}

function macFromNumber(n) {
  return Buffer.from([0x52, 0x54, 0x00, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function buildTCPFrame({ vmMAC, srcIP, dstIP, srcPort, dstPort, seq, ack = 0, flags = {}, payload = Buffer.alloc(0), window = 65535 }) {
  const tcp = Buffer.alloc(20 + payload.length);
  tcp.writeUInt16BE(srcPort, 0);
  tcp.writeUInt16BE(dstPort, 2);
  tcp.writeUInt32BE(seq >>> 0, 4);
  tcp.writeUInt32BE(ack >>> 0, 8);
  tcp[12] = 5 << 4;
  tcp[13] = (flags.fin ? 0x01 : 0) | (flags.syn ? 0x02 : 0) | (flags.rst ? 0x04 : 0) |
    (flags.psh ? 0x08 : 0) | (flags.ack ? 0x10 : 0);
  tcp.writeUInt16BE(window, 14);
  payload.copy(tcp, 20);
  const ip = buildIPv4Packet(tcp, srcIP, dstIP, 6, 1);
  ip.writeUInt16BE(tcpChecksum(ip), 36);
  const frame = Buffer.alloc(14 + ip.length);
  GATEWAY_MAC.copy(frame, 0);
  vmMAC.copy(frame, 6);
  frame.writeUInt16BE(0x0800, 12);
  ip.copy(frame, 14);
  return frame;
}

function buildUDPFrame({ vmMAC, srcIP, dstIP, srcPort, dstPort, payload = Buffer.alloc(8) }) {
  const udp = Buffer.alloc(8 + payload.length);
  udp.writeUInt16BE(srcPort, 0);
  udp.writeUInt16BE(dstPort, 2);
  udp.writeUInt16BE(udp.length, 4);
  payload.copy(udp, 8);
  const ip = buildIPv4Packet(udp, srcIP, dstIP, 17, 1);
  const frame = Buffer.alloc(14 + ip.length);
  GATEWAY_MAC.copy(frame, 0);
  vmMAC.copy(frame, 6);
  frame.writeUInt16BE(0x0800, 12);
  ip.copy(frame, 14);
  return frame;
}

function buildARPRequest({ vmMAC, vmIP, targetIP = GATEWAY_IP }) {
  const frame = Buffer.alloc(42);
  frame.fill(0xff, 0, 6);
  vmMAC.copy(frame, 6);
  frame.writeUInt16BE(0x0806, 12);
  frame.writeUInt16BE(1, 14);
  frame.writeUInt16BE(0x0800, 16);
  frame[18] = 6;
  frame[19] = 4;
  frame.writeUInt16BE(1, 20);
  vmMAC.copy(frame, 22);
  Buffer.from(vmIP.split(".").map(Number)).copy(frame, 28);
  Buffer.alloc(6).copy(frame, 32);
  Buffer.from(targetIP.split(".").map(Number)).copy(frame, 38);
  return frame;
}

function parseFrame(frame) {
  if (!Buffer.isBuffer(frame) || frame.length < 14) return null;
  const etherType = frame.readUInt16BE(12);
  if (etherType === 0x0806) {
    return {
      kind: "arp",
      opcode: frame.readUInt16BE(20),
      senderIP: Array.from(frame.subarray(28, 32)).join("."),
      targetIP: Array.from(frame.subarray(38, 42)).join("."),
    };
  }
  if (etherType !== 0x0800) return null;
  const parsed = parseIPv4Packet(frame.subarray(14));
  if (!parsed) return null;
  const offset = parsed.headerLength;
  if (parsed.protocol === 6 && parsed.packet.length >= offset + 20) {
    const flags = parsed.packet[offset + 13];
    const dataOffset = (parsed.packet[offset + 12] >>> 4) * 4;
    return {
      kind: "tcp",
      srcIP: parsed.srcIP,
      dstIP: parsed.dstIP,
      srcPort: parsed.packet.readUInt16BE(offset),
      dstPort: parsed.packet.readUInt16BE(offset + 2),
      seq: parsed.packet.readUInt32BE(offset + 4),
      ack: parsed.packet.readUInt32BE(offset + 8),
      syn: (flags & 0x02) !== 0,
      ackFlag: (flags & 0x10) !== 0,
      rst: (flags & 0x04) !== 0,
      fin: (flags & 0x01) !== 0,
      payload: parsed.packet.subarray(offset + dataOffset),
    };
  }
  if (parsed.protocol === 17 && parsed.packet.length >= offset + 8) {
    return {
      kind: "udp",
      srcIP: parsed.srcIP,
      dstIP: parsed.dstIP,
      srcPort: parsed.packet.readUInt16BE(offset),
      dstPort: parsed.packet.readUInt16BE(offset + 2),
      payload: parsed.packet.subarray(offset + 8),
    };
  }
  return { kind: "ip", protocol: parsed.protocol, srcIP: parsed.srcIP, dstIP: parsed.dstIP };
}

class FrameQueue {
  constructor(ws) {
    this.frames = [];
    ws.on("message", (data, isBinary) => {
      if (!isBinary) return;
      const parsed = parseFrame(data);
      if (parsed) this.frames.push(parsed);
    });
  }

  async waitFor(predicate, timeoutMs = 1500) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const index = this.frames.findIndex(predicate);
      if (index !== -1) return this.frames.splice(index, 1)[0];
      await delay(5);
    }
    throw new Error("Timed out waiting for frame");
  }

  async expectNone(predicate, durationMs) {
    const deadline = Date.now() + durationMs;
    while (Date.now() < deadline) {
      if (this.frames.some(predicate)) return false;
      await delay(5);
    }
    return true;
  }
}

// Resolves { ws } on 101, or { status } on a rejected handshake.
function openWebSocket(port, { token = null, bearer = null, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const protocols = token ? ["relay.v1", `relay.token.${token}`] : ["relay.v1"];
    const options = { perMessageDeflate: false, headers: { ...headers } };
    if (bearer) options.headers.Authorization = `Bearer ${bearer}`;
    const ws = new WebSocket(`ws://127.0.0.1:${port}`, protocols, options);
    ws.once("open", () => resolve({ ws, status: 101 }));
    ws.once("unexpected-response", (_req, res) => {
      res.resume();
      resolve({ ws: null, status: res.statusCode });
      ws.terminate();
    });
    ws.once("error", reject);
  });
}

async function waitForWebSocket(port, child, options = {}) {
  const deadline = Date.now() + 5000;
  let lastError;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`Relay exited (${child.exitCode})`);
    try {
      return await openWebSocket(port, options);
    } catch (error) {
      lastError = error;
      await delay(25);
    }
  }
  throw lastError || new Error("Relay did not accept WebSocket");
}

function httpJson(port, { method = "GET", path: pathname = "/", body = null, cookie = null, headers = {} } = {}) {
  const payload = body === null ? null : JSON.stringify(body);
  const requestHeaders = { ...headers };
  if (payload !== null) {
    requestHeaders["Content-Type"] = "application/json";
    requestHeaders["Content-Length"] = Buffer.byteLength(payload);
  }
  if (cookie) requestHeaders.Cookie = cookie;
  return new Promise((resolve, reject) => {
    const request = http.request({ host: "127.0.0.1", port, path: pathname, method, headers: requestHeaders }, (response) => {
      let data = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => {
        data += chunk;
      });
      response.on("end", () => {
        let json = null;
        try {
          json = data ? JSON.parse(data) : null;
        } catch (_error) {
          json = null;
        }
        resolve({ status: response.statusCode, headers: response.headers, body: json, text: data });
      });
    });
    request.once("error", reject);
    if (payload !== null) request.write(payload);
    request.end();
  });
}

async function adminLogin(port, { username = ADMIN_USER, password = ADMIN_PASSWORD } = {}) {
  const deadline = Date.now() + 5000;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const response = await httpJson(port, { method: "POST", path: "/api/login", body: { username, password } });
      if (response.status === 200) {
        return (response.headers["set-cookie"] || []).map((value) => value.split(";")[0]).join("; ");
      }
      lastError = new Error(`Admin login failed: ${response.status}`);
      if (response.status !== 401) break;
      await delay(50);
    } catch (error) {
      lastError = error;
      await delay(20);
    }
  }
  throw lastError;
}

async function startRelay({ env = {}, hosted = false } = {}) {
  const wsPort = await freeTcpPort();
  const adminPort = await freeTcpPort();
  const dbPath = path.join(os.tmpdir(), `rootlessrelay-hosted-${process.pid}-${adminPort}.sqlite`);
  const childEnv = {
    ...process.env,
    ADMIN_SESSION_SECRET: ADMIN_SECRET,
    ADMIN_BOOTSTRAP_USERNAME: ADMIN_USER,
    ADMIN_BOOTSTRAP_PASSWORD: ADMIN_PASSWORD,
    ADMIN_AUTH_DB_PATH: dbPath,
    ENABLE_WSS: "false",
    LOG_LEVEL: "0",
    WS_BIND_ADDRESS: "127.0.0.1",
    WS_PORT: String(wsPort),
    ADMIN_BIND_ADDRESS: "127.0.0.1",
    ADMIN_PORT: String(adminPort),
    PROXY_BIND_ADDRESS: "127.0.0.1",
    PROXY_PORT: "0",
    TCP_RTO_INITIAL_MS: "50",
    TCP_RTO_MAX_MS: "100",
    TCP_RTO_MAX_RETRANSMISSIONS: "2",
    ...(hosted
      ? {
        RELAY_MODE: "hosted",
        ANON_TOKEN_SECRET: "test-anon-secret",
        LOG_JSON: "false",
        TRUST_PROXY: "false",
      }
      : {}),
    ...env,
  };
  const child = spawn(process.execPath, [path.join(ROOT, "relay.js")], {
    cwd: ROOT,
    env: childEnv,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => {
    stdout += chunk.toString();
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });
  const exited = new Promise((resolve) => child.once("exit", (code, signal) => resolve({ code, signal })));

  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`Relay exited (${child.exitCode})\n${stderr}\n${stdout}`);
    }
    try {
      const health = await httpJson(wsPort, { path: "/healthz" });
      if (health.status === 200) break;
    } catch (_error) {
      // not listening yet
    }
    await delay(25);
  }

  return {
    child,
    wsPort,
    adminPort,
    dbPath,
    exited,
    stdout: () => stdout,
    stderr: () => stderr,
    async adminCookie() {
      return adminLogin(adminPort);
    },
    async close() {
      for (const suffix of ["", "-wal", "-shm"]) fs.rm(`${dbPath}${suffix}`, { force: true }, () => {});
      if (child.exitCode !== null) return exited;
      child.kill("SIGTERM");
      return Promise.race([exited, delay(1000).then(() => {
        child.kill("SIGKILL");
        return exited;
      })]);
    },
  };
}

module.exports = {
  ADMIN_PASSWORD,
  ADMIN_USER,
  FrameQueue,
  GATEWAY_IP,
  GATEWAY_MAC,
  adminLogin,
  buildARPRequest,
  buildTCPFrame,
  buildUDPFrame,
  delay,
  freeTcpPort,
  httpJson,
  listen,
  macFromNumber,
  openWebSocket,
  parseFrame,
  startRelay,
  waitForWebSocket,
};
