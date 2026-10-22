"use strict";

// The admin app reached two ways: on its own (private) port, and through the
// public listener for ADMIN_PUBLIC_HOST. Host check, write header, security
// headers, and /metrics staying private on the public side.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const WebSocket = require("ws");
const { resolveConfig } = require("../config");
const admin = require("../admin/app");
const { openDatabase } = require("../auth/db");
const { createUserStore } = require("../auth/users");
const { createApiTokenStore } = require("../auth/tokens");
const { createPublicServer } = require("../server/public");

const quietLog = { debug() {}, info() {}, warn() {}, error() {} };
const ADMIN_HOST = "admin.example.test";

function call(port, { method = "GET", path: urlPath = "/", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : JSON.stringify(body);
    const all = { ...(payload ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) } : {}), ...headers };
    const req = http.request({ host: "127.0.0.1", port, method, path: urlPath, headers: all }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function start(t) {
  const config = resolveConfig({
    RELAY_MODE: "hosted",
    ADMIN_SESSION_SECRET: "s",
    ANON_TOKEN_SECRET: "a",
    LOG_LEVEL: "0",
    ADMIN_PUBLIC_HOST: ADMIN_HOST,
    ADMIN_COOKIE_SECURE: "true",
    ADMIN_TRUST_PROXY: "true",
    METRICS_ENABLED: "true",
    METRICS_PUBLIC: "true",
  });
  const db = openDatabase(":memory:");
  await db.migrate();
  const users = createUserStore(db, { bcryptRounds: 4 });
  admin.configurePassport({ users });
  const metrics = { enabled: true, contentType: "text/plain", render: async () => "relay_up 1\n" };
  const app = admin.createAdminApp({
    config, users, apiTokens: createApiTokenStore(db), activeSessions: new Map(), registry: null, rules: null,
    proxyPort: 0, poolCtx: { poolPrefix: "10.0.2.", dhcpStart: 15, dhcpEnd: 254 }, metrics, log: quietLog,
  });
  const adminServer = await admin.startAdminServer(app, { port: 0, host: "127.0.0.1", log: quietLog });
  const publicServer = createPublicServer({ config, log: quietLog, adminApp: app, lifecycle: { isShuttingDown: () => false } });
  const address = await publicServer.listen(0, "127.0.0.1");
  t.after(async () => {
    await new Promise((r) => adminServer.close(r));
    await new Promise((r) => publicServer.server.close(r));
    await db.close();
  });
  return { adminPort: adminServer.address().port, publicPort: address.port };
}

test("the admin app answers only to loopback names, IP literals and ADMIN_PUBLIC_HOST", async (t) => {
  const { adminPort } = await start(t);
  for (const host of ["localhost:8001", "127.0.0.1:8001", "[::1]:8001", "[fdaa:0:1::2]:8001", ADMIN_HOST, "ADMIN.example.test"]) {
    assert.equal((await call(adminPort, { path: "/api/auth/status", headers: { Host: host } })).status, 200, host);
  }
  for (const host of ["rebind.attacker.example", "relay.example.test", "localhost.attacker.example"]) {
    assert.equal((await call(adminPort, { path: "/api/auth/status", headers: { Host: host } })).status, 421, host);
  }
  // The private scraper may use any name for /metrics.
  assert.equal((await call(adminPort, { path: "/metrics", headers: { Host: "abc.vm.relay.internal:8001" } })).status, 200);
});

test("writes need X-Requested-With: relaynet-admin, and a cross-site Origin is still refused", async (t) => {
  const { adminPort } = await start(t);
  const login = (headers) => call(adminPort, { method: "POST", path: "/api/login", headers: { Host: "localhost", ...headers }, body: { username: "x", password: "y" } });
  const missing = await login({});
  assert.equal(missing.status, 403);
  assert.match(missing.body, /X-Requested-With/);
  assert.equal((await login({ "X-Requested-With": "XMLHttpRequest" })).status, 403);
  assert.equal((await login({ "X-Requested-With": "relaynet-admin", Origin: "https://evil.example" })).status, 403);
  assert.equal((await login({ "X-Requested-With": "relaynet-admin", Origin: "http://localhost" })).status, 401, "reaches the login check");
  assert.equal((await login({ "X-Requested-With": "relaynet-admin" })).status, 401);
});

test("security headers: CSP pins the panel's inline script, no framing, no X-Powered-By", async (t) => {
  const { adminPort } = await start(t);
  const res = await call(adminPort, { path: "/", headers: { Host: "localhost" } });
  assert.equal(res.status, 200);
  const html = fs.readFileSync(path.join(__dirname, "..", "admin.html"), "utf8");
  const inline = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  assert.equal(inline.length, 1);
  const hash = crypto.createHash("sha256").update(inline[0]).digest("base64");
  const csp = res.headers["content-security-policy"];
  assert.ok(csp.includes(`script-src 'sha256-${hash}'`), csp);
  for (const directive of ["default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "connect-src 'self'"]) {
    assert.ok(csp.includes(directive), directive);
  }
  assert.equal(res.headers["x-frame-options"], "DENY");
  assert.equal(res.headers["x-content-type-options"], "nosniff");
  assert.equal(res.headers["referrer-policy"], "no-referrer");
  assert.equal(res.headers["strict-transport-security"], "max-age=31536000");
  assert.equal(res.headers["x-powered-by"], undefined);
});

test("ADMIN_PUBLIC_HOST: the public port serves the panel for that name only, and /metrics stays private", async (t) => {
  const { publicPort, adminPort } = await start(t);
  const panel = await call(publicPort, { path: "/", headers: { Host: ADMIN_HOST } });
  assert.equal(panel.status, 200);
  assert.match(panel.body, /<script>/);
  assert.ok(panel.headers["content-security-policy"]);
  assert.equal((await call(publicPort, { path: "/api/auth/status", headers: { Host: `${ADMIN_HOST}:443` } })).status, 200);
  assert.equal((await call(publicPort, { path: "/", headers: { Host: "relay.example.test" } })).status, 404, "other names get the relay");
  assert.equal((await call(publicPort, { path: "/healthz", headers: { Host: "relay.example.test" } })).status, 200);

  // METRICS_PUBLIC is for the private port; from the internet it needs a sign-in or the token.
  assert.equal((await call(publicPort, { path: "/metrics", headers: { Host: ADMIN_HOST } })).status, 401);
  assert.equal((await call(adminPort, { path: "/metrics", headers: { Host: "localhost" } })).status, 200);

  // No relay sessions on the admin name.
  const status = await new Promise((resolve) => {
    const ws = new WebSocket(`ws://127.0.0.1:${publicPort}/`, ["relay.v1"], { headers: { Host: ADMIN_HOST } });
    ws.on("unexpected-response", (_req, res) => { res.resume(); resolve(res.statusCode); ws.terminate(); });
    ws.on("open", () => { ws.close(); resolve(101); });
    ws.on("error", () => resolve(0));
  });
  assert.equal(status, 404);
});

test("ADMIN_PUBLIC_HOST must be a bare hostname and needs secure cookies", () => {
  const base = { RELAY_MODE: "hosted", ADMIN_SESSION_SECRET: "s", ANON_TOKEN_SECRET: "a" };
  assert.throws(() => resolveConfig({ ...base, ADMIN_PUBLIC_HOST: ADMIN_HOST }), /ADMIN_COOKIE_SECURE/);
  for (const bad of ["https://admin.example.test", "admin.example.test:443", "admin", "admin.example.test/x"]) {
    assert.throws(() => resolveConfig({ ...base, ADMIN_COOKIE_SECURE: "true", ADMIN_PUBLIC_HOST: bad }), /ADMIN_PUBLIC_HOST/, bad);
  }
  const ok = resolveConfig({ ...base, ADMIN_COOKIE_SECURE: "true", ADMIN_TRUST_PROXY: "true", ADMIN_PUBLIC_HOST: "Admin.Example.Test" });
  assert.equal(ok.adminPublicHost, "admin.example.test");
  const noProxy = resolveConfig({ ...base, ADMIN_COOKIE_SECURE: "true", ADMIN_TRUST_PROXY: "false", ADMIN_PUBLIC_HOST: ADMIN_HOST });
  assert.ok(noProxy.warnings.some((w) => /ADMIN_TRUST_PROXY/.test(w)));
});
