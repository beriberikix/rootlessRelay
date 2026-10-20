"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const WebSocket = require("ws");
const { resolveConfig } = require("../config");
const {
  AuthError,
  createPublicServer,
  extractCredential,
  extractOrg,
  selectProtocol,
} = require("../server/public");

const quietLog = { debug() {}, info() {}, warn() {}, error() {} };

function request(port, { method = "GET", path = "/", headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path, headers }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        data += chunk;
      });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

function connect(port, options = {}) {
  return new Promise((resolve) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/`, options.protocols, options);
    ws.on("open", () => resolve({ ws, status: 101 }));
    ws.on("unexpected-response", (_req, res) => {
      res.resume();
      resolve({ ws: null, status: res.statusCode });
      ws.terminate();
    });
    ws.on("error", (error) => resolve({ ws: null, status: 0, error }));
  });
}

async function startServer(overrides = {}) {
  const config = resolveConfig(overrides.env || {});
  const connections = [];
  const shuttingDown = { value: false };
  const server = createPublicServer({
    config,
    log: quietLog,
    authenticate: overrides.authenticate || null,
    admission: overrides.admission || null,
    lifecycle: { isShuttingDown: () => shuttingDown.value },
    sessionCount: () => connections.length,
    handleAnonToken: overrides.handleAnonToken || null,
  });
  server.wss.on("connection", (ws, _req, extra) => {
    connections.push({ ws, extra });
    ws.on("message", (data) => ws.send(data));
  });
  const address = await server.listen(0, "127.0.0.1");
  return { server, port: address.port, connections, shuttingDown, config };
}

test("credential extraction prefers the subprotocol, then bearer, then query only when allowed", () => {
  const req = (headers, url = "/") => ({ headers, url });
  assert.deepEqual(
    extractCredential(req({ "sec-websocket-protocol": "relay.v1, relay.token.abc" })),
    { token: "abc", source: "subprotocol" },
  );
  assert.deepEqual(
    extractCredential(req({ authorization: "Bearer xyz" })),
    { token: "xyz", source: "header" },
  );
  assert.equal(extractCredential(req({}, "/?token=q")), null);
  assert.deepEqual(
    extractCredential(req({}, "/?token=q"), { allowQueryToken: true }),
    { token: "q", source: "query" },
  );
  assert.equal(selectProtocol(new Set(["relay.token.abc", "relay.v1"])), "relay.v1");
  assert.equal(selectProtocol(new Set(["relay.token.abc", "custom"])), "custom");
  assert.equal(selectProtocol(new Set(["relay.token.abc"])), false);
  assert.equal(selectProtocol(new Set(["relay.token.abc", "relay.org.7"])), false, "the org entry is not a protocol to select");
  assert.equal(selectProtocol(new Set(["relay.org.7", "relay.v1"])), "relay.v1");
});

test("the org a request names comes from a subprotocol entry or X-Relay-Org; anything else is refused", () => {
  const req = (headers) => ({ headers, url: "/" });
  assert.equal(extractOrg(req({})), null);
  assert.equal(extractOrg(req({ "sec-websocket-protocol": "relay.v1, relay.token.abc, relay.org.42" })), 42);
  assert.equal(extractOrg(req({ "x-relay-org": " 9 " })), 9);
  assert.equal(extractOrg(req({ "x-relay-org": "" })), null);
  const invalid = (error) => error instanceof AuthError && error.status === 400 && error.code === "invalid-org";
  for (const bad of ["0", "-1", "1.5", "abc", "1e3", "12345678901", "7 8"]) {
    assert.throws(() => extractOrg(req({ "x-relay-org": bad })), invalid, bad);
  }
  assert.throws(() => extractOrg(req({ "sec-websocket-protocol": "relay.org.x" })), invalid);
});

test("local mode: healthz, 404s, plain WebSocket accepted as local identity, 503 while shutting down", async () => {
  const { server, port, connections, shuttingDown } = await startServer();
  try {
    const health = await request(port, { path: "/healthz" });
    assert.equal(health.status, 200);
    assert.deepEqual(JSON.parse(health.body), { ok: true, mode: "local", sessions: 0 });
    assert.equal((await request(port, { path: "/whatever" })).status, 404);
    assert.equal((await request(port, { method: "POST", path: "/api/anon/token" })).status, 404);

    const { ws, status } = await connect(port, { protocols: ["relay.v1", "relay.token.ignored"] });
    assert.equal(status, 101);
    assert.equal(ws.protocol, "relay.v1");
    assert.equal(connections.length, 1);
    assert.deepEqual(connections[0].extra.identity, { kind: "local", owner: "local", tier: "local" });
    assert.equal(connections[0].extra.clientIP, "127.0.0.1");
    ws.close();

    shuttingDown.value = true;
    assert.equal((await request(port, { path: "/healthz" })).status, 503);
    assert.equal((await connect(port)).status, 503);
  } finally {
    await server.close();
  }
});

test("hosted mode: credential required, authenticator errors map to HTTP statuses, identity flows through", async () => {
  const seen = [];
  const { server, port, connections } = await startServer({
    env: { RELAY_MODE: "hosted", ADMIN_SESSION_SECRET: "s", ANON_TOKEN_SECRET: "a", LOG_LEVEL: "0" },
    authenticate: async (token, { clientIP, orgId }) => {
      seen.push({ token, clientIP, orgId });
      if (token === "good") return { kind: "user", owner: "user:1", tier: "user", username: "alice" };
      if (token === "banned") throw new AuthError(403, "account-suspended");
      throw new AuthError(401, "invalid-token");
    },
  });
  try {
    assert.equal((await connect(port)).status, 401);
    assert.equal((await connect(port, { headers: { Authorization: "Bearer nope" } })).status, 401);
    assert.equal((await connect(port, { headers: { Authorization: "Bearer banned" } })).status, 403);
    const { ws, status } = await connect(port, { protocols: ["relay.v1", "relay.token.good"] });
    assert.equal(status, 101);
    assert.equal(connections[0].extra.identity.username, "alice");
    assert.equal(seen.at(-1).token, "good");
    assert.equal(seen.at(-1).orgId, null);
    ws.close();

    // The org named in the handshake reaches the authenticator.
    const named = await connect(port, { protocols: ["relay.v1", "relay.token.good", "relay.org.5"] });
    assert.equal(named.status, 101);
    assert.equal(seen.at(-1).orgId, 5);
    named.ws.close();
    assert.equal((await connect(port, { protocols: ["relay.v1", "relay.token.good", "relay.org.nope"] })).status, 400);
  } finally {
    await server.close();
  }
});

test("SESSION_ALLOWED_ORIGINS=* opens sessions to any origin while the API list still applies", async () => {
  const { server, port } = await startServer({
    env: { ALLOWED_ORIGINS: "https://app.example.com", SESSION_ALLOWED_ORIGINS: "*" },
    handleAnonToken: async () => ({ token: "t" }),
  });
  try {
    const embedded = await connect(port, { headers: { Origin: "https://someone-else.example" } });
    assert.equal(embedded.status, 101);
    embedded.ws.close();
    const denied = await request(port, {
      method: "POST",
      path: "/api/anon/token",
      headers: { Origin: "https://someone-else.example", "Content-Type": "application/json" },
      body: "{}",
    });
    assert.equal(denied.status, 403);
  } finally {
    await server.close();
  }
});

test("origin allow list applies to upgrades and the anon token endpoint; CORS headers are emitted", async () => {
  const { server, port } = await startServer({
    env: { ALLOWED_ORIGINS: "https://app.example.com" },
    handleAnonToken: async ({ body, clientIP }) => ({ token: `anon-for-${clientIP}`, echo: body }),
  });
  try {
    assert.equal((await connect(port, { headers: { Origin: "https://evil.example" } })).status, 403);
    const ok = await connect(port, { headers: { Origin: "https://app.example.com" } });
    assert.equal(ok.status, 101);
    ok.ws.close();
    const noOrigin = await connect(port);
    assert.equal(noOrigin.status, 101, "non-browser clients without Origin are accepted");
    noOrigin.ws.close();

    const preflight = await request(port, {
      method: "OPTIONS",
      path: "/api/anon/token",
      headers: { Origin: "https://app.example.com" },
    });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers["access-control-allow-origin"], "https://app.example.com");

    const denied = await request(port, {
      method: "POST",
      path: "/api/anon/token",
      headers: { Origin: "https://evil.example", "Content-Type": "application/json" },
      body: "{}",
    });
    assert.equal(denied.status, 403);

    const issued = await request(port, {
      method: "POST",
      path: "/api/anon/token",
      headers: { Origin: "https://app.example.com", "Content-Type": "application/json" },
      body: JSON.stringify({ turnstileToken: "t" }),
    });
    assert.equal(issued.status, 200);
    assert.deepEqual(JSON.parse(issued.body), {
      token: "anon-for-127.0.0.1",
      echo: { turnstileToken: "t" },
    });
    assert.equal(issued.headers["access-control-allow-origin"], "https://app.example.com");

    const badJson = await request(port, {
      method: "POST",
      path: "/api/anon/token",
      headers: { "Content-Type": "application/json" },
      body: "{",
    });
    assert.equal(badJson.status, 400);
  } finally {
    await server.close();
  }
});

test("admission verdicts reject before the handshake", async () => {
  let allow = true;
  const { server, port } = await startServer({
    admission: { admit: () => (allow ? { ok: true } : { ok: false, status: 429, reason: "too many" }) },
  });
  try {
    const first = await connect(port);
    assert.equal(first.status, 101);
    allow = false;
    assert.equal((await connect(port)).status, 429);
    first.ws.close();
  } finally {
    await server.close();
  }
});
