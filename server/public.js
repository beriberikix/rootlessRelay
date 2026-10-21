"use strict";

// The single public listener: WebSocket upgrades (with authentication and
// admission control in front of the handshake), /healthz, the anonymous
// token endpoint, the account-scoped /api/me routes (server/user_api.js) and
// CORS for the browser frontend. Replaces the WS/WSS
// server creation that used to live in relay.js.

const http = require("http");
const https = require("https");
const WebSocket = require("ws");
const { resolveClientIP } = require("./client_ip");

const STATUS_TEXT = {
  400: "Bad Request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not Found",
  405: "Method Not Allowed",
  413: "Payload Too Large",
  429: "Too Many Requests",
  500: "Internal Server Error",
  503: "Service Unavailable",
};

const TOKEN_PROTOCOL_PREFIX = "relay.token.";
const ORG_PROTOCOL_PREFIX = "relay.org.";
const ORG_HEADER = "x-relay-org";
const RELAY_PROTOCOL = "relay.v1";

class AuthError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.status = status;
    this.code = code;
  }
}

function parseProtocols(header) {
  if (!header) return [];
  return String(header).split(",").map((entry) => entry.trim()).filter(Boolean);
}

// Browsers cannot set headers on a WebSocket, so the token travels as a
// subprotocol entry next to "relay.v1". Non-browser clients may use a bearer
// header instead. Query strings are opt-in because they leak into logs.
function extractCredential(req, { allowQueryToken = false } = {}) {
  for (const protocol of parseProtocols(req.headers["sec-websocket-protocol"])) {
    if (protocol.startsWith(TOKEN_PROTOCOL_PREFIX)) {
      return { token: protocol.slice(TOKEN_PROTOCOL_PREFIX.length), source: "subprotocol" };
    }
  }
  const authorization = req.headers.authorization;
  if (typeof authorization === "string" && /^bearer\s+/i.test(authorization)) {
    return { token: authorization.replace(/^bearer\s+/i, "").trim(), source: "header" };
  }
  if (allowQueryToken && req.url) {
    const index = req.url.indexOf("?");
    if (index !== -1) {
      const params = new URLSearchParams(req.url.slice(index + 1));
      const token = params.get("token");
      if (token) return { token, source: "query" };
    }
  }
  return null;
}

// The org a request acts in, when the client names one: a `relay.org.<id>`
// subprotocol entry on a WebSocket (browsers cannot set headers there) or an
// `X-Relay-Org` header. Null means "the account's default org".
function extractOrg(req) {
  let raw = null;
  for (const protocol of parseProtocols(req.headers["sec-websocket-protocol"])) {
    if (protocol.startsWith(ORG_PROTOCOL_PREFIX)) raw = protocol.slice(ORG_PROTOCOL_PREFIX.length);
  }
  if (raw === null && typeof req.headers[ORG_HEADER] === "string") raw = req.headers[ORG_HEADER].trim();
  if (raw === null || raw === "") return null;
  if (!/^[1-9][0-9]{0,9}$/.test(raw)) throw new AuthError(400, "invalid-org");
  return Number(raw);
}

function selectProtocol(protocols) {
  if (protocols.has(RELAY_PROTOCOL)) return RELAY_PROTOCOL;
  for (const protocol of protocols) {
    if (!protocol.startsWith(TOKEN_PROTOCOL_PREFIX) && !protocol.startsWith(ORG_PROTOCOL_PREFIX)) return protocol;
  }
  return false;
}

function writeJson(res, status, body, extraHeaders = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
    "Cache-Control": "no-store",
    ...extraHeaders,
  });
  res.end(payload);
}

function rejectUpgrade(socket, status, message) {
  if (socket.destroyed) return;
  const body = JSON.stringify({ error: message || STATUS_TEXT[status] || "Error" });
  socket.write(
    `HTTP/1.1 ${status} ${STATUS_TEXT[status] || "Error"}\r\n` +
    "Connection: close\r\n" +
    "Content-Type: application/json\r\n" +
    `Content-Length: ${Buffer.byteLength(body)}\r\n` +
    "\r\n" +
    body,
  );
  socket.destroy();
}

function readJsonBody(req, { limit = 16 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new AuthError(413, "payload-too-large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (chunks.length === 0) {
        resolve({});
        return;
      }
      // Every route takes an object; null, arrays and bare values are 400s
      // here rather than TypeErrors in the handlers.
      let body;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch (_error) {
        reject(new AuthError(400, "invalid-json"));
        return;
      }
      if (body === null || typeof body !== "object" || Array.isArray(body)) {
        reject(new AuthError(400, "invalid-json"));
        return;
      }
      resolve(body);
    });
    req.on("error", reject);
  });
}

const LOCAL_IDENTITY = Object.freeze({ kind: "local", owner: "local", tier: "local" });

function createPublicServer({
  config,
  log,
  tls = null,
  authenticate = null,
  admission = null,
  wssOptions = {},
  lifecycle = null,
  sessionCount = () => 0,
  handleAnonToken = null,
  adminApp = null,
  metrics = null,
  userApi = null,
}) {
  const allowedOrigins = config.allowedOrigins ? new Set(config.allowedOrigins) : null;
  const sessionOrigins = config.sessionAllowedOrigins ? new Set(config.sessionAllowedOrigins) : null;

  function originAllowed(origin) {
    if (!allowedOrigins) return true;
    return typeof origin === "string" && allowedOrigins.has(origin);
  }

  function corsHeaders(req) {
    const origin = req.headers.origin;
    if (!origin || !originAllowed(origin)) return {};
    return {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Relay-Org",
      "Access-Control-Max-Age": "600",
      Vary: "Origin",
    };
  }

  async function requestHandler(req, res) {
    const path = req.url.split("?")[0];

    if (adminApp && config.adminPublicPath &&
      (path === config.adminPublicPath || path.startsWith(`${config.adminPublicPath}/`))) {
      req.url = req.url.slice(config.adminPublicPath.length) || "/";
      adminApp(req, res);
      return;
    }

    if (req.method === "OPTIONS") {
      res.writeHead(allowedOrigins ? 204 : 404, corsHeaders(req));
      res.end();
      return;
    }

    if (path === "/healthz") {
      if (req.method !== "GET" && req.method !== "HEAD") {
        writeJson(res, 405, { error: "method not allowed" });
        return;
      }
      const shuttingDown = lifecycle ? lifecycle.isShuttingDown() : false;
      writeJson(res, shuttingDown ? 503 : 200, {
        ok: !shuttingDown,
        mode: config.mode,
        sessions: sessionCount(),
      });
      return;
    }

    if (path === "/api/anon/token") {
      if (req.method !== "POST") {
        writeJson(res, 405, { error: "method not allowed" }, corsHeaders(req));
        return;
      }
      if (!handleAnonToken) {
        writeJson(res, 404, { error: "anonymous access is disabled" }, corsHeaders(req));
        return;
      }
      if (req.headers.origin && !originAllowed(req.headers.origin)) {
        writeJson(res, 403, { error: "origin not allowed" });
        return;
      }
      try {
        const body = await readJsonBody(req);
        const clientIP = resolveClientIP(req, config.clientIpOptions);
        const result = await handleAnonToken({ body, clientIP, req });
        writeJson(res, 200, result, corsHeaders(req));
      } catch (error) {
        const status = error.status || 500;
        if (status >= 500) log?.error("anon token error", { error });
        const message = status >= 500 ? "internal-error" : error.code || error.message || "error";
        writeJson(res, status, { error: message }, corsHeaders(req));
      }
      return;
    }

    if (userApi && userApi.matches(path)) {
      if (req.headers.origin && !originAllowed(req.headers.origin)) {
        writeJson(res, 403, { error: "origin not allowed" });
        return;
      }
      const clientIP = resolveClientIP(req, config.clientIpOptions);
      await userApi.handle(req, res, { path, clientIP, corsHeaders: corsHeaders(req) });
      return;
    }

    writeJson(res, 404, { error: "not found" });
  }

  const server = tls
    ? https.createServer(tls, requestHandler)
    : http.createServer(requestHandler);
  // Bound how long a client may take to send headers, so slow connections
  // cannot hold proxy slots before authenticating. Upgraded sockets leave
  // the HTTP server and are not affected.
  server.headersTimeout = 10000;
  server.requestTimeout = 15000;

  const wss = new WebSocket.Server({
    noServer: true,
    perMessageDeflate: false,
    handleProtocols: selectProtocol,
    ...wssOptions,
  });

  server.on("upgrade", async (req, socket, head) => {
    try {
      if (lifecycle && lifecycle.isShuttingDown()) {
        rejectUpgrade(socket, 503, "server shutting down");
        return;
      }
      const clientIP = resolveClientIP(req, config.clientIpOptions);
      if (req.headers.origin && sessionOrigins && !sessionOrigins.has(req.headers.origin)) {
        log?.warn("upgrade rejected: origin", { clientIP, origin: req.headers.origin });
        rejectUpgrade(socket, 403, "origin not allowed");
        return;
      }

      const credential = extractCredential(req, { allowQueryToken: config.allowQueryToken });
      let identity = LOCAL_IDENTITY;
      if (config.authRequired && !authenticate) {
        rejectUpgrade(socket, 401, "authentication required");
        return;
      }
      if (authenticate && (config.authRequired || credential)) {
        identity = await authenticate(credential ? credential.token : null, { clientIP, req, orgId: extractOrg(req) });
      }

      let admitted = null;
      if (admission) {
        const verdict = await admission.admit({ identity, clientIP });
        if (!verdict.ok) {
          log?.warn("upgrade rejected: admission", { clientIP, owner: identity.owner, reason: verdict.reason });
          metrics?.upgradeRejections?.inc({ status: String(verdict.status) });
          rejectUpgrade(socket, verdict.status, verdict.reason);
          return;
        }
        admitted = verdict;
      }

      // The admission reservation is released by the connection handler once
      // the session is registered, or here if the handshake never completes.
      const release = admitted && admitted.release ? admitted.release : null;
      if (release) socket.once("close", release);
      wss.handleUpgrade(req, socket, head, (ws) => {
        wss.emit("connection", ws, req, { identity, clientIP, release });
      });
    } catch (error) {
      if (error instanceof AuthError || (error && error.status)) {
        log?.warn("upgrade rejected: auth", { code: error.code, status: error.status });
        metrics?.authFailures?.inc({ code: String(error.code || error.status) });
        metrics?.upgradeRejections?.inc({ status: String(error.status) });
        rejectUpgrade(socket, error.status, error.code);
        return;
      }
      log?.error("upgrade failed", { error, stack: error && error.stack });
      rejectUpgrade(socket, 500, "internal error");
    }
  });

  return {
    server,
    wss,
    listen(port, host) {
      return new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => {
          server.off("error", reject);
          resolve(server.address());
        });
      });
    },
    close() {
      // Upgraded sockets keep http.Server.close() waiting; drop them first.
      for (const client of wss.clients) client.terminate();
      if (typeof server.closeIdleConnections === "function") server.closeIdleConnections();
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

module.exports = {
  AuthError,
  LOCAL_IDENTITY,
  RELAY_PROTOCOL,
  ORG_PROTOCOL_PREFIX,
  TOKEN_PROTOCOL_PREFIX,
  createPublicServer,
  extractCredential,
  extractOrg,
  readJsonBody,
  rejectUpgrade,
  selectProtocol,
  writeJson,
};
