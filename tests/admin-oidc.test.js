"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const express = require("express");
const expressSession = require("express-session");
const passport = require("passport");
const jose = require("jose");
const { createOidcLogin } = require("../admin/oidc");

const ISSUER = "https://idp.example/";

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
}

function get(port, path, cookie = "") {
  return new Promise((resolve, reject) => {
    http.get({ host: "127.0.0.1", port, path, headers: { host: `127.0.0.1:${port}`, cookie } }, (res) => {
      let body = "";
      res.on("data", (c) => { body += c; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body }));
    }).on("error", reject);
  });
}

async function setup({ amr = ["pwd", "mfa"], role = "operator", sub = "auth0|op" } = {}) {
  const { privateKey, publicKey } = await jose.generateKeyPair("RS256");
  const jwks = jose.createLocalJWKSet({ keys: [{ ...(await jose.exportJWK(publicKey)), alg: "RS256" }] });
  const users = {
    async findByExternalSub(ext) {
      return ext === `${ISSUER}|auth0|op` ? { id: 7, username: "ops@example.com", role, status: "active" } : undefined;
    },
    async touchLogin() {},
  };
  let lastAuthorize = null;
  const fetchFn = async (url, init) => {
    const href = String(url);
    if (href.endsWith("/.well-known/openid-configuration")) {
      return new Response(JSON.stringify({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}authorize`,
        token_endpoint: `${ISSUER}oauth/token`,
        jwks_uri: `${ISSUER}.well-known/jwks.json`,
      }));
    }
    if (href === `${ISSUER}oauth/token`) {
      const form = new URLSearchParams(init.body);
      assert.equal(form.get("client_secret"), "secret");
      assert.ok(form.get("code_verifier"));
      const idToken = await new jose.SignJWT({ nonce: lastAuthorize.get("nonce"), amr, email: "ops@example.com" })
        .setProtectedHeader({ alg: "RS256" })
        .setIssuer(ISSUER).setAudience("cid").setSubject(sub)
        .setIssuedAt().setExpirationTime("5m")
        .sign(privateKey);
      return new Response(JSON.stringify({ id_token: idToken }));
    }
    throw new Error(`unexpected fetch ${href}`);
  };

  const app = express();
  app.use(expressSession({ secret: "s", resave: false, saveUninitialized: false }));
  app.use(passport.initialize());
  app.use(passport.session());
  passport.serializeUser((user, done) => done(null, user));
  passport.deserializeUser((user, done) => done(null, user));
  app.get("/", (req, res) => res.json({ user: req.user || null }));
  const server = http.createServer(app);
  const port = await listen(server);
  createOidcLogin({
    issuer: ISSUER, clientId: "cid", clientSecret: "secret",
    redirectUrl: `http://127.0.0.1:${port}/auth/callback`, users, fetchFn, jwks,
  }).mount(app);

  async function login(stateOverride = null) {
    const start = await get(port, "/auth/login");
    assert.equal(start.status, 302);
    const authorize = new URL(start.headers.location);
    lastAuthorize = authorize.searchParams;
    assert.equal(authorize.searchParams.get("code_challenge_method"), "S256");
    const cookie = start.headers["set-cookie"][0].split(";")[0];
    const state = stateOverride || authorize.searchParams.get("state");
    const cb = await get(port, `/auth/callback?code=abc&state=${encodeURIComponent(state)}`, cookie);
    const after = cb.headers["set-cookie"] ? cb.headers["set-cookie"][0].split(";")[0] : cookie;
    return { cb, me: JSON.parse((await get(port, "/", after)).body) };
  }
  return { server, port, login };
}

test("operator OIDC sign-in: success with MFA", async () => {
  const { server, login } = await setup();
  try {
    const { cb, me } = await login();
    assert.equal(cb.status, 302);
    assert.equal(cb.headers.location, "/");
    assert.deepEqual(me.user, { id: 7, username: "ops@example.com", role: "operator" });
  } finally {
    server.close();
  }
});

test("operator OIDC sign-in is refused without MFA, for non-operators, unknown subjects and bad state", async () => {
  for (const [opts, status] of [[{ amr: ["pwd"] }, 403], [{ role: "user" }, 403], [{ sub: "auth0|stranger" }, 403]]) {
    const { server, login } = await setup(opts);
    try {
      const { cb, me } = await login();
      assert.equal(cb.status, status, JSON.stringify(opts));
      assert.equal(me.user, null);
    } finally {
      server.close();
    }
  }
  const { server, login } = await setup();
  try {
    const { cb, me } = await login("forged-state");
    assert.equal(cb.status, 400);
    assert.equal(me.user, null);
  } finally {
    server.close();
  }
});

test("login starts on the redirect host", async () => {
  const { server, port } = await setup();
  try {
    const res = await new Promise((resolve) => http.get({ host: "127.0.0.1", port, path: "/auth/login", headers: { host: `localhost:${port}` } }, resolve));
    assert.equal(res.statusCode, 302);
    assert.equal(res.headers.location, `http://127.0.0.1:${port}/auth/login`);
  } finally {
    server.close();
  }
});
