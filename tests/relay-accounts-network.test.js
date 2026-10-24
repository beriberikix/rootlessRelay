"use strict";

// Dashboard sign-in with relay accounts (USER_PASSWORD_LOGIN), end to end
// against a running relay: config, login, the session token on the account
// API and the WebSocket, logout, rate limiting, invite sign-up, and the
// operator and password-change rules.

const test = require("node:test");
const assert = require("node:assert/strict");
const { ADMIN_PASSWORD, ADMIN_USER, httpJson, openWebSocket, startRelay } = require("./helpers/relay_harness");

const NETWORK = { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 30000 };
const bearer = (token) => ({ Authorization: `Bearer ${token}` });
const login = (relay, username, password) =>
  httpJson(relay.wsPort, { method: "POST", path: "/api/auth/login", body: { username, password } });

test("off by default: config says so and the routes answer 404", NETWORK, async () => {
  const relay = await startRelay({ hosted: true });
  try {
    const config = await httpJson(relay.wsPort, { path: "/api/auth/config" });
    assert.equal(config.status, 200);
    assert.deepEqual(config.body, { passwordLogin: false, signup: null, oidc: null });
    assert.equal((await login(relay, ADMIN_USER, ADMIN_PASSWORD)).status, 404);
  } finally {
    await relay.close();
  }
});

test("password sign-in: session token works on the API and the WebSocket until sign-out", NETWORK, async () => {
  const relay = await startRelay({ hosted: true, env: { USER_PASSWORD_LOGIN: "true" } });
  try {
    const cookie = await relay.adminCookie();
    const created = await httpJson(relay.adminPort, {
      method: "POST", path: "/api/users", cookie, body: { username: "alice", password: "alice-password" },
    });
    assert.equal(created.status, 201, created.text);

    assert.deepEqual((await httpJson(relay.wsPort, { path: "/api/auth/config" })).body,
      { passwordLogin: true, signup: null, oidc: null });
    assert.equal((await login(relay, "alice", "wrong-password")).status, 401);
    assert.equal((await login(relay, "nobody", "whatever-password")).status, 401);

    const signedIn = await login(relay, "alice", "alice-password");
    assert.equal(signedIn.status, 200, signedIn.text);
    assert.match(signedIn.body.token, /^rs_[0-9a-f]{12}_/);
    assert.equal(signedIn.body.user.username, "alice");
    const token = signedIn.body.token;

    const me = await httpJson(relay.wsPort, { path: "/api/me", headers: bearer(token) });
    assert.equal(me.status, 200, me.text);
    assert.equal(me.body.user.username, "alice");

    // Signed in, not an API token: may create API tokens.
    const minted = await httpJson(relay.wsPort, { method: "POST", path: "/api/me/tokens", headers: bearer(token), body: { name: "vm" } });
    assert.equal(minted.status, 201, minted.text);

    const ws = await openWebSocket(relay.wsPort, { token });
    assert.equal(ws.status, 101);
    ws.ws.close();

    const out = await httpJson(relay.wsPort, { method: "POST", path: "/api/auth/logout", headers: bearer(token) });
    assert.equal(out.status, 204);
    assert.equal((await httpJson(relay.wsPort, { path: "/api/me", headers: bearer(token) })).status, 401);

    // A new password from the operator ends every sign-in.
    const again = (await login(relay, "alice", "alice-password")).body.token;
    const reset = await httpJson(relay.adminPort, {
      method: "POST", path: `/api/users/${created.body.id}/password`, cookie, body: { password: "new-alice-password" },
    });
    assert.equal(reset.status, 204);
    assert.equal((await httpJson(relay.wsPort, { path: "/api/me", headers: bearer(again) })).status, 401);
    assert.equal((await login(relay, "alice", "new-alice-password")).status, 200);
  } finally {
    await relay.close();
  }
});

test("repeated failures for one username are throttled", NETWORK, async () => {
  const relay = await startRelay({ hosted: true, env: { USER_PASSWORD_LOGIN: "true" } });
  try {
    const statuses = [];
    for (let i = 0; i < 11; i += 1) statuses.push((await login(relay, "bob", `guess-${i}-password`)).status);
    assert.deepEqual(statuses.slice(0, 10), Array(10).fill(401));
    assert.equal(statuses[10], 429);
  } finally {
    await relay.close();
  }
});

test("operators sign in with a password only where the operator panel allows passwords", NETWORK, async () => {
  const allowed = await startRelay({ hosted: true, env: { USER_PASSWORD_LOGIN: "true" } });
  try {
    assert.equal((await login(allowed, ADMIN_USER, ADMIN_PASSWORD)).status, 200);
  } finally {
    await allowed.close();
  }
  const ssoOnly = await startRelay({ hosted: true, env: { USER_PASSWORD_LOGIN: "true", ADMIN_PASSWORD_LOGIN: "false" } });
  try {
    assert.equal((await login(ssoOnly, ADMIN_USER, ADMIN_PASSWORD)).status, 401);
  } finally {
    await ssoOnly.close();
  }
});

test("sign-up with an invite code creates an active account and signs it in", NETWORK, async () => {
  const relay = await startRelay({
    hosted: true,
    env: { USER_PASSWORD_LOGIN: "true", USER_SIGNUP: "true", SIGNUP_MODE: "invite" },
  });
  try {
    assert.equal((await httpJson(relay.wsPort, { path: "/api/auth/config" })).body.signup, "invite");
    const signup = (body) => httpJson(relay.wsPort, { method: "POST", path: "/api/auth/signup", body });

    assert.equal((await signup({ username: "carol", password: "carol-password" })).status, 400, "code required");
    assert.equal((await signup({ username: "carol", password: "carol-password", code: "RLY-NOPE-NOPE-NOPE" })).status, 400);
    assert.equal((await login(relay, "carol", "carol-password")).status, 401, "the failed sign-up left no account");

    const cookie = await relay.adminCookie();
    const invite = await httpJson(relay.adminPort, { method: "POST", path: "/api/invites", cookie, body: { note: "test" } });
    assert.equal(invite.status, 201, invite.text);
    const ok = await signup({ username: "carol", password: "carol-password", code: invite.body.code });
    assert.equal(ok.status, 201, ok.text);
    assert.equal(ok.body.user.status, "active");
    assert.equal((await httpJson(relay.wsPort, { path: "/api/me", headers: bearer(ok.body.token) })).body.user.status, "active");

    assert.equal((await signup({ username: "carol", password: "other-password", code: invite.body.code })).status, 409);
    assert.equal((await signup({ username: "dave", password: "short", code: invite.body.code })).status, 400);
  } finally {
    await relay.close();
  }
});
