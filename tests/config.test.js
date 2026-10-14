"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { ConfigError, resolveConfig } = require("../config");

const HOSTED_MIN = {
  RELAY_MODE: "hosted",
  ADMIN_SESSION_SECRET: "a-strong-secret",
  ANON_TOKEN_SECRET: "anon-secret",
  LOG_LEVEL: "0",
};

test("local mode defaults keep upstream behavior", () => {
  const config = resolveConfig({});
  assert.equal(config.mode, "local");
  assert.equal(config.authRequired, false);
  assert.equal(config.anonEnabled, false);
  assert.equal(config.egressPolicy, "open");
  assert.deepEqual(config.egressDenyPorts, []);
  assert.equal(config.inboundRulesEnabled, true);
  assert.equal(config.trustProxy, false);
  assert.equal(config.antiSpoof, true);
  assert.equal(config.auditEnabled, false);
  assert.equal(config.jwt, null);
  assert.ok(config.warnings.some((w) => w.includes("ADMIN_SESSION_SECRET")));
});

test("hosted mode flips the safety defaults", () => {
  const config = resolveConfig(HOSTED_MIN);
  assert.equal(config.hosted, true);
  assert.equal(config.authRequired, true);
  assert.equal(config.anonEnabled, true);
  assert.equal(config.egressPolicy, "hosted");
  assert.deepEqual(config.egressDenyPorts, [25]);
  assert.equal(config.inboundRulesEnabled, false);
  assert.equal(config.trustProxy, true);
  assert.equal(config.adminTrustProxy, true);
  assert.equal(config.auditEnabled, true);
  assert.equal(config.metricsEnabled, true);
  assert.equal(config.metricsPublic, false);
  assert.equal(config.logJson, true);
  assert.ok(config.warnings.some((w) => w.includes("ALLOWED_ORIGINS")));
});

test("env overrides win over mode defaults", () => {
  const config = resolveConfig({
    ...HOSTED_MIN,
    AUTH_REQUIRED: "false",
    INBOUND_RULES_ENABLED: "true",
    EGRESS_DENY_PORTS: "25,465,587",
    EGRESS_ALLOW_CIDRS: "127.0.0.0/8, 10.1.0.0/16",
    ALLOWED_ORIGINS: "https://app.example.com,https://beta.example.com",
    TRUST_PROXY_HOPS: "2",
    TIERS_JSON: '{"anon":{"maxSessionMs":60000}}',
  });
  assert.equal(config.authRequired, false);
  assert.equal(config.inboundRulesEnabled, true);
  assert.deepEqual(config.egressDenyPorts, [25, 465, 587]);
  assert.deepEqual(config.egressAllowCidrs, ["127.0.0.0/8", "10.1.0.0/16"]);
  assert.deepEqual(config.allowedOrigins, [
    "https://app.example.com",
    "https://beta.example.com",
  ]);
  assert.equal(config.trustProxyHops, 2);
  assert.deepEqual(config.tiersJson, { anon: { maxSessionMs: 60000 } });
});

test("hosted mode refuses unsafe settings", () => {
  assert.throws(
    () => resolveConfig({ RELAY_MODE: "hosted", ANON_TOKEN_SECRET: "x" }),
    ConfigError,
  );
  assert.throws(
    () => resolveConfig({ RELAY_MODE: "hosted", ADMIN_SESSION_SECRET: "s" }),
    /ANON_TOKEN_SECRET/,
  );
  assert.throws(
    () => resolveConfig({ ...HOSTED_MIN, EGRESS_POLICY: "open" }),
    /EGRESS_POLICY/,
  );
  assert.throws(
    () => resolveConfig({ ...HOSTED_MIN, ADMIN_PUBLIC_PATH: "/admin" }),
    /ADMIN_COOKIE_SECURE/,
  );
  assert.throws(() => resolveConfig({ RELAY_MODE: "cloud" }), /RELAY_MODE/);
});

test("partial JWT configuration is rejected and full configuration parsed", () => {
  assert.throws(() => resolveConfig({ JWT_ISSUER: "https://issuer" }), /JWT_/);
  const config = resolveConfig({
    JWT_ISSUER: "https://issuer",
    JWT_AUDIENCE: "relay",
    JWT_JWKS_URL: "https://issuer/.well-known/jwks.json",
  });
  assert.deepEqual(config.jwt, {
    issuer: "https://issuer",
    audience: "relay",
    jwksUrl: "https://issuer/.well-known/jwks.json",
    usernameClaim: "email",
    verifiedClaim: null,
    algorithms: ["RS256"],
    defaultTier: "user",
  });
});

test("invalid scalar values raise ConfigError", () => {
  assert.throws(() => resolveConfig({ ANTI_SPOOF: "maybe" }), ConfigError);
  assert.throws(() => resolveConfig({ WS_HEARTBEAT_MS: "soon" }), ConfigError);
  assert.throws(() => resolveConfig({ TRUST_PROXY_HOPS: "0" }), ConfigError);
  assert.throws(() => resolveConfig({ TIERS_JSON: "{" }), ConfigError);
});

test("METRICS_PUBLIC opts the scrape endpoint out of auth", () => {
  const config = resolveConfig({ ...HOSTED_MIN, METRICS_PUBLIC: "true" });
  assert.equal(config.metricsPublic, true);
});

test("SIGNUP_MODE defaults to open and accepts only open or invite", () => {
  assert.equal(resolveConfig({}).signupMode, "open");
  assert.equal(resolveConfig({ SIGNUP_MODE: "invite" }).signupMode, "invite");
  assert.throws(() => resolveConfig({ SIGNUP_MODE: "closed" }), ConfigError);
});
