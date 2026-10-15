"use strict";

const { parseProxyRanges } = require("./server/client_ip");

// Hosted-mode configuration. RELAY_MODE picks a set of defaults; every
// individual setting can still be overridden by its own environment variable.
// The upstream data-plane settings in relay.js are untouched by this module.

const MODES = ["local", "hosted"];

const MODE_DEFAULTS = {
  local: {
    authRequired: false,
    anonEnabled: false,
    egressPolicy: "open",
    egressDenyPorts: [],
    trustProxy: false,
    inboundRulesEnabled: true,
    auditEnabled: false,
    metricsEnabled: false,
    logJson: false,
  },
  hosted: {
    authRequired: true,
    anonEnabled: true,
    egressPolicy: "hosted",
    egressDenyPorts: [25],
    trustProxy: true,
    inboundRulesEnabled: false,
    auditEnabled: true,
    metricsEnabled: true,
    logJson: true,
  },
};

const DEFAULT_SESSION_SECRET = "change-me-in-production";

class ConfigError extends RangeError {}

function parseBool(value, fallback) {
  if (value === undefined || value === "") return fallback;
  if (value === "true" || value === "1") return true;
  if (value === "false" || value === "0") return false;
  throw new ConfigError(`Expected a boolean, got "${value}"`);
}

function parseInteger(value, fallback, { name, min = 0 }) {
  if (value === undefined || value === "") return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || String(parsed) !== String(value).trim()) {
    throw new ConfigError(`${name} must be an integer, got "${value}"`);
  }
  if (parsed < min) {
    throw new ConfigError(`${name} must be >= ${min}, got ${parsed}`);
  }
  return parsed;
}

function parseList(value, fallback = []) {
  if (value === undefined) return fallback;
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

function parsePortList(value, fallback, name) {
  if (value === undefined) return fallback;
  return parseList(value).map((entry) =>
    parseInteger(entry, undefined, { name, min: 1 })
  );
}

function parseJson(value, name) {
  if (value === undefined || value === "") return null;
  try {
    return JSON.parse(value);
  } catch (error) {
    throw new ConfigError(`${name} is not valid JSON: ${error.message}`);
  }
}

function parseSessionOrigins(sessionValue, allowedValue) {
  const value = sessionValue === undefined || sessionValue === "" ? allowedValue : sessionValue;
  if (!value || value.trim() === "*") return null;
  return parseList(value);
}

function resolveConfig(env = process.env) {
  const mode = env.RELAY_MODE || "local";
  if (!MODES.includes(mode)) {
    throw new ConfigError(
      `RELAY_MODE must be one of ${MODES.join(", ")}, got "${mode}"`,
    );
  }
  const defaults = MODE_DEFAULTS[mode];
  const warnings = [];

  const jwtIssuer = env.JWT_ISSUER;
  const jwtAudience = env.JWT_AUDIENCE;
  const jwtJwksUrl = env.JWT_JWKS_URL;
  const jwtConfigured = Boolean(jwtIssuer || jwtAudience || jwtJwksUrl);
  if (jwtConfigured && !(jwtIssuer && jwtAudience && jwtJwksUrl)) {
    throw new ConfigError(
      "JWT_ISSUER, JWT_AUDIENCE and JWT_JWKS_URL must all be set to enable external JWT auth",
    );
  }

  const egressPolicy = env.EGRESS_POLICY || defaults.egressPolicy;
  if (!["open", "hosted"].includes(egressPolicy)) {
    throw new ConfigError(
      `EGRESS_POLICY must be "open" or "hosted", got "${egressPolicy}"`,
    );
  }

  const signupMode = env.SIGNUP_MODE || "open";
  if (!["open", "invite"].includes(signupMode)) {
    throw new ConfigError(`SIGNUP_MODE must be "open" or "invite", got "${signupMode}"`);
  }

  const trustProxy = parseBool(env.TRUST_PROXY, defaults.trustProxy);
  const adminSessionSecret = env.ADMIN_SESSION_SECRET || DEFAULT_SESSION_SECRET;

  const config = {
    mode,
    hosted: mode === "hosted",

    authRequired: parseBool(env.AUTH_REQUIRED, defaults.authRequired),
    anonEnabled: parseBool(env.ANON_ENABLED, defaults.anonEnabled),
    anonTokenSecret: env.ANON_TOKEN_SECRET || null,
    anonTokenTtlMs: parseInteger(env.ANON_TOKEN_TTL_S, 900, {
      name: "ANON_TOKEN_TTL_S",
      min: 1,
    }) * 1000,
    anonTokenBindIp: parseBool(env.ANON_TOKEN_BIND_IP, true),
    anonTokensPerIpPerHour: parseInteger(env.ANON_TOKENS_PER_IP_PER_HOUR, 10, {
      name: "ANON_TOKENS_PER_IP_PER_HOUR",
      min: 1,
    }),
    turnstileSecret: env.TURNSTILE_SECRET || null,
    // "invite": accounts first seen through an external identity provider
    // start pending and cannot connect until they redeem an invite code.
    signupMode,

    jwt: jwtConfigured
      ? {
        issuer: jwtIssuer,
        audience: jwtAudience,
        jwksUrl: jwtJwksUrl,
        usernameClaim: env.JWT_USERNAME_CLAIM || "email",
        verifiedClaim: env.JWT_VERIFIED_CLAIM || null,
        algorithms: parseList(env.JWT_ALGORITHMS || "RS256"),
        defaultTier: env.JWT_DEFAULT_TIER || "user",
      }
      : null,

    allowedOrigins: env.ALLOWED_ORIGINS ? parseList(env.ALLOWED_ORIGINS) : null,
    // Origins allowed to open relay sessions (WebSocket upgrades). Defaults
    // to ALLOWED_ORIGINS; "*" allows any origin. Sessions authenticate with a
    // token, never a cookie, so a cross-site page cannot ride on a visitor's
    // credentials; ALLOWED_ORIGINS keeps guarding the HTTP APIs.
    sessionAllowedOrigins: parseSessionOrigins(env.SESSION_ALLOWED_ORIGINS, env.ALLOWED_ORIGINS),
    allowQueryToken: parseBool(env.ALLOW_QUERY_TOKEN, false),

    egressPolicy,
    egressDenyCidrs: parseList(env.EGRESS_DENY_CIDRS),
    egressAllowCidrs: parseList(env.EGRESS_ALLOW_CIDRS),
    egressDenyPorts: parsePortList(
      env.EGRESS_DENY_PORTS,
      defaults.egressDenyPorts,
      "EGRESS_DENY_PORTS",
    ),

    antiSpoof: parseBool(env.ANTI_SPOOF, true),

    trustProxy,
    trustProxyHops: parseInteger(env.TRUST_PROXY_HOPS, 1, {
      name: "TRUST_PROXY_HOPS",
      min: 1,
    }),
    clientIpHeader: (env.CLIENT_IP_HEADER || "x-forwarded-for").toLowerCase(),
    // Header from the platform edge naming the immediate peer (e.g.
    // fly-client-ip), and the ranges whose CLIENT_IP_HEADER is believed.
    peerIpHeader: env.PEER_IP_HEADER ? env.PEER_IP_HEADER.toLowerCase() : null,
    trustedProxyCidrs: parseList(env.TRUSTED_PROXY_CIDRS || ""),

    inboundRulesEnabled: parseBool(
      env.INBOUND_RULES_ENABLED,
      defaults.inboundRulesEnabled,
    ),

    tiersJson: parseJson(env.TIERS_JSON, "TIERS_JSON"),

    wsHeartbeatMs: parseInteger(env.WS_HEARTBEAT_MS, 30000, {
      name: "WS_HEARTBEAT_MS",
    }),
    sessionIdleTimeoutMs: parseInteger(env.SESSION_IDLE_TIMEOUT_MS, 0, {
      name: "SESSION_IDLE_TIMEOUT_MS",
    }),
    shutdownTimeoutMs: parseInteger(env.SHUTDOWN_TIMEOUT_MS, 500, {
      name: "SHUTDOWN_TIMEOUT_MS",
    }),
    hardExitMs: parseInteger(env.SHUTDOWN_HARD_EXIT_MS, 800, {
      name: "SHUTDOWN_HARD_EXIT_MS",
    }),

    auditEnabled: parseBool(env.AUDIT_ENABLED, defaults.auditEnabled),
    auditRetentionDays: parseInteger(env.AUDIT_RETENTION_DAYS, 30, {
      name: "AUDIT_RETENTION_DAYS",
      min: 1,
    }),
    usageFlushIntervalMs: parseInteger(env.USAGE_FLUSH_INTERVAL_MS, 30000, {
      name: "USAGE_FLUSH_INTERVAL_MS",
      min: 100,
    }),
    metricsEnabled: parseBool(env.METRICS_ENABLED, defaults.metricsEnabled),
    metricsToken: env.METRICS_TOKEN || null,
    metricsPublic: parseBool(env.METRICS_PUBLIC, false),
    logJson: parseBool(env.LOG_JSON, defaults.logJson),

    adminPublicPath: env.ADMIN_PUBLIC_PATH || null,
    adminAuthDbPath: env.ADMIN_AUTH_DB_PATH || null,
    adminSessionSecret,
    adminSessionSecretIsDefault: adminSessionSecret === DEFAULT_SESSION_SECRET,
    adminBootstrapUsername: env.ADMIN_BOOTSTRAP_USERNAME || null,
    adminBootstrapPassword: env.ADMIN_BOOTSTRAP_PASSWORD || null,
    adminTrustProxy: parseBool(env.ADMIN_TRUST_PROXY, trustProxy),
    // Operator sign-in through OIDC (all four required to enable it), and
    // whether the username/password form stays available.
    adminOidc: env.ADMIN_OIDC_ISSUER && env.ADMIN_OIDC_CLIENT_ID && env.ADMIN_OIDC_CLIENT_SECRET && env.ADMIN_OIDC_REDIRECT_URL
      ? {
        issuer: env.ADMIN_OIDC_ISSUER,
        clientId: env.ADMIN_OIDC_CLIENT_ID,
        clientSecret: env.ADMIN_OIDC_CLIENT_SECRET,
        redirectUrl: env.ADMIN_OIDC_REDIRECT_URL,
        requireMfa: parseBool(env.ADMIN_OIDC_REQUIRE_MFA, true),
      }
      : null,
    adminPasswordLogin: parseBool(env.ADMIN_PASSWORD_LOGIN, true),
    adminCookieSecure: parseBool(env.ADMIN_COOKIE_SECURE, false),
    adminLoginWindowMs: parseInteger(env.ADMIN_LOGIN_WINDOW_MS, 10 * 60 * 1000, {
      name: "ADMIN_LOGIN_WINDOW_MS",
      min: 1,
    }),
    adminLoginMaxAttempts: parseInteger(env.ADMIN_LOGIN_MAX_ATTEMPTS, 6, {
      name: "ADMIN_LOGIN_MAX_ATTEMPTS",
      min: 1,
    }),

    warnings,
  };

  if (config.adminPublicPath && !config.adminPublicPath.startsWith("/")) {
    throw new ConfigError("ADMIN_PUBLIC_PATH must start with /");
  }

  if (config.hosted) {
    if (config.adminSessionSecretIsDefault) {
      throw new ConfigError(
        "ADMIN_SESSION_SECRET must be set to a strong value in hosted mode",
      );
    }
    if (config.anonEnabled && !config.anonTokenSecret) {
      throw new ConfigError(
        "ANON_TOKEN_SECRET must be set when ANON_ENABLED is true in hosted mode",
      );
    }
    if (config.egressPolicy === "open") {
      throw new ConfigError("EGRESS_POLICY=open is not allowed in hosted mode");
    }
    if (config.adminPublicPath && !config.adminCookieSecure) {
      throw new ConfigError(
        "ADMIN_PUBLIC_PATH requires ADMIN_COOKIE_SECURE=true",
      );
    }
    if (!config.allowedOrigins) {
      warnings.push(
        "ALLOWED_ORIGINS is not set; browser clients from any origin can use the HTTP APIs",
      );
    }
    const logLevel = env.LOG_LEVEL === undefined ? 1 : Number.parseInt(env.LOG_LEVEL, 10);
    if (logLevel > 0) {
      warnings.push(
        "LOG_LEVEL is above 0 in hosted mode; the data plane logs every packet",
      );
    }
  } else if (config.adminSessionSecretIsDefault) {
    warnings.push(
      "ADMIN_SESSION_SECRET is using the default value. Set a strong secret for production.",
    );
  }

  let trustedProxies = null;
  try {
    trustedProxies = parseProxyRanges(config.trustedProxyCidrs);
  } catch (error) {
    throw new ConfigError(`TRUSTED_PROXY_CIDRS: ${error.message}`);
  }
  if (config.hosted && config.trustProxy && !trustedProxies) {
    warnings.push(
      "TRUST_PROXY is on without TRUSTED_PROXY_CIDRS; clients that reach the relay directly can forge their address",
    );
  }
  // Options for server/client_ip.js resolveClientIP, shared by every caller.
  config.clientIpOptions = {
    trustProxy: config.trustProxy,
    hops: config.trustProxyHops,
    header: config.clientIpHeader,
    peerHeader: config.peerIpHeader,
    trustedProxies,
  };

  return config;
}

module.exports = {
  ConfigError,
  DEFAULT_SESSION_SECRET,
  MODE_DEFAULTS,
  resolveConfig,
};
