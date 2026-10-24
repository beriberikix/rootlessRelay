"use strict";

// Hosted mode needs ADMIN_SESSION_SECRET (and ANON_TOKEN_SECRET when the
// anonymous tier is on). When they are not set, generate them once and keep
// them next to the database, so a fresh `docker compose up` starts with no
// configuration and keeps working across restarts. Values set in the
// environment always win. GENERATE_SECRETS=false turns this off (the start
// then fails as before when a secret is missing).

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const FILE_NAME = "secrets.json";

function wanted(env) {
  if ((env.RELAY_MODE || "local") !== "hosted") return [];
  if (env.GENERATE_SECRETS === "false") return [];
  const names = [];
  if (!env.ADMIN_SESSION_SECRET) names.push("ADMIN_SESSION_SECRET");
  const anon = env.ANON_ENABLED === undefined ? true : /^(1|true|yes|on)$/i.test(env.ANON_ENABLED);
  if (anon && !env.ANON_TOKEN_SECRET) names.push("ANON_TOKEN_SECRET");
  return names;
}

function readFile(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return {};
    throw new Error(`${file} is not readable JSON: ${error.message}`);
  }
}

// Returns { env, file, generated, loaded }: env with the missing secrets
// filled in, the names created now, and the names read from the file.
function withGeneratedSecrets(env) {
  const names = wanted(env);
  if (names.length === 0 || !env.ADMIN_AUTH_DB_PATH || env.ADMIN_AUTH_DB_PATH === ":memory:") {
    return { env, file: null, generated: [], loaded: [] };
  }
  const file = path.join(path.dirname(path.resolve(env.ADMIN_AUTH_DB_PATH)), FILE_NAME);
  const stored = readFile(file);
  const generated = [];
  const loaded = [];
  for (const name of names) {
    if (typeof stored[name] === "string" && stored[name].length >= 32) {
      loaded.push(name);
    } else {
      stored[name] = crypto.randomBytes(32).toString("base64url");
      generated.push(name);
    }
  }
  if (generated.length > 0) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, `${JSON.stringify(stored, null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(tmp, file);
  }
  const filled = { ...env };
  for (const name of names) filled[name] = stored[name];
  return { env: filled, file, generated, loaded };
}

module.exports = { withGeneratedSecrets, FILE_NAME };
