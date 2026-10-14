"use strict";

// Small structured logger for the hosted modules. The upstream data plane keeps
// its own console logging gated by LOG_LEVEL; this logger is for lifecycle,
// auth, policy and admin events, which must stay readable in a log aggregator.

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

function formatValue(value) {
  if (value instanceof Error) return value.message;
  if (typeof value === "string") {
    return /[\s"=]/.test(value) ? JSON.stringify(value) : value;
  }
  return JSON.stringify(value);
}

function createLogger({
  json = false,
  level = "info",
  stream = process.stdout,
  now = Date.now,
  fields = {},
} = {}) {
  const threshold = LEVELS[level];
  if (threshold === undefined) {
    throw new RangeError(`Unknown log level "${level}"`);
  }

  function write(levelName, msg, extra) {
    if (LEVELS[levelName] < threshold) return;
    const record = { ...fields, ...extra };
    if (json) {
      const entry = { ts: new Date(now()).toISOString(), level: levelName, msg };
      for (const [key, value] of Object.entries(record)) {
        entry[key] = value instanceof Error ? value.message : value;
      }
      stream.write(`${JSON.stringify(entry)}\n`);
      return;
    }
    const suffix = Object.entries(record)
      .map(([key, value]) => `${key}=${formatValue(value)}`)
      .join(" ");
    stream.write(`[${levelName}] ${msg}${suffix ? ` ${suffix}` : ""}\n`);
  }

  const logger = {
    debug: (msg, extra = {}) => write("debug", msg, extra),
    info: (msg, extra = {}) => write("info", msg, extra),
    warn: (msg, extra = {}) => write("warn", msg, extra),
    error: (msg, extra = {}) => write("error", msg, extra),
    child: (childFields) =>
      createLogger({
        json,
        level,
        stream,
        now,
        fields: { ...fields, ...childFields },
      }),
  };
  return logger;
}

module.exports = { LEVELS, createLogger };
