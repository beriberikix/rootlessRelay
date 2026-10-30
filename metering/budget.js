"use strict";

// Relay-wide monthly egress budget: a pure state machine over the month's
// byte count (kept and stored by metering/usage.js). Past the throttle
// threshold, new sessions in the budget tiers start at a lower rate; past the
// pause threshold they are closed and refused until the next UTC month. An
// operator override ("open" | "paused") wins until cleared or the month
// rolls over. With either threshold unset the budget is off: always open.

const STATES = ["open", "throttled", "paused"];

// First day of the next UTC month, as YYYY-MM-DD.
function nextMonthStart(ts) {
  const date = new Date(ts);
  const next = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 1));
  return next.toISOString().slice(0, 10);
}

function createBudget({ throttleBytes = null, pauseBytes = null, throttleBps = 65536, tiers = [] } = {}) {
  const enabled = throttleBytes !== null && pauseBytes !== null;
  const budgetTiers = new Set(tiers);

  return {
    enabled,
    throttleBytes: enabled ? throttleBytes : null,
    pauseBytes: enabled ? pauseBytes : null,
    tiers: [...budgetTiers],
    appliesTo(tierName) {
      return enabled && budgetTiers.has(tierName);
    },
    evaluate({ bytes = 0, forced = null, now = Date.now() } = {}) {
      if (!enabled) return { state: "open", pausedUntil: null };
      let state;
      if (forced === "open" || forced === "paused") state = forced;
      else if (bytes >= pauseBytes) state = "paused";
      else if (bytes >= throttleBytes) state = "throttled";
      else state = "open";
      return { state, pausedUntil: state === "paused" ? nextMonthStart(now) : null };
    },
    // Never raises a tier's rate: an unlimited direction becomes the throttle.
    throttledRates(tier) {
      return {
        uploadBps: Math.min(tier.uploadBps ?? Infinity, throttleBps),
        downloadBps: Math.min(tier.downloadBps ?? Infinity, throttleBps),
      };
    },
  };
}

function createDisabledBudget() {
  return createBudget();
}

module.exports = { STATES, createBudget, createDisabledBudget, nextMonthStart };
