"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { MAX_STRING, createLogger } = require("../log");

function capture(json) {
  const lines = [];
  const log = createLogger({ json, stream: { write: (line) => lines.push(line) }, now: () => 0 });
  return { log, lines };
}

test("long string fields are clipped, in JSON and text output", () => {
  const origin = `https://${"a".repeat(5000)}.example`;
  const json = capture(true);
  json.log.warn("upgrade rejected: origin", { origin, clientIP: "203.0.113.5", count: 3 });
  const entry = JSON.parse(json.lines[0]);
  assert.equal(entry.origin.length, MAX_STRING + "…(+".length + String(origin.length - MAX_STRING).length + 1);
  assert.ok(entry.origin.startsWith("https://aaa"));
  assert.ok(entry.origin.endsWith(`…(+${origin.length - MAX_STRING})`));
  assert.deepEqual([entry.clientIP, entry.count, entry.msg], ["203.0.113.5", 3, "upgrade rejected: origin"]);

  const text = capture(false);
  text.log.warn("token from unknown issuer", { issuer: "x".repeat(1000), error: new Error("e".repeat(1000)) });
  assert.ok(text.lines[0].length < 2 * MAX_STRING + 100);
  assert.match(text.lines[0], /issuer=x+…\(\+744\) error=e+…\(\+744\)/);
});
