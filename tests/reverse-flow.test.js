"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { getReverseFlow } = require("../tcp_utils");

test("getReverseFlow flips packet direction for gateway->VM replies", () => {
  const flow = getReverseFlow("10.0.2.15", "10.0.2.2", 53742, 30000);

  assert.equal(flow.relaySrcIP, "10.0.2.2");
  assert.equal(flow.relayDstIP, "10.0.2.15");
  assert.equal(flow.relaySrcPort, 30000);
  assert.equal(flow.relayDstPort, 53742);
});
