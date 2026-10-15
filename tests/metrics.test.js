"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { createMetrics } = require("../metrics");

const sidecar = `# HELP litestream_sync_error_count Number of sync errors
# TYPE litestream_sync_error_count counter
litestream_sync_error_count{db="/data/relay.sqlite"} 0
# HELP rootlessrelay_sessions Duplicate family
# TYPE rootlessrelay_sessions gauge
rootlessrelay_sessions{tier="x"} 9
`;

test("render appends merged endpoints, skipping duplicate families and failures", async () => {
  const fetched = [];
  const metrics = createMetrics({
    mergeUrls: ["http://sidecar/metrics", "http://down/metrics"],
    fetch: async (url) => {
      fetched.push(url);
      if (url.includes("down")) throw new Error("ECONNREFUSED");
      return { ok: true, text: async () => sidecar };
    },
  });
  metrics.sessionsGauge.labels("user").set(2);

  const text = await metrics.render();
  assert.deepEqual(fetched, ["http://sidecar/metrics", "http://down/metrics"]);
  assert.match(text, /^litestream_sync_error_count\{db="\/data\/relay.sqlite"\} 0$/m);
  assert.match(text, /^rootlessrelay_sessions\{tier="user"\} 2$/m);
  assert.doesNotMatch(text, /tier="x"/);
  assert.equal(text.match(/^# TYPE rootlessrelay_sessions /gm).length, 1);
});

test("render without merge URLs returns only the relay's metrics", async () => {
  const metrics = createMetrics({ fetch: () => assert.fail("no fetch expected") });
  assert.match(await metrics.render(), /^# TYPE rootlessrelay_sessions gauge$/m);
});
