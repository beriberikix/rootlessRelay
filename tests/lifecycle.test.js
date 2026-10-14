"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { installLifecycle } = require("../server/lifecycle");

function fakeProcess() {
  const proc = new EventEmitter();
  proc.exits = [];
  proc.exit = (code) => proc.exits.push(code);
  return proc;
}

function fakeServer() {
  return { closed: 0, close() { this.closed += 1; } };
}

function fakeWs() {
  return { closes: [], close(code, reason) { this.closes.push({ code, reason }); } };
}

const quietLog = { info() {}, warn() {}, error() {} };

test("SIGTERM closes servers, tells clients to reconnect, flushes, and exits 0", async () => {
  const proc = fakeProcess();
  const server = fakeServer();
  const ws = fakeWs();
  let flushed = false;
  installLifecycle({
    proc,
    servers: [server],
    getSessions: () => [{ ws }],
    flushers: [async () => { flushed = true; }],
    timeoutMs: 50,
    hardExitMs: 100,
    log: quietLog,
  });
  proc.emit("SIGTERM");
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(server.closed, 1);
  assert.deepEqual(ws.closes, [{ code: 1001, reason: "server shutting down" }]);
  assert.equal(flushed, true);
  assert.deepEqual(proc.exits, [0]);
});

test("a slow flusher is abandoned after the timeout and the exit still happens", async () => {
  const proc = fakeProcess();
  installLifecycle({
    proc,
    flushers: [() => new Promise(() => {})],
    timeoutMs: 20,
    hardExitMs: 1000,
    log: quietLog,
  });
  proc.emit("SIGINT");
  await new Promise((resolve) => setTimeout(resolve, 60));
  assert.deepEqual(proc.exits, [0]);
});

test("uncaught exceptions shut down with exit code 1 and the hard timer fires if flush hangs", async () => {
  const proc = fakeProcess();
  const timers = [];
  installLifecycle({
    proc,
    flushers: [() => new Promise(() => {})],
    timeoutMs: 10000,
    hardExitMs: 15,
    log: quietLog,
    setTimeoutFn: (fn, ms) => {
      const timer = setTimeout(fn, ms);
      timers.push(timer);
      return timer;
    },
  });
  proc.emit("uncaughtException", new Error("boom"));
  await new Promise((resolve) => setTimeout(resolve, 40));
  assert.deepEqual(proc.exits, [1]);
  for (const timer of timers) clearTimeout(timer);
});

test("a second signal exits immediately", async () => {
  const proc = fakeProcess();
  const lifecycle = installLifecycle({
    proc,
    flushers: [() => new Promise(() => {})],
    timeoutMs: 10000,
    hardExitMs: 10000,
    log: quietLog,
    setTimeoutFn: () => ({ unref() {} }),
  });
  proc.emit("SIGTERM");
  assert.equal(lifecycle.isShuttingDown(), true);
  proc.emit("SIGTERM");
  assert.deepEqual(proc.exits, [0]);
});
