"use strict";

// Graceful shutdown and crash handling. Hosting platforms send SIGTERM and
// kill shortly after (the test harnesses wait 1 s), so the whole sequence is
// bounded: stop accepting, tell every client to reconnect, flush metering,
// exit. A hard-exit timer guarantees the process never hangs.

function installLifecycle({
  proc = process,
  servers = [],
  getSessions = () => [],
  flushers = [],
  timeoutMs = 500,
  hardExitMs = 800,
  log,
  setTimeoutFn = setTimeout,
} = {}) {
  let shuttingDown = false;

  function closeServers() {
    for (const server of servers) {
      try {
        server.close();
      } catch (error) {
        log?.warn("server close failed", { error });
      }
    }
  }

  function closeSessions(code, reason) {
    for (const session of getSessions()) {
      const ws = session.ws || session;
      try {
        if (typeof ws.close === "function") ws.close(code, reason);
      } catch (error) {
        log?.warn("session close failed", { error });
      }
    }
  }

  async function flush() {
    const results = await Promise.race([
      Promise.allSettled(flushers.map((flusher) => Promise.resolve().then(flusher))),
      new Promise((resolve) => {
        const timer = setTimeoutFn(() => resolve("timeout"), timeoutMs);
        if (timer && typeof timer.unref === "function") timer.unref();
      }),
    ]);
    if (results === "timeout") {
      log?.warn("shutdown flush timed out", { timeoutMs });
      return;
    }
    for (const result of results) {
      if (result.status === "rejected") {
        log?.warn("shutdown flush failed", { error: result.reason });
      }
    }
  }

  async function shutdown(reason, code = 0) {
    if (shuttingDown) {
      log?.warn("shutdown already in progress; exiting now", { reason });
      proc.exit(code);
      return;
    }
    shuttingDown = true;
    log?.info("shutting down", { reason, code });
    const hardExit = setTimeoutFn(() => {
      log?.error("shutdown exceeded hard limit; exiting", { hardExitMs });
      proc.exit(code || 1);
    }, hardExitMs);
    if (hardExit && typeof hardExit.unref === "function") hardExit.unref();

    closeServers();
    closeSessions(1001, "server shutting down");
    await flush();
    proc.exit(code);
  }

  proc.on("SIGTERM", () => {
    shutdown("SIGTERM", 0);
  });
  proc.on("SIGINT", () => {
    shutdown("SIGINT", 0);
  });
  proc.on("uncaughtException", (error) => {
    log?.error("uncaught exception", { error, stack: error && error.stack });
    shutdown("uncaughtException", 1);
  });
  proc.on("unhandledRejection", (reason) => {
    const error = reason instanceof Error ? reason : new Error(String(reason));
    log?.error("unhandled rejection", { error, stack: error.stack });
    shutdown("unhandledRejection", 1);
  });

  return {
    shutdown,
    isShuttingDown: () => shuttingDown,
    addServer: (server) => servers.push(server),
    addFlusher: (flusher) => flushers.push(flusher),
  };
}

module.exports = { installLifecycle };
