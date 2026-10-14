"use strict";

// express-session store backed by the relay's SQLite database, so operator
// logins survive restarts (the default MemoryStore does not).

const { Store } = require("express-session");

const DEFAULT_TTL_MS = 8 * 60 * 60 * 1000;

class SqliteSessionStore extends Store {
  constructor({ db, now = Date.now, pruneIntervalMs = 60000, ttlMs = DEFAULT_TTL_MS }) {
    super();
    this.db = db;
    this.now = now;
    this.ttlMs = ttlMs;
    this.pruneTimer = null;
    if (pruneIntervalMs > 0) {
      this.pruneTimer = setInterval(() => {
        this.prune().catch(() => {});
      }, pruneIntervalMs);
      this.pruneTimer.unref();
    }
  }

  expiresAtFor(session) {
    const cookie = session && session.cookie;
    if (cookie && cookie.expires) {
      const expires = new Date(cookie.expires).getTime();
      if (Number.isFinite(expires)) return expires;
    }
    if (cookie && Number.isFinite(cookie.maxAge)) return this.now() + cookie.maxAge;
    return this.now() + this.ttlMs;
  }

  get(sid, callback) {
    this.db.get("SELECT data, expires_at FROM admin_sessions WHERE sid = ?", [sid])
      .then((row) => {
        if (!row) {
          callback(null, null);
          return;
        }
        if (row.expires_at <= this.now()) {
          this.db.run("DELETE FROM admin_sessions WHERE sid = ?", [sid]).catch(() => {});
          callback(null, null);
          return;
        }
        callback(null, JSON.parse(row.data));
      })
      .catch(callback);
  }

  set(sid, session, callback) {
    const data = JSON.stringify(session);
    this.db.run(
      "INSERT INTO admin_sessions (sid, data, expires_at) VALUES (?, ?, ?) " +
      "ON CONFLICT(sid) DO UPDATE SET data = excluded.data, expires_at = excluded.expires_at",
      [sid, data, this.expiresAtFor(session)],
    )
      .then(() => callback && callback(null))
      .catch((error) => callback && callback(error));
  }

  touch(sid, session, callback) {
    this.db.run("UPDATE admin_sessions SET expires_at = ? WHERE sid = ?", [this.expiresAtFor(session), sid])
      .then(() => callback && callback(null))
      .catch((error) => callback && callback(error));
  }

  destroy(sid, callback) {
    this.db.run("DELETE FROM admin_sessions WHERE sid = ?", [sid])
      .then(() => callback && callback(null))
      .catch((error) => callback && callback(error));
  }

  length(callback) {
    this.db.get("SELECT COUNT(*) AS count FROM admin_sessions WHERE expires_at > ?", [this.now()])
      .then((row) => callback(null, row.count))
      .catch(callback);
  }

  clear(callback) {
    this.db.run("DELETE FROM admin_sessions")
      .then(() => callback && callback(null))
      .catch((error) => callback && callback(error));
  }

  async prune() {
    const result = await this.db.run("DELETE FROM admin_sessions WHERE expires_at <= ?", [this.now()]);
    return result.changes;
  }

  close() {
    if (this.pruneTimer) clearInterval(this.pruneTimer);
  }
}

module.exports = { SqliteSessionStore };
