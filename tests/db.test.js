"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { openDatabase } = require("../auth/db");

test("statements from other callers never join or roll back with an open transaction", async () => {
  const db = openDatabase(":memory:");
  await db.exec("CREATE TABLE t (k TEXT PRIMARY KEY, v TEXT)");
  await db.run("INSERT INTO t VALUES ('ban', 'active')");

  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const failing = db.transaction(async () => {
    await db.run("INSERT INTO t VALUES ('tx', '1')");
    await gate; // hold the transaction open while others queue up
    throw new Error("roll back");
  });
  const outside = db.run("UPDATE t SET v = 'banned' WHERE k = 'ban'");
  const second = db.transaction(async () => db.run("INSERT INTO t VALUES ('tx2', '1')"));
  release();

  await assert.rejects(failing, /roll back/);
  assert.equal((await outside).changes, 1);
  await second;
  const rows = await db.all("SELECT k, v FROM t ORDER BY k");
  assert.deepEqual(rows, [{ k: "ban", v: "banned" }, { k: "tx2", v: "1" }]);
  await db.close();
});
