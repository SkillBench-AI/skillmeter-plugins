"use strict";
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { sandbox, PLUGIN_ROOT, license } = require("../../../test-support/plugin.cjs");

const command = path.join(PLUGIN_ROOT, "bin", "sk-recover-cutover");
const bytes = '{"event":"synthetic-one"}\n{"event":"synthetic-two"}\n';
const digest = crypto.createHash("sha256").update(bytes).digest("hex");

function fixture(t) {
  const s = sandbox(t);
  const logDir = path.join(s.data, "logs");
  fs.mkdirSync(logDir, { recursive: true });
  const active = path.join(logDir, "events.jsonl");
  fs.writeFileSync(active, bytes);
  fs.writeFileSync(s.sessionFile, JSON.stringify({
    license_jwt: license(), refresh_token: "synthetic-refresh", auth_generation: "old",
  }));
  const run = hash => s.spawn([command, "--expected-sha256", hash]);
  return { s, logDir, active, run };
}

test("reviewed active queue is quarantined without upload and broker session is adopted", t => {
  const { s, logDir, active, run } = fixture(t);
  const result = run(digest);
  assert.equal(result.status, 0, result.stderr);
  const outcome = JSON.parse(result.stdout);
  assert.equal(outcome.status, "quarantined");
  assert.equal(outcome.sha256, digest);
  assert.equal(outcome.rows, 2);
  assert.equal(fs.existsSync(active), false);
  assert.equal(fs.readFileSync(path.join(outcome.directory, "events.jsonl"), "utf8"), bytes);
  assert.equal(fs.readFileSync(path.join(outcome.directory, "events.jsonl.backup"), "utf8"), bytes);
  assert.equal(JSON.parse(fs.readFileSync(path.join(outcome.directory, "manifest.json"))).disposition,
    "quarantined-not-uploaded");
  assert.equal(fs.statSync(path.join(logDir, "cutover-review")).mode & 0o077, 0);
  assert.equal(fs.statSync(path.join(outcome.directory, "events.jsonl.backup")).mode & 0o077, 0);
  const session = JSON.parse(fs.readFileSync(s.sessionFile));
  assert.equal(session.event_cutover, 1);
  assert.equal(session.auth_generation, "old");
  assert.equal(session.refresh_token, "synthetic-refresh");
  assert.equal(s.spawned(), false);
  const second = run(digest);
  assert.notEqual(second.status, 0);
  assert.match(second.stderr, /cutover-already-complete/);
});

test("changed digest holds the queue and session marker", t => {
  const { s, active, logDir, run } = fixture(t);
  const result = run("0".repeat(64));
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /event-file-digest-changed/);
  assert.equal(fs.readFileSync(active, "utf8"), bytes);
  assert.equal(JSON.parse(fs.readFileSync(s.sessionFile)).event_cutover, undefined);
  assert.equal(fs.existsSync(path.join(logDir, "cutover-review")), false);
});

test("an extra pending batch holds recovery without changing either file", t => {
  const { s, active, logDir, run } = fixture(t);
  const batch = path.join(logDir, "events.jsonl.123");
  fs.writeFileSync(batch, bytes);
  const result = run(digest);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /expected-one-active-event-file/);
  assert.equal(fs.readFileSync(active, "utf8"), bytes);
  assert.equal(fs.readFileSync(batch, "utf8"), bytes);
  assert.equal(JSON.parse(fs.readFileSync(s.sessionFile)).event_cutover, undefined);
});

test("a busy event file holds recovery without changing the queue", t => {
  const { s, active, run } = fixture(t);
  const lock = require("../../../plugins/skillmeter/scripts/lib/transcript-delta").acquireLock(`${active}.lock`);
  assert.ok(lock);
  try {
    const result = run(digest);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /event-file-busy/);
    assert.equal(fs.readFileSync(active, "utf8"), bytes);
    assert.equal(JSON.parse(fs.readFileSync(s.sessionFile)).event_cutover, undefined);
  } finally { lock(); }
});

test("signed-out and unknown-version sessions cannot adopt a pending queue", t => {
  const { s, active, run } = fixture(t);
  for (const state of [
    { refresh_token: "old", signed_out: true },
    { license_jwt: license(), event_cutover: 2 },
    {},
  ]) {
    fs.writeFileSync(s.sessionFile, JSON.stringify(state));
    const result = run(digest);
    assert.notEqual(result.status, 0);
    assert.equal(fs.readFileSync(active, "utf8"), bytes);
    assert.deepEqual(JSON.parse(fs.readFileSync(s.sessionFile)), state);
  }
});
