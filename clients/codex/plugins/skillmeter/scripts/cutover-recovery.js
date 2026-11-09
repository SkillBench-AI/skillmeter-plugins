"use strict";

// Explicit recovery for one active event file left by a markerless broker
// session. Call only after stopping older plugin workers and reviewing the
// pending file. This command makes no network request and never replays it.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const credstore = require("./credstore");
const logger = require("./logger");
const { acquireLock } = require("./lib/transcript-delta");

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function syncFile(file) {
  const fd = fs.openSync(file, "r");
  try { fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
}

function syncDirectory(dir) {
  let fd;
  try {
    fd = fs.openSync(dir, "r");
    fs.fsyncSync(fd);
  } catch (error) {
    if (!["EINVAL", "ENOTSUP", "EISDIR", "EBADF"].includes(error.code)) throw error;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function pendingNames() {
  try { return fs.readdirSync(logger.LOG_DIR).filter(name => /^events\.jsonl(?:\.\d+)?$/.test(name)); }
  catch (error) { if (error.code === "ENOENT") return []; throw error; }
}

function recover({ expectedSha256 }) {
  if (!/^[0-9a-f]{64}$/.test(expectedSha256 || "")) throw new Error("expected-sha256-required");
  if (credstore.isEventCutoverComplete()) throw new Error("cutover-already-complete");
  let archived;
  const committed = credstore.completeQuarantinedEventCutover(() => {
    const names = pendingNames();
    if (names.length !== 1 || names[0] !== "events.jsonl") throw new Error("expected-one-active-event-file");
    const source = path.join(logger.LOG_DIR, names[0]);
    const release = acquireLock(`${source}.lock`);
    if (!release) throw new Error("event-file-busy");
    let moved = false;
    let destination;
    try {
      const before = fs.lstatSync(source);
      if (!before.isFile() || before.nlink !== 1) throw new Error("event-file-not-regular");
      if (sha256(source) !== expectedSha256) throw new Error("event-file-digest-changed");

      const root = path.join(logger.LOG_DIR, "cutover-review");
      fs.mkdirSync(root, { recursive: true, mode: 0o700 });
      const rootStat = fs.lstatSync(root);
      if (!rootStat.isDirectory() || (rootStat.mode & 0o077) !== 0) throw new Error("quarantine-root-not-private");
      destination = path.join(root, `${new Date().toISOString().replace(/[:.]/g, "-")}-${crypto.randomUUID()}`);
      fs.mkdirSync(destination, { mode: 0o700 });
      const backup = path.join(destination, "events.jsonl.backup");
      fs.copyFileSync(source, backup, fs.constants.COPYFILE_EXCL);
      fs.chmodSync(backup, 0o600);
      syncFile(backup);
      const after = fs.lstatSync(source);
      if (after.ino !== before.ino || after.size !== before.size || after.mtimeMs !== before.mtimeMs ||
          sha256(source) !== expectedSha256 || sha256(backup) !== expectedSha256) {
        throw new Error("event-file-changed-during-backup");
      }
      const lines = fs.readFileSync(backup, "utf8").split("\n").filter(Boolean);
      const manifest = {
        disposition: "quarantined-not-uploaded",
        created_at: new Date().toISOString(),
        original: names[0],
        sha256: expectedSha256,
        bytes: before.size,
        rows: lines.length,
      };
      const manifestPath = path.join(destination, "manifest.json");
      fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n", { flag: "wx", mode: 0o600 });
      syncFile(manifestPath);
      syncDirectory(destination);
      fs.renameSync(source, path.join(destination, names[0]));
      moved = true;
      syncDirectory(destination);
      syncDirectory(logger.LOG_DIR);
      archived = { directory: destination, ...manifest };
      return true;
    } finally {
      release();
      if (!moved && destination) fs.rmSync(destination, { recursive: true, force: true });
    }
  }, logger.eventQueueEmpty);
  if (!committed || !archived) throw new Error("cutover-not-committed");
  return archived;
}

function main(argv = process.argv.slice(2)) {
  if (argv.length !== 2 || argv[0] !== "--expected-sha256") {
    process.stderr.write("Usage: sk-recover-cutover --expected-sha256 <digest>\n");
    return 2;
  }
  try {
    const outcome = recover({ expectedSha256: argv[1] });
    process.stdout.write(JSON.stringify({ status: "quarantined", ...outcome }) + "\n");
    return 0;
  } catch (error) {
    process.stderr.write(`SkillMeter cutover recovery held: ${error.message}\n`);
    return 1;
  }
}

if (require.main === module) process.exitCode = main();
module.exports = { recover, main };
