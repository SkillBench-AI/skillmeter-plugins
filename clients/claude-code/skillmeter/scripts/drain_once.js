#!/usr/bin/env node
/**
 * Drain durable queues in a detached process so hooks do not wait on uploads.
 * The drains refresh the license before sending. Failed uploads stay queued
 * for the next drain.
 */

const {
  clearDrainOnceLock,
  drainQueuesOnce,
  spawnDetachedDrain,
  takeDrainRequest,
} = require("./lib/transfer");

// Hooks that run while this drain does ask for another pass (transfer.js
// shouldSpawnDrainOnce). Bounded so a busy session cannot keep one alive.
const MAX_PASSES = 5;

async function main() {
  try {
    for (let pass = 0; pass < MAX_PASSES; pass++) {
      await drainQueuesOnce();
      if (!takeDrainRequest()) break;
    }
  } finally {
    clearDrainOnceLock();
  }
  // A request made while the lock was being released, or after the last
  // pass, gets a drain of its own.
  if (takeDrainRequest()) spawnDetachedDrain();
}

main().catch((err) => {
  process.stderr.write(`[skillmeter-drain-once] ${err && err.message ? err.message : err}\n`);
  clearDrainOnceLock();
  process.exit(0);
});
