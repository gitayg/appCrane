/**
 * Port allocation scheme:
 *   DeployHub API: 5001 (fixed)
 *   App slot N:
 *     Prod FE: 3000 + (N*2 - 1)  = 3001, 3003, 3005...
 *     Prod BE: 4000 + (N*2 - 1)  = 4001, 4003, 4005...
 *     Sand FE: 3000 + (N*2)      = 3002, 3004, 3006...
 *     Sand BE: 4000 + (N*2)      = 4002, 4004, 4006...
 *
 * v2.6.10: getNextSlot now skips slots whose allocation lands on a
 * WHATWG-blocked port (Node's fetch() refuses those, so the health
 * probe dies silently and the deploy never goes live). Castle hit
 * this at slot 23 → prod_be 4045 (NFS lockd) and every retry failed
 * with no diagnostic signal. See blockedPorts.js for the list.
 */

import { arePortsSafe } from './blockedPorts.js';

export function getPortsForSlot(slot) {
  return {
    prod_fe: 3000 + (slot * 2 - 1),
    prod_be: 4000 + (slot * 2 - 1),
    sand_fe: 3000 + (slot * 2),
    sand_be: 4000 + (slot * 2),
  };
}

/**
 * First slot at or after `max(slot)+1` whose ports are all safe.
 * Capped at 1000 attempts so a misconfigured blocklist can't spin.
 */
export function getNextSlot(db) {
  const row = db.prepare('SELECT MAX(slot) as max_slot FROM apps').get();
  let candidate = (row?.max_slot || 0) + 1;
  for (let i = 0; i < 1000; i++) {
    if (arePortsSafe(getPortsForSlot(candidate))) return candidate;
    candidate++;
  }
  throw new Error(`Port allocator: no safe slot found in the next 1000 candidates from slot ${(row?.max_slot || 0) + 1}. Inspect the WHATWG-bad-ports blocklist in blockedPorts.js and the slot→port formula.`);
}
