/**
 * Port allocation scheme:
 *   DeployHub API: 5001 (fixed)
 *   App slot N:
 *     Prod FE: 3000 + (N*2 - 1)  = 3001, 3003, 3005...
 *     Prod BE: 4000 + (N*2 - 1)  = 4001, 4003, 4005...
 *     Sand FE: 3000 + (N*2)      = 3002, 3004, 3006...
 *     Sand BE: 4000 + (N*2)      = 4002, 4004, 4006...
 */

export function getPortsForSlot(slot) {
  return {
    prod_fe: 3000 + (slot * 2 - 1),
    prod_be: 4000 + (slot * 2 - 1),
    sand_fe: 3000 + (slot * 2),
    sand_be: 4000 + (slot * 2),
  };
}

export function getNextSlot(db) {
  const row = db.prepare('SELECT MAX(slot) as max_slot FROM apps').get();
  return (row?.max_slot || 0) + 1;
}
