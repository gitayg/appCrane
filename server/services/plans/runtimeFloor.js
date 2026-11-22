// Contract between the plans feature (owner of this file) and the container
// runtime feature: the least isolated runtime an app's plan allows.
// Returns 'runsc' when the app must run under gVisor, or null for no floor.
export function planRuntimeFloor(_db, _app) {
  return null;
}
