// Pause between deploy-time health probe attempts: 250 ms, doubling to a 2 s
// cap. An app that is up within a second is seen within a second instead of
// after a fixed 2 s sleep; one that takes longer is polled as often as before.
export const PROBE_BACKOFF_START_MS = 250;
export const PROBE_BACKOFF_CAP_MS = 2000;

/** Delay after the `attempt`-th failed attempt (0-based). */
export function probeBackoffMs(attempt) {
  return Math.min(PROBE_BACKOFF_CAP_MS, PROBE_BACKOFF_START_MS * 2 ** Math.min(attempt, 10));
}
