// Can image trust be switched to enforce without stopping anything? Under
// enforce a container whose image this instance has not signed is not started
// or restarted, so every running unsigned image is an app whose next health
// auto-restart is refused. So is a signed image without its SBOM attestation
// and one whose attestation does not verify: running_unsigned lists all three. Those block the switch (unless an admin acknowledges
// them). Unsigned images on disk do not: a rollback runs through the deploy
// pipeline, which signs a cached image it starts (attest.js attestDeployImage),
// so they are listed for the backfill, not counted against the switch.

import { getDb } from '../../db.js';
import { signCurrentImages } from './backfill.js';
import { backfillDiskImages } from './diskBackfill.js';
import { openTrustEvents } from './events.js';

// Every running state verify-before-run refuses under enforce: no signature, a
// signature whose SBOM attestation was never made (the scanner was missing),
// and a signed row whose documents do not verify.
export const REFUSED_STATES = new Set(['unsigned', 'sbom-missing', 'invalid']);

export async function enforceReadiness(db = getDb()) {
  const envs = await signCurrentImages({ db, dryRun: true });
  const disk = await backfillDiskImages({ db, dryRun: true });
  const runningUnsigned = envs.filter((e) => REFUSED_STATES.has(e.state));
  return {
    ready: runningUnsigned.length === 0,
    running_unsigned: runningUnsigned,
    would_refuse: {
      total: runningUnsigned.length,
      unsigned: envs.filter((e) => e.state === 'unsigned').length,
      sbom_missing: envs.filter((e) => e.state === 'sbom-missing').length,
      scanner_missing: envs.filter((e) => e.state === 'sbom-missing' && e.scanner_missing).length,
      invalid: envs.filter((e) => e.state === 'invalid').length,
    },
    on_disk_unsigned: disk.images.filter((i) => i.state === 'unsigned'),
    on_disk_unprovable: disk.images.filter((i) => i.state === 'unprovable'),
    ...(disk.error ? { on_disk_error: disk.error } : {}),
    events: openTrustEvents(db),
  };
}
