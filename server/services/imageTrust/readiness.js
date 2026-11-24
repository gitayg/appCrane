// Can image trust be switched to enforce without stopping anything? Under
// enforce a container whose image this instance has not signed is not started
// or restarted, so every running unsigned image is an app whose next health
// auto-restart is refused. Those block the switch (unless an admin acknowledges
// them). Unsigned images on disk do not: a rollback runs through the deploy
// pipeline, which signs a cached image it starts (attest.js attestDeployImage),
// so they are listed for the backfill, not counted against the switch.

import { getDb } from '../../db.js';
import { signCurrentImages } from './backfill.js';
import { backfillDiskImages } from './diskBackfill.js';
import { openTrustEvents } from './events.js';

export async function enforceReadiness(db = getDb()) {
  const envs = await signCurrentImages({ db, dryRun: true });
  const disk = await backfillDiskImages({ db, dryRun: true });
  const runningUnsigned = envs.filter((e) => e.state === 'unsigned');
  return {
    ready: runningUnsigned.length === 0,
    running_unsigned: runningUnsigned,
    on_disk_unsigned: disk.images.filter((i) => i.state === 'unsigned'),
    on_disk_unprovable: disk.images.filter((i) => i.state === 'unprovable'),
    ...(disk.error ? { on_disk_error: disk.error } : {}),
    events: openTrustEvents(db),
  };
}
