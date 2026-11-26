import { Router } from 'express';
import { requireAuth, requirePlatformAdmin } from '../middleware/auth.js';
import { getDb } from '../db.js';
import { computePosture } from '../services/hostFirewall/posture.js';
import { getLastSync, readCurrentChains, DEFAULT_DEPS } from '../services/hostFirewall/publishChain.js';

// Settings > Job Health > Host network (platform admin, read only). Mounted at
// /api/platform. Reading needs no step-up: it changes nothing, and the same
// facts are what host hardening's status already shows a platform admin.

export function createHostNetworkRouter(deps = {}) {
  const d = { ...DEFAULT_DEPS, ...deps };
  const router = Router();

  router.get('/host-network', requireAuth, requirePlatformAdmin, async (req, res) => {
    const lastSync = d.lastSync ?? getLastSync();
    const posture = await computePosture({ deps: { ...d, lastSync }, db: getDb() });
    const chain = posture.applicable ? await readCurrentChains(d.run) : {};
    for (const [fam, c] of Object.entries(chain)) {
      const written = lastSync?.mode === 'helper' ? lastSync.families?.[fam] : null;
      if (c.state === 'no_permission' && written?.state === 'applied') chain[fam] = { state: 'helper', exists: true, entries: written.entries, at: lastSync.at };
    }
    res.json({
      posture: { applicable: posture.applicable, reason: posture.reason || null, at: posture.at, findings: posture.findings, families: posture.families, listen: posture.listen || null, imds: posture.imds || null },
      chain,
      desired: posture.desired,
      strays: posture.strays,
      docker: posture.docker || null,
      db: posture.db || null,
      last_sync: lastSync ? { status: lastSync.status, at: lastSync.at, mode: lastSync.mode || null, reason: lastSync.reason || null } : null,
    });
  });

  return router;
}

export default createHostNetworkRouter();
