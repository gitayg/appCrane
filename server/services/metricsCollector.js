import { getDb } from '../db.js';
import { getPortsForSlot } from './portAllocator.js';
import { getProcessMetrics } from './docker.js';
import log from '../utils/logger.js';

/**
 * Collect metrics for all apps from Docker.
 */
export async function collectAllMetrics() {
  const db = getDb();
  const apps = db.prepare('SELECT * FROM apps').all();

  return Promise.all(apps.map(async (app) => {
    const ports = getPortsForSlot(app.slot);

    const [prodProc, sandProc] = await Promise.all([
      getProcessMetrics(app.slug, 'production'),
      getProcessMetrics(app.slug, 'sandbox'),
    ]);

    const healthProd = db.prepare('SELECT * FROM health_state WHERE app_id = ? AND env = ?').get(app.id, 'production');
    const healthSand = db.prepare('SELECT * FROM health_state WHERE app_id = ? AND env = ?').get(app.id, 'sandbox');

    const lastDeployProd = db.prepare(
      'SELECT version, status, finished_at FROM deployments WHERE app_id = ? AND env = ? ORDER BY started_at DESC LIMIT 1'
    ).get(app.id, 'production');
    const lastDeploySand = db.prepare(
      'SELECT version, status, finished_at FROM deployments WHERE app_id = ? AND env = ? ORDER BY started_at DESC LIMIT 1'
    ).get(app.id, 'sandbox');

    return {
      slug: app.slug,
      name: app.name,
      domain: app.domain,
      production: {
        ports: { fe: ports.prod_fe, be: ports.prod_be },
        process: prodProc,
        health: healthProd ? {
          status: healthProd.is_down ? 'down' : (healthProd.last_status === 200 ? 'healthy' : 'unknown'),
          response_ms: healthProd.last_response_ms,
        } : { status: 'unknown' },
        deploy: lastDeployProd,
      },
      sandbox: {
        ports: { fe: ports.sand_fe, be: ports.sand_be },
        process: sandProc,
        health: healthSand ? {
          status: healthSand.is_down ? 'down' : (healthSand.last_status === 200 ? 'healthy' : 'unknown'),
          response_ms: healthSand.last_response_ms,
        } : { status: 'unknown' },
        deploy: lastDeploySand,
      },
    };
  }));
}
