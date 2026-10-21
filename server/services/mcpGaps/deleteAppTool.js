// appcrane_delete_app: the MCP face of DELETE /api/apps/:slug. Registered in
// mcpTools.js's TOOLS array. Runs the same teardown (services/appDelete.js).

import { existsSync } from 'fs';
import { getDb } from '../../db.js';
import { logAudit } from '../../middleware/audit.js';
import { userHasAppPermission, isAppOwnerOrPlatformAdmin } from '../permissions.js';
import { resolveMcpApp, assertWriteCaller } from './access.js';

export const deleteAppTool = {
  name: 'appcrane_delete_app',
  description:
    'Permanently delete an app from AppCrane. IRREVERSIBLE. Stops and removes its sandbox and production containers, images and Docker volume records, drops its managed databases, and deletes its rows (deployments, env vars, health, webhooks, backups records, roles, sessions); Caddy routes are removed. ' +
    'Pass confirm_slug equal to slug, typed out: a call without it, or with any other value, is refused and changes nothing. Ask the user before calling this. ' +
    'Only the app\'s owner or a platform admin may delete, and only when the role matrix also grants app.delete (the same gate as the dashboard\'s Delete button). Read-only keys, the coder\'s connection, and keys whose MCP scope excludes the app are refused. ' +
    'Kept: the audit trail; files under the app\'s data directory on the host; for a Crane-hosted (local git) managed app its bare repository at DATA_DIR/repos/<slug>.git, so a new managed app cannot reuse the slug until an operator removes that repository; a GitHub repository is never touched.',
  inputSchema: {
    type: 'object',
    properties: {
      slug: { type: 'string', description: 'Slug of the app to delete.' },
      confirm_slug: { type: 'string', description: 'Must equal slug exactly. A safeguard against deleting the wrong app.' },
    },
    required: ['slug', 'confirm_slug'],
    additionalProperties: false,
  },
  requiredRole: 'any',
  handler: async (user, args) => {
    assertWriteCaller(user, 'delete apps');
    if (typeof args.confirm_slug !== 'string' || args.confirm_slug !== args.slug) {
      throw new Error(`CONFIRMATION_REQUIRED: pass confirm_slug="${args.slug}" (exactly the slug) to delete this app. Nothing was deleted.`);
    }
    const app = resolveMcpApp(user, args.slug);
    if (!isAppOwnerOrPlatformAdmin(user, app) || !userHasAppPermission(user, app, 'app.delete')) {
      throw new Error(`Forbidden: deleting ${app.slug} requires the app owner or a platform admin, with app.delete granted in the role matrix.`);
    }
    let repoKept = null;
    if (app.repo_backend === 'local') {
      const { repoPath } = await import('../localGit.js');
      try { repoKept = existsSync(repoPath(app.slug)) ? `repos/${app.slug}.git` : null; } catch (_) { repoKept = null; }
    }
    logAudit(user.id, app.id, 'app-delete', { via: 'mcp', slug: app.slug }, user.kind || 'agent');
    const { deleteApp } = await import('../appDelete.js');
    const out = await deleteApp(app);
    const { reloadCaddy } = await import('../caddy.js');
    reloadCaddy().catch(() => {});
    const stillThere = !!getDb().prepare('SELECT 1 FROM apps WHERE id = ?').get(app.id);
    return {
      deleted: !stillThere,
      slug: out.slug,
      managed_databases: out.managed_databases,
      ...(repoKept ? { local_repo_kept: repoKept, note: 'The Crane-hosted repository was kept (as the dashboard delete does). A new managed app cannot reuse this slug until an operator removes it.' } : {}),
    };
  },
};
