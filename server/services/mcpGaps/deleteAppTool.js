// appcrane_delete_app: the MCP face of DELETE /api/apps/:slug. Registered in
// mcpTools.js's TOOLS array. Runs the same teardown (services/appDelete.js).

import { getDb } from '../../db.js';
import { logAudit } from '../../middleware/audit.js';
import { userHasAppPermission, isAppOwnerOrPlatformAdmin } from '../permissions.js';
import { resolveMcpApp, assertWriteCaller } from './access.js';
import { isPlatformAdmin } from '../../utils/roles.js';
import { assertToolStepUp } from '../stepUp.js';

export const deleteAppTool = {
  name: 'appcrane_delete_app',
  description:
    'Permanently delete an app from AppCrane. IRREVERSIBLE. Stops and removes its sandbox and production containers, images and Docker volume records, drops its managed databases, and deletes its rows (deployments, env vars, health, webhooks, backups records, roles, sessions); Caddy routes are removed. ' +
    'Pass confirm_slug equal to slug, typed out: a call without it, or with any other value, is refused and changes nothing. Ask the user before calling this. A key or agent also needs the user\'s recent confirmation: a call refused with STEP_UP_REQUIRED names a link for the user to open and confirm, then retry within the minutes it states. ' +
    'Only the app\'s owner or a platform admin may delete, and only when the role matrix also grants app.delete (the same gate as the dashboard\'s Delete button). Read-only keys, the coder\'s connection, and keys whose MCP scope excludes the app are refused. ' +
    'Moved to the trash (DATA_DIR/trash, kept 30 days, never purged automatically; a platform admin can purge it from the Reconcile page): the app\'s data directory and, for a Crane-hosted (local git) managed app, its bare repository, so the slug can be reused. Kept: the audit trail; a GitHub repository is never touched.',
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
    assertToolStepUp(user, 'delete_app', app);
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
      ...(out.aws_secrets_retained && { aws_secrets_retained: out.aws_secrets_retained }),
      moved_to_trash: out.moved_to_trash,
      ...(out.leftovers_kept && { leftovers_kept: out.leftovers_kept }),
      ...(out.off_site_copies_retained && (isPlatformAdmin(user) ? { off_site_copies_retained: out.off_site_copies_retained } : { off_site_copies_note: 'Platform off-site backups taken before this delete may still contain this app. A platform admin can see where.' })),
    };
  },
};
