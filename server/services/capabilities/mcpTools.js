// MCP face of capability approvals. Agents may REQUEST and LIST; there is
// deliberately no approve, deny, confirm or revoke tool. A decision is made by
// a human platform admin signed in to the dashboard (store.js assertApprover).

import { getDb } from '../../db.js';
import { resolveMcpApp, assertWriteCaller } from '../mcpGaps/access.js';
import { CAPABILITIES, CAPABILITY_IDS } from './registry.js';
import { createRequest, listRequests, appCapabilities } from './store.js';

const scopeHelp = CAPABILITY_IDS.map((id) => `${id} ${JSON.stringify(CAPABILITIES[id].example)}`).join('; ');

export const requestCapabilityTool = {
  name: 'appcrane_request_capability',
  description:
    'Ask a platform admin to approve a sensitive capability for an app: a managed database, sign-in bypass paths, headless mode, public visibility, '
    + 'a raw TCP/UDP host port, a custom domain without AppCrane sign-in, outbound e-mail, an external secret store connection, the LLM gateway, outbound internet hosts (egress) or a platform API connection (connection:<name>). Owner or app admin of the app. '
    + 'Give a reason and the narrowest scope that works; the admin may narrow it further and set an expiry. One open request per app and capability: '
    + 'asking again returns the open one. This only files the request: a platform admin decides it in the dashboard, and an agent can never approve one. '
    + `Scope by capability (examples): ${scopeHelp}.`,
  inputSchema: {
    type: 'object',
    properties: {
      slug: { type: 'string', description: 'App slug.' },
      capability: {
        type: 'string',
        pattern: `^(${CAPABILITY_IDS.join('|')}|connection:[a-z0-9][a-z0-9-]{0,62})$`,
        description: `One of ${CAPABILITY_IDS.join(', ')}, or connection:<name> for a platform connection (scope { methods, path_prefixes }).`,
      },
      scope: { type: 'object', description: 'What exactly is needed, in the shape shown for the capability.' },
      reason: { type: 'string', description: 'Why the app needs it (required, up to 1000 characters).' },
    },
    required: ['slug', 'capability', 'reason'],
    additionalProperties: false,
  },
  requiredRole: 'any',
  handler: async (user, args) => {
    assertWriteCaller(user, 'request a capability');
    const app = resolveMcpApp(user, args.slug);
    const out = createRequest(getDb(), { app, user, capability: args.capability, scope: args.scope, reason: args.reason, via: 'mcp' });
    return {
      ...out,
      next: out.created
        ? 'Filed. A platform admin was notified and decides it in AppCrane; until then the capability stays refused.'
        : 'An open request for this capability already exists; it is returned unchanged.',
    };
  },
};

export const listCapabilityRequestsTool = {
  name: 'appcrane_list_capability_requests',
  description:
    'See capability approvals. With slug: that app\'s policy per capability, its active grants (including grandfathered, unreviewed ones) and open requests; any member of the app. '
    + 'Without slug: platform admins get the platform-wide queue (status pending by default; unreviewed, active, flagged, denied or all), others get the open requests of the apps they own or administer.',
  inputSchema: {
    type: 'object',
    properties: {
      slug: { type: 'string', description: 'App slug (optional).' },
      status: { type: 'string', enum: ['pending', 'unreviewed', 'active', 'flagged', 'approved', 'denied', 'cancelled', 'expired', 'revoked', 'all'] },
    },
    additionalProperties: false,
  },
  requiredRole: 'any',
  readOnly: true,
  handler: async (user, args) => {
    const db = getDb();
    if (args.slug) return appCapabilities(db, resolveMcpApp(user, args.slug), user);
    const status = args.status || 'pending';
    if (user.role === 'platform_admin') {
      // A key scoped to some apps (mcp_app_scope, or its blueprint's apps)
      // sees only those apps' requests, as every per-app tool does.
      const all = listRequests(db, { status });
      if (user.mcp_app_scope == null || user.mcp_app_scope === '') return { requests: all };
      const inScope = (slug) => { try { resolveMcpApp(user, slug); return true; } catch (_) { return false; } };
      return { requests: all.filter((q) => q.app && inScope(q.app.slug)) };
    }
    const apps = db.prepare("SELECT a.id, a.slug FROM app_user_roles r JOIN apps a ON a.id = r.app_id WHERE r.user_id = ? AND r.app_role IN ('owner', 'admin')").all(user.id);
    const requests = [];
    for (const a of apps) {
      try { resolveMcpApp(user, a.slug); } catch (_) { continue; }
      requests.push(...listRequests(db, { status, appId: a.id }));
    }
    return { requests };
  },
};
