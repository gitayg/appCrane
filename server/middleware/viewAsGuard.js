import { AppError } from '../utils/errors.js';
import { viewAsOnAnyCredential, viewAsRefusalMessage } from '../services/viewAs.js';

// While a credential is viewing as another role, nothing it sends may change
// state. Mounted once at /api, ahead of every router, because several routers
// (coder, presence, ask, plan, identity) authenticate on their own and never
// reach requireAuth. Reads pass; requireAuth gives them the target role's view.
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

// Writes a viewer still needs: leaving or switching the preview, signing out,
// re-setting the session cookie the SPA posts on every load, and MCP, whose
// reads are POSTs too (routes/mcp.js refuses the write tools per call).
const ALLOWED_WRITES = new Set([
  '/api/auth/stop-viewing-as',
  '/api/auth/view-as',
  '/api/identity/logout',
  '/api/identity/refresh-cookie',
  '/api/mcp',
]);

export function viewAsWriteGuard(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();
  const path = (req.originalUrl || '').split('?')[0].replace(/\/+$/, '');
  if (ALLOWED_WRITES.has(path)) return next();
  const va = viewAsOnAnyCredential(req);
  if (!va) return next();
  return next(new AppError(viewAsRefusalMessage(va), 403, 'VIEW_AS_READ_ONLY'));
}
