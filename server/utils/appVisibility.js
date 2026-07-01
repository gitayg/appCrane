/**
 * Single source of truth for the app `visibility` <-> `public_access` invariant.
 *
 * Every write path (the REST /api/apps update and the MCP config tools) used to
 * hand-roll this mapping, so a fix in one drifted from the others — an app could
 * end up publicly reachable (public_access=1) yet catalog-private
 * (visibility='private'), which made the launcher prompt users to "Request
 * access" to an already-open app. Both interfaces now call resolveVisibility so
 * the two columns can never diverge again.
 */

export const VISIBILITIES = ['hidden', 'private', 'public'];

/**
 * Resolve the visibility/public_access columns to persist from a partial patch,
 * keeping them in lock-step. `visibility` wins when both are supplied. Returns
 * {} when neither is present (nothing to change). Throws on an invalid
 * visibility value — callers map the error to their own response shape
 * (REST -> 400 AppError, MCP -> tool error).
 *
 * @param {{ visibility?: string, public_access?: number|boolean }} patch
 * @returns {{ visibility?: string, public_access?: number }}
 */
export function resolveVisibility({ visibility, public_access } = {}) {
  if (visibility !== undefined) {
    if (!VISIBILITIES.includes(visibility)) {
      throw new Error(`visibility must be one of: ${VISIBILITIES.join(', ')}`);
    }
    return { visibility, public_access: visibility === 'public' ? 1 : 0 };
  }
  if (public_access !== undefined) {
    return { public_access: public_access ? 1 : 0, visibility: public_access ? 'public' : 'private' };
  }
  return {};
}
