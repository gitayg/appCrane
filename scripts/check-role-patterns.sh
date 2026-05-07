#!/usr/bin/env bash
#
# check-role-patterns.sh — flag global-role checks that don't account for
# platform_admin.
#
# Why this exists: v2.1.3 introduced platform_admin alongside admin as a
# global-role tier. Every `user.role === 'admin'` (or `!== 'admin'`) check
# in the codebase that meant "global admin" silently locked platform_admin
# out of the protected path. v2.1.5, v2.2.6, and v2.2.9 each shipped fixes
# for the same class of bug, hitting different files. This script flags
# any new instances introduced going forward so the next platform-level
# tier doesn't take three releases to land cleanly.
#
# Usage:
#   bash scripts/check-role-patterns.sh                # run interactively
#   bash scripts/check-role-patterns.sh --strict       # exit 1 if any found
#
# False positives this script intentionally tolerates:
#   - `app_role === 'admin'` — per-app role tier, NOT global. Different
#     concept.
#   - `role === 'admin' ? 'admin' : ...` inside a string-literal context
#     where the value is a role name being assigned, not a check on
#     the caller. Manually reviewed.
#
# True positives look like one of:
#   - `user.role === 'admin'`     (allow check)
#   - `user.role !== 'admin'`     (deny check)
#   - `req.user.role === 'admin'`
#   - `session.role === 'admin'`
#   - `auth.role === 'admin'`
#   - `crane_role === 'admin'`
#   - `target.role === 'admin'`
#
# When this script flags a hit, replace with one of:
#   - inline:  `(user.role === 'admin' || user.role === 'platform_admin')`
#   - helper:  import { isAdmin } from '../utils/roles.js'; isAdmin(user)
#
# Exits 0 on no hits, 1 on hits with --strict.

set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

STRICT=0
[[ "${1:-}" == "--strict" ]] && STRICT=1

# Match `<accessor>.role` or `<accessor>.crane_role` compared to the literal
# 'admin' or "admin". The leading `.` requirement skips bare `role === 'admin'`
# in role-name-assignment contexts (e.g. `if (role === 'admin')` while reading
# req.body.role at user-creation time — that's setting a role, not checking
# the caller's role).
#
# Filter out:
#   - app_role (per-app tier — different concept, correct as-is)
#   - lines that already include platform_admin nearby (already covered)
#   - lines marked `// role:platform-admin-skipped` (intentional regular-admin-only paths)
#   - vendored / generated output (node_modules, dist/, docs/admin-app/)
HITS=$(
  grep -rnE "\.(role|crane_role)\s*[!=]==\s*['\"]admin['\"]" \
    server/ \
    --include="*.js" 2>/dev/null \
  | grep -vE "app_role" \
  | grep -vE "platform_admin" \
  | grep -vE "role:platform-admin-skipped" \
  | grep -vE "node_modules|/dist/|docs/admin-app/" \
  | grep -vE "server/utils/roles\.js" \
  || true
)

if [[ -z "$HITS" ]]; then
  echo "[check-role-patterns] OK — no untreated role==='admin' checks found."
  exit 0
fi

echo "[check-role-patterns] FOUND role==='admin' checks that may need platform_admin coverage:"
echo
echo "$HITS"
echo
echo "Each hit is either a real bug (platform_admin gets the deny path) or a"
echo "false positive that should be re-reviewed. To fix a real bug, replace with"
echo "one of:"
echo "  inline:  (user.role === 'admin' || user.role === 'platform_admin')"
echo "  helper:  import { isAdmin } from '../utils/roles.js'; isAdmin(user)"
echo
echo "Once fixed, this script should report OK on the same files."

[[ $STRICT -eq 1 ]] && exit 1
exit 0
