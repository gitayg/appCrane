#!/usr/bin/env bash
#
# check-role-patterns.sh — flag any check of the GLOBAL role against 'admin'.
#
# Why this exists: the global 'admin' tier (users.role = 'admin') was retired
# in migration 105 — it made a person admin on every app without assignment,
# and the database now refuses that value. Any code that still compares a
# global role to 'admin' is either dead or, worse, a grant waiting for a row
# the trigger was meant to stop. Before the retirement this script enforced
# the opposite (every `=== 'admin'` had to be paired with platform_admin);
# that pairing is now exactly what it flags.
#
# Usage:
#   bash scripts/check-role-patterns.sh                # run interactively
#   bash scripts/check-role-patterns.sh --strict       # exit 1 if any found
#
# Not flagged:
#   - `app_role === 'admin'` / appRole — the per-app tier, which still exists.
#   - lines marked `// role:platform-admin-skipped` — manually reviewed
#     (e.g. a role NAME in a reserved-word list, not a check on a caller).
#
# When this script flags a hit, replace it with one of:
#   - helper:  import { isAdmin } from '../utils/roles.js'; isAdmin(user)
#              (true for platform_admin only)
#   - inline:  user.role === 'platform_admin'
#
# Exits 0 on no hits, 1 on hits with --strict.

set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

STRICT=0
[[ "${1:-}" == "--strict" ]] && STRICT=1

# Match anything that compares a role-shaped identifier to 'admin'/"admin".
# Two patterns covered:
#   .role / .crane_role / .app_role-style member access
#   bare local variables: role, userRole, sessionRole, callerRole, etc.
# The bare-variable form is what got us in v2.2.11 — enhancements.js had
# `const isAdmin = userRole === 'admin'` and the original .role-only regex
# missed it.
#
# Filter out:
#   - app_role (per-app tier — different concept, correct as-is)
#   - lines marked `// role:platform-admin-skipped` (intentional)
#   - vendored / generated output
HITS=$(
  grep -rnE "(\.|\b)((user|session|caller|target)?[Rr]ole|crane_role)\s*[!=]==\s*['\"]admin['\"]" \
    server/ \
    --include="*.js" 2>/dev/null \
  | grep -vE "app_role|appRole" \
  | grep -vE "role:platform-admin-skipped" \
  | grep -vE "node_modules|/dist/|docs/admin-app/" \
  | grep -vE "server/utils/roles\.js" \
  || true
)

if [[ -z "$HITS" ]]; then
  echo "[check-role-patterns] OK — no checks of the retired global 'admin' role found."
  exit 0
fi

echo "[check-role-patterns] FOUND checks of the retired global 'admin' role:"
echo
echo "$HITS"
echo
echo "users.role can no longer be 'admin' (migration 105). Replace with one of:"
echo "  helper:  import { isAdmin } from '../utils/roles.js'; isAdmin(user)"
echo "  inline:  user.role === 'platform_admin'"
echo "If the hit is a per-app role or a role NAME rather than a caller check,"
echo "mark the line with // role:platform-admin-skipped."

[[ $STRICT -eq 1 ]] && exit 1
exit 0
