#!/usr/bin/env bash
#
# install-hooks.sh — installs the local git hooks for AppCrane.
#
# Run once after `git clone` (or any time the hook script changes):
#   bash scripts/install-hooks.sh
#
# What it installs:
#   - .git/hooks/pre-commit → runs scripts/check-role-patterns.sh --strict
#   - .git/hooks/pre-commit → runs scripts/check-no-shadow-js.sh --strict
#
# Both scripts already exist in the repo and are versioned. The hook is
# a thin wrapper that exits non-zero if either watchdog fires, blocking
# the commit until the issue is fixed (or use `--no-verify` to override).
#
# CI runs the same scripts via .github/workflows/role-check.yml — this
# hook is for fast local feedback, the CI is the safety net.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

HOOK_DIR=".git/hooks"
HOOK_FILE="$HOOK_DIR/pre-commit"

if [ ! -d "$HOOK_DIR" ]; then
  echo "[install-hooks] $HOOK_DIR not found. Are you in a git checkout?"
  exit 1
fi

cat > "$HOOK_FILE" <<'HOOK'
#!/usr/bin/env bash
# Installed by scripts/install-hooks.sh — re-run that script if the watchdog
# set changes. Override individual commits with `git commit --no-verify`.
set -e
bash scripts/check-role-patterns.sh --strict
bash scripts/check-no-shadow-js.sh --strict
bash scripts/check-test-portability.sh --strict
HOOK

chmod +x "$HOOK_FILE"
echo "[install-hooks] Installed $HOOK_FILE"
echo "[install-hooks] Test it now with: bash $HOOK_FILE"
