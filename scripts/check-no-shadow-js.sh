#!/usr/bin/env bash
#
# check-no-shadow-js.sh — fail if any .js file under studio-web/src/ has a
# .ts or .tsx sibling.
#
# Why: Vite's default resolve.extensions puts .js before .tsx. A stray
# emitted .js (from `tsc -b`, an editor build, an automated linter that
# unexpectedly runs the TS compiler) silently shadows the source file —
# every edit to the .tsx becomes a no-op, builds appear to do nothing.
# Pre-v2.2.10 this happened on production for an unknown number of UI
# changes and ate a full diagnostic session before being caught.
#
# Defenses (multi-layer):
#   1. .gitignore excludes studio-web/src/**/*.js (this script's job is
#      to catch anything that bypasses .gitignore, e.g. force-added)
#   2. studio-web/vite.config.js sets resolve.extensions with .tsx first
#      so even if a shadow .js exists, the source wins
#   3. This script: any .js under src/ with a .ts/.tsx sibling is a
#      shadow — fail loudly
#
# Usage:
#   bash scripts/check-no-shadow-js.sh           # report-only, exit 0
#   bash scripts/check-no-shadow-js.sh --strict  # exit 1 on findings (CI)

set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

STRICT=0
[[ "${1:-}" == "--strict" ]] && STRICT=1

SHADOWS=()
while IFS= read -r -d '' js; do
  base="${js%.js}"
  if [[ -f "${base}.ts" || -f "${base}.tsx" ]]; then
    SHADOWS+=("$js")
  fi
done < <(find studio-web/src -name '*.js' -type f -print0 2>/dev/null)

if [[ ${#SHADOWS[@]} -eq 0 ]]; then
  echo "[check-no-shadow-js] OK — no .js shadows of .ts/.tsx under studio-web/src/."
  exit 0
fi

echo "[check-no-shadow-js] FOUND ${#SHADOWS[@]} shadow .js file(s) that will silently override their .ts/.tsx source:"
for s in "${SHADOWS[@]}"; do
  echo "  $s"
done
echo
echo "Fix:"
echo "  rm \"\${SHADOWS[@]}\""
echo "  # then commit + verify build picks up the .tsx versions"

[[ $STRICT -eq 1 ]] && exit 1
exit 0
