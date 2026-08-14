#!/usr/bin/env bash
# Catch tests that pass on a developer's machine and fail on the CI runner.
#
# Four of these shipped in one week, all the same shape: an assumption that holds
# here and not there. Each cost a red release and a follow-up patch, and none was
# a product bug — so the suite was green, twice, while being wrong.
#
#   1. A baseline read from git.       `git show HEAD:...` is meaningful only
#      until it is committed; afterwards HEAD contains the change and the test
#      compares it against itself. And actions/checkout is shallow with no tags,
#      so HEAD~1 and release tags are unreachable on the runner either way.
#      Vendor a snapshot under test/fixtures/ instead.
#
#   2. Docker host-gateway networking.  `--add-host host.docker.internal:host-gateway`
#      does not route back to the host on a GitHub runner, so the container gets
#      502 for everything. Probe reachability and skip with a reason; do not
#      gate on Docker merely being installed, which it is.
#
#   3. Waiting for one thing, asserting several.  A helper that resolves on the
#      first array element, followed by an assertion of a larger count, is a race
#      the slower machine loses. Wait for the count you intend to assert.
#
# Not exhaustive, and deliberately narrow: every rule here is a mistake this repo
# actually made, not a style opinion. Add to it when a fifth one bites.

set -uo pipefail
cd "$(dirname "$0")/.."

strict=0
[[ "${1:-}" == "--strict" ]] && strict=1
fail=0

report() {            # report <heading> <body>
  printf '\n[check-test-portability] %s\n%s\n' "$1" "$2"
  fail=1
}

# --- 1. git-derived baselines -------------------------------------------------
# `git rev-parse` etc. to locate the repo root is fine; reading FILE CONTENT out
# of a commit is what rots, so match only the content-reading forms.
# The comment filter has to strip grep's own "file:line:" prefix first — without
# that, `^\s*//` never matches and the checker flags the comments that exist to
# warn against this exact practice. (It did, on its first run.)
git_baselines=$(grep -rnE "git['\"],\s*\[['\"]show|git show [A-Za-z0-9_^~-]+:" test/ 2>/dev/null \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|\*|/\*)' \
  | grep -v 'check-test-portability' || true)
if [[ -n "$git_baselines" ]]; then
  report "a test baseline is read out of git — it will not survive being committed:" "$git_baselines
  Fix: vendor the 'before' file under test/fixtures/ and read it from disk.
  Precedent: test/fixtures/docker.pre-isolation.js."
fi

# --- 2. host-gateway without a reachability guard -----------------------------
for f in $(grep -rlE 'host-gateway' test/ 2>/dev/null || true); do
  # A guard is any skip/probe that reacts to the container failing to reach the
  # host, rather than to docker being absent.
  if ! grep -qE 'skip|probe|reach|502' "$f"; then
    report "docker host-gateway with no reachability guard in $f:" \
"  A GitHub runner cannot route host-gateway back to the host; every request 502s.
  Fix: probe once and skip with the reason. Checking that docker EXISTS is not
  enough — it exists on the runner."
  fi
done

# --- 3. wait-for-one, assert-many ---------------------------------------------
# Heuristic and intentionally conservative: only flags a waitFor whose predicate
# never mentions length/count, followed closely by an equality assertion on a
# count above one.
suspects=$(awk '
  /await waitFor\(/ { w=NR; pred="" }
  w && NR<=w+6      { pred = pred $0 }
  w && NR>w+6       { if (pred !~ /length|count|>=|\.length/) hold=w; w=0; pred="" }
  hold && NR<=hold+12 && /assert\.(equal|strictEqual)\([^,]*\.length,\s*([2-9]|[1-9][0-9])/ {
    printf "%s:%d: waits for the first item, asserts %s\n", FILENAME, hold, $0; hold=0
  }
  hold && NR>hold+12 { hold=0 }
' test/*.test.js 2>/dev/null || true)
if [[ -n "$suspects" ]]; then
  report "a test waits for one result then asserts several — the slower machine loses this:" "$suspects
  Fix: make the wait predicate require the count you are about to assert."
fi

if [[ "$fail" -eq 0 ]]; then
  echo "[check-test-portability] OK — no known local-only test assumptions found."
  exit 0
fi
[[ "$strict" -eq 1 ]] && exit 1
exit 0
