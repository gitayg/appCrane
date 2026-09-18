/**
 * Run the supply-chain commit verification CONCURRENTLY with the image build,
 * and gate the container swap on its result (v2.78.2).
 *
 * Why this file exists
 * --------------------
 * verifyCommitSha() is a GitHub API round trip: one branch read, retried up to
 * three times with a 1.5s + 3s backoff and an 8s per-attempt timeout. It used
 * to be `await`ed the moment the clone finished, so every deploy paid for it
 * before `docker build` was even spawned — and the build does not depend on its
 * answer. Nothing in the build reads the remote SHA; only the DECISION TO START
 * THE CONTAINER does.
 *
 * So the call now starts where it always started (right after the clone, with
 * the same arguments) and is awaited where its answer is first needed: after
 * the image exists, before anything runs a container. Everything between the
 * two — the icon pickup, the manifest read, the dist consistency check, the
 * Dockerfile generation and the build itself — overlaps it.
 *
 * What must NOT change, and how it is preserved
 * ---------------------------------------------
 *   * A verification failure still stops the deploy, with the SAME error the
 *     verifier formatted. settle() rethrows the original Error object — it is
 *     never wrapped, re-messaged, or downgraded to a warning.
 *   * It still stops the deploy BEFORE any container starts. settle() is
 *     awaited ahead of preflightEntryCheck (which runs `docker run --rm`),
 *     ahead of dockerStop, and ahead of dockerStart. A failed verification
 *     therefore leaves the previous version running and nothing new started.
 *   * Nothing becomes fail-open. This module makes no policy decision at all:
 *     fail-closed, APPCRANE_REQUIRE_VERIFY=0, the settings kill-switch and the
 *     two inapplicable-skip cases are entirely inside supplyChain.js and are
 *     reached unchanged. An inconclusive check stays inconclusive in the same
 *     way, because the same function decides it.
 *   * The deploy log keeps the verifier's exact lines. They are BUFFERED rather
 *     than written as they happen, and flushed at settle(). Writing them live
 *     would interleave them into the middle of streamed `docker build` output,
 *     where an operator reading the log cannot tell which phase produced what.
 *     The text of each line is passed through untouched.
 *
 * Unhandled rejections
 * --------------------
 * A promise that rejects while nobody is awaiting it crashes Node under
 * --unhandled-rejections=throw. The verification is therefore *immediately*
 * given a handler that converts settlement into a plain value; settle() reads
 * that value and rethrows. There is no window in which the rejection is
 * floating unobserved.
 */

/**
 * Start the verification and return a gate.
 *
 * @param {object}   app        the apps row
 * @param {string}   releaseDir the cloned working tree
 * @param {string}   branch     the branch that was checked out
 * @param {Function} appendLog  deploy-log writer (called at flush time)
 * @param {Function} [verify]   test seam: stands in for verifyCommitSha
 * @returns {{ settle: () => Promise<any>, flush: () => Promise<void> }}
 */
export function startCommitVerification({ app, releaseDir, branch, appendLog, verify }) {
  const buffered = [];
  const collect = (line) => { buffered.push(line); };

  // Started here, not awaited here. The async IIFE also carries the dynamic
  // import, so an import failure lands on this promise like any other error
  // instead of throwing at the call site and skipping the check.
  const running = (async () => {
    const fn = verify || (await import('./supplyChain.js')).verifyCommitSha;
    return fn(app, releaseDir, branch, collect);
  })();

  // Attached synchronously: from this statement on the rejection is observed.
  const settled = running.then(
    (result) => ({ result }),
    (error) => ({ error }),
  );

  let flushed = false;
  const flushLines = () => {
    if (flushed) return;
    flushed = true;
    for (const line of buffered) appendLog(line);
  };

  return {
    /**
     * Wait for the verification, write its deploy-log lines, and rethrow its
     * error unchanged if it failed. The caller does nothing with the return
     * value; the point is the throw.
     */
    async settle() {
      const { result, error } = await settled;
      flushLines();
      if (error) throw error;
      return result;
    },

    /**
     * Wait for the verification and write its lines, but never throw. For the
     * deploy's failure handler: if the BUILD failed, the verifier's lines would
     * otherwise be lost, and re-throwing its error there would mask the build's.
     */
    async flush() {
      try {
        await settled;
      } catch (_) { /* settled never rejects; belt and braces */ }
      flushLines();
    },
  };
}
