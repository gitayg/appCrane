/**
 * The exact `docker run` argv startApp() produced for an ORDINARY HTTP APP at
 * v2.44.2 — the release immediately before the data-plane work.
 *
 * Vendored, not read out of git. `git show HEAD:server/services/docker.js` is a
 * baseline only until it is committed, at which point HEAD contains the change
 * and the test compares it against itself; and actions/checkout is shallow, so
 * HEAD~1 is not even reachable on the runner. scripts/check-test-portability.sh
 * fails the build for that pattern. Same precedent as
 * test/fixtures/docker.pre-isolation.js.
 *
 * PROVENANCE, so this can be regenerated rather than trusted: extracted with
 * `git archive HEAD | tar -x` into a scratch tree, then the REAL startApp() was
 * called there with a `docker` shim on PATH that records its argv —
 *   { slug: 'dp-http', env: 'production', image: 'appcrane-x:abc123',
 *     hostPort: 4321, memoryMb: 512, cpus: 0.5 }
 * against an apps row that sets no ingress_type, no public_port and no
 * data_plane_port. This is the recorded argv, not a hand-transcription of the
 * source.
 *
 * What it is for: the platform has ~57 apps and every one of them is this
 * shape. v2.45.0 must not move a single byte of their container start, so the
 * dual-plane tests measure themselves against the argv that actually shipped.
 */
export const HTTP_BASELINE_V2_44_2 = [
  'run',
  '-d',
  '--name',
  'appcrane-dp-http-production',
  '--label',
  'appcrane=true',
  '--label',
  'slug=dp-http',
  '--label',
  'env=production',
  '--restart=on-failure:5',
  '--network',
  'appcrane-apps',
  '--memory=512m',
  '--cpus=0.5',
  '--pids-limit=512',
  '--security-opt',
  'no-new-privileges',
  '--cap-drop',
  'NET_RAW',
  '-p',
  '127.0.0.1:4321:3000',
  '--log-opt',
  'max-size=10m',
  '--log-opt',
  'max-file=3',
  '-e',
  'PORT=3000',
  '-e',
  'NODE_ENV=production',
  '-e',
  'DATA_DIR=/data',
  'appcrane-x:abc123',
];

/**
 * The same argv for a different slug / env / loopback host port.
 *
 * Substitution rather than a second fixture: what these tests assert is that
 * the ONLY thing v2.45.0 adds is a second `-p`, so every other element has to
 * keep coming from the recorded v2.44.2 line. The five substituted values are
 * the only ones that are a function of the caller's arguments.
 */
export function httpBaselineFor(slug, env, hostPort) {
  const nodeEnv = env === 'production' ? 'production' : 'development';
  return HTTP_BASELINE_V2_44_2.map((arg) => {
    if (arg === 'appcrane-dp-http-production') return `appcrane-${slug}-${env}`;
    if (arg === 'slug=dp-http') return `slug=${slug}`;
    if (arg === 'env=production') return `env=${env}`;
    if (arg === '127.0.0.1:4321:3000') return `127.0.0.1:${hostPort}:3000`;
    if (arg === 'NODE_ENV=production') return `NODE_ENV=${nodeEnv}`;
    return arg;
  });
}
