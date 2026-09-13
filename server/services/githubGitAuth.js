/**
 * Handing a GitHub App installation token to `git` without it outliving the
 * process (v2.75.0).
 *
 * The PAT path puts the credential in the clone URL, which means it is in argv
 * (visible to `ps`), in the "Command failed: git clone …" text of any error,
 * and in the remote URL git writes into the release directory's .git/config. An
 * hour-long token deserves better, and services/localGit.js already has the
 * pattern: the credential travels as GIT_CONFIG_COUNT/KEY/VALUE in the child's
 * environment -- readable only by the same uid -- scoped to the remote's origin
 * so a redirect cannot carry it elsewhere.
 */

const AUTH_USER = 'x-access-token';

/**
 * Environment for a git child that authenticates with `token` against `url`.
 * Appends to any GIT_CONFIG_COUNT already in `baseEnv` rather than clobbering it.
 *
 * https only. Plain http is refused unless APPCRANE_GITHUB_ALLOW_HTTP_GIT=1,
 * which exists so the test suite can run a real git server on 127.0.0.1 and
 * nothing else -- sending a bearer credential over cleartext to a real host is
 * not a thing an operator should be able to turn on by accident.
 */
/**
 * Any stored GitHub credential -- a personal access token, the managed-app
 * service-account token, or an installation token -- goes to git this way.
 * The same `x-access-token:<token>` Basic header actions/checkout sends for a
 * user-supplied PAT. Putting the token in the clone URL instead (`https://<token>@github.com/...`)
 * left it in argv, in error text, and in the remote URL git writes into
 * .git/config, where it stayed on disk for as long as the directory existed.
 */
export function tokenGitEnv(url, token, baseEnv = process.env) {
  const u = new URL(url);
  const scheme = u.protocol.replace(/:$/, '');
  if (scheme !== 'https' && !(scheme === 'http' && process.env.APPCRANE_GITHUB_ALLOW_HTTP_GIT === '1')) {
    throw new Error(`Refusing to send a GitHub token over '${scheme}' to ${u.host}.`);
  }
  const start = Number.parseInt(baseEnv.GIT_CONFIG_COUNT || '0', 10);
  const n = Number.isInteger(start) && start > 0 ? start : 0;
  return {
    ...baseEnv,
    GIT_CONFIG_COUNT: String(n + 1),
    [`GIT_CONFIG_KEY_${n}`]: `http.${u.origin}/.extraHeader`,
    [`GIT_CONFIG_VALUE_${n}`]: `Authorization: Basic ${Buffer.from(`${AUTH_USER}:${token}`).toString('base64')}`,
  };
}

/** Kept for the GitHub App call sites; identical to tokenGitEnv. */
export function installationGitEnv(url, token, baseEnv = process.env) {
  return tokenGitEnv(url, token, baseEnv);
}

/** Remove a token (and its base64 basic-auth form) from any text before it escapes. */
export function scrubToken(text, token) {
  if (!token) return String(text);
  return String(text)
    .replaceAll(token, '[redacted]')
    .replaceAll(Buffer.from(`${AUTH_USER}:${token}`).toString('base64'), '[redacted]');
}
