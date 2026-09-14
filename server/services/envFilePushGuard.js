/**
 * .env* files never go into a Crane-hosted app's repository.
 *
 * A Crane-hosted app (managedRepo.usesLocalRepo) keeps its .env files outside
 * git, encrypted in app_env_files (envFileStore.js), and deploy writes them
 * into the release over whatever the clone has at that path. So a pushed .env
 * is two problems at once: its secrets sit in git and in every repository
 * backup forever, and at deploy a stored file at the same path silently
 * replaces it. Refusing the push is the only outcome that is not a surprise.
 *
 * The rule is by BASENAME, case-insensitive, at any depth: `.env`, `.ENV`,
 * `.env.example`, `web/.env.local` are all refused. That is wider than
 * conversion's case-sensitive exclusion on purpose — git on a case-insensitive
 * filesystem checks `.ENV` out as a file dotenv loaders read.
 *
 * GitHub-backed managed apps are not affected: their pushes were never merged
 * with stored files, and changing what they accept is a separate decision.
 *
 * Errors carry paths only, never content.
 */

export const ENV_FILE_IN_PUSH = 'ENV_FILE_IN_PUSH';

export function isEnvFilePath(path) {
  if (typeof path !== 'string') return false;
  const base = path.split('/').pop();
  return base.toLowerCase().startsWith('.env');
}

/** Throw ENV_FILE_IN_PUSH (status 422) when any of `paths` is a .env* file. */
export function refuseEnvFilePaths(slug, paths) {
  const offending = [...new Set(paths.filter(isEnvFilePath))];
  if (offending.length === 0) return;
  const err = new Error(
    `${ENV_FILE_IN_PUSH}: refusing to commit .env file(s) to '${slug}': ${offending.map((p) => JSON.stringify(p)).join(', ')}. ` +
    'This app\'s repository is hosted on AppCrane, which keeps .env files out of git so their secrets never enter the repository or its backups. ' +
    'Nothing was committed. Set each value as an environment variable instead (appcrane_set_secret), ' +
    'or have an app owner replace the stored .env file in the AppCrane dashboard (app page, "Stored .env files", or PUT /api/apps/<slug>/env-files). ' +
    'Remove the .env file(s) from this push and retry.',
  );
  err.code = ENV_FILE_IN_PUSH;
  err.status = 422;
  err.paths = offending;
  throw err;
}

/**
 * Audit-log copy of MCP push arguments with the content of any .env* file
 * replaced by its length. The push is refused, but the call is still audited,
 * and redactAuditArgs keeps the first 120 characters of a `content` string.
 */
export function redactEnvFileContentInArgs(args) {
  if (!args || typeof args !== 'object') return args;
  const mask = (v) => (typeof v === 'string' ? `[redacted .env content: ${v.length} chars]` : v);
  let out = args;
  if (Array.isArray(args.files) && args.files.some((f) => f && isEnvFilePath(f.path))) {
    out = { ...out, files: args.files.map((f) => (f && isEnvFilePath(f.path) && 'content' in f ? { ...f, content: mask(f.content) } : f)) };
  }
  if (isEnvFilePath(args.path) && 'content' in args) out = { ...out, content: mask(args.content) };
  return out;
}
