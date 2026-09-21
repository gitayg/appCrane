/**
 * The one place that decides where a managed app's git repository lives.
 *
 * A managed app (source_type='managed') is backed by exactly one of:
 *   - GitHub: AMC_<slug> on the service account (services/githubService.js)
 *   - local:  <DATA_DIR>/repos/<slug>.git on this host (services/localGit.js)
 *
 * apps.repo_backend (migration 090) is the ONLY input to that decision:
 *   NULL / absent -> GitHub. Every app that existed before 090 is NULL, so it
 *                    keeps exactly the behaviour it had.
 *   'local'       -> this host.
 *   anything else -> refused. A typo must fail loudly, not route to GitHub.
 *
 * Deliberately NOT consulted: whether <DATA_DIR>/repos/<slug>.git exists on
 * disk, or the shape of github_url. A directory left behind by a deleted app,
 * or dropped in by a restore, must never move a production app off GitHub.
 *
 * Why a facade rather than `if (local)` at each call site: the decision is
 * needed at create/repair, three push tools, one read, deploy clone, promote,
 * the SHA check, AskClaude and the credential probe. Ten copies of it are ten
 * places a later change can get it subtly different — e.g. one site treating
 * an unknown value as GitHub. Here it is written once and the call sites only
 * ask "which backend" or call through.
 */

export const REPO_BACKEND_GITHUB = 'github';
export const REPO_BACKEND_LOCAL = 'local';

/** The backend appcrane_create_managed_app gives a NEW managed app. */
export const NEW_MANAGED_APP_REPO_BACKEND = REPO_BACKEND_LOCAL;

export function repoBackendOf(app) {
  if (!app || typeof app !== 'object') throw new Error('managedRepo: an apps row is required');
  const v = app.repo_backend;
  if (v === null || v === undefined) return REPO_BACKEND_GITHUB;
  if (v === REPO_BACKEND_LOCAL) return REPO_BACKEND_LOCAL;
  throw new Error(
    `App '${app.slug}' has repo_backend=${JSON.stringify(v)}, which this AppCrane does not recognise. ` +
    `Refusing to guess where its source lives (NULL means GitHub, 'local' means this host).`,
  );
}

/** True only for a managed app whose marker says 'local'. Throws on an unknown marker. */
export function usesLocalRepo(app) {
  return app?.source_type === 'managed' && repoBackendOf(app) === REPO_BACKEND_LOCAL;
}

function backendModule(backend) {
  if (backend === REPO_BACKEND_LOCAL) return import('./localGit.js');
  if (backend === REPO_BACKEND_GITHUB) return import('./githubService.js');
  throw new Error(`managedRepo: unknown backend ${JSON.stringify(backend)}`);
}

function requireLocal(app) {
  if (!usesLocalRepo(app)) {
    throw new Error(`managedRepo: app '${app?.slug}' is not a local-backed managed app`);
  }
}

/** Create the repo. There is no row yet, so the caller names the backend. */
export async function createManagedRepo(backend, slug, opts) {
  return (await backendModule(backend)).createAppRepo(slug, opts);
}

/**
 * Commit `files` to the app's repo. `opts.actorId` (the pushing user) is
 * consumed here and never reaches the backend.
 *
 * Deploy on push lives HERE, not at the MCP tools that call this, because this
 * is the one point every committed push to a managed repo passes through and a
 * staged chunk (appcrane_managed_push_chunk) never does. A fourth commit path
 * added later inherits it instead of having to remember it. It runs only for a
 * local repo: a GitHub-backed app's push returns exactly what it returned
 * before, with no deploy and no extra key.
 */
export async function pushFilesToManagedRepo(app, files, opts = {}) {
  const { actorId = null, ...backendOpts } = opts;
  const deletions = Array.isArray(backendOpts.deletions) ? backendOpts.deletions : [];
  // Deletion is a local-backend capability only. GitHub's contents API has no
  // way to express one, so rather than let a caller believe a path was removed
  // from an AMC_ repo on GitHub, refuse here and name the reason.
  if (deletions.length > 0 && repoBackendOf(app) === REPO_BACKEND_GITHUB) {
    throw new Error(
      `Deleting files is not supported for GitHub-backed managed apps: '${app?.slug}' keeps its source on GitHub, whose contents API cannot express a deletion. Nothing was committed. Remove the file(s) on GitHub directly.`,
    );
  }
  // Before the backend is touched, so a refused push writes no blob and no ref:
  // the whole push is refused, never committed in part (envFilePushGuard.js).
  // Deleted paths are guarded too: a .env* the guard keeps out of git is a file
  // git should never have had, so a push naming one is wrong either way, and
  // letting DELETE through would be a second spelling of the same request.
  if (usesLocalRepo(app)) {
    const { refuseEnvFilePaths } = await import('./envFilePushGuard.js');
    refuseEnvFilePaths(app.slug, [
      ...(Array.isArray(files) ? files.map((f) => f?.path) : []),
      ...deletions,
    ]);
  }
  const result = await (await backendModule(repoBackendOf(app))).pushFilesToManagedRepo(app.slug, files, backendOpts);
  if (usesLocalRepo(app)) {
    // Record the pushed commit BEFORE its deploy starts. The supply-chain check
    // refuses a managed clone whose HEAD is not apps.last_managed_push_sha. The
    // push tools write that column too, but only after this returns — and a
    // caller that is not one of those tools never writes it — so without this
    // the deploy this push starts is checked against the PREVIOUS push.
    if (/^[0-9a-f]{40}$/.test(result?.commit?.sha || '')) {
      const { getDb } = await import('../db.js');
      getDb().prepare('UPDATE apps SET last_managed_push_sha = ? WHERE id = ?').run(result.commit.sha, app.id);
    }
    const { deployAfterLocalPush } = await import('./deployTrigger.js');
    result.auto_deploy = await deployAfterLocalPush(app, result, { actorId });
  }
  return result;
}

export async function readManagedRepoFile(app, path, opts) {
  return (await backendModule(repoBackendOf(app))).readManagedRepoFile(app.slug, path, opts);
}

/** Branch tip of a local app's repo, for the supply-chain check. */
export async function localBranchHeadSha(app, branch) {
  requireLocal(app);
  return (await import('./localGit.js')).getBranchHeadSha(app.slug, branch);
}

/** Shallow clone of a local app's repo into `destDir`, for a deploy. */
export async function cloneLocalRepoForDeploy(app, destDir, branch) {
  requireLocal(app);
  return (await import('./localGit.js')).cloneForDeploySync(app.slug, destDir, branch);
}

/** Move a deploy clone of a local app to an exact commit (promote). */
export async function pinLocalDeployClone(app, workTree, commit, branch) {
  requireLocal(app);
  return (await import('./localGit.js')).pinDeployCloneSync(app.slug, workTree, commit, branch);
}
