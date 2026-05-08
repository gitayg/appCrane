import { execFileSync } from 'child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, unlinkSync, symlinkSync } from 'fs';
import { join, resolve } from 'path';
import { getDb } from '../db.js';
import { decrypt } from './encryption.js';
import log from '../utils/logger.js';
import { ensureCodebaseContext } from './appstudio/contextBuilder.js';

/**
 * Health-endpoint contract for AppCrane apps:
 *   - Responds 200 within the timeout
 *   - Body is JSON
 *   - Body has both `status` and `version` fields (any non-empty value)
 *
 * Pre-v2.2.11 the deployer only ran a health check when manifest.be.health
 * was explicitly declared; apps without one deployed "successfully" and
 * then sat with no health monitor data forever. Now health is mandatory:
 * if the manifest doesn't say where, we assume `/api/health` and require
 * it to satisfy the contract above.
 *
 * Returns:
 *   { ok: true }                                  on contract met
 *   { ok: false, reason: 'timeout', detail }      no 200 within window
 *   { ok: false, reason: 'not_json', detail }     200 but body wasn't JSON
 *   { ok: false, reason: 'missing_fields', detail } JSON but lacks status/version
 */
async function probeHealthEndpoint(url, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  let lastStatus = null;
  let lastBodyPreview = null;

  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(3000) });
      lastStatus = res.status;
      if (res.ok) {
        const text = await res.text();
        lastBodyPreview = text.slice(0, 200);
        let body;
        try {
          body = JSON.parse(text);
        } catch {
          return {
            ok: false,
            reason: 'not_json',
            detail: `Health endpoint returned 200 but body wasn't JSON. Got: ${JSON.stringify(text.slice(0, 80))}. Expected: {"status": "ok", "version": "<your-app-version>"}`,
          };
        }
        if (body && typeof body === 'object' && body.status !== undefined && body.version !== undefined) {
          return { ok: true };
        }
        return {
          ok: false,
          reason: 'missing_fields',
          detail: `Health endpoint returned JSON but missing required fields. Got: ${JSON.stringify(body).slice(0, 120)}. Expected both "status" and "version" fields.`,
        };
      }
    } catch (e) {
      lastError = e.message || String(e);
    }
    await new Promise(r => setTimeout(r, 2000));
  }
  return {
    ok: false,
    reason: 'timeout',
    detail: lastError
      ? `No healthy response within ${timeoutMs}ms (last error: ${lastError})`
      : `No healthy response within ${timeoutMs}ms (last status: ${lastStatus ?? 'no response'}, last body: ${JSON.stringify(lastBodyPreview ?? '')})`,
  };
}

/**
 * Post-deploy probe — fetches the user-visible index page through Caddy and
 * verifies every asset reference (src=/href=) returns non-404. Catches the
 * "container is up, /api/health is green, users see a white page" failure
 * mode where the frontend asset URLs don't resolve through Caddy's routing
 * for some reason (missing dist, bad APP_BASE_PATH, mis-routed slug, etc.).
 *
 * Returns one of:
 *   { status: 'ok' }
 *   { status: 'missing', missing: [...refs that 404'd] }
 *   { status: 'inconclusive', reason: 'why we couldn't tell' }
 */
async function probeFrontendAssets(slug, env) {
  const caddyPort = process.env.CADDY_HTTP_PORT || '80';
  const basePath = env === 'production' ? `/${slug}/` : `/${slug}-sandbox/`;
  const indexUrl = `http://127.0.0.1:${caddyPort}${basePath}`;

  let html;
  try {
    const r = await fetch(indexUrl, { signal: AbortSignal.timeout(8000), redirect: 'manual' });
    if (r.status >= 300 && r.status < 400) {
      return { status: 'inconclusive', reason: `Caddy returned ${r.status} (likely SSO/auth redirect); cannot probe assets without a token` };
    }
    if (!r.ok) return { status: 'inconclusive', reason: `index page returned ${r.status}` };
    html = await r.text();
  } catch (e) {
    return { status: 'inconclusive', reason: `index fetch failed: ${e.message}` };
  }

  const refs = [];
  const matcher = /\b(?:src|href)=["']([^"']+)["']/gi;
  for (const m of html.matchAll(matcher)) {
    const ref = m[1];
    if (/^(https?:|data:|\/\/|mailto:|tel:|#)/i.test(ref)) continue;
    refs.push(ref);
  }
  if (!refs.length) return { status: 'inconclusive', reason: 'index.html has no asset references to probe' };

  const missing = [];
  for (const ref of refs) {
    const url = ref.startsWith('/')
      ? `http://127.0.0.1:${caddyPort}${ref}`
      : `http://127.0.0.1:${caddyPort}${basePath}${ref.replace(/^\.\//, '')}`;
    try {
      const r = await fetch(url, { method: 'HEAD', signal: AbortSignal.timeout(3000), redirect: 'manual' });
      if (r.status === 404) missing.push(ref);
    } catch (_) { /* network error — don't false-positive */ }
  }

  return missing.length ? { status: 'missing', missing } : { status: 'ok' };
}

function parseResourceLimits(raw) {
  try {
    const parsed = typeof raw === 'string' ? JSON.parse(raw) : (raw || {});
    return {
      max_ram_mb: Number(parsed.max_ram_mb) || 512,
      max_cpu_percent: Number(parsed.max_cpu_percent) || 50,
    };
  } catch (e) {
    return { max_ram_mb: 512, max_cpu_percent: 50 };
  }
}

/**
 * Allowlist of executables permitted in deployhub.json build/entry commands.
 * Prevents arbitrary command execution via attacker-controlled manifest fields.
 */
const SAFE_EXECUTABLES = new Set([
  'node', 'npm', 'yarn', 'pnpm', 'npx', 'bun',
  'ts-node', 'tsx', 'vite', 'next', 'nuxt', 'tsc', 'react-scripts',
]);

/**
 * Validate a command string from deployhub.json before execution.
 * Throws if the command contains dangerous characters, an absolute path,
 * path traversal, or a non-allowlisted executable.
 */
function validateManifestCommand(value, field) {
  if (!value) return;
  const tokens = value.trim().split(/\s+/);
  const executable = tokens[0];
  if (!SAFE_EXECUTABLES.has(executable)) {
    throw new Error(
      `deployhub.json ${field}: executable "${executable}" is not allowed. ` +
      `Permitted: ${[...SAFE_EXECUTABLES].join(', ')}`
    );
  }
  for (const token of tokens) {
    if (/[;&|`$(){}<>!\n\r]/.test(token)) {
      throw new Error(`deployhub.json ${field}: token "${token}" contains unsafe shell characters`);
    }
    if (token.startsWith('/')) {
      throw new Error(`deployhub.json ${field}: absolute paths are not allowed`);
    }
    if (token.includes('..')) {
      throw new Error(`deployhub.json ${field}: path traversal ("..") is not allowed`);
    }
  }
}

/**
 * Core deploy pipeline.
 * 1. Clone repo (or use uploaded files)
 * 2. npm install
 * 3. npm run build (FE)
 * 4. Write .env file from encrypted vars
 * 5. Symlink shared data dirs
 * 6. Start Docker container on allocated ports
 * 7. Health check
 * 8. Swap 'current' symlink
 * 9. Cleanup old releases (keep last 5)
 */
export async function deployApp(deployId, app, env, ports, opts = {}) {
  const db = getDb();
  const dataDir = resolve(process.env.DATA_DIR || './data');
  const appDir = resolve(join(dataDir, 'apps', app.slug, env));
  const releasesDir = resolve(join(appDir, 'releases'));
  const sharedDir = resolve(join(appDir, 'shared'));

  // Security: ensure all paths are within dataDir (prevent path traversal)
  for (const p of [appDir, releasesDir, sharedDir]) {
    if (!p.startsWith(dataDir)) {
      throw new Error(`Security: path ${p} is outside data directory ${dataDir}`);
    }
  }

  mkdirSync(releasesDir, { recursive: true });
  const sharedData = join(sharedDir, 'data');
  mkdirSync(sharedData, { recursive: true });

  // Bind-mounted volumes inherit host ownership, not container ownership.
  // Our Dockerfile runs as the `node` user (UID 1000 in node:*-alpine), so
  // chown -R the shared dir to 1000:1000 on Linux; otherwise the container
  // gets a read-only /data and apps crash with EACCES on their first write.
  // Recursive chown also fixes files left over from older rootful containers.
  // No-op on macOS/dev (chown fails silently, containers run rootful there).
  try {
    execFileSync('chown', ['-R', '1000:1000', sharedData], { stdio: 'pipe', timeout: 30000 });
  } catch (_) {}

  const deployLog = [];
  let deployFinished = false;
  const appendLog = (msg) => {
    const line = `[${new Date().toISOString().slice(11, 19)}] ${msg}`;
    deployLog.push(line);
    log.info(`[deploy:${deployId}] ${msg}`);
    // Update log in DB (don't overwrite status after deploy is done)
    if (!deployFinished) {
      db.prepare("UPDATE deployments SET log = ?, status = 'building' WHERE id = ?")
        .run(deployLog.join('\n'), deployId);
    }
  };

  try {
    // 1. Clone or locate release
    const timestamp = Date.now();
    let commitHash = 'unknown';
    let releaseDir;

    if (opts.preExtractedDir) {
      releaseDir = resolve(opts.preExtractedDir);
      if (!releaseDir.startsWith(dataDir)) throw new Error('Security: preExtractedDir is outside data directory');
      commitHash = opts.commitHash || 'unknown';
      appendLog(`Using pre-extracted release: ${releaseDir.split('/').pop()}`);
    } else if (app.source_type === 'github' && app.github_url) {
      appendLog(`Cloning ${app.github_url} (branch: ${app.branch || 'main'})...`);

      releaseDir = resolve(join(releasesDir, `${timestamp}-git`));
      mkdirSync(releaseDir, { recursive: true });

      let cloneUrl = app.github_url;
      if (app.github_token_encrypted) {
        const token = decrypt(app.github_token_encrypted);
        const url = new URL(app.github_url);
        url.username = token;
        cloneUrl = url.toString();
      }

      try {
        execFileSync('git', [
          'clone', '--depth', '1',
          '--branch', app.branch || 'main',
          cloneUrl, releaseDir,
        ], { timeout: 120000, stdio: 'pipe' });
      } catch (err) {
        throw new Error(err.message.replaceAll(cloneUrl, app.github_url));
      }

      // Get commit hash
      try {
        commitHash = execFileSync('git', ['-C', releaseDir, 'rev-parse', '--short', 'HEAD'], { timeout: 5000 })
          .toString().trim();
      } catch (e) {}

      appendLog(`Cloned successfully. Commit: ${commitHash}`);

      // v2.3.6: cross-check local HEAD against GitHub's claim for this
      // branch. Mismatch = refuse deploy. Skips quietly when disabled,
      // for non-github URLs, or when GitHub is unreachable (we log but
      // don't block on transient network issues).
      try {
        const { verifyCommitSha } = await import('./supplyChain.js');
        await verifyCommitSha(app, releaseDir, app.branch || 'main', appendLog);
      } catch (e) {
        // Genuine mismatch — abort the deploy. The verifier already
        // formatted a clear error; just rethrow.
        throw e;
      }
    } else if (app.source_type === 'managed_legacy') {
      // v2.3.1: deprecation branch — replays the last upload-time release
      // dir for apps that pre-date the service-account model. Upload as a
      // feature is gone (POST /api/apps/:slug/upload/:env was removed) so
      // this code only finds artifacts written by older versions of
      // AppCrane. Promote these apps to 'github' or 'managed' to retire it.
      const releases = readdirSync(releasesDir)
        .filter(d => d.includes('upload'))
        .sort()
        .reverse();

      if (releases.length === 0) {
        throw new Error(
          `No legacy release found for app '${app.slug}'. Upload-based deploys were removed in v2.3.1; ` +
          `promote this app to source_type='github' (with a github_url) or 'managed' (service-account repo) to deploy fresh.`
        );
      }

      releaseDir = resolve(join(releasesDir, releases[0]));
      appendLog(`Using legacy upload release (deprecated): ${releases[0]}`);
    } else {
      throw new Error(
        `App '${app.slug}' has source_type='${app.source_type || '(unset)'}' which is not deployable. ` +
        `Set source_type to 'github' with a github_url, or 'managed' for a service-account-owned repo.`
      );
    }

    // Read deployhub.json manifest (everything except `version`)
    let manifest = {};
    const manifestPath = join(releaseDir, 'deployhub.json');
    if (existsSync(manifestPath)) {
      manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    } else {
      appendLog('WARNING: No deployhub.json found. Using defaults.');
    }

    // Resolve `version` with precedence:
    //   1. package.json:version (always wins for Node apps — the field
    //      developers actually bump)
    //   2. deployhub.json:version (fallback for non-Node apps, e.g. Python/Go)
    //   3. package.json:name (fills `manifest.name` if deployhub.json is absent)
    // This eliminates the drift class where deployhub.json:version goes stale
    // because every Node release bumps package.json but forgets the manifest.
    const pkgPath = join(releaseDir, 'package.json');
    if (existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
        if (pkg.version) manifest.version = pkg.version;
        if (!manifest.name && pkg.name) manifest.name = pkg.name;
      } catch (e) {
        appendLog(`WARNING: package.json parse failed (${e.message}); falling back to deployhub.json:version`);
      }
    }
    if (existsSync(manifestPath)) {
      appendLog(`Found deployhub.json: ${manifest.name || '(no name)'} v${manifest.version || '(no version)'}`);
    }

    const envVars = db.prepare(
      'SELECT key, value_encrypted FROM env_vars WHERE app_id = ? AND env = ?'
    ).all(app.id, env);

    const bePort = env === 'production' ? ports.prod_be : ports.sand_be;
    const cranePort = process.env.PORT || 5001;
    const craneUrl = process.env.CRANE_DOMAIN
      ? `https://${process.env.CRANE_DOMAIN}`
      : `http://localhost:${cranePort}`;
    const craneInternalUrl = `http://localhost:${cranePort}`;

    const appBasePath = env === 'production' ? `/${app.slug}/` : `/${app.slug}-sandbox/`;

    db.prepare("UPDATE deployments SET status = 'deploying' WHERE id = ?").run(deployId);

    const { dockerAvailable, buildImageIfNeeded, getContainerImage, startApp: dockerStart, stopApp: dockerStop, pruneOldImages, pruneDanglingImages } = await import('./docker.js');
    const { ensureDockerfile, injectAppBasePathArg } = await import('./dockerfileGen.js');
    const { validateDockerfile } = await import('./dockerfileValidator.js');
    const { validateDistConsistency } = await import('./distValidator.js');

    if (!await dockerAvailable()) throw new Error('Docker daemon is not available on this host');

    // Pre-build: if the app committed a `dist/`, verify it's not stale.
    // Catches the "white page on live" failure mode where index.html
    // references hashed asset names that don't exist on disk anymore.
    const distCheck = validateDistConsistency(releaseDir);
    for (const w of distCheck.warnings) appendLog(`⚠ ${w}`);
    if (!distCheck.valid) {
      throw new Error(
        `DIST_OUT_OF_SYNC: committed ${distCheck.foundDistAt} is stale.\n` +
        distCheck.errors.map(e => '  • ' + e).join('\n')
      );
    }
    if (distCheck.foundDistAt) {
      appendLog(`Committed ${distCheck.foundDistAt} validated — index.html references resolve.`);
    }

    const { userProvided } = ensureDockerfile({ releaseDir, manifest, appBasePath, craneUrl, craneInternalUrl });

    if (userProvided) {
      const expectedPort = manifest?.port || manifest?.be?.port || 3000;
      const { valid, errors, warnings } = validateDockerfile(releaseDir, { expectedPort });
      for (const w of warnings) appendLog(`⚠ Dockerfile: ${w}`);
      if (!valid) throw new Error(`Dockerfile validation failed:\n${errors.map(e => '  • ' + e).join('\n')}`);
      injectAppBasePathArg(join(releaseDir, 'Dockerfile'));
      appendLog('Using app-provided Dockerfile (validated)');
    } else {
      appendLog('Generated Dockerfile (Node Alpine, non-root)');
    }

    appendLog('Building docker image...');
    const image = await buildImageIfNeeded({
      slug: app.slug,
      env,
      contextDir: releaseDir,
      commitHash,
      appBasePath,
      onLog: (line) => { if (deployLog.length < 500) appendLog(`  ${line}`); },
    });
    appendLog(`Image ready: ${image}`);

    // Capture old image tag so we can revert if health check fails (Feature 9)
    let prevImage = null;
    try { prevImage = await getContainerImage(app.slug, env); } catch (_) {}

    await dockerStop(app.slug, env).catch(() => {});

    const runtimeEnvVars = {};
    for (const v of envVars) {
      try { runtimeEnvVars[v.key] = decrypt(v.value_encrypted); } catch (_) {}
    }
    // APP_BASE_PATH is intentionally NOT set at runtime: Caddy strips the slug
    // prefix before requests reach the container, so backends must mount at '/'.
    // The variable is build-time only (bundlers need it for asset URLs) — see
    // bugs/2026-04-26-appcrane-app-base-path-resolution.md
    Object.assign(runtimeEnvVars, {
      CRANE_URL: craneUrl,
      CRANE_INTERNAL_URL: craneInternalUrl,
    });

    const limits = parseResourceLimits(app.resource_limits);
    await dockerStart({
      slug: app.slug,
      env,
      image,
      hostPort: bePort,
      envVars: runtimeEnvVars,
      volumes: [{ host: resolve(join(sharedDir, 'data')), container: '/data' }],
      memoryMb: limits.max_ram_mb,
      cpus: limits.max_cpu_percent / 100,
    });
    appendLog(`Container started: appcrane-${app.slug}-${env} (host port ${bePort})`);

    // Health-validate the new container; revert to previous image on failure (Feature 9).
    // v2.2.11: health check is now mandatory. If manifest.be.health is unset
    // we assume the /api/health convention and require the same contract:
    // 200 + JSON with {status, version}. Apps without a health endpoint used
    // to deploy "successfully" then leave the dashboard's version/health
    // columns blank forever, with no signal to the developer that anything
    // was wrong.
    const healthPath = manifest.be?.health || '/api/health';
    const healthSource = manifest.be?.health ? `manifest.be.health="${manifest.be.health}"` : `default /api/health (manifest.be.health unset)`;
    const healthUrl = `http://localhost:${bePort}${healthPath}`;
    appendLog(`Validating new container health at ${healthPath} (30s, ${healthSource})…`);
    const healthResult = await probeHealthEndpoint(healthUrl, 30000);
    if (!healthResult.ok) {
      appendLog(`Health check failed (${healthResult.reason}): ${healthResult.detail}`);
      await dockerStop(app.slug, env).catch(() => {});
      if (prevImage) {
        appendLog(`Reverting to previous image: ${prevImage}`);
        await dockerStart({ slug: app.slug, env, image: prevImage, hostPort: bePort, envVars: runtimeEnvVars, volumes: [{ host: resolve(join(sharedDir, 'data')), container: '/data' }], memoryMb: limits.max_ram_mb, cpus: limits.max_cpu_percent / 100 }).catch(() => {});
      }
      throw new Error(
        `New container failed health check at ${healthPath}: ${healthResult.detail}\n` +
        `Add a route that returns JSON like {"status":"ok","version":"1.0.0"} ` +
        `(declare the path in deployhub.json as be.health, or use the default /api/health). ` +
        `Previous version restored.`
      );
    }
    appendLog('Health check passed');

    pruneOldImages(app.slug, env, (app.image_retention ?? 0) + 1);
    // Reclaim dangling layers from failed/interrupted prior builds (safe — never touches in-use images).
    pruneDanglingImages();

    // 7. Update current symlink (remove old even if target is gone).
    // This is the atomic publish step — until it lands, the release isn't
    // visible to the worker / enhancement lookups. We validate after the
    // flip so a partial deploy can't quietly leave the app in the
    // "deployed but unfindable" state described in the
    // 2026-05-02 current-symlink-missing triage.
    const currentLink = resolve(join(appDir, 'current'));
    try { unlinkSync(currentLink); } catch (e) {} // ignore if doesn't exist
    symlinkSync(resolve(releaseDir), currentLink);
    if (!existsSync(currentLink)) {
      throw new Error(`Deploy verification failed: current symlink at ${currentLink} did not resolve after creation`);
    }
    if (!existsSync(join(currentLink, 'package.json')) && !existsSync(join(currentLink, 'deployhub.json'))) {
      throw new Error(`Deploy verification failed: current symlink target ${releaseDir} has no package.json or deployhub.json`);
    }
    appendLog(`Updated current symlink → ${releaseDir.split('/').pop()}`);

    // 8. Update deployment record
    deployFinished = true;
    appendLog(`Deploy complete! Version: ${manifest.version || 'unknown'}`);
    db.prepare(`
      UPDATE deployments SET status = 'live', version = ?, commit_hash = ?, release_path = ?, finished_at = datetime('now'), log = ?
      WHERE id = ?
    `).run(manifest.version || 'unknown', commitHash, releaseDir, deployLog.join('\n'), deployId);
    // Refresh AI codebase context in background after production deploy
    if (env === 'production') {
      ensureCodebaseContext(app.slug, releaseDir).catch(err => log.warn(`Context refresh failed for ${app.slug}: ${err.message}`));
    }

    // 9. Persist health endpoint from manifest
    if (manifest.be?.health) {
      db.prepare(`
        INSERT INTO health_configs (app_id, env, endpoint)
        VALUES (?, ?, ?)
        ON CONFLICT(app_id, env) DO UPDATE SET endpoint = excluded.endpoint
      `).run(app.id, env, manifest.be.health);
      appendLog(`Health endpoint set to ${manifest.be.health}`);
    }

    // 10. Ensure Caddy has routes for this app
    try {
      const { reloadCaddy } = await import('./caddy.js');
      const result = await reloadCaddy();
      if (result.success) {
        appendLog('Caddy config updated');
      } else {
        appendLog(`Caddy update skipped: ${result.error || 'not available'}`);
      }
    } catch (e) {
      appendLog(`Caddy update skipped: ${e.message}`);
    }

    // 10b. Post-deploy frontend asset probe. Catches the "white page on live"
    // class of bug — container is healthy, /api/health is green, but Caddy
    // returns 404 for one or more script/style refs in the served index.
    // Result is persisted on the deployment row so MCP agents can read it.
    let frontendAssets = null;
    try {
      const probe = await probeFrontendAssets(app.slug, env);
      frontendAssets = probe.status;
      if (probe.status === 'missing') {
        const sample = probe.missing.slice(0, 5).join(', ');
        const more = probe.missing.length > 5 ? ` (+${probe.missing.length - 5} more)` : '';
        appendLog(`⚠ frontend_assets=missing — Caddy 404'd: ${sample}${more}`);
      } else if (probe.status === 'inconclusive') {
        appendLog(`frontend_assets=inconclusive — ${probe.reason}`);
      } else {
        appendLog('frontend_assets=ok — every asset reference resolved through Caddy');
      }
    } catch (e) {
      appendLog(`Frontend probe error: ${e.message}`);
    }
    try {
      db.prepare('UPDATE deployments SET frontend_assets = ?, log = ? WHERE id = ?')
        .run(frontendAssets, deployLog.join('\n'), deployId);
    } catch (_) {}

    // Cleanup old releases (keep last 5)
    try {
      const allReleases = readdirSync(releasesDir).sort().reverse();
      for (const dir of allReleases.slice(5)) {
        const fullPath = join(releasesDir, dir);
        rmSync(fullPath, { recursive: true, force: true });
        appendLog(`Cleaned up old release: ${dir}`);
      }
    } catch (e) {}

    // Send notification
    try {
      const { notifyDeploy } = await import('./emailService.js');
      await notifyDeploy(app, env, manifest.version || 'unknown', 'success');
    } catch (e) {}

    return { success: true, version: manifest.version };

  } catch (error) {
    appendLog(`DEPLOY FAILED: ${error.message}`);
    db.prepare(`
      UPDATE deployments SET status = 'failed', finished_at = datetime('now'), log = ?
      WHERE id = ?
    `).run(deployLog.join('\n'), deployId);

    // Send failure notification
    try {
      const { notifyDeploy } = await import('./emailService.js');
      await notifyDeploy(app, env, 'unknown', 'failed', error.message);
    } catch (e) {}

    throw error;
  }
}
