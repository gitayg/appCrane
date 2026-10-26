import { detectProject, CONTAINER_PORT } from './detect.js';
import { scanEnv } from './env.js';
import { scanSecrets } from './secrets.js';
import { detectBackends } from './backends.js';
import { scaffoldFiles } from './scaffold.js';
import { allDeps, has, jsonOf, scannable } from './projectFiles.js';

// The adoption report: what works as is, what needs a change (each change can
// become a request for the coder), the env vars to fill, and the risks found.

const SSO_NOTE = 'Behind AppCrane\'s SSO gate every request already arrives signed in: AppCrane passes the verified identity in X-AppCrane-* headers (and /api/me), so the app can drop its own sign-in screen and trust those headers instead.';

function browserRouterWithoutBasename(files) {
  for (const [path, text] of scannable(files)) {
    if (!/\.[jt]sx?$/.test(path)) continue;
    if (/<BrowserRouter(?![^>]*basename)/.test(text) || /createBrowserRouter\((?![\s\S]{0,4000}basename)/.test(text)) return path;
  }
  return null;
}

function item(level, id, title, detail, extra = {}) {
  return { id, level, title, detail, request: false, blocking: false, ...extra };
}

export function buildReport(files, { name = 'app', skipped = [] } = {}) {
  const project = detectProject(files);
  const env = scanEnv(files, project);
  const secrets = scanSecrets(files, project);
  const backends = detectBackends(files);
  const scaffold = scaffoldFiles(files, project, { name });
  const pkg = jsonOf(files, 'package.json');
  const deps = allDeps(pkg);
  const works = [];
  const changes = [];

  if (project.framework === 'unknown') {
    changes.push(item('change', 'unknown-framework', 'AppCrane could not tell how to build this project',
      'No package.json, Python manifest or index.html was recognised. Add a Dockerfile that listens on port 3000 before adopting, or adopt and ask the coder to add one.',
      { request: true, blocking: true }));
  } else {
    works.push(item('ok', 'framework', `${project.label} detected`,
      [project.build && `Build: ${project.build}`, project.start && `Start: ${project.start}`, project.output_dir && project.kind === 'spa' && `Output: ${project.output_dir}/`]
        .filter(Boolean).join(' | ') || 'Static files served as is.'));
  }
  if (project.origin.tool !== 'generic') {
    works.push(item('ok', 'origin', `Exported from ${project.origin.label}`, `Confidence ${project.origin.confidence}: ${project.origin.evidence.join(', ')}.`));
  }
  if (project.has_dockerfile) {
    works.push(item('ok', 'dockerfile', 'The project ships its own Dockerfile',
      'AppCrane uses it as is and checks it at deploy: EXPOSE 3000, a non-root USER in the final stage, and no secrets in ENV lines.'));
  }
  if (scaffold.length) {
    works.push(item('ok', 'scaffold', `AppCrane adds ${scaffold.length} file(s)`, scaffold.map((f) => `${f.path}: ${f.why}`).join(' ')));
  }

  if (project.framework === 'tanstack-start') {
    changes.push(item('change', 'tanstack-start', 'Check the TanStack Start start command',
      `Lovable projects created since May 2026 use TanStack Start, which renders on the server. The adopted container starts it with "${project.start}". If the build writes its server somewhere else, change the start command.`,
      { request: true }));
  }
  if (project.framework === 'python-django') {
    changes.push(item('change', 'django-start', 'Add a start command for Django',
      'Add gunicorn to requirements.txt and a Dockerfile that runs "gunicorn --bind 0.0.0.0:3000 <project>.wsgi".', { request: true, blocking: true }));
  }

  const { port } = project;
  const wrongPorts = port.literal_ports.filter((p) => p !== CONTAINER_PORT);
  if (project.kind === 'server' && !port.reads_env_port && wrongPorts.length) {
    changes.push(item('change', 'port', `The server listens on port ${wrongPorts.join(', ')}`,
      `AppCrane routes to port ${CONTAINER_PORT} and sets PORT=${CONTAINER_PORT}. Change the listen call to use process.env.PORT (or os.environ["PORT"]), falling back to ${CONTAINER_PORT}.`,
      { request: true, blocking: true }));
  } else if (port.replit_local_port && port.replit_local_port !== CONTAINER_PORT && !port.reads_env_port) {
    changes.push(item('change', 'port', `.replit maps local port ${port.replit_local_port}`,
      `Make sure the server reads process.env.PORT; AppCrane sets it to ${CONTAINER_PORT}.`, { request: true }));
  } else if (project.kind === 'server') {
    works.push(item('ok', 'port', 'Port', port.reads_env_port ? 'The server reads PORT from the environment, which AppCrane sets.' : `AppCrane routes to port ${CONTAINER_PORT}.`));
  }

  if (project.kind === 'server' && !project.health_route) {
    changes.push(item('change', 'health', 'Add a /api/health endpoint',
      'Every AppCrane deploy checks GET /api/health and expects 200 with JSON {"status":"ok","version":"<app version>"}. Without it the sandbox deploy fails its health check.',
      { request: true, blocking: true }));
  }

  if (project.framework === 'next') {
    changes.push(item('change', 'next-subpath', 'Next.js under a sub-path',
      'AppCrane serves the app at /<slug>/ (and /<slug>-sandbox/). Next.js needs assetPrefix set from process.env.APP_BASE_PATH so its /_next/ assets resolve there, and links built with absolute paths need the same prefix.',
      { request: true }));
  }
  const router = deps['react-router-dom'] || deps['react-router'] ? browserRouterWithoutBasename(files) : null;
  if (router && project.kind === 'spa') {
    changes.push(item('change', 'router-basename', 'Client-side routes need the sub-path',
      `${router} creates a browser router without a basename. Set basename={import.meta.env.BASE_URL} so routes work under /<slug>/.`,
      { request: true }));
  }

  const sb = backends.supabase;
  if (sb.used) {
    if (sb.auth) {
      changes.push(item('change', 'supabase-auth', 'Signs users in with Supabase Auth',
        `${SSO_NOTE} Supabase Auth keeps working if you keep it (add the sandbox URL to the Supabase Auth redirect URLs), but users would sign in twice.${sb.database ? ' Row Level Security policies that use auth.uid() must be reworked if you drop it.' : ''}`,
        { request: true }));
    }
    if (sb.database || sb.migrations) {
      changes.push(item('decision', 'supabase-db', 'Uses Supabase Postgres',
        `Tables seen: ${sb.tables.slice(0, 12).join(', ') || 'none named in code'}${sb.migrations ? '; schema in supabase/migrations' : ''}. Keep it as an external database (nothing to change, set the keys below) or move it to an AppCrane managed Postgres later and switch the data calls to a server route.`));
    }
    if (sb.storage) works.push(item('ok', 'supabase-storage', 'Supabase Storage', 'Keeps working from AppCrane with the same keys.'));
    if (sb.realtime) works.push(item('ok', 'supabase-realtime', 'Supabase Realtime', 'Keeps working from AppCrane with the same keys.'));
    if (sb.edge_functions) works.push(item('ok', 'supabase-functions', 'Supabase Edge Functions stay on Supabase', 'supabase/functions runs on Supabase, not in the AppCrane container. Deploy them with the Supabase CLI as before.'));
    if (sb.hardcoded_url) {
      changes.push(item('change', 'supabase-hardcoded', 'Supabase URL and key are hardcoded',
        `${sb.client_files.join(', ') || 'The Supabase client'} embeds the project URL. Read it from VITE_SUPABASE_URL / VITE_SUPABASE_PUBLISHABLE_KEY instead so the sandbox can point at a separate Supabase project.`,
        { request: true }));
    }
  }
  for (const [key, label] of [['firebase', 'Firebase Auth'], ['clerk', 'Clerk'], ['auth0', 'Auth0'], ['next_auth', 'NextAuth / Auth.js']]) {
    const b = backends[key];
    if (b.used && (key !== 'firebase' || b.auth)) {
      changes.push(item('change', `${key}-auth`, `Signs users in with ${label}`, SSO_NOTE, { request: true }));
    }
  }
  if (backends.databases.length) {
    works.push(item('ok', 'databases', `Database clients: ${backends.databases.join(', ')}`, 'Point them at an existing database with the env vars below, or provision an AppCrane managed database after adoption.'));
  }

  if (project.runtime === 'node' && !['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'].some((f) => has(files, f))) {
    changes.push(item('risk', 'lockfile', 'No npm lockfile',
      project.package_manager === 'bun' ? 'The project pins dependencies with bun, which the build does not use, so dependencies are re-resolved at every build. Commit a package-lock.json.' : 'Dependencies are re-resolved at every build. Commit a lockfile.',
      { severity: 'low' }));
  }

  const risks = secrets.map((s) => ({
    ...item('risk', `secret:${s.rule}:${s.path}:${s.line}`, `${s.title} in ${s.path}:${s.line}`, s.detail),
    severity: s.severity, side: s.side, preview: s.preview, rule: s.rule,
    request: s.severity === 'critical' || s.severity === 'high',
  }));

  const envVars = env.vars.filter((v) => v.scope !== 'supabase-edge');
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const r of risks) counts[r.severity]++;
  const blocking = changes.filter((c) => c.blocking).length;
  const verdict = counts.critical ? 'critical_risks' : blocking ? 'needs_changes' : changes.some((c) => c.level === 'change') ? 'works_with_changes' : 'ready';

  return {
    verdict,
    project: {
      framework: project.framework, label: project.label, runtime: project.runtime, kind: project.kind,
      build: project.build, start: project.start, output_dir: project.output_dir, package_manager: project.package_manager,
      port: project.port, health_route: project.health_route, has_dockerfile: project.has_dockerfile, origin: project.origin,
      replit: project.replit ? { run: project.replit.run, deployment: project.replit.deployment, ports: project.replit.ports } : null,
    },
    backends,
    works,
    changes,
    risks,
    risk_counts: counts,
    env: envVars,
    supabase_edge_env: env.vars.filter((v) => v.scope === 'supabase-edge').map((v) => v.key),
    scaffold: scaffold.map((f) => ({ path: f.path, why: f.why })),
    skipped,
    file_count: files.size,
  };
}

/** The scaffold files with content, for the adopt step. */
export function scaffoldFor(files, name) {
  return scaffoldFiles(files, detectProject(files), { name });
}

/** Uploaded .env values keyed by name. Server side only. */
export function uploadedEnvValues(files) {
  return scanEnv(files, detectProject(files)).uploaded_values;
}
