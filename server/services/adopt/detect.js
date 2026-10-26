import { allDeps, has, hasDir, jsonOf, scannable, textOf } from './projectFiles.js';

// Static detection only: nothing here runs the project's code or its package
// manager. Every answer comes from file names and file contents.

export const CONTAINER_PORT = 3000;

/** Minimal reader for the keys of a .replit file that matter here. */
export function parseReplit(text) {
  const out = { run: null, deployment: { run: null, build: null }, ports: [], modules: [] };
  if (!text) return out;
  let section = '';
  let currentPort = null;
  const value = (raw) => {
    const v = raw.trim();
    if (v.startsWith('[')) {
      const parts = [...v.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]);
      if (parts.length >= 3 && parts[0] === 'sh' && parts[1] === '-c') return parts.slice(2).join(' ');
      return parts.join(' ');
    }
    const m = v.match(/^"((?:[^"\\]|\\.)*)"/) || v.match(/^'([^']*)'/);
    return m ? m[1] : v;
  };
  for (const line of text.split('\n')) {
    const l = line.replace(/\s+#.*$/, '').trim();
    if (!l || l.startsWith('#')) continue;
    if (/^\[\[ports\]\]$/.test(l)) { section = 'ports'; currentPort = {}; out.ports.push(currentPort); continue; }
    const sec = l.match(/^\[([^\]]+)\]$/);
    if (sec) { section = sec[1].trim(); continue; }
    const kv = l.match(/^([A-Za-z0-9_.-]+)\s*=\s*(.+)$/);
    if (!kv) continue;
    const [, key, raw] = kv;
    if (section === '' && key === 'run') out.run = value(raw);
    else if (section === '' && key === 'modules') out.modules = [...raw.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
    else if (section === 'deployment' && (key === 'run' || key === 'build')) out.deployment[key] = value(raw);
    else if (section === 'ports' && currentPort && (key === 'localPort' || key === 'externalPort')) currentPort[key] = Number(raw);
  }
  return out;
}

function packageManager(files) {
  if (has(files, 'pnpm-lock.yaml')) return 'pnpm';
  if (has(files, 'yarn.lock')) return 'yarn';
  if (has(files, 'package-lock.json') || has(files, 'npm-shrinkwrap.json')) return 'npm';
  if (has(files, 'bun.lockb') || has(files, 'bun.lock')) return 'bun';
  return has(files, 'package.json') ? 'npm' : null;
}

function originTool(files, pkg) {
  const deps = allDeps(pkg);
  const evidence = [];
  const supaClient = textOf(files, 'src/integrations/supabase/client.ts') || textOf(files, 'src/integrations/supabase/client.js');
  if (deps['lovable-tagger']) evidence.push('lovable-tagger in devDependencies');
  if (Object.keys(deps).some((d) => d.startsWith('@lovable.dev/'))) evidence.push('@lovable.dev package dependency');
  if (supaClient && /automatically generated/i.test(supaClient)) evidence.push('generated src/integrations/supabase/client');
  if (evidence.length) return { tool: 'lovable', label: 'Lovable', confidence: deps['lovable-tagger'] || evidence.length > 1 ? 'high' : 'medium', evidence };

  if (hasDir(files, '.bolt')) {
    const cfg = jsonOf(files, '.bolt/config.json');
    return { tool: 'bolt', label: 'Bolt.new', confidence: 'high', evidence: ['.bolt/ directory', ...(cfg?.template ? [`template ${cfg.template}`] : [])] };
  }
  if (has(files, '.replit') || has(files, 'replit.nix')) {
    return { tool: 'replit', label: 'Replit', confidence: 'high', evidence: [has(files, '.replit') ? '.replit file' : 'replit.nix file'] };
  }
  if (deps.next && has(files, 'components.json')) {
    const named = /v0/i.test(String(pkg?.name || ''));
    return { tool: 'v0', label: 'v0', confidence: named ? 'high' : 'low', evidence: [named ? `package name ${pkg.name}` : 'Next.js with a shadcn/ui components.json (v0 output shape; not unique to v0)'] };
  }
  const readme = textOf(files, 'README.md') || '';
  if (/figma\s*make/i.test(readme)) return { tool: 'figma-make', label: 'Figma Make', confidence: 'low', evidence: ['README mentions Figma Make'] };
  return { tool: 'generic', label: 'Generic project', confidence: 'n/a', evidence: [] };
}

function pythonFramework(files) {
  const req = [textOf(files, 'requirements.txt'), textOf(files, 'pyproject.toml'), textOf(files, 'Pipfile')].filter(Boolean).join('\n').toLowerCase();
  if (!req && !has(files, 'main.py') && !has(files, 'app.py')) return null;
  const entryFile = ['main.py', 'app.py', 'server.py', 'wsgi.py', 'app/main.py'].find((p) => has(files, p)) || null;
  const mod = entryFile ? entryFile.replace(/\.py$/, '').replace(/\//g, '.') : 'main';
  if (/\bfastapi\b/.test(req)) return { framework: 'python-fastapi', label: 'Python FastAPI', start: `uvicorn ${mod}:app --host 0.0.0.0 --port ${CONTAINER_PORT}`, entryFile, needs: /\buvicorn\b/.test(req) ? [] : ['uvicorn'] };
  if (/\bflask\b/.test(req)) return { framework: 'python-flask', label: 'Python Flask', start: `gunicorn --bind 0.0.0.0:${CONTAINER_PORT} ${mod}:app`, entryFile, needs: /\bgunicorn\b/.test(req) ? [] : ['gunicorn'] };
  if (/\bdjango\b/.test(req)) return { framework: 'python-django', label: 'Python Django', start: null, entryFile, needs: [] };
  return { framework: 'python', label: 'Python', start: entryFile ? `python ${entryFile}` : null, entryFile, needs: [] };
}

const SERVER_DEPS = ['express', 'fastify', 'koa', 'hono', '@hono/node-server', '@nestjs/core', 'restify', 'polka', 'h3'];

function serverEntry(files, pkg) {
  if (pkg?.main && has(files, pkg.main)) return pkg.main;
  return ['server/index.ts', 'server/index.js', 'server.js', 'server.ts', 'index.js', 'src/server.ts', 'src/server.js', 'app.js', 'src/index.ts', 'src/index.js']
    .find((p) => has(files, p)) || null;
}

/** Port the code listens on, as far as static reading can tell. */
export function detectListenPort(files) {
  let envPort = false;
  const literal = new Set();
  for (const [path, text] of scannable(files)) {
    if (!/\.(?:[cm]?[jt]s|py)$/.test(path) || path.includes('supabase/functions/')) continue;
    if (/process\.env\.PORT|os\.environ(?:\.get)?\(?\[?["']PORT|getenv\(["']PORT/.test(text)) envPort = true;
    for (const m of text.matchAll(/\.listen\(\s*(\d{2,5})\b/g)) literal.add(Number(m[1]));
    for (const m of text.matchAll(/\bport\s*[:=]\s*(\d{2,5})\b/g)) {
      if (/vite\.config|next\.config/.test(path)) continue;
      literal.add(Number(m[1]));
    }
  }
  return { reads_env_port: envPort, literal_ports: [...literal].filter((p) => p >= 80 && p <= 65535).sort((a, b) => a - b) };
}

function healthRouteFound(files) {
  for (const [path, text] of scannable(files)) {
    if (/\.(?:[cm]?[jt]sx?|py)$/.test(path) && /["'`]\/api\/health["'`]/.test(text)) return path;
  }
  if (['app/api/health/route.ts', 'app/api/health/route.js', 'src/app/api/health/route.ts', 'src/app/api/health/route.js',
    'pages/api/health.ts', 'pages/api/health.js', 'src/pages/api/health.ts', 'src/pages/api/health.js'].some((p) => has(files, p))) return 'api/health route file';
  return null;
}

/**
 * What the project is and how it builds and runs. Never executes anything.
 */
export function detectProject(files) {
  const pkg = jsonOf(files, 'package.json');
  const deps = allDeps(pkg);
  const scripts = pkg?.scripts || {};
  const replit = has(files, '.replit') ? parseReplit(textOf(files, '.replit')) : null;
  const origin = originTool(files, pkg);
  const pm = packageManager(files);
  const run = pm === 'yarn' ? 'yarn' : pm === 'pnpm' ? 'pnpm run' : 'npm run';
  const result = {
    origin,
    package_manager: pm,
    has_dockerfile: has(files, 'Dockerfile'),
    has_manifest: has(files, 'deployhub.json'),
    replit,
    framework: 'unknown',
    label: 'Unrecognised project',
    runtime: null,
    kind: null,
    build: null,
    start: null,
    output_dir: null,
    router: null,
    entry: null,
  };

  if (pkg) {
    result.runtime = 'node';
    const serverDep = SERVER_DEPS.find((d) => deps[d]);
    if (deps.next) {
      const appDir = hasDir(files, 'app') ? 'app' : hasDir(files, 'src/app') ? 'src/app' : null;
      const pagesDir = hasDir(files, 'pages') ? 'pages' : hasDir(files, 'src/pages') ? 'src/pages' : null;
      Object.assign(result, {
        framework: 'next', label: 'Next.js', kind: 'ssr',
        build: `${run} build`, start: `npx next start -p ${CONTAINER_PORT}`,
        router: appDir ? { type: 'app', dir: appDir } : pagesDir ? { type: 'pages', dir: pagesDir } : null,
      });
    } else if (deps['@tanstack/react-start'] || deps['@tanstack/start']) {
      Object.assign(result, {
        framework: 'tanstack-start', label: 'TanStack Start', kind: 'ssr',
        build: `${run} build`, start: scripts.start ? `${run} start` : 'node .output/server/index.mjs',
      });
    } else if (Object.keys(deps).some((d) => d.startsWith('@remix-run/')) || deps['@react-router/serve']) {
      Object.assign(result, {
        framework: 'remix', label: deps['@react-router/serve'] ? 'React Router (framework mode)' : 'Remix', kind: 'ssr',
        build: `${run} build`, start: `${run} start`,
      });
    } else if (serverDep && (scripts.start || serverEntry(files, pkg))) {
      const entry = serverEntry(files, pkg);
      Object.assign(result, {
        framework: 'node-server', label: `Node server (${serverDep}${deps.vite ? ' + Vite client' : ''})`, kind: 'server',
        build: scripts.build ? `${run} build` : null,
        start: scripts.start ? `${run} start` : entry && /\.js$/.test(entry) ? `node ${entry}` : null,
        entry,
      });
    } else if (deps.vite) {
      Object.assign(result, {
        framework: 'vite-spa', label: `Vite single-page app${deps.react ? ' (React)' : deps.vue ? ' (Vue)' : deps.svelte ? ' (Svelte)' : ''}`,
        kind: 'spa', build: 'npx vite build --base "${APP_BASE_PATH:-./}"', output_dir: 'dist',
      });
    } else if (deps['react-scripts']) {
      Object.assign(result, { framework: 'cra', label: 'Create React App', kind: 'spa', build: `${run} build`, output_dir: 'build' });
    } else if (scripts.start) {
      Object.assign(result, { framework: 'node-server', label: 'Node app', kind: 'server', build: scripts.build ? `${run} build` : null, start: `${run} start` });
    } else if (has(files, 'index.html')) {
      Object.assign(result, { framework: 'static', label: 'Static site', kind: 'static', runtime: 'static', output_dir: '.' });
    }
  } else {
    const py = pythonFramework(files);
    if (py) {
      Object.assign(result, { framework: py.framework, label: py.label, runtime: 'python', kind: 'server', start: py.start, entry: py.entryFile, python_needs: py.needs });
    } else if (has(files, 'index.html')) {
      Object.assign(result, { framework: 'static', label: 'Static site', runtime: 'static', kind: 'static', output_dir: '.' });
    }
  }

  if (replit?.deployment?.run && result.framework === 'unknown') {
    Object.assign(result, { framework: 'replit-run', label: 'Replit run command', kind: 'server', start: replit.deployment.run, build: replit.deployment.build || null });
  }

  const listen = detectListenPort(files);
  const replitPort = replit?.ports?.find((p) => p.localPort)?.localPort || null;
  result.port = {
    container: CONTAINER_PORT,
    reads_env_port: listen.reads_env_port,
    literal_ports: listen.literal_ports,
    replit_local_port: replitPort,
  };
  result.health_route = healthRouteFound(files);
  return result;
}
