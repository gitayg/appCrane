import { has, jsonOf, textOf } from '../projectFiles.js';
import { parseCron } from '../../cronScheduler.js';
import { DEFAULT_URL_ENV, parseManifestDatabase, RESERVED_ENV_NAMES, RESERVED_ENV_PREFIX } from '../../manifestDatabase.js';
import { parseYamlLite } from './yamlLite.js';
import { parseTomlLite } from './tomlLite.js';
import { isReservedKey } from './reservedKeys.js';
import { mapProcfile } from './procfile.js';
import { mapRender } from './render.js';
import { mapRailway } from './railway.js';
import { mapAppJson, mapHerokuYml } from './heroku.js';

// Platform manifests an app leaving Heroku, Render or Railway ships with, read
// statically and merged into one plan the adoption report shows and the
// scaffold writes into deployhub.json. Values in a manifest are never carried
// over: only env var NAMES, with how the platform filled each one.

export const PLATFORM_LABEL = {
  render: 'Render', railway: 'Railway', 'heroku-app-json': 'Heroku', 'heroku-yml': 'Heroku', procfile: 'Heroku',
};
const WEB_ORDER = ['render', 'railway', 'heroku-yml', 'procfile'];
const ENGINE_ORDER = ['postgres', 'mariadb', 'mongo', 'redis'];
const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const MAX_CRONS = 50;
const HEROKU_KEYS = ['env', 'addons', 'formation', 'scripts', 'buildpacks', 'stack', 'image', 'success_url', 'environments'];

function unreadable(format, file, e) {
  return {
    format, file, web: null, health: null, release: [], crons: [], env: [], databases: [], notes: [],
    unmapped: [{ field: '(file)', kind: 'unreadable', title: `${file} could not be read`, detail: `${e.message}. Nothing was imported from it.` }],
  };
}

function reservedKeyIn(v, depth = 0) {
  if (depth > 64 || !v || typeof v !== 'object') return null;
  for (const k of Object.keys(v)) {
    if (isReservedKey(k)) return k;
    const inner = reservedKeyIn(v[k], depth + 1);
    if (inner) return inner;
  }
  return null;
}

function readJson(files, format, path, map) {
  const j = jsonOf(files, path);
  if (j === null) return unreadable(format, path, new Error('not valid JSON'));
  const bad = reservedKeyIn(j);
  if (bad) return unreadable(format, path, new Error(`key "${bad}" is not allowed`));
  return map ? map(j, path) : j;
}

function readFragments(files) {
  const out = [];
  const yaml = (format, path, map) => {
    try { out.push(map(parseYamlLite(textOf(files, path)), path)); } catch (e) { out.push(unreadable(format, path, e)); }
  };
  for (const p of ['render.yaml', 'render.yml']) if (has(files, p)) { yaml('render', p, mapRender); break; }
  if (has(files, 'railway.json')) {
    out.push(readJson(files, 'railway', 'railway.json', mapRailway));
  } else if (has(files, 'railway.toml')) {
    try { out.push(mapRailway(parseTomlLite(textOf(files, 'railway.toml')), 'railway.toml')); } catch (e) { out.push(unreadable('railway', 'railway.toml', e)); }
  }
  if (has(files, 'heroku.yml')) yaml('heroku-yml', 'heroku.yml', mapHerokuYml);
  if (has(files, 'Procfile')) out.push(mapProcfile(textOf(files, 'Procfile'), 'Procfile'));
  if (has(files, 'app.json')) {
    const j = jsonOf(files, 'app.json');
    const heroku = j && typeof j === 'object' && !Array.isArray(j) && !Object.hasOwn(j, 'expo') && HEROKU_KEYS.some((k) => Object.hasOwn(j, k));
    if (j === null || heroku) out.push(readJson(files, 'heroku-app-json', 'app.json', mapAppJson));
  }
  if (has(files, '.railway/railway.ts')) {
    out.push({
      format: 'railway', file: '.railway/railway.ts', web: null, health: null, release: [], crons: [], env: [], databases: [], notes: [],
      unmapped: [{ field: '(file)', kind: 'unreadable', title: '.railway/railway.ts is not read', detail: 'Railway Infrastructure as Code is TypeScript, and AppCrane never runs project code during adoption. Copy its start command, cron schedule and health path into the report\'s changes by hand.' }],
    });
  }
  return out;
}

const where = (frag, field) => `${frag.file}${field ? ` ${field}` : ''}`;

/** The literal port a start command binds, when it names one instead of $PORT. */
export function literalPortIn(command) {
  if (!command || /\$\{?PORT\b/.test(command)) return null;
  const m = command.match(/(?:^|\s)(?:-p|--port|-b|--bind)(?:\s+|=)(?:[\w.[\]-]*:)?(\d{2,5})\b/) || command.match(/(?:^|\s)PORT=(\d{2,5})\b/);
  return m ? Number(m[1]) : null;
}

/**
 * The merged plan, or null when the project ships no platform manifest.
 * { sources, web, health, crons, database, env, release, unmapped, notes, mapped }
 */
export function detectPlatforms(files) {
  const frags = readFragments(files);
  if (!frags.length) return null;
  const unmapped = [];
  const mapped = [];
  const notes = [];
  for (const f of frags) {
    for (const u of f.unmapped) unmapped.push({ ...u, source: f.file, platform: PLATFORM_LABEL[f.format] });
    for (const n of f.notes) notes.push(`${f.file}: ${n}`);
  }

  const webFrags = WEB_ORDER.flatMap((fmt) => frags.filter((f) => f.format === fmt && f.web));
  let web = null;
  const startFrag = webFrags.find((f) => f.web.start);
  const buildFrag = (startFrag && startFrag.web.build ? startFrag : null) || webFrags.find((f) => f.web.build);
  if (startFrag || buildFrag) {
    web = {
      start: startFrag ? startFrag.web.start : null,
      start_source: startFrag ? where(startFrag, startFrag.web.field) : null,
      build: buildFrag ? buildFrag.web.build : null,
      build_source: buildFrag ? buildFrag.file : null,
      docker_command: Boolean(startFrag?.web.docker_command),
      runtime: startFrag?.web.runtime || null,
      literal_port: startFrag ? literalPortIn(startFrag.web.start) : null,
    };
    if (web.start) mapped.push({ from: web.start_source, to: 'start command', value: web.start });
    if (web.build) mapped.push({ from: `${web.build_source} build command`, to: 'build command', value: web.build });
    for (const f of webFrags) {
      if (f !== startFrag && f.web.start && f.web.start !== web.start) {
        unmapped.push({ field: f.web.field, title: `${f.file} starts the app differently`, detail: `"${f.web.start}" is not used; ${web.start_source} ("${web.start}") was.`, source: f.file, platform: PLATFORM_LABEL[f.format] });
      }
    }
  }

  const healthFrag = WEB_ORDER.flatMap((fmt) => frags.filter((f) => f.format === fmt && f.health))[0] || null;
  const health = healthFrag ? { path: healthFrag.health.path, source: where(healthFrag, healthFrag.health.field) } : null;
  if (health && !/^\/[^\s?#]*$/.test(health.path)) {
    unmapped.push({ field: healthFrag.health.field, title: `Health path "${health.path}" is not usable`, detail: 'It must be a path starting with "/".', source: healthFrag.file });
  }
  const healthOk = health && /^\/[^\s?#]*$/.test(health.path) ? health : null;

  const crons = [];
  const names = new Set();
  for (const f of frags) {
    for (const c of f.crons) {
      try { parseCron(c.schedule); } catch (e) {
        unmapped.push({ field: c.field, title: `Cron ${c.name} has a schedule AppCrane cannot run`, detail: `"${c.schedule}": ${e.message}.`, source: f.file, platform: PLATFORM_LABEL[f.format] });
        continue;
      }
      if (names.has(c.name) || crons.length >= MAX_CRONS) {
        unmapped.push({ field: c.field, title: `Cron ${c.name} was not imported`, detail: names.has(c.name) ? 'Another job has that name.' : `Only ${MAX_CRONS} jobs are imported.`, source: f.file });
        continue;
      }
      names.add(c.name);
      crons.push({ name: c.name, schedule: c.schedule.split(/\s+/).join(' '), command: c.command, source: where(f, c.field) });
      mapped.push({ from: where(f, c.field), to: `cron job ${c.name}`, value: `${c.schedule} ${c.command}` });
      if (c.build) notes.push(`${f.file}: cron ${c.name} had its own build ("${c.build}"); it now runs in the web container's image.`);
    }
  }

  const candidates = frags.flatMap((f) => f.databases.map((d) => ({ ...d, source: f.file, platform: PLATFORM_LABEL[f.format] })));
  candidates.sort((a, b) => (Number(b.referenced || 0) - Number(a.referenced || 0)) || (ENGINE_ORDER.indexOf(a.engine) - ENGINE_ORDER.indexOf(b.engine)));
  let database = null;
  for (const d of candidates) {
    if (database) {
      unmapped.push({ field: d.origin, kind: 'database', title: `${d.engine} (${d.origin}) is not provisioned`, detail: `deployhub.json declares one managed database per app; ${database.block.engine} from ${database.origin} was chosen. Provision this one by hand after adoption, or keep it external.`, source: d.source, platform: d.platform });
      continue;
    }
    const block = { engine: d.engine };
    if (d.url_env && d.url_env !== DEFAULT_URL_ENV[d.engine]) block.url_env = d.url_env;
    if (!d.url_env && d.env && Object.keys(d.env).length) block.url_env = null;
    if (d.env && Object.keys(d.env).length) block.env = d.env;
    try {
      const needs = parseManifestDatabase(block);
      database = { block, injects: [needs.url_env, ...Object.values(needs.env || {})].filter(Boolean), origin: d.origin, source: d.source, platform: d.platform, vendor: d.vendor || null, version: d.version || null };
      mapped.push({ from: `${d.source} ${d.origin}`, to: `managed ${d.engine} database`, value: database.injects.join(', ') });
    } catch (e) {
      unmapped.push({ field: d.origin, kind: 'database', title: `${d.engine} (${d.origin}) could not be mapped`, detail: e.message, source: d.source, platform: d.platform });
    }
  }

  const env = new Map();
  const reserved = [];
  for (const f of frags) {
    for (const e of f.env) {
      if (!ENV_KEY_RE.test(e.key) || isReservedKey(e.key)) continue;
      if (RESERVED_ENV_NAMES.includes(e.key.toUpperCase()) || e.key.toUpperCase().startsWith(RESERVED_ENV_PREFIX)) { reserved.push(`${e.key} (${f.file})`); continue; }
      const prev = env.get(e.key);
      const entry = prev || { key: e.key, value: e.value, sources: [], description: null, required: true, reference: null, provided_by_database: false };
      if (!entry.sources.includes(f.file)) entry.sources.push(f.file);
      if (e.value === 'literal' || (entry.value !== 'literal' && e.value === 'generate')) entry.value = e.value;
      if (e.description && !entry.description) entry.description = e.description;
      if (e.required === false) entry.required = false;
      if (e.reference && !entry.reference) entry.reference = e.reference;
      env.set(e.key, entry);
    }
  }
  if (database) for (const k of database.injects) if (env.has(k)) env.get(k).provided_by_database = true;
  if (reserved.length) {
    unmapped.push({ field: 'env', kind: 'env', title: 'Variables AppCrane sets itself', detail: `${reserved.join(', ')}: AppCrane sets PORT=3000 and its own platform variables, so these are not imported.` });
  }

  if (frags.some((f) => f.format.startsWith('heroku') || f.format === 'procfile')) {
    unmapped.push({ field: '(Heroku Scheduler)', kind: 'dashboard', title: 'Heroku Scheduler jobs are not in these files', detail: 'Heroku Scheduler is configured in the dashboard, not in app.json, heroku.yml or the Procfile. Recreate each job as an AppCrane cron job (deployhub.json "cron").', source: 'Heroku', platform: 'Heroku' });
  }

  const release = frags.flatMap((f) => f.release.map((r) => ({ command: r.command, source: where(f, r.field), platform: PLATFORM_LABEL[f.format] })));

  return {
    sources: frags.map((f) => ({ format: f.format, file: f.file, platform: PLATFORM_LABEL[f.format] })),
    web, health: healthOk, crons, database, release, notes, mapped, unmapped,
    env: [...env.values()].sort((a, b) => a.key.localeCompare(b.key)),
  };
}

/** The health path deployhub.json declares for this project: the platform's, when the app answers it itself. */
export function platformHealthPath(project) {
  const h = project?.platform?.health;
  if (!h) return null;
  if (!['server', 'ssr'].includes(project.kind) || project.framework === 'next' || project.health_route) return null;
  return h.path;
}
