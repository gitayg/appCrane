import { CONTAINER_PORT } from './detect.js';
import { isPublicPrefix } from './env.js';
import { platformHealthPath } from './platforms/index.js';

// The adoption report's view of an imported Heroku / Render / Railway
// manifest: what was mapped, what needs a change, and the env var names to
// fill. Manifest values are never shown or carried over.

function item(level, id, title, detail, extra = {}) {
  return { id, level, title, detail, request: false, blocking: false, ...extra };
}

const platformsOf = (p) => [...new Set(p.sources.map((s) => s.platform))].join(', ');

export function platformItems(project, { hasManifest }) {
  const p = project.platform;
  const works = [];
  const changes = [];
  const files = p.sources.map((s) => s.file).join(', ');

  if (p.mapped.length) {
    works.push(item('ok', 'platform-import', `Imported from ${files}`, p.mapped.map((m) => `${m.from} -> ${m.to}`).join(' | ')));
  }

  const web = p.web;
  if (web?.start && !web.applied) {
    if (web.not_applied === 'dockerfile') {
      changes.push(item('decision', 'platform-start-dockerfile', 'The project\'s Dockerfile decides how it starts',
        `${web.start_source} starts it with "${web.start}". AppCrane runs the Dockerfile's CMD and has no command override${web.docker_command ? ', so make the CMD run that command' : ''}.`,
        { request: web.docker_command }));
    } else if (web.not_applied === 'static') {
      changes.push(item('decision', 'platform-start-static', `${web.start_source} is not used`,
        `This is a ${project.label}; AppCrane serves its build output itself, so "${web.start}" is not run.`));
    } else {
      changes.push(item('change', 'platform-start-runtime', `AppCrane cannot build a ${web.runtime || 'project of this kind'} without a Dockerfile`,
        `${web.start_source} starts the app with "${web.start}". AppCrane generates Dockerfiles for Node and Python projects only. Add a Dockerfile that installs the app and runs that command, listening on $PORT (AppCrane sets PORT=${CONTAINER_PORT}).`,
        { request: true }));
    }
  }
  if (web?.applied && web.literal_port && web.literal_port !== CONTAINER_PORT) {
    changes.push(item('change', 'platform-port', `The start command binds port ${web.literal_port}`,
      `"${web.start}" names port ${web.literal_port}. AppCrane routes to port ${CONTAINER_PORT} and sets PORT=${CONTAINER_PORT}: use $PORT in the command.`,
      { request: true, blocking: true }));
  }
  if (web?.build && project.runtime === 'python') {
    changes.push(item('decision', 'platform-build-python', 'The build command is not run',
      `${web.build_source} builds with "${web.build}". The generated Python Dockerfile installs requirements.txt (or the pyproject) itself; anything else the build did must go into a Dockerfile.`));
  }

  if (p.health) {
    const hp = platformHealthPath(project);
    if (hp) {
      changes.push(item('change', 'health', `Health check at ${hp} must answer AppCrane's contract`,
        `${p.health.source} sets the health path, and deployhub.json now declares it. AppCrane checks GET ${hp} after every deploy and expects 200 with JSON {"status":"ok","version":"<app version>"}; on ${platformsOf(p)} the path only had to answer. Return that body there, or the sandbox deploy fails its health check.`,
        { request: true, blocking: true }));
    } else {
      const why = project.health_route ? 'the code already serves' : project.kind === 'spa' || project.kind === 'static' ? 'the generated static server answers' : 'AppCrane adds';
      works.push(item('ok', 'platform-health', 'Health check', `${p.health.source} (${p.health.path}) is not used: AppCrane checks /api/health, which ${why}.`));
    }
  }

  if (p.database) {
    const d = p.database;
    const extra = [
      d.vendor === 'third-party' ? `The add-on chose its own variable name, which the manifest does not show; AppCrane injects ${d.injects.join(', ')}, so point the code at that.` : '',
      d.block.engine === 'mariadb' ? 'AppCrane offers MariaDB, which speaks the MySQL protocol; check any MySQL-only features the app uses.' : '',
      d.version ? `${d.platform} pinned Postgres ${d.version}; the managed server runs AppCrane's version.` : '',
    ].filter(Boolean).join(' ');
    changes.push(item('decision', 'platform-database', `Managed ${d.block.engine} database instead of ${d.origin}`,
      `${hasManifest ? 'Add a "database" block to deployhub.json' : 'deployhub.json declares it'} so the sandbox deploy provisions an AppCrane managed ${d.block.engine} database and injects ${d.injects.join(', ')}. The data is not copied: dump it from ${d.platform} and restore it into the sandbox database.${extra ? ` ${extra}` : ''}`));
  }

  if (p.crons.length) {
    works.push(item('ok', 'platform-crons', `${p.crons.length} cron job(s)`,
      `${p.crons.map((c) => `${c.name}: "${c.schedule}" runs "${c.command}"`).join(' | ')}. They run inside the app's container at the schedule (UTC)${hasManifest ? ' once added to deployhub.json' : ', declared in deployhub.json'}.`));
  }

  p.release.forEach((r, i) => {
    changes.push(item('change', `platform-release:${i}`, `Pre-deploy command is not run: ${r.command}`,
      `${r.source} ran it before each release on ${r.platform}. AppCrane has no pre-deploy hook. Run it at container start ahead of the server (CMD sh -c "${r.command} && <start>"), which repeats it on every start, or have the app run its migrations on boot.`,
      { request: true }));
  });

  if (hasManifest && (p.crons.length || p.database || platformHealthPath(project))) {
    changes.push(item('decision', 'platform-manifest-exists', 'deployhub.json already exists and was not changed',
      'Add the health path, cron jobs and database listed here to it by hand.', { request: true }));
  }

  const literal = p.env.filter((e) => e.value === 'literal' && !e.provided_by_database).map((e) => e.key);
  const generated = p.env.filter((e) => e.value === 'generate').map((e) => e.key);
  if (literal.length || generated.length) {
    changes.push(item('decision', 'platform-env-values', 'Manifest values were not imported',
      [
        literal.length ? `${literal.join(', ')} have values in ${files}. Treat them as secrets: they were not imported or stored. Enter the ones the app needs below.` : '',
        generated.length ? `${generated.join(', ')} were random values generated by ${platformsOf(p)}. Enter a new random value for each (e.g. openssl rand -hex 32).` : '',
      ].filter(Boolean).join(' ')));
  }

  for (const u of p.unmapped.filter((x) => x.request)) {
    changes.push(item('change', `platform-unmapped:${u.source}:${u.field}`, u.title, u.detail, { request: true }));
  }
  return { works, changes };
}

function hintFor(e, platform) {
  const base = e.description ? `${e.description.replace(/[.\s]*$/, '')}. ` : '';
  if (e.value === 'literal') return `${base}${e.sources.join(', ')} sets a value; it was not imported.`;
  if (e.value === 'generate') return `${base}${platform} generated a random value; enter a new one.`;
  if (e.value === 'prompt') return `${base}Entered by hand on ${platform}; the manifest holds no value.`;
  if (e.reference) return `${base}On ${platform} this came from ${e.reference}.`;
  return base.trim() || null;
}

/** Code-detected env vars plus the names the manifests declare. Keys the managed database injects are dropped. */
export function platformEnv(vars, platform) {
  if (!platform) return vars;
  const injected = new Set(platform.database?.injects || []);
  const out = vars.filter((v) => !injected.has(v.key)).map((v) => ({ ...v }));
  const label = platformsOf(platform);
  for (const e of platform.env) {
    if (e.provided_by_database || injected.has(e.key)) continue;
    const manifest = { sources: e.sources, value: e.value, required: e.required, reference: e.reference };
    const existing = out.find((v) => v.key === e.key);
    if (existing) {
      existing.manifest = manifest;
      existing.hint = existing.hint || hintFor(e, label);
      continue;
    }
    out.push({
      key: e.key, scope: isPublicPrefix(e.key) ? 'client' : 'server', build_time: isPublicPrefix(e.key),
      sources: e.sources, in_template: false, value_in_upload: false, hint: hintFor(e, label), manifest,
    });
  }
  return out;
}

export function platformView(p) {
  if (!p) return null;
  return {
    sources: p.sources,
    mapped: p.mapped,
    unmapped: p.unmapped.map((u) => ({ source: u.source, platform: u.platform || null, field: u.field, kind: u.kind || null, title: u.title, detail: u.detail })),
    notes: p.notes,
    start: p.web?.start || null,
    start_applied: Boolean(p.web?.applied),
    health: p.health,
    crons: p.crons,
    database: p.database ? { ...p.database.block, injects: p.database.injects, origin: p.database.origin } : null,
    release: p.release,
  };
}
