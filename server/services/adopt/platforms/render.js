// render.yaml (Render Blueprint), https://render.com/docs/blueprint-spec
//   type: "web", "pserv", "worker", "cron", "keyvalue" ("redis" is a
//   deprecated alias), "workflow".
//   buildCommand: "The command Render runs to build the service."
//   startCommand: "The command Render runs to start the service."
//   preDeployCommand: runs "after buildCommand and before startCommand".
//   healthCheckPath: web services only; "always starts with /".
//   schedule: required for cron jobs; a cron expression.
//   envVars: key + value ("Hardcoded value"), generateValue: true ("Generate a
//   base64-encoded 256-bit value"), sync: false ("Prompt for a value in the
//   Render Dashboard"), fromDatabase / fromService (a property of another
//   resource), fromGroup (all variables of an environment group).
//   databases: "A list of Postgres databases"; fromDatabase properties include
//   connectionString, host, port, user, password, database.
//   repo: "Default: Repo containing render.yaml"; rootDir: "Default: Repo root".

const DB_PROPERTY = Object.assign(Object.create(null), { connectionString: 'url', host: 'host', port: 'port', user: 'user', password: 'password', database: 'name' });
const IGNORED = ['plan', 'region', 'numInstances', 'scaling', 'domains', 'autoDeploy', 'autoDeployTrigger', 'branch', 'previews', 'buildFilter',
  'maxShutdownDelaySeconds', 'renderSubdomainPolicy', 'ipAllowList', 'maintenanceMode', 'registryCredential', 'initialDeployHook', 'disk'];

const str = (v) => (typeof v === 'string' && v.trim() ? v.trim() : null);
const sameRepoDir = (d) => d == null || ['', '.', './'].includes(String(d).trim());

function envOf(list, groups, field, out, dbRefs) {
  if (!Array.isArray(list)) return [];
  const env = [];
  list.forEach((e, idx) => {
    if (!e || typeof e !== 'object') return;
    const f = `${field}[${idx}]`;
    if (typeof e.fromGroup === 'string') {
      const g = groups.get(e.fromGroup);
      if (!g) { out.unmapped.push({ field: f, title: `Environment group "${e.fromGroup}" is not in the file`, detail: 'Its variable names could not be read; copy them from the Render Dashboard.' }); return; }
      for (const ge of envOf(g, new Map(), `envVarGroups.${e.fromGroup}`, out, null)) env.push({ ...ge, group: e.fromGroup });
      return;
    }
    const key = str(e.key);
    if (!key) return;
    if (e.fromDatabase && typeof e.fromDatabase === 'object') {
      const prop = DB_PROPERTY[e.fromDatabase.property];
      if (dbRefs && prop) dbRefs.push({ kind: 'postgres', name: e.fromDatabase.name, prop, key });
      env.push({ key, field: f, value: prop ? 'database' : 'reference', reference: `database ${e.fromDatabase.name}.${e.fromDatabase.property}` });
      return;
    }
    if (e.fromService && typeof e.fromService === 'object') {
      const s = e.fromService;
      const isKv = s.type === 'keyvalue' || s.type === 'redis';
      const prop = isKv ? DB_PROPERTY[s.property] : null;
      if (isKv && prop && prop !== 'user' && prop !== 'name' && dbRefs) dbRefs.push({ kind: 'redis', name: s.name, prop, key });
      env.push({ key, field: f, value: isKv && prop ? 'database' : 'reference', reference: `${s.type || 'service'} ${s.name}.${s.property || s.envVarKey || ''}` });
      return;
    }
    if (e.generateValue === true) { env.push({ key, field: f, value: 'generate' }); return; }
    if (e.sync === false) { env.push({ key, field: f, value: 'prompt' }); return; }
    env.push({ key, field: f, value: e.value !== undefined && e.value !== null ? 'literal' : 'prompt' });
  });
  return env;
}

function ignoredSettings(svc, label, out) {
  const keys = IGNORED.filter((k) => svc[k] !== undefined);
  if (keys.length) {
    out.unmapped.push({
      field: `${label}.(${keys.join(', ')})`, title: `Render settings not imported for ${svc.name}`,
      detail: `${keys.join(', ')}: scaling, plans, regions, domains and deploy triggers are set in AppCrane itself.${svc.disk ? ' The persistent disk is not recreated: every AppCrane app container has a persistent /data mounted (DATA_DIR), so move files written to the disk\'s mountPath there.' : ''}`,
    });
  }
}

export function mapRender(doc, file = 'render.yaml') {
  const out = { format: 'render', file, web: null, health: null, release: [], crons: [], env: [], databases: [], unmapped: [], notes: [] };
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    out.unmapped.push({ field: '(file)', title: `${file} is not a mapping`, detail: 'Nothing was read from it.' });
    return out;
  }
  const groups = new Map();
  for (const g of Array.isArray(doc.envVarGroups) ? doc.envVarGroups : []) {
    if (g && typeof g.name === 'string') groups.set(g.name, g.envVars);
  }
  const services = Array.isArray(doc.services) ? doc.services : [];
  const dbRefs = [];
  const keyvalues = new Map();
  let webIndex = -1;

  services.forEach((svc, idx) => {
    if (!svc || typeof svc !== 'object') return;
    const label = `services[${idx}]`;
    const name = str(svc.name) || label;
    const type = svc.type;
    if (type === 'keyvalue' || type === 'redis') { keyvalues.set(name, idx); return; }
    if (!sameRepoDir(svc.rootDir)) {
      out.unmapped.push({ field: `${label}.rootDir`, kind: 'service', title: `Service ${name} lives in ${svc.rootDir}/`, detail: 'AppCrane builds an app from the repository root. Adopt that directory as its own app.' });
      return;
    }
    if (type === 'web' && svc.runtime === 'static') {
      out.unmapped.push({ field: label, kind: 'service', title: `Static site ${name} is not imported from render.yaml`, detail: `AppCrane detects a static or single-page build from the code itself.${svc.buildCommand ? ` Render built it with "${svc.buildCommand}" into ${svc.staticPublishPath || 'its publish path'}.` : ''} Headers and routes rules are not imported.` });
      return;
    }
    if (type === 'web' && webIndex === -1) {
      webIndex = idx;
      const docker = svc.runtime === 'docker' || svc.runtime === 'image';
      const start = docker ? str(svc.dockerCommand) : str(svc.startCommand);
      out.web = { start, build: docker ? null : str(svc.buildCommand), docker_command: docker, runtime: svc.runtime || null, name, field: `${label}.${docker ? 'dockerCommand' : 'startCommand'}` };
      if (svc.runtime === 'image') out.unmapped.push({ field: `${label}.image`, kind: 'service', title: `${name} runs a prebuilt image`, detail: 'Deploy the image as an AppCrane image app instead of adopting the repository.' });
      if (docker && svc.dockerfilePath && String(svc.dockerfilePath).replace(/^\.\//, '') !== 'Dockerfile') {
        out.unmapped.push({ field: `${label}.dockerfilePath`, title: `Dockerfile at ${svc.dockerfilePath}`, detail: 'AppCrane builds the Dockerfile at the repository root. Move or copy it there.', request: true });
      }
      if (str(svc.healthCheckPath)) out.health = { path: svc.healthCheckPath.trim(), field: `${label}.healthCheckPath` };
      if (str(svc.preDeployCommand)) out.release.push({ command: svc.preDeployCommand.trim(), field: `${label}.preDeployCommand` });
      if (svc.repo) out.notes.push(`${name} names repo ${svc.repo}; AppCrane assumed it is the repository being adopted.`);
      out.env.push(...envOf(svc.envVars, groups, `${label}.envVars`, out, dbRefs));
      ignoredSettings(svc, label, out);
      return;
    }
    if (type === 'cron') {
      const docker = svc.runtime === 'docker';
      const command = docker ? str(svc.dockerCommand) : str(svc.startCommand);
      if (svc.repo) {
        out.unmapped.push({ field: label, kind: 'service', title: `Cron job ${name} builds from ${svc.repo}`, detail: `It runs "${command}" on "${svc.schedule}" from another repository; AppCrane cron jobs run inside this app's container.` });
        return;
      }
      if (!command || !str(svc.schedule)) {
        out.unmapped.push({ field: label, title: `Cron job ${name} has no ${command ? 'schedule' : 'command'}`, detail: 'It was not imported.' });
        return;
      }
      out.crons.push({ name: `render:${name}`, schedule: svc.schedule.trim(), command, field: `${label}.schedule`, build: str(svc.buildCommand) });
      for (const e of envOf(svc.envVars, groups, `${label}.envVars`, out, dbRefs)) out.env.push(e);
      return;
    }
    const what = type === 'web' ? 'another web service' : type === 'worker' ? 'a background worker' : type === 'pserv' ? 'a private service' : type === 'workflow' ? 'a workflow' : `a ${type || 'typeless'} service`;
    out.unmapped.push({
      field: label, kind: 'service', title: `${name} (${what}) is not run`,
      detail: `${svc.startCommand ? `Render runs "${svc.startCommand}". ` : ''}An AppCrane app runs one web container per stage. Adopt it as its own app${type === 'worker' ? ', fold it into the web process, or make it a cron job if it is periodic' : ''}.`,
    });
  });

  const dbs = Array.isArray(doc.databases) ? doc.databases : [];
  const fieldsFor = (kind, name) => {
    const refs = dbRefs.filter((r) => r.kind === kind && r.name === name);
    const url = refs.find((r) => r.prop === 'url');
    const env = {};
    for (const r of refs) if (r.prop !== 'url' && !env[r.prop]) env[r.prop] = r.key;
    return { url_env: url ? url.key : null, env, referenced: refs.length > 0 };
  };
  dbs.forEach((d, idx) => {
    const name = d && str(d.name);
    if (!name) return;
    const f = fieldsFor('postgres', name);
    out.databases.push({ engine: 'postgres', ...f, origin: `databases[${idx}] ${name}`, version: d.postgresMajorVersion ? String(d.postgresMajorVersion) : null });
    if (d.readReplicas || d.highAvailability) out.unmapped.push({ field: `databases[${idx}]`, title: `Replicas / high availability for ${name} are not recreated`, detail: 'An AppCrane managed Postgres is a single instance.' });
  });
  for (const [name, idx] of keyvalues) {
    const f = fieldsFor('redis', name);
    out.databases.push({ engine: 'redis', ...f, origin: `services[${idx}] ${name} (keyvalue)` });
  }
  for (const r of dbRefs) {
    if (r.kind === 'postgres' && !dbs.some((d) => d && d.name === r.name)) {
      out.unmapped.push({ field: r.key, title: `${r.key} reads database "${r.name}", which is not in the file`, detail: 'The database is managed outside this Blueprint; set the variable yourself or add a managed database.' });
    }
  }
  if (!services.length && !dbs.length) out.unmapped.push({ field: 'services', title: `${file} declares no services`, detail: 'Nothing to import.' });
  return out;
}
