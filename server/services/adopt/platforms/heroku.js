import { herokuAddon } from './addons.js';

// Heroku app.json and heroku.yml.
//
// app.json, https://devcenter.heroku.com/articles/app-json-schema:
//   env: "Keys are the names of the config variables. Values can be strings or
//   objects." Object fields: description, "value : a default value to use",
//   "required : A boolean ... (default: true)", "generator ... Currently the
//   only supported generator is secret".
//   scripts.postdeploy: "The postdeploy script is run once, after the app is
//   created and not on subsequent deploys to the app".
//   "The app.json will only be processed and analyzed when creating a new app,
//   not when re-deploying one."
// heroku.yml, https://devcenter.heroku.com/articles/build-docker-images-heroku-yml:
//   "setup – Specifies the add-ons and config vars to create during app
//   provisioning; build – Specifies the Dockerfile to build; release –
//   Specifies the release phase tasks to execute; run – Specifies process types
//   and the commands to run for each type".

const META_KEYS = new Set(['name', 'description', 'keywords', 'website', 'repository', 'logo', 'success_url']);

const empty = (format, file) => ({ format, file, web: null, health: null, release: [], crons: [], env: [], databases: [], unmapped: [], notes: [] });

function addAddons(out, list, field) {
  if (list === undefined) return;
  if (!Array.isArray(list)) { out.unmapped.push({ field, title: `${field} is not a list`, detail: 'Add-ons were not read.' }); return; }
  for (const entry of list) {
    const a = herokuAddon(entry);
    if (!a) { out.unmapped.push({ field, title: 'An add-on entry has no plan', detail: JSON.stringify(entry).slice(0, 120) }); continue; }
    if (a.engine) out.databases.push({ engine: a.engine, url_env: a.url_env, env: {}, origin: `${field}: ${a.plan}`, vendor: a.vendor });
    else {
      out.unmapped.push({
        field, kind: 'addon', title: `Add-on ${a.name} has no AppCrane equivalent`,
        detail: `${a.plan} is provisioned by Heroku. Keep using the provider directly (set its env vars below) or replace it.`,
      });
    }
  }
}

export function mapAppJson(json, file = 'app.json') {
  const out = empty('heroku-app-json', file);
  if (!json || typeof json !== 'object' || Array.isArray(json)) {
    out.unmapped.push({ field: '(file)', title: `${file} is not a JSON object`, detail: 'Nothing was read from it.' });
    return out;
  }
  if (json.env !== undefined) {
    if (!json.env || typeof json.env !== 'object' || Array.isArray(json.env)) out.unmapped.push({ field: 'env', title: 'env is not an object', detail: 'No env var names were read.' });
    else {
      for (const [key, v] of Object.entries(json.env)) {
        if (typeof v === 'string') { out.env.push({ key, value: 'literal', field: `env.${key}` }); continue; }
        const o = v && typeof v === 'object' ? v : {};
        out.env.push({
          key, field: `env.${key}`,
          value: o.generator === 'secret' ? 'generate' : typeof o.value === 'string' || typeof o.value === 'number' ? 'literal' : 'prompt',
          required: o.required !== false,
          description: typeof o.description === 'string' ? o.description.slice(0, 300) : null,
        });
      }
    }
  }
  addAddons(out, json.addons, 'addons');
  if (json.formation && typeof json.formation === 'object') {
    for (const [type, f] of Object.entries(json.formation)) {
      if (type === 'web') {
        if (f && Number(f.quantity) > 1) out.unmapped.push({ field: 'formation.web.quantity', title: `${f.quantity} web dynos`, detail: 'AppCrane runs one container per stage; scale is not imported.' });
        continue;
      }
      out.unmapped.push({ field: `formation.${type}`, kind: 'process', title: `Process "${type}" is not run`, detail: 'app.json scales a process other than web. An AppCrane app runs the web process only; run it as its own app or a cron job.' });
    }
  }
  const scripts = json.scripts && typeof json.scripts === 'object' ? json.scripts : {};
  for (const [name, v] of Object.entries(scripts)) {
    const cmd = typeof v === 'string' ? v : v && typeof v.command === 'string' ? v.command : null;
    if (name === 'postdeploy') {
      out.unmapped.push({
        field: 'scripts.postdeploy', kind: 'release', request: true,
        title: 'One-time postdeploy script is not run',
        detail: `Heroku ran "${cmd}" once, after the app was created. AppCrane has no post-create hook; run it once against the sandbox after the first deploy (for example from a cron job you trigger by hand), then remove it.`,
      });
    } else {
      out.unmapped.push({ field: `scripts.${name}`, title: `scripts.${name} is not run`, detail: `${name} is a Heroku Review/CI lifecycle script ("${cmd}"); AppCrane has no equivalent.` });
    }
  }
  if (json.buildpacks !== undefined) out.unmapped.push({ field: 'buildpacks', title: 'Buildpacks are not used', detail: 'AppCrane builds from a Dockerfile (generated from the detected framework, or the project\'s own). Anything a buildpack installed must be in that Dockerfile.' });
  if (json.environments !== undefined) out.unmapped.push({ field: 'environments', title: 'Heroku CI / Review App overrides are not used', detail: `Overrides for ${Object.keys(json.environments || {}).join(', ') || 'no environment'} apply to Heroku CI and Review Apps only.` });
  for (const k of ['image', 'stack']) {
    if (json[k] !== undefined) out.unmapped.push({ field: k, title: `${k} is not used`, detail: `${k} "${String(json[k]).slice(0, 60)}" selects a Heroku build image; AppCrane picks the base image from the detected runtime.` });
  }
  for (const k of Object.keys(json)) {
    if (!META_KEYS.has(k) && !['env', 'addons', 'formation', 'scripts', 'buildpacks', 'environments', 'image', 'stack'].includes(k)) {
      out.unmapped.push({ field: k, title: `${k} is not read`, detail: `"${k}" is not part of what AppCrane imports from app.json.` });
    }
  }
  return out;
}

function commandOf(v) {
  if (typeof v === 'string') return v;
  if (v && typeof v === 'object') {
    const c = v.command;
    if (typeof c === 'string') return c;
    if (Array.isArray(c) && c.every((x) => typeof x === 'string')) return c.join(' && ');
  }
  return null;
}

export function mapHerokuYml(doc, file = 'heroku.yml') {
  const out = empty('heroku-yml', file);
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    out.unmapped.push({ field: '(file)', title: `${file} is not a mapping`, detail: 'Nothing was read from it.' });
    return out;
  }
  const setup = doc.setup && typeof doc.setup === 'object' ? doc.setup : {};
  addAddons(out, setup.addons, 'setup.addons');
  if (setup.config && typeof setup.config === 'object') {
    for (const key of Object.keys(setup.config)) out.env.push({ key, value: 'literal', field: `setup.config.${key}` });
  }
  const build = doc.build && typeof doc.build === 'object' ? doc.build : {};
  const docker = build.docker && typeof build.docker === 'object' ? build.docker : {};
  for (const [proc, df] of Object.entries(docker)) {
    const path = typeof df === 'string' ? df : df && typeof df.dockerfile === 'string' ? df.dockerfile : null;
    if (proc === 'web') {
      if (path && path.replace(/^\.\//, '') !== 'Dockerfile') out.unmapped.push({ field: 'build.docker.web', title: `Web image is built from ${path}`, detail: 'AppCrane builds the Dockerfile at the repository root. Move or copy it there.', request: true });
      if (df && typeof df === 'object' && df.target) out.unmapped.push({ field: 'build.docker.web.target', title: `Build target "${df.target}" is not used`, detail: 'AppCrane builds the final stage of the Dockerfile.' });
    } else if (proc !== 'release') {
      out.unmapped.push({ field: `build.docker.${proc}`, kind: 'process', title: `Image "${proc}" is not built`, detail: `${path || 'A Dockerfile'} builds the ${proc} image. AppCrane builds one image per app.` });
    }
  }
  if (build.config && typeof build.config === 'object') {
    const keys = Object.keys(build.config);
    out.unmapped.push({
      field: 'build.config', kind: 'build-args',
      title: `Docker build args are not passed: ${keys.join(', ')}`,
      detail: 'heroku.yml passes these as build-time ARGs. AppCrane does not pass them, and their values were not imported. Give the ARGs defaults in the Dockerfile, or read them as env vars at run time.',
    });
  }
  if (doc.release !== undefined) {
    const cmd = commandOf(doc.release);
    if (cmd) out.release.push({ command: cmd, field: 'release.command' });
    if (doc.release && typeof doc.release === 'object' && doc.release.image && doc.release.image !== 'web') {
      out.notes.push(`The release phase runs in the ${doc.release.image} image, which AppCrane does not build.`);
    }
  }
  const run = doc.run && typeof doc.run === 'object' ? doc.run : {};
  for (const [proc, v] of Object.entries(run)) {
    const cmd = commandOf(v);
    if (proc === 'web') {
      if (cmd) out.web = { start: cmd, build: null, docker_command: true, field: 'run.web' };
      continue;
    }
    out.unmapped.push({ field: `run.${proc}`, kind: 'process', title: `Process "${proc}" is not run`, detail: `heroku.yml runs "${cmd}". An AppCrane app runs the web process only; run it as its own app or a cron job.` });
  }
  return out;
}
