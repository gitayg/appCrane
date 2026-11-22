// railway.json / railway.toml (Railway config as code),
// https://docs.railway.com/reference/config-as-code and
// https://docs.railway.com/config-as-code:
//   build.builder (Railpack, the default, or Dockerfile), build.buildCommand,
//   build.dockerfilePath, build.watchPatterns; deploy.startCommand,
//   deploy.preDeployCommand (e.g. ["npm run db:migrate"]), deploy.healthcheckPath,
//   deploy.healthcheckTimeout, deploy.cronSchedule (e.g. "*/15 * * * *"),
//   deploy.restartPolicyType, deploy.multiRegionConfig.<region>.numReplicas,
//   environments.<name> overrides.
//   "Everything in the build and deploy sections of the service settings page
//   can be specified in this configuration file." Variables and databases are
//   not among them, so neither can be imported from it.
//   "Config as Code is deprecated. Prefer Infrastructure as Code
//   (.railway/railway.ts) ... until 2026-12-01 (hard cutoff)."

const str = (v) => (typeof v === 'string' && v.trim() ? v.trim() : null);
const IGNORED_DEPLOY = ['healthcheckTimeout', 'restartPolicyType', 'restartPolicyMaxRetries', 'multiRegionConfig', 'numReplicas', 'region',
  'overlapSeconds', 'drainingSeconds', 'sleepApplication', 'runtime', 'limitOverride', 'requiredMountPath'];
const IGNORED_BUILD = ['watchPatterns', 'railpackVersion', 'nixpacksPlan', 'nixpacksConfigPath', 'nixpacksVersion', 'buildEnvironment'];

export function mapRailway(cfg, file) {
  const out = { format: 'railway', file, web: null, health: null, release: [], crons: [], env: [], databases: [], unmapped: [], notes: [] };
  if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) {
    out.unmapped.push({ field: '(file)', title: `${file} is not an object`, detail: 'Nothing was read from it.' });
    return out;
  }
  const build = cfg.build && typeof cfg.build === 'object' ? cfg.build : {};
  const deploy = cfg.deploy && typeof cfg.deploy === 'object' ? cfg.deploy : {};
  const docker = /^dockerfile$/i.test(String(build.builder || ''));
  if (str(build.dockerfilePath) && build.dockerfilePath.replace(/^\.\//, '') !== 'Dockerfile') {
    out.unmapped.push({ field: 'build.dockerfilePath', title: `Dockerfile at ${build.dockerfilePath}`, detail: 'AppCrane builds the Dockerfile at the repository root. Move or copy it there.', request: true });
  }
  const start = str(deploy.startCommand);
  const buildCmd = docker ? null : str(build.buildCommand);
  if (str(deploy.cronSchedule)) {
    if (start) out.crons.push({ name: 'railway:cron', schedule: deploy.cronSchedule.trim(), command: start, field: 'deploy.cronSchedule' });
    else out.unmapped.push({ field: 'deploy.cronSchedule', title: 'cronSchedule without a startCommand', detail: 'Railway runs the image\'s own command on the schedule; AppCrane needs the command to run. Add it as a cron job by hand.' });
    out.notes.push('On Railway this service is a cron job: it starts on the schedule and exits. AppCrane runs the command inside the app\'s always-on container, which still needs a web process that answers the health check.');
    if (buildCmd) out.web = { start: null, build: buildCmd, docker_command: docker, field: 'build.buildCommand' };
  } else if (start || buildCmd) {
    out.web = { start, build: buildCmd, docker_command: docker, field: 'deploy.startCommand' };
  }
  if (docker && str(build.buildCommand)) out.unmapped.push({ field: 'build.buildCommand', title: 'buildCommand with the Dockerfile builder', detail: 'The Dockerfile decides the build; the command was not used.' });
  const pre = Array.isArray(deploy.preDeployCommand) ? deploy.preDeployCommand.filter((c) => typeof c === 'string' && c.trim()) : str(deploy.preDeployCommand) ? [deploy.preDeployCommand] : [];
  if (pre.length) out.release.push({ command: pre.join(' && '), field: 'deploy.preDeployCommand' });
  if (str(deploy.healthcheckPath)) out.health = { path: deploy.healthcheckPath.trim(), field: 'deploy.healthcheckPath' };
  const ignored = [...IGNORED_BUILD.filter((k) => build[k] !== undefined).map((k) => `build.${k}`), ...IGNORED_DEPLOY.filter((k) => deploy[k] !== undefined).map((k) => `deploy.${k}`)];
  if (ignored.length) {
    out.unmapped.push({ field: ignored.join(', '), title: 'Railway settings not imported', detail: `${ignored.join(', ')}: restart policy, replicas, regions, timeouts and build-trigger settings are AppCrane's own.` });
  }
  if (cfg.environments && typeof cfg.environments === 'object') {
    out.unmapped.push({ field: 'environments', title: 'Per-environment overrides are not imported', detail: `${Object.keys(cfg.environments).join(', ')} override the base config on Railway. AppCrane's sandbox and production use the same commands; only the base config was imported.` });
  }
  out.unmapped.push({
    field: '(variables, databases)', kind: 'dashboard',
    title: 'Railway variables and databases are not in this file',
    detail: 'Railway keeps service variables and its Postgres / MySQL / Redis / MongoDB services in the dashboard, not in config as code. Copy the variable names from the Railway dashboard, and provision an AppCrane managed database if the service used a Railway database.',
  });
  return out;
}
