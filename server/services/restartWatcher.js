// Records the container stops and deaths no AppCrane code path records itself,
// from `docker events`. Measured against Docker 29 (the sequences below are
// what the daemon emits, per container):
//   crash               die (exitCode != 0), then start when on-failure restarts it
//   OOM kill            oom, die (exitCode 137), then start
//   docker stop/restart kill (signal 15), [kill (9)], stop, die, [start, restart]
//   docker rm -f        kill (9), die, destroy
// So a die with no kill just before it is the container's own doing (crash or
// OOM), and one after a kill is a planned stop by someone: the health checker
// and container recovery record theirs and announce them (expectPlanned); the
// rest are attributed from AppCrane's own records (sleep state, a restore in
// progress, a 'restart' audit row, a deploy in flight) or recorded as a stop
// outside AppCrane.
//
// Memory for a planned stop is read at the kill, while the process is still
// shutting down; a crashed or OOM-killed container's cgroup is already gone at
// the die, so only its exit state and logs are captured (not_captured says so).

import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { getDb } from '../db.js';
import log from '../utils/logger.js';
import { captureContainer } from './restartCapture.js';
import { recordIncident, takeExpected, recentIncident } from './restartIncidents.js';

export const KILL_WINDOW_MS = 30_000;
export const OOM_WINDOW_MS = 10_000;
export const ATTRIBUTE_DELAY_MS = 30_000;
const NAME_RE = /^appcrane-([a-z0-9][a-z0-9-]*)-(production|sandbox)$/;

const byContainer = new Map();
let attributeDelayMs = ATTRIBUTE_DELAY_MS;
export function _setAttributeDelayForTests(ms) { attributeDelayMs = ms; }
let child = null;
let stopped = true;
let retryMs = 5000;
let retryTimer = null;

function entry(id) {
  let e = byContainer.get(id);
  if (!e) { e = { killAt: 0, oomAt: 0, killCapture: null }; byContainer.set(id, e); }
  return e;
}

function appFor(db, ev) {
  const a = ev.Actor?.Attributes || {};
  const m = NAME_RE.exec(a.name || '');
  if (!m || a.slug !== m[1] || a.env !== m[2]) return null;
  const app = db.prepare('SELECT id, slug FROM apps WHERE slug = ?').get(a.slug);
  return app ? { app, env: a.env, name: a.name } : null;
}

/** Who stopped it, from AppCrane's own records. null = a path that records itself. */
export async function attributePlanned({ db, app, env, sinceMs, now = Date.now() }) {
  const expected = takeExpected(app.id, env, now);
  if (expected) return null;
  if (recentIncident({ appId: app.id, env, ms: now - sinceMs + 120_000, triggers: ['health', 'recovery'], db, now })) return null;
  const { envIsSleepingById } = await import('./envSleepState.js');
  if (envIsSleepingById(app.id, env, db)) return 'sleep';
  const { restoreInProgress } = await import('./managedDbRestoreGuard.js');
  if (restoreInProgress(app.slug, env)) return 'restore';
  const sqlSince = new Date(sinceMs - 120_000).toISOString().replace('T', ' ').slice(0, 19);
  const manual = db.prepare(`SELECT 1 FROM audit_log WHERE app_id = ? AND action = 'restart' AND created_at >= ? AND detail LIKE ? LIMIT 1`)
    .get(app.id, sqlSince, `%"env":"${env}"%`);
  if (manual) return 'manual';
  const deploy = db.prepare(`SELECT 1 FROM deployments WHERE app_id = ? AND env = ?
      AND (status IN ('pending', 'building', 'deploying') OR finished_at >= ?) LIMIT 1`).get(app.id, env, sqlSince);
  if (deploy) return 'deploy';
  return 'stop';
}

export async function handleEvent(ev, { db = getDb(), now = () => Date.now(), delayMs = attributeDelayMs } = {}) {
  if (ev?.Type !== 'container') return null;
  const id = ev.Actor?.ID || ev.id;
  const action = String(ev.Action || ev.status || '');
  if (!id) return null;
  if (action === 'destroy') { byContainer.delete(id); return null; }
  if (!['kill', 'oom', 'die'].includes(action)) return null;
  const who = appFor(db, ev);
  if (!who) return null;
  const e = entry(id);
  const t = now();

  if (action === 'oom') { e.oomAt = t; return null; }
  if (action === 'kill') {
    if (!e.killCapture || t - e.killAt > KILL_WINDOW_MS) e.killCapture = captureContainer(who.name, { timeoutMs: 6000 });
    e.killAt = t;
    return null;
  }

  // die
  const exitCode = ev.Actor?.Attributes?.exitCode != null ? Number(ev.Actor.Attributes.exitCode) : null;
  const planned = e.killAt && t - e.killAt <= KILL_WINDOW_MS;
  if (!planned) {
    const capture = await captureContainer(who.name, { memory: false });
    const oom = (e.oomAt && t - e.oomAt <= OOM_WINDOW_MS) || capture.state?.oom_killed;
    const restarts = capture.state?.restart_count ?? null;
    return recordIncident({
      appId: who.app.id, env: who.env, trigger: oom ? 'oom' : 'crash', action: 'observed', capture, db,
      detail: { exit_code: exitCode, docker_restarts: exitCode !== 0 && restarts != null && restarts < 2, restart_count: restarts },
    });
  }
  const killCapture = e.killCapture;
  const killAt = e.killAt;
  e.killCapture = null;
  e.killAt = 0;
  if (delayMs) await new Promise(r => setTimeout(r, delayMs));
  const trigger = await attributePlanned({ db, app: who.app, env: who.env, sinceMs: killAt, now: now() });
  if (!trigger) return null;
  const capture = killCapture ? await killCapture : await captureContainer(who.name, { memory: false });
  return recordIncident({ appId: who.app.id, env: who.env, trigger, action: 'observed', capture, db, detail: { exit_code: exitCode } });
}

function connect() {
  if (stopped) return;
  const p = spawn('docker', ['events', '--filter', 'type=container', '--filter', 'label=appcrane=true', '--format', '{{json .}}'],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  child = p;
  let stderr = '';
  p.stderr.on('data', d => { stderr = (stderr + d).slice(-500); });
  createInterface({ input: p.stdout }).on('line', (line) => {
    retryMs = 5000;
    let ev;
    try { ev = JSON.parse(line); } catch { return; }
    handleEvent(ev).catch(err => log.warn(`[restart-watcher] event not recorded: ${err.message}`));
  });
  p.on('error', (err) => log.warn(`[restart-watcher] docker events failed to start: ${err.message}`));
  p.on('close', (code) => {
    if (child === p) child = null;
    if (stopped) return;
    log.warn(`[restart-watcher] docker events exited (${code}${stderr ? `: ${stderr.trim()}` : ''}); reconnecting in ${retryMs / 1000}s`);
    retryTimer = setTimeout(connect, retryMs);
    retryTimer.unref?.();
    retryMs = Math.min(retryMs * 2, 5 * 60_000);
  });
}

export function startRestartWatcher() {
  if (!stopped) return;
  stopped = false;
  process.once('exit', () => child?.kill());
  connect();
}

export function stopRestartWatcher() {
  stopped = true;
  if (retryTimer) clearTimeout(retryTimer);
  retryTimer = null;
  if (child) child.kill();
  child = null;
  byContainer.clear();
}

/** True once `docker events` is running (for tests). */
export function watcherConnected() {
  return !!child && child.exitCode == null;
}
