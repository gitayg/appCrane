// Anonymous daily install check-in (v2.93.0).
//
// Without it nobody can say how many AppCrane installs exist, which versions
// they run, or how many are stuck below the Node floor. Once a day each server
// sends ONE small JSON document, and nothing else:
//
//   install_id      random, generated on first boot, stored in DATA_DIR/install-id;
//                   tied to nothing (not the host, the domain or any user)
//   version         AppCrane version
//   node, os, arch  runtime: process.version, process.platform, process.arch
//   apps            number of registered apps
//   apps_deployed   number of apps with at least one live deploy
//   users           number of active human users
//
// Counts only: no app names, domains, emails, IPs or anything an app contains.
// The receiver (ping.appcrane.dev) does not store the sender's IP.
//
// On by default, off with APPCRANE_CHECKIN=off (or DO_NOT_TRACK=1). Every boot
// logs what is sent and how to turn it off. A failed send is logged at debug
// level and never retried early: the check-in must never affect the platform.

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join, resolve } from 'path';
import { randomBytes } from 'crypto';
import { getDb } from '../db.js';
import log from '../utils/logger.js';

export const DEFAULT_CHECKIN_URL = 'https://ping.appcrane.dev/v1/checkin';
const DAY_MS = 24 * 60 * 60 * 1000;
const ID_RE = /^[A-Za-z0-9_-]{22}$/;

/** Why the check-in is off, or null when it is on. */
export function checkinDisabledReason(env = process.env) {
  const v = String(env.APPCRANE_CHECKIN || '').toLowerCase();
  if (['off', '0', 'false', 'no', 'disabled'].includes(v)) return 'APPCRANE_CHECKIN=off';
  if (env.DO_NOT_TRACK === '1') return 'DO_NOT_TRACK=1';
  // Test runs are not installs.
  if (env.NODE_TEST_CONTEXT || env.NODE_ENV === 'test') return 'test run';
  return null;
}

/** The install's random id, created on first call. */
export function installId(dataDir = process.env.DATA_DIR || './data') {
  const dir = resolve(dataDir);
  const file = join(dir, 'install-id');
  if (existsSync(file)) {
    const id = readFileSync(file, 'utf8').trim();
    if (ID_RE.test(id)) return id;
  }
  const id = randomBytes(16).toString('base64url');
  mkdirSync(dir, { recursive: true });
  writeFileSync(file, `${id}\n`, { mode: 0o600 });
  return id;
}

/** The exact document sent. Counts only; see the header for every field. */
export function checkinPayload({ version, dataDir } = {}) {
  const db = getDb();
  const count = (sql) => {
    try { return db.prepare(sql).get().n; } catch (_) { return null; }
  };
  return {
    install_id: installId(dataDir),
    version: String(version || ''),
    node: process.version,
    os: process.platform,
    arch: process.arch,
    apps: count('SELECT COUNT(*) AS n FROM apps'),
    apps_deployed: count("SELECT COUNT(DISTINCT app_id) AS n FROM deployments WHERE status = 'live'"),
    users: count("SELECT COUNT(*) AS n FROM users WHERE active = 1 AND kind = 'human'"),
  };
}

/** Send one check-in. Resolves true on a 2xx, false otherwise; never throws. */
export async function sendCheckin({ version, url = process.env.APPCRANE_CHECKIN_URL || DEFAULT_CHECKIN_URL, fetchImpl = globalThis.fetch } = {}) {
  try {
    const r = await fetchImpl(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(checkinPayload({ version })),
      signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) log.debug(`[checkin] ${url} answered HTTP ${r.status}`);
    return r.ok;
  } catch (e) {
    log.debug(`[checkin] not sent: ${e.message}`);
    return false;
  }
}

/**
 * Start the daily schedule: first send a few minutes after boot (spread out, so
 * a fleet restarted together does not arrive at once), then every 24 h.
 * Returns a stop function. Does nothing when disabled.
 */
export function startInstallCheckin({ version } = {}) {
  const off = checkinDisabledReason();
  const url = process.env.APPCRANE_CHECKIN_URL || DEFAULT_CHECKIN_URL;
  if (off) {
    log.info(`[checkin] anonymous daily check-in is off (${off})`);
    return () => {};
  }
  log.info(`[checkin] once a day this install sends ${url} an anonymous check-in: a random install id, ` +
    'the AppCrane, Node and OS versions, and how many apps and users it has (counts only). ' +
    'Set APPCRANE_CHECKIN=off to turn it off.');
  let timer = setTimeout(function tick() {
    void sendCheckin({ version, url });
    timer = setTimeout(tick, DAY_MS);
    timer.unref();
  }, 60_000 + Math.floor(Math.random() * 10 * 60_000));
  timer.unref();
  return () => clearTimeout(timer);
}
