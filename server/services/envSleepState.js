import { getDb } from '../db.js';

// Sleep state of an app environment (env_sleep). Synchronous and free of Docker
// so the readers that must not react to a stopped-on-purpose container — the
// health checker, container recovery, the cron scheduler, docker.startApp — can
// ask without an import cycle.
//
// 'sleeping' and 'waking' both mean "AppCrane stopped this on purpose and owns
// starting it again". A missing row is 'awake'.

export function sleepRow(db, appId, env) {
  return db.prepare('SELECT * FROM env_sleep WHERE app_id = ? AND env = ?').get(appId, env) || null;
}

export function sleepStateOf(db, appId, env) {
  return sleepRow(db, appId, env)?.state || 'awake';
}

export function envIsSleepingById(appId, env, db = getDb()) {
  const s = sleepStateOf(db, appId, env);
  return s === 'sleeping' || s === 'waking';
}

export function envIsSleeping(slug, env, db = getDb()) {
  try {
    const row = db.prepare(`SELECT s.state FROM env_sleep s JOIN apps a ON a.id = s.app_id
                            WHERE a.slug = ? AND s.env = ?`).get(slug, env);
    return row?.state === 'sleeping' || row?.state === 'waking';
  } catch (_) {
    return false;
  }
}

export function setSleepState(db, appId, env, fields) {
  const cols = Object.keys(fields);
  db.prepare(`INSERT INTO env_sleep (app_id, env, ${cols.join(', ')}) VALUES (?, ?, ${cols.map(() => '?').join(', ')})
              ON CONFLICT(app_id, env) DO UPDATE SET ${cols.map(c => `${c} = excluded.${c}`).join(', ')}`)
    .run(appId, env, ...cols.map(c => fields[c]));
}

/**
 * A container was (re)created or restarted by something other than a wake — a
 * deploy, a rollback, container recovery, a manual restart. Whatever slept, the
 * env is awake now.
 */
export function markAwakeBySlug(slug, env, wakeReason, db = getDb()) {
  try {
    db.prepare(`UPDATE env_sleep SET state = 'awake', woke_at = datetime('now'), wake_reason = ?, last_error = NULL
                WHERE env = ? AND state != 'awake' AND app_id = (SELECT id FROM apps WHERE slug = ?)`)
      .run(wakeReason, env, slug);
  } catch (_) { /* sleep bookkeeping never fails a container start */ }
}
