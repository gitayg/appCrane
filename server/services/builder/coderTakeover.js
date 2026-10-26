import { getDb } from '../../db.js';
import { preserveThenEvict } from './appContainer.js';

// One app, one coder container, so one live session at a time. Before v2.111.0
// a second user met BUILDER_OCCUPIED for as long as the first user's session
// was idle — up to the 30-minute idle sweep, and with nothing in the panel to
// do about it. Every coder user is the app's owner or a platform admin
// (routes/coder.js gates the whole router on that), so either may take the
// coder over from the other, on these terms:
//
//  - never mid-turn: a session that is starting, running or has a turn queued
//    keeps the container (BUILDER_BUSY);
//  - never at the cost of work: the holder's unreleased changes are committed
//    to agent/<userId>/<sessionId> before the container is reused, and a rescue
//    that fails leaves their session exactly as it was;
//  - never silently: the holder's transcript says who took over and where
//    their work went, and their open panel is told at once.

export function holderName(row) {
  return row.user_name || row.user_username || `user ${row.user_id}`;
}

function takerName(userId) {
  const u = getDb().prepare('SELECT name, username FROM users WHERE id = ?').get(userId);
  return u?.name || u?.username || `user ${userId}`;
}

function busyError(message) {
  const err = new Error(message);
  err.code = 'BUILDER_BUSY';
  return err;
}

/**
 * Take the app's coder over from `holder` (the other user's live session row).
 * `turnRunning` is the in-memory answer builderSession holds; the DB statuses
 * are checked as well. Throws BUILDER_BUSY or TAKEOVER_FAILED and changes
 * nothing; on success the holder's session is paused and notified.
 */
export function takeOverAppCoder({ slug, userId, holder, turnRunning, notify }) {
  const who = holderName(holder);
  const inFlight = getDb().prepare(
    "SELECT 1 FROM coder_sessions WHERE app_slug = ? AND user_id != ? AND status IN ('starting', 'active', 'queued') LIMIT 1",
  ).get(slug, userId);
  if (turnRunning || inFlight) {
    throw busyError(`${who} has a coder turn running on this app. You can take over once it finishes.`);
  }

  let preserved;
  try {
    preserved = preserveThenEvict(slug, { id: holder.id, user_id: holder.user_id }, `takeover:${userId}`);
  } catch (err) {
    if (err.code === 'BUILDER_BUSY') throw busyError(`${who} has a coder turn running on this app. You can take over once it finishes.`);
    const e = new Error(`${who}'s unreleased work could not be saved, so their session was left as it was: ${err.message}`);
    e.code = 'TAKEOVER_FAILED';
    throw e;
  }

  // The evict hook pauses the sessions it holds in memory; a row that says idle
  // without one (it cannot be resumed into anything) is paused here too.
  getDb().prepare(
    "UPDATE coder_sessions SET status = 'paused', container_id = NULL WHERE app_slug = ? AND user_id != ? AND status = 'idle'",
  ).run(slug, userId);

  const saved = preserved?.preserved
    ? `Your unreleased changes were saved on the branch ${preserved.branch} in this app's repository.`
    : 'You had no unreleased changes, so nothing needed saving.';
  const envNote = preserved?.skippedEnvFiles?.length
    ? ` Environment files are never committed, so ${preserved.skippedEnvFiles.join(', ')} were not saved.`
    : '';
  notify(holder.id, `${takerName(userId)} took over this app's coder, so this session was paused. ${saved}${envNote}`);
  return preserved;
}
