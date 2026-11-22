// AI-use records for the compliance evidence pack (evidencePack/index.js).

import { toCsv, json, scrub, periodBounds } from '../evidencePack/util.js';
import { aiInventoryCsv } from './inventory.js';
import { retentionPolicy } from './retention.js';
import { statement } from './literacy.js';

export const AI_EVIDENCE_FILES = Object.freeze([
  'AI/ai-inventory.csv', 'AI/ai-use-changes.csv', 'AI/ai-literacy-acknowledgements.csv', 'AI/llm-log-retention.json',
]);

const CHANGE_ACTIONS = ['app-ai-use-set', 'app-ai-use-change', 'app-ai-notice-change', 'ai-literacy-acknowledge', 'llm-gateway-retention-change'];

export function aiUseChanges(db, period) {
  const [from, to] = periodBounds(period);
  const rows = db.prepare(`SELECT l.id, l.created_at, l.user_id, u.username, a.slug AS app, l.action, l.detail
      FROM audit_log l LEFT JOIN users u ON u.id = l.user_id LEFT JOIN apps a ON a.id = l.app_id
      WHERE l.action IN (${CHANGE_ACTIONS.map(() => '?').join(', ')})
        AND datetime(l.created_at) >= datetime(?) AND datetime(l.created_at) < datetime(?) ORDER BY l.id`)
    .all(...CHANGE_ACTIONS, from, to);
  return toCsv(rows.map((r) => ({ ...r, detail: scrub(r.detail) })), ['id', 'created_at', 'user_id', 'username', 'app', 'action', 'detail']);
}

export function literacyAcks(db) {
  const rows = db.prepare(`SELECT k.user_id, u.username, u.kind, k.statement_version, k.statement_sha256, k.acknowledged_at
      FROM ai_literacy_acks k LEFT JOIN users u ON u.id = k.user_id ORDER BY k.acknowledged_at, k.user_id`).all();
  return toCsv(rows, ['user_id', 'username', 'kind', 'statement_version', 'statement_sha256', 'acknowledged_at']);
}

export function collectAiEvidence(db, period, put) {
  put('AI/ai-inventory.csv', aiInventoryCsv(db));
  put('AI/ai-use-changes.csv', aiUseChanges(db, period));
  put('AI/ai-literacy-acknowledgements.csv', literacyAcks(db));
  put('AI/llm-log-retention.json', json({ ...retentionPolicy(db), current_statement: statement() }));
}
