import { getDb } from '../../db.js';
import { getCampaign } from './campaigns.js';
import { getPolicy } from './policy.js';

// The campaign report: what was reviewed, by whom, what was decided. JSON for
// machines, CSV for auditors.

export const CSV_COLUMNS = Object.freeze([
  'campaign_id', 'campaign_name', 'campaign_status', 'started_at', 'due_at', 'review_id', 'review_kind',
  'app_slug', 'app_name', 'data_classification', 'reviewers', 'user_id', 'user_name', 'user_email', 'role',
  'granted_via', 'last_access_at', 'decision', 'new_role', 'decided_by', 'decided_by_name', 'decided_at', 'note',
]);

export function campaignReport(db, id) {
  const campaign = getCampaign(db, id);
  if (!campaign) return null;
  const reviews = db.prepare('SELECT * FROM access_reviews WHERE campaign_id = ? ORDER BY id').all(id).map(r => ({
    ...r,
    reviewers: db.prepare(`SELECT rv.user_id, u.name, u.email FROM access_review_reviewers rv LEFT JOIN users u ON u.id = rv.user_id
                            WHERE rv.review_id = ? ORDER BY rv.user_id`).all(r.id),
    items: db.prepare(`SELECT i.*, d.name AS decided_by_name FROM access_review_items i LEFT JOIN users d ON d.id = i.decided_by
                        WHERE i.review_id = ? ORDER BY i.id`).all(r.id),
  }));
  return { campaign, reviews };
}

function cell(v) {
  if (v == null) return '';
  let s = String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function reportRows(report) {
  const c = report.campaign;
  const rows = [];
  for (const r of report.reviews) {
    const reviewers = r.reviewers.map(x => x.name || `#${x.user_id}`).join('; ');
    for (const i of r.items) {
      rows.push({
        campaign_id: c.id, campaign_name: c.name, campaign_status: c.status, started_at: c.started_at, due_at: c.due_at,
        review_id: r.id, review_kind: r.kind, app_slug: r.app_slug, app_name: r.app_name, data_classification: r.data_classification,
        reviewers, user_id: i.user_id, user_name: i.user_name, user_email: i.user_email, role: i.role, granted_via: i.granted_via,
        last_access_at: i.last_access_at, decision: i.decision || 'unreviewed', new_role: i.new_role, decided_by: i.decided_by,
        decided_by_name: i.decided_by_name, decided_at: i.decided_at, note: i.note,
      });
    }
  }
  return rows;
}

export function toCsv(rows) {
  return [CSV_COLUMNS.join(','), ...rows.map(r => CSV_COLUMNS.map(k => cell(r[k])).join(','))].join('\n') + '\n';
}

export function campaignCsv(db, id) {
  const report = campaignReport(db, id);
  return report ? toCsv(reportRows(report)) : null;
}

/**
 * Evidence for an audit period: every campaign started in [from, to] (dates or
 * SQLite timestamps), with its reviews and decisions, plus the same as CSV.
 */
export function getAccessReviewEvidence({ from = null, to = null } = {}, db = getDb()) {
  const lo = from ? String(from).replace('T', ' ').slice(0, 19) : '0000-01-01';
  const hi = to ? (String(to).length <= 10 ? `${to} 23:59:59` : String(to).replace('T', ' ').slice(0, 19)) : '9999-12-31';
  const ids = db.prepare('SELECT id FROM access_review_campaigns WHERE started_at >= ? AND started_at <= ? ORDER BY id').all(lo, hi).map(r => r.id);
  const campaigns = ids.map(id => campaignReport(db, id));
  return {
    generated_at: new Date().toISOString(),
    from, to,
    policy: getPolicy(db),
    campaigns,
    csv: toCsv(campaigns.flatMap(reportRows)),
  };
}
