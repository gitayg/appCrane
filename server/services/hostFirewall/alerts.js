import { createHash } from 'node:crypto';
import { getDb } from '../../db.js';
import { enqueueEmail } from '../emailQueue.js';
import { dashboardBaseUrl } from '../vulnRequests.js';
import { BRAND, bulletList, renderBrandedEmail } from '../mail/brandedLayout.js';
import log from '../../utils/logger.js';

export const MAIL_SOURCE = 'host-network';
const DAY_MS = 24 * 60 * 60_000;
const MAILED = new Set(['high', 'medium']);

function admins(db) {
  return db.prepare(`SELECT email FROM users WHERE role = 'platform_admin' AND active = 1
                     AND email IS NOT NULL AND trim(email) != ''`).all().map((r) => r.email);
}

export function findingSetKey(findings) {
  const ids = findings.filter(f => MAILED.has(f.severity)).map(f => f.id).sort();
  if (!ids.length) return null;
  return createHash('sha256').update(ids.join('\n')).digest('hex').slice(0, 16);
}

/**
 * Mail every platform admin once per distinct set of high/medium findings per
 * day. The key is stored as the queue row's idempotency key and checked here,
 * because the queue's own unique index does not cover rows with no app.
 */
export function mailPostureFindings(posture, { db = getDb(), now = Date.now() } = {}) {
  const findings = (posture?.findings || []).filter(f => MAILED.has(f.severity));
  const set = findingSetKey(findings);
  if (!set) return [];
  const day = Math.floor(now / DAY_MS);
  const lines = findings.map(f => `${f.severity.toUpperCase()}: ${f.message}${f.fix ? ` Fix: ${f.fix}` : ''}`);
  const subject = `[AppCrane] Host network: ${findings.length} finding${findings.length === 1 ? '' : 's'} to fix`;
  const intro = 'AppCrane checked this server\'s firewall and found the following.';
  const sent = [];
  for (const to of admins(db)) {
    const key = `host-network:${set}:${day}:${to.trim().toLowerCase()}`;
    if (db.prepare('SELECT 1 FROM email_queue WHERE source = ? AND idempotency_key = ?').get(MAIL_SOURCE, key)) continue;
    try {
      enqueueEmail({
        to, subject, appId: null, source: MAIL_SOURCE,
        text: `${intro}\n\n${lines.join('\n\n')}\n\nSee Settings > Job Health > Host network.\n`,
        html: renderBrandedEmail({
          preheader: lines[0], greeting: 'Hi,', intro,
          bodyHtml: bulletList(lines)
            + `<p style="margin:12px 0 0;font-size:13px;color:${BRAND.dim};">The full picture is in Settings &gt; Job Health &gt; Host network.</p>`,
          cta: { label: 'Open Job Health', url: `${dashboardBaseUrl()}/settings#jobs` },
          footer: 'You get this because you are a platform admin of this AppCrane.',
        }),
        idempotencyKey: key,
      });
      sent.push(to);
    } catch (e) {
      log.warn(`[host-network] alert to ${to} skipped: ${e.message}`);
    }
  }
  return sent;
}
