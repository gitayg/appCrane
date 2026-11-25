// License-policy findings, counted once.
//
// Every deploy records its own license check on its attestation row, so three
// apps built from one SBOM with 3 flagged components each read as 3 x deploys
// warnings. This is the deduplicated view: one finding per (app, component,
// version, license), taken from the newest signed attestation of each app/env
// (what is deployed now), with the rule that matched and how many recorded
// deploys reported it. The policy and the per-deploy rows are unchanged.

const HISTORY_ROWS = 2000;

function parse(json) {
  try { const v = JSON.parse(json); return v && typeof v === 'object' ? v : null; } catch { return null; }
}

function splitLabel(label) {
  const at = label.lastIndexOf('@');
  return at > 0 ? { component: label.slice(0, at), version: label.slice(at + 1) } : { component: label, version: null };
}

/**
 * The findings of one stored check. Rows written before v2.145.0 carry only
 * reasons ("name@version: LIC, LIC", at most 10), so those are parsed and the
 * result says when the row named more than it listed.
 * @returns {{ findings: Array<{ component: string, version: string|null, license: string, rule: string }>, complete: boolean }}
 */
export function findingsOfCheck(check) {
  if (!check || !Array.isArray(check.reasons)) return { findings: [], complete: true };
  if (Array.isArray(check.findings)) return { findings: check.findings, complete: !check.findings_truncated };
  const rule = check.status === 'fail' ? 'denied' : 'flagged';
  const findings = [];
  for (const r of check.reasons.slice(1)) {
    const m = /^(.+): (.+)$/.exec(String(r));
    if (!m || /^and \d+ under a flagged license$/.test(r)) continue;
    const { component, version } = splitLabel(m[1]);
    for (const license of m[2].split(', ')) findings.push({ component, version, license, rule });
  }
  const named = check.status === 'fail' ? (check.denied || 0) : (check.flagged || 0);
  const components = new Set(findings.map((f) => `${f.component}@${f.version}`)).size;
  return { findings, complete: components >= named };
}

function ruleDetail(f) {
  const list = f.rule === 'denied' ? 'denied' : 'flagged';
  return f.license === 'unknown'
    ? `the SBOM names no license for this component, and "unknown" is on the ${list} list`
    : `${f.license} is on the ${list} list`;
}

const keyOf = (slug, f) => JSON.stringify([slug, f.component, f.version, f.license]);

/**
 * @param {object} db
 * @param {{ appId?: number|null, slugs?: Set<string>|null }} [opts] one app, or the apps a caller may see
 * @returns {{ count: number, by_rule: Record<string, number>, findings: object[], incomplete: string[], checks_read: number }}
 */
export function licenseFindings(db, { appId = null, slugs = null } = {}) {
  const where = appId != null ? 'AND a.app_id = ?' : '';
  const args = appId != null ? [appId] : [];
  const current = db.prepare(`SELECT a.id, a.app_id, a.env, a.deployment_id, a.created_at, a.license_check_json, p.slug
    FROM deploy_attestations a JOIN apps p ON p.id = a.app_id
    WHERE a.status = 'signed' AND a.license_check_json IS NOT NULL ${where}
      AND a.id = (SELECT MAX(x.id) FROM deploy_attestations x
                  WHERE x.app_id = a.app_id AND x.env = a.env AND x.status = 'signed' AND x.license_check_json IS NOT NULL)
    ORDER BY p.slug, a.env`).all(...args).filter((r) => !slugs || slugs.has(r.slug));

  const out = new Map();
  const incomplete = [];
  for (const row of current) {
    const { findings, complete } = findingsOfCheck(parse(row.license_check_json));
    if (!complete) incomplete.push(`${row.slug}/${row.env}`);
    for (const f of findings) {
      const k = keyOf(row.slug, f);
      const e = out.get(k) || {
        app: row.slug, component: f.component, version: f.version ?? null, license: f.license, rule: f.rule, rule_detail: ruleDetail(f),
        envs: [], deploys: 0, first_seen: null, last_seen: row.created_at,
      };
      if (!e.envs.includes(row.env)) e.envs.push(row.env);
      if (row.created_at > e.last_seen) e.last_seen = row.created_at;
      out.set(k, e);
    }
  }

  if (out.size) {
    const appIds = [...new Set(current.map((r) => r.app_id))];
    const history = db.prepare(`SELECT a.created_at, a.license_check_json, p.slug FROM deploy_attestations a JOIN apps p ON p.id = a.app_id
      WHERE a.status = 'signed' AND a.license_check_json IS NOT NULL AND a.app_id IN (${appIds.map(() => '?').join(',')})
      ORDER BY a.id DESC LIMIT ${HISTORY_ROWS}`).all(...appIds);
    for (const h of history) {
      const seen = new Set();
      for (const f of findingsOfCheck(parse(h.license_check_json)).findings) {
        const k = keyOf(h.slug, f);
        const e = out.get(k);
        if (!e || seen.has(k)) continue;
        seen.add(k);
        e.deploys += 1;
        if (!e.first_seen || h.created_at < e.first_seen) e.first_seen = h.created_at;
      }
    }
  }

  const findings = [...out.values()].sort((a, b) => (a.rule === b.rule ? 0 : a.rule === 'denied' ? -1 : 1)
    || a.app.localeCompare(b.app) || a.component.localeCompare(b.component));
  const byRule = {};
  for (const f of findings) byRule[f.rule] = (byRule[f.rule] || 0) + 1;
  return { count: findings.length, by_rule: byRule, findings, incomplete, checks_read: current.length };
}
