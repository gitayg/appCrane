// License policy evaluated against one CycloneDX SBOM.
//
// Returns the release-check item shape releaseCheck.js builds with check():
// { id, label, status: 'pass'|'warn'|'fail', reasons: string[], ...extra }.
// A denied license fails, a flagged one (AGPL and "unknown" by default) warns.
// A component with no license is "unknown", never a pass: CISA asks for an
// unknown license to be stated as unknown, and a policy cannot clear what it
// cannot see. An SPDX expression counts every license it names, so
// "MIT OR AGPL-3.0-only" is flagged: which branch an app relies on is not in
// the SBOM.

import { getLicensePolicy, UNKNOWN_LICENSE } from './policy.js';

export const CHECK_ID = 'licenses';
export const LABEL = 'License policy';
const MAX_LISTED = 10;

function expressionIds(expr) {
  return String(expr).replace(/[()]/g, ' ').split(/\s+/)
    .filter((t) => t && !/^(AND|OR|WITH)$/i.test(t));
}

/** Every license id a component names, or ['unknown']. */
export function componentLicenses(c) {
  const ids = [];
  for (const l of Array.isArray(c?.licenses) ? c.licenses : []) {
    if (l?.license?.id) ids.push(String(l.license.id));
    else if (l?.license?.name) ids.push(String(l.license.name));
    else if (l?.expression) ids.push(...expressionIds(l.expression));
  }
  return ids.length ? [...new Set(ids)] : [UNKNOWN_LICENSE];
}

function walk(components, fn) {
  for (const c of components || []) {
    fn(c);
    if (Array.isArray(c.components)) walk(c.components, fn);
  }
}

function label(c) { return `${c.name || '?'}${c.version ? `@${c.version}` : ''}`; }

/**
 * @param {object} app   the apps row (slug used in reasons)
 * @param {object|null} sbom CycloneDX document
 * @param {{ denied: string[], flagged: string[] }} [policy]
 */
export function licensePolicyCheck(app, sbom, policy = getLicensePolicy()) {
  const who = app?.slug ? ` (${app.slug})` : '';
  if (!sbom || !Array.isArray(sbom.components)) {
    return { id: CHECK_ID, label: LABEL, status: 'warn', reasons: [`No SBOM for this release${who}, so its licenses were not checked`], components: 0, denied: 0, flagged: 0 };
  }
  const deny = new Set(policy.denied.map((x) => x.toLowerCase()));
  const flag = new Set(policy.flagged.map((x) => x.toLowerCase()));
  const denied = [];
  const flagged = [];
  let n = 0;
  walk(sbom.components, (c) => {
    n += 1;
    const ids = componentLicenses(c);
    const d = ids.filter((x) => deny.has(x.toLowerCase()));
    if (d.length) { denied.push(`${label(c)}: ${d.join(', ')}`); return; }
    const f = ids.filter((x) => flag.has(x.toLowerCase()));
    if (f.length) flagged.push(`${label(c)}: ${f.join(', ')}`);
  });
  const extra = { components: n, denied: denied.length, flagged: flagged.length };
  if (denied.length) {
    return { id: CHECK_ID, label: LABEL, status: 'fail', reasons: [
      `${denied.length} component(s) under a denied license${who}`, ...denied.slice(0, MAX_LISTED),
      ...(flagged.length ? [`and ${flagged.length} under a flagged license`] : []),
    ], ...extra };
  }
  if (flagged.length) {
    return { id: CHECK_ID, label: LABEL, status: 'warn', reasons: [`${flagged.length} component(s) under a flagged license${who}`, ...flagged.slice(0, MAX_LISTED)], ...extra };
  }
  return { id: CHECK_ID, label: LABEL, status: 'pass', reasons: [`${n} component(s); none under a denied or flagged license`], ...extra };
}
