import { findSecret } from '../crewSecrets.js';
import { isEnvFile, scannable } from './projectFiles.js';
import { fileSide, BUNDLED_SIDES } from './side.js';

// Hardcoded credentials in the imported source. Findings carry the file, line,
// rule and a masked preview; the value itself never leaves this module.

export function mask(value) {
  const s = String(value || '');
  return s.length <= 8 ? '****' : `${s.slice(0, 4)}****${s.slice(-2)}`;
}

/** Decode a JWT payload without verifying it, or null. */
export function jwtPayload(token) {
  const parts = String(token).split('.');
  if (parts.length !== 3) return null;
  try {
    const json = Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const obj = JSON.parse(json);
    return obj && typeof obj === 'object' ? obj : null;
  } catch { return null; }
}

const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
const EXTRA_RULES = [
  { id: 'supabase-secret-key', re: /\bsb_secret_[A-Za-z0-9_-]{16,}/g, serverOnly: true, title: 'Supabase secret key' },
  { id: 'supabase-publishable-key', re: /\bsb_publishable_[A-Za-z0-9_-]{16,}/g, publicByDesign: true, title: 'Supabase publishable key' },
  { id: 'stripe-live-secret', re: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}/g, serverOnly: true, title: 'Live secret key (sk_live_, Stripe or Clerk)' },
  { id: 'stripe-test-secret', re: /\b(?:sk|rk)_test_[A-Za-z0-9]{16,}/g, serverOnly: true, title: 'Test secret key (sk_test_, Stripe or Clerk)', test: true },
  { id: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, publicByDesign: true, title: 'Google / Firebase API key' },
];
const CREW_TITLES = {
  'private-key': 'Private key', 'aws-access-key': 'AWS access key id', 'appcrane-key': 'AppCrane API key',
  'github-token': 'GitHub token', 'anthropic-key': 'Anthropic API key', 'openai-key': 'OpenAI API key',
  'slack-token': 'Slack token', 'bearer-token': 'Bearer token',
};

function severityFor({ serverOnly, publicByDesign, test }, side) {
  if (publicByDesign) return 'info';
  if (serverOnly && side === 'client') return test ? 'high' : 'critical';
  if (serverOnly && BUNDLED_SIDES.has(side)) return test ? 'medium' : 'high';
  return test ? 'low' : 'high';
}

/**
 * Scan every text file except real .env files (those are the user's own
 * secret store, handled as env values instead) and return findings.
 */
export function scanSecrets(files, project) {
  const findings = [];
  const seen = new Set();
  const add = (f) => {
    const k = `${f.path}:${f.line}:${f.rule}`;
    if (seen.has(k)) return;
    seen.add(k);
    findings.push(f);
  };
  for (const [path, text] of scannable(files)) {
    if (isEnvFile(path)) continue;
    const side = fileSide(path, text, project);
    const lines = text.split('\n');
    lines.forEach((line, i) => {
      if (line.length > 5000) return;
      for (const m of line.matchAll(JWT_RE)) {
        const payload = jwtPayload(m[0]);
        const role = payload?.role;
        const isSupabase = payload?.iss === 'supabase' || /supabase/.test(String(payload?.iss || '')) || typeof payload?.ref === 'string';
        if (role === 'service_role') {
          add({
            rule: 'supabase-service-role-key', title: 'Supabase service-role key', path, line: i + 1, side, preview: mask(m[0]),
            severity: severityFor({ serverOnly: true }, side),
            detail: side === 'client'
              ? 'A service-role key in client code is shipped to every visitor and bypasses Row Level Security on the whole database. Rotate it in Supabase now and move server work behind a server route.'
              : 'Service-role key committed in source. Move it to an AppCrane secret and rotate it in Supabase.',
          });
        } else if (role === 'anon' && isSupabase) {
          add({
            rule: 'supabase-anon-key', title: 'Supabase anon key', path, line: i + 1, side, preview: mask(m[0]), severity: 'info',
            detail: 'Public by design, but hardcoded. Anyone with it can call your Supabase API, so the data is only as safe as its Row Level Security policies. Prefer an env var so the sandbox can point at a different project.',
          });
        }
      }
      for (const r of EXTRA_RULES) {
        r.re.lastIndex = 0;
        for (const m of line.matchAll(r.re)) {
          add({
            rule: r.id, title: r.title, path, line: i + 1, side, preview: mask(m[0]),
            severity: severityFor(r, side),
            detail: r.publicByDesign
              ? 'Public by design; restrict it at the provider (allowed origins, Row Level Security or API restrictions).'
              : side === 'client'
                ? 'A server-only secret in client code is published to every visitor. Rotate it and move the call to a server route.'
                : 'Secret committed in source. Move it to an AppCrane secret and rotate it.',
          });
        }
      }
      const crew = findSecret(line);
      if (crew) {
        add({
          rule: crew, title: CREW_TITLES[crew] || crew, path, line: i + 1, side, preview: '****',
          severity: side === 'client' ? 'critical' : 'high',
          detail: 'Credential committed in source. Rotate it and move it to an AppCrane secret.',
        });
      }
    });
  }
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return findings.sort((a, b) => order[a.severity] - order[b.severity] || a.path.localeCompare(b.path) || a.line - b.line);
}
