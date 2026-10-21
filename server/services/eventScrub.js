import { scrub } from './clientErrors.js';
import { sanitizeError } from './jobHealth.js';
import { redactAuditArgs } from '../utils/auditRedact.js';

// What may be written to events.summary / events.data. Both pass through the
// client-error scrubber (dhk_ keys, Bearer, JWTs, query strings, key=value
// secrets, e-mails, long hex/base64) and Job Health's sanitizeError (GitHub /
// Anthropic / AWS keys, URL credentials, paths), and data is first masked by
// key name with the audit redactor.

export const SUMMARY_MAX = 300;
export const DATA_MAX = 2000;

export function scrubText(value) {
  if (value == null) return '';
  return scrub(sanitizeError(String(value)));
}

function scrubDeep(value, depth = 0) {
  if (value == null) return value;
  if (typeof value === 'string') return scrubText(value);
  if (typeof value !== 'object') return value;
  if (depth > 6) return '[nested]';
  if (Array.isArray(value)) return value.map(v => scrubDeep(v, depth + 1));
  const out = {};
  for (const [k, v] of Object.entries(value)) out[k] = scrubDeep(v, depth + 1);
  return out;
}

export function scrubSummary(value) {
  const s = scrubText(value);
  return s.length > SUMMARY_MAX ? s.slice(0, SUMMARY_MAX - 3) + '...' : s;
}

/** JSON string for events.data, or null. Oversized payloads keep only their keys. */
export function scrubData(data) {
  if (data == null) return null;
  let value = data;
  if (typeof value === 'string') {
    try { value = JSON.parse(value); } catch { value = { text: value }; }
  }
  if (typeof value !== 'object') value = { value };
  const json = JSON.stringify(scrubDeep(redactAuditArgs(value)));
  if (json.length <= DATA_MAX) return json;
  return JSON.stringify({ truncated: true, keys: Array.isArray(value) ? [] : Object.keys(value).slice(0, 20) });
}
