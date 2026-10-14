// One rule for apps.frame_ancestors, shared by every writer and by the
// Caddyfile generator. The value lands inside a quoted header directive in the
// Caddyfile, so a quote, brace, newline or `{placeholder}` in it rewrites the
// live proxy config — and a malformed one fails every later reload, for every
// app. The REST route validated it; the MCP update tool stored String(value)
// as-is, and the generator trusted the column.

const CHARSET_RE = /^[A-Za-z0-9 _.\-:/'*]+$/;
const TOKEN_RE = /^('self'|'none'|https?:\/\/(\*\.)?[a-z0-9.\-]+(:\d+)?)$/i;
const MAX_LEN = 512;

/** Normalised value, null to clear, or throws Error with an operator-readable message. */
export function normalizeFrameAncestors(value) {
  if (value === null || value === undefined || value === '') return null;
  const v = String(value).trim();
  if (!CHARSET_RE.test(v)) throw new Error('frame_ancestors contains invalid characters');
  if (v.length > MAX_LEN) throw new Error(`frame_ancestors too long (max ${MAX_LEN} chars)`);
  const tokens = v.split(/\s+/).filter(Boolean);
  const bad = tokens.find((t) => !TOKEN_RE.test(t));
  if (bad) throw new Error(`frame_ancestors token "${bad}" is not a valid CSP source`);
  return tokens.join(' ');
}

/** For the generator: a stored value that would not pass today is ignored, not emitted. */
export function safeFrameAncestors(value) {
  try { return normalizeFrameAncestors(value); } catch { return null; }
}
