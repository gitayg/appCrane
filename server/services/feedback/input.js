// Validation for appcrane_submit_feedback. callTool does not enforce the
// input schema, so the handler does: unknown keys are refused at both levels
// (a free-form context object would be a channel for anything an agent has
// in memory), oversized fields are refused rather than silently cut, except
// error text, which is capped because a tool's error output is often long and
// a report should not fail over it.

export const KINDS = ['bug', 'feature', 'other'];
export const ENVS = ['sandbox', 'production'];
export const MESSAGE_MAX = 4000;
export const ERROR_MAX = 4096;
export const CONTEXT_LIMITS = Object.freeze({ tool: 100, task: 1000, deploy_id: 64, client: 200 });

const TOP_KEYS = new Set(['message', 'kind', 'slug', 'env', 'stage', 'context']);
const CONTEXT_KEYS = new Set([...Object.keys(CONTEXT_LIMITS), 'error']);

export class FeedbackInputError extends Error {}

const refuse = (msg) => { throw new FeedbackInputError(`Invalid feedback: ${msg}`); };

// Control characters other than newline and tab never reach the stored text.
const clean = (s) => String(s).replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, '').trim();

function boundedString(name, value, max) {
  if (typeof value !== 'string') refuse(`${name} must be a string`);
  const s = clean(value);
  if (s.length > max) refuse(`${name} is ${s.length} characters, over the ${max}-character limit`);
  return s;
}

function normalizeContext(raw) {
  if (raw == null) return {};
  if (typeof raw !== 'object' || Array.isArray(raw)) refuse('context must be an object');
  const extra = Object.keys(raw).filter((k) => !CONTEXT_KEYS.has(k));
  if (extra.length) refuse(`unknown context field(s): ${extra.join(', ')}. Allowed: ${[...CONTEXT_KEYS].join(', ')}`);
  const out = {};
  for (const [k, max] of Object.entries(CONTEXT_LIMITS)) {
    if (raw[k] == null) continue;
    const v = k === 'deploy_id' && Number.isInteger(raw[k]) ? String(raw[k]) : raw[k];
    const s = boundedString(`context.${k}`, v, max);
    if (s) out[k] = s;
  }
  if (raw.error != null) {
    if (typeof raw.error !== 'string') refuse('context.error must be a string');
    const s = clean(raw.error);
    if (s) out.error = s.length > ERROR_MAX ? `${s.slice(0, ERROR_MAX)} [cut]` : s;
  }
  return out;
}

/**
 * The tool's arguments, checked and trimmed. callTool mirrors env into stage
 * (and back), so both names arrive; stage is accepted only as that echo.
 */
export function normalizeFeedbackArgs(args) {
  if (args == null || typeof args !== 'object' || Array.isArray(args)) refuse('arguments must be an object');
  const extra = Object.keys(args).filter((k) => !TOP_KEYS.has(k));
  if (extra.length) refuse(`unknown field(s): ${extra.join(', ')}`);
  if (args.message == null) refuse('message is required');
  const message = boundedString('message', args.message, MESSAGE_MAX);
  if (!message) refuse('message is empty');
  const kind = args.kind == null ? 'bug' : args.kind;
  if (!KINDS.includes(kind)) refuse(`kind must be one of ${KINDS.join(', ')}`);
  const env = args.env ?? args.stage ?? null;
  if (env != null && !ENVS.includes(env)) refuse(`env must be one of ${ENVS.join(', ')}`);
  if (args.env != null && args.stage != null && args.env !== args.stage) refuse('env and stage disagree');
  let slug = null;
  if (args.slug != null) {
    slug = boundedString('slug', args.slug, 100);
    if (!slug) slug = null;
  }
  return { message, kind, env, slug, context: normalizeContext(args.context) };
}
