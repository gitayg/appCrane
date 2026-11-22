// ── pricing: what the same tokens would cost on the Claude API ──
// Team, Max and Enterprise seats are billed per seat, so /usage on those plans
// shows plan limits rather than a bill. Pricing the transcript's own usage at
// API list rates gives a comparable dollar figure: the API-equivalent value of
// the work, not an invoice. $ per million tokens, first-party Claude API rates
// from platform.claude.com/docs/en/about-claude/pricing as of PRICES_AS_OF.
// test/fixtures/claude-pricing.json records that page's rows on the same date,
// and test/work-review-prices.test.js fails when this table and it disagree:
// update both together, from the page.
// Cache writes are priced from `in`: ×1.25 for the 5-minute TTL, ×2 for 1-hour.
// No side effects: the analyzer and the tests both import this file.
export const PRICES_AS_OF = '2026-11-17';
export const BASE_PRICES = {
  'claude-fable-5-2': { in: 8, out: 40, read: 0.2 },
  'claude-mythos-5-2': { in: 8, out: 40, read: 0.2 },
  'claude-fable-5-1': { in: 10, out: 50, read: 0.25 },
  'claude-mythos-5-1': { in: 10, out: 50, read: 0.25 },
  'claude-fable-5': { in: 10, out: 50, read: 1 },
  'claude-mythos-5': { in: 10, out: 50, read: 1 },
  'claude-opus-5-5': { in: 4, out: 20, read: 0.2 },
  'claude-opus-5': { in: 5, out: 25, read: 0.5 },
  'claude-opus-4-8': { in: 5, out: 25, read: 0.5 },
  'claude-opus-4-7': { in: 5, out: 25, read: 0.5 },
  'claude-opus-4-6': { in: 5, out: 25, read: 0.5 },
  'claude-sonnet-5-5': { in: 2, out: 10, read: 0.1 },
  'claude-sonnet-5': { in: 2, out: 10, read: 0.2 },
  'claude-sonnet-4-6': { in: 3, out: 15, read: 0.3 },
  // Haiku 5.5: prompts over 100K tokens are billed at the higher pair.
  'claude-haiku-5-5': { in: 0.1, out: 0.5, read: 0.01, longAt: 100_000, longIn: 0.5, longOut: 2.5 },
  'claude-haiku-4-5': { in: 1, out: 5, read: 0.1 },
};
// Requests pinned to US-only inference (`inference_geo`) cost 1.1× on Claude
// 4.6 and later; the default global routing costs list price.
const US_ONLY = 1.1;

/** A lookup over BASE_PRICES plus any overrides ({ "<model-id prefix>": { in, out, read } }). */
export function makePricer(overrides = {}) {
  const prices = { ...BASE_PRICES, ...overrides };
  const keys = Object.keys(prices).sort((a, b) => b.length - a.length);   // claude-opus-5-5 before claude-opus-5
  const priceFor = model => {
    const id = String(model || '').toLowerCase()
      .replace(/\[[^\]]*\]/g, '')                       // claude-opus-5-5[1m]
      .replace(/^(?:(?:us|eu|apac|global)\.)?anthropic\./, '') // Bedrock-style prefixes
      .replace(/@.*$/, '').replace(/-\d{8}$/, '').trim();    // dated snapshots
    const key = keys.find(k => id === k || id.startsWith(k + '-'));
    return key ? prices[key] : null;
  };
  /** Dollars for one message's usage, or null when the model is not priced. */
  const usdOf = (u, model) => {
    const p = priceFor(model);
    if (!p) return null;
    const fresh = u.input_tokens || 0, read = u.cache_read_input_tokens || 0, write = u.cache_creation_input_tokens || 0;
    const long = p.longAt && fresh + read + write > p.longAt;
    const rin = long ? p.longIn : p.in, rout = long ? p.longOut : p.out, rread = long ? p.longIn * (p.read / p.in) : p.read;
    const w1h = Math.min(write, u.cache_creation?.ephemeral_1h_input_tokens || 0);
    const fast = u.speed === 'fast' ? 2 : 1;   // fast mode: 2× standard on the models that offer it
    const geo = u.inference_geo === 'us' ? US_ONLY : 1;
    return fast * geo * (fresh * rin + (u.output_tokens || 0) * rout + read * rread + (write - w1h) * rin * 1.25 + w1h * rin * 2) / 1e6;
  };
  return { priceFor, usdOf };
}
