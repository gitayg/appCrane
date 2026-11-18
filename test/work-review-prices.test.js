import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { join } from 'path';

// work-review's API-list-price table (plugins/work-review/skills/work-review/scripts/prices.mjs)
// against the Claude pricing page, as recorded in test/fixtures/claude-pricing.json.
//
// Every dollar figure in a work review, and every "this would cost less on
// Sonnet" estimate, comes from this table. It had drifted: Fable 5.2 was
// missing and fell back to Fable 5's rates (5x the cache-read price), and
// Sonnet 5.5's cache reads were priced at $0.20 instead of $0.10. Most tokens
// in a Claude Code session are cache reads, so both moved real totals.

const { BASE_PRICES, PRICES_AS_OF, makePricer } = await import('../plugins/work-review/skills/work-review/scripts/prices.mjs');
const page = JSON.parse(readFileSync(join(import.meta.dirname, 'fixtures', 'claude-pricing.json'), 'utf8'));
const { priceFor, usdOf } = makePricer();
const M = 1e6;
const near = (a, b, msg) => assert.ok(Math.abs(a - b) < 1e-9, `${msg}: got ${a}, page says ${b}`);

test('the table and the recorded pricing page are from the same date and cover the same models', () => {
  assert.equal(PRICES_AS_OF, page.asOf, 'update prices.mjs and the fixture together, from the page');
  assert.deepEqual(Object.keys(BASE_PRICES).sort(), Object.keys(page.models).sort());
});

test('every model costs what the pricing page says, for each kind of token', () => {
  // Priced as ten 100K-token requests, the way they are billed: one 1M-token
  // prompt would cross Haiku 5.5's 100K line.
  const n = 10, per = M / n, each = (u, id) => n * usdOf(u, id);
  for (const [id, p] of Object.entries(page.models)) {
    near(each({ input_tokens: per }, id), p.in, `${id} input`);
    near(each({ output_tokens: per }, id), p.out, `${id} output`);
    near(each({ cache_read_input_tokens: per }, id), p.read, `${id} cache read`);
    near(each({ cache_creation_input_tokens: per }, id), p.write5m, `${id} 5-minute cache write`);
    near(each({ cache_creation_input_tokens: per, cache_creation: { ephemeral_1h_input_tokens: per } }, id), p.write1h, `${id} 1-hour cache write`);
  }
});

test('Haiku 5.5 prompts over 100K tokens use the higher rates, for every kind of token', () => {
  const hi = page.models['claude-haiku-5-5'].over100k, big = 200_000, f = M / big;
  near(f * usdOf({ input_tokens: big }, 'claude-haiku-5-5'), hi.in, 'input over 100K');
  near(f * usdOf({ input_tokens: 0, cache_read_input_tokens: big }, 'claude-haiku-5-5'), hi.read, 'cache read over 100K');
  near(f * usdOf({ cache_creation_input_tokens: big }, 'claude-haiku-5-5'), hi.write5m, '5-minute write over 100K');
  near(usdOf({ input_tokens: big, output_tokens: M }, 'claude-haiku-5-5') - usdOf({ input_tokens: big }, 'claude-haiku-5-5'), hi.out, 'output on a prompt over 100K');
});

test('fast mode and US-only inference apply their multipliers; ids resolve to the right row', () => {
  near(usdOf({ input_tokens: M, speed: 'fast' }, 'claude-opus-5-5'), 4 * page.multipliers.fastMode, 'fast mode');
  near(usdOf({ input_tokens: M, inference_geo: 'us' }, 'claude-opus-5-5'), 4 * page.multipliers.usOnlyInference, 'US-only inference');
  near(usdOf({ input_tokens: M, inference_geo: 'global' }, 'claude-opus-5-5'), 4, 'global routing is list price');
  assert.equal(priceFor('claude-fable-5-2').in, 8, 'Fable 5.2 is not priced as Fable 5');
  assert.equal(priceFor('claude-opus-5').in, 5, 'Opus 5 is not priced as Opus 5.5');
  assert.equal(priceFor('claude-opus-5-5[1m]').in, 4);
  assert.equal(priceFor('us.anthropic.claude-sonnet-5-5').read, 0.1);
  assert.equal(priceFor('some-future-model'), null, 'an unknown model is never guessed');
});
