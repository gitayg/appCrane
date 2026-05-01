// Single Anthropic SDK helper for non-tool-using LLM calls.
// All callers go through here so the client init, model defaults, prompt
// caching policy, cost math, and retry/timeout behavior live in one place.
//
// Use this for: planner (JSON extraction), codebase summary, classification,
// short Q&A. For anything that needs to read/write files or run shell, use
// runAgent.js (the CLI-in-Docker substrate) instead.

import Anthropic from '@anthropic-ai/sdk';

const DEFAULT_MODEL = process.env.APPSTUDIO_PLANNER_MODEL || 'claude-sonnet-4-6';

let _client = null;
function client() {
  if (!_client) {
    if (!process.env.ANTHROPIC_API_KEY) throw new Error('ANTHROPIC_API_KEY not set');
    _client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
  }
  return _client;
}

// Drop the cached client — call this when ANTHROPIC_API_KEY changes at runtime
// (e.g. via PUT /api/appstudio/anthropic-key) so subsequent calls pick up the
// new key. Safe to call when no client has been built yet.
export function resetClient() { _client = null; }

// Sonnet 4.6 list pricing as of Apr 2026 (USD per 1M tokens).
// Bump in one place when models or pricing change.
const PRICING = {
  'claude-sonnet-4-6':   { input: 3,  output: 15 },
  'claude-opus-4-7':     { input: 15, output: 75 },
  'claude-haiku-4-5':    { input: 1,  output: 5  },
};

function priceFor(model) {
  const exact = PRICING[model];
  if (exact) return exact;
  if (model?.startsWith('claude-opus'))   return PRICING['claude-opus-4-7'];
  if (model?.startsWith('claude-haiku'))  return PRICING['claude-haiku-4-5'];
  return PRICING['claude-sonnet-4-6'];
}

export function usdCost(usage, model) {
  const p = priceFor(model);
  const tokIn  = (usage?.input_tokens || 0) + (usage?.cache_read_input_tokens || 0) + (usage?.cache_creation_input_tokens || 0);
  const tokOut =  usage?.output_tokens || 0;
  return ((tokIn * p.input) + (tokOut * p.output)) / 1_000_000;
}

// Normalize the system field — accepts a string (auto-wraps with ephemeral
// cache_control), an already-formed array of system blocks, or undefined.
function normalizeSystem(system) {
  if (system == null) return undefined;
  if (typeof system === 'string') {
    return [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }];
  }
  return system;
}

// One-shot, non-streaming. Use when you don't need token-by-token output.
// Returns { text, usage, costUsd }.
export async function complete({
  prompt,
  system,
  messages,
  model = DEFAULT_MODEL,
  maxTokens = 2048,
}) {
  if (!prompt && !messages) throw new Error('oneShot.complete: prompt or messages required');
  const msg = await client().messages.create({
    model,
    max_tokens: maxTokens,
    ...(normalizeSystem(system) ? { system: normalizeSystem(system) } : {}),
    messages: messages || [{ role: 'user', content: prompt }],
  });
  const text = msg.content.find(b => b.type === 'text')?.text || '';
  return { text, usage: msg.usage, costUsd: usdCost(msg.usage, model) };
}

// Streaming variant. Calls onChunk(fullTextSoFar) for every text delta and
// onTokens(totalTokensSoFar) when usage updates. Returns the final
// { text, usage, costUsd } once the stream completes.
export async function stream({
  prompt,
  system,
  messages,
  model = DEFAULT_MODEL,
  maxTokens = 4096,
  onChunk,
  onTokens,
}) {
  if (!prompt && !messages) throw new Error('oneShot.stream: prompt or messages required');
  const s = client().messages.stream({
    model,
    max_tokens: maxTokens,
    ...(normalizeSystem(system) ? { system: normalizeSystem(system) } : {}),
    messages: messages || [{ role: 'user', content: prompt }],
  });

  let text = '';
  let tokensIn = 0;
  let tokensOut = 0;

  for await (const ev of s) {
    if (ev.type === 'message_start' && ev.message?.usage) {
      tokensIn = ev.message.usage.input_tokens || 0;
      onTokens?.(tokensIn + tokensOut);
    } else if (ev.type === 'message_delta' && ev.usage) {
      tokensOut = ev.usage.output_tokens || 0;
      onTokens?.(tokensIn + tokensOut);
    } else if (ev.type === 'content_block_delta' && ev.delta?.type === 'text_delta') {
      text += ev.delta.text;
      onChunk?.(text);
    }
  }

  const final = await s.finalMessage();
  return { text, usage: final.usage, costUsd: usdCost(final.usage, model) };
}

// Convenience: extract the first ```json fenced block from a text body,
// falling back to the largest {...} substring. Used by planner-style callers.
export function extractJsonBlock(text) {
  const fenced = text.match(/```json\s*([\s\S]*?)```/);
  const candidate = (fenced ? fenced[1] : text).trim();
  try { return JSON.parse(candidate); } catch (_) {}
  const first = candidate.indexOf('{');
  const last  = candidate.lastIndexOf('}');
  if (first >= 0 && last > first) {
    try { return JSON.parse(candidate.slice(first, last + 1)); } catch (_) {}
  }
  return null;
}
