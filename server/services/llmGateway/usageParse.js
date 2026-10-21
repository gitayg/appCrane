import { Transform } from 'stream';
import { StringDecoder } from 'string_decoder';

// Reads token counts from provider responses. Only the usage block is looked
// at; content passes through untouched and is never kept.
//
//   Anthropic messages   usage.{input_tokens, cache_*_input_tokens, output_tokens}
//                        streamed: message_start.message.usage, then message_delta.usage
//   OpenAI chat          usage.{prompt_tokens, completion_tokens}
//                        streamed: a final chunk with usage (stream_options.include_usage)
//   OpenAI responses     usage.{input_tokens, output_tokens}
//                        streamed: response.completed.response.usage
//   OpenAI embeddings    usage.prompt_tokens

const MAX_LINE = 1024 * 1024;

function num(v) { return Number.isFinite(v) ? v : 0; }

function usageOf(obj) {
  return obj?.usage || obj?.message?.usage || obj?.response?.usage || null;
}

export class UsageCounter {
  constructor() { this.input = 0; this.output = 0; }

  take(obj) {
    const u = usageOf(obj);
    if (!u || typeof u !== 'object') return;
    const input = num(u.input_tokens ?? u.prompt_tokens) + num(u.cache_creation_input_tokens) + num(u.cache_read_input_tokens);
    const output = num(u.output_tokens ?? u.completion_tokens);
    if (input > this.input) this.input = input;
    if (output > this.output) this.output = output;
  }

  takeJsonText(text) {
    try { this.take(JSON.parse(text)); } catch { /* not JSON: nothing to count */ }
  }
}

/** A pass-through stream that counts usage from SSE `data:` lines as they go by. */
export function sseUsageTap(counter) {
  let line = '';
  let skipping = false;
  const decoder = new StringDecoder('utf8');
  const onLine = (l) => {
    if (!l.startsWith('data:') || !l.includes('"usage"')) return;
    counter.takeJsonText(l.slice(5).trim());
  };
  return new Transform({
    transform(chunk, _enc, cb) {
      const s = decoder.write(chunk);
      let start = 0;
      for (let i = 0; i < s.length; i++) {
        if (s[i] !== '\n') continue;
        if (!skipping) onLine((line + s.slice(start, i)).replace(/\r$/, ''));
        line = '';
        skipping = false;
        start = i + 1;
      }
      if (!skipping) {
        line += s.slice(start);
        if (line.length > MAX_LINE) { line = ''; skipping = true; }
      }
      cb(null, chunk);
    },
    flush(cb) {
      if (!skipping && line) onLine(line.replace(/\r$/, ''));
      cb();
    },
  });
}
