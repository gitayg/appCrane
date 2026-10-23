// Preloaded with --import into a real AppCrane process by test/brotli-guard.test.js:
// records every call into node:zlib's Brotli decoder, so the test can show a
// `Content-Encoding: br` body never reaches it.
import zlib from 'node:zlib';
import { appendFileSync } from 'node:fs';

const out = process.env.BROTLI_SPY_FILE;
for (const name of ['createBrotliDecompress', 'brotliDecompress', 'brotliDecompressSync']) {
  const orig = zlib[name];
  Object.defineProperty(zlib, name, {
    configurable: true, enumerable: true, writable: false,
    value: function spied(...args) {
      appendFileSync(out, `${name}\n`);
      return orig.apply(this, args);
    },
  });
}
