// Minimal, strict unified-diff applier for the pure-MCP managed_patch tool.
// Intentionally conservative: it matches each hunk's context/deletion lines
// against the file by CONTENT (not just by the @@ line numbers, which drift),
// and throws loudly if a hunk doesn't apply cleanly. A thrown error means no
// commit is made — far better than silently landing a corrupted file. There is
// no fuzz/offset guessing beyond an exact-match search, on purpose.

function splitLines(text) {
  const hadTrailingNewline = text.endsWith('\n');
  // Normalize CRLF the way git stores it isn't our job; we operate on the raw
  // bytes the repo returned. Split on \n and, if the file ended with a newline,
  // drop the empty trailing element so `lines` is the content lines only.
  const lines = text.length === 0 ? [] : text.split('\n');
  if (hadTrailingNewline) lines.pop();
  return { lines, hadTrailingNewline };
}

function parseHunks(diffText) {
  const raw = diffText.split('\n');
  const hunks = [];
  let current = null;
  for (const line of raw) {
    if (line.startsWith('@@')) {
      const m = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(line);
      if (!m) throw new Error(`malformed hunk header: ${line}`);
      current = {
        oldStart: parseInt(m[1], 10),
        oldLen: m[2] === undefined ? 1 : parseInt(m[2], 10),
        newStart: parseInt(m[3], 10),
        newLen: m[4] === undefined ? 1 : parseInt(m[4], 10),
        oldLines: [],
        newLines: [],
      };
      hunks.push(current);
      continue;
    }
    if (!current) {
      // Header noise before the first hunk: ---/+++/diff --git/index lines.
      continue;
    }
    if (line.length === 0) {
      // A bare empty line inside a hunk represents a context blank line.
      current.oldLines.push('');
      current.newLines.push('');
      continue;
    }
    const tag = line[0];
    const rest = line.slice(1);
    if (tag === ' ') { current.oldLines.push(rest); current.newLines.push(rest); }
    else if (tag === '-') { current.oldLines.push(rest); }
    else if (tag === '+') { current.newLines.push(rest); }
    else if (tag === '\\') { /* "\ No newline at end of file" — ignore */ }
    else throw new Error(`unexpected line in hunk (must start with ' ', '-', '+' or '\\'): ${line}`);
  }
  if (hunks.length === 0) throw new Error('no hunks found in unified_diff');
  return hunks;
}

function blockMatchesAt(lines, block, idx) {
  if (idx < 0 || idx + block.length > lines.length) return false;
  for (let i = 0; i < block.length; i++) {
    if (lines[idx + i] !== block[i]) return false;
  }
  return true;
}

// Apply a unified diff to `original` text, returning the patched text.
// Throws if any hunk does not match cleanly.
export function applyUnifiedDiff(original, diffText) {
  if (typeof original !== 'string') throw new Error('original must be a string');
  if (typeof diffText !== 'string' || diffText.trim() === '') throw new Error('unified_diff is empty');

  const hunks = parseHunks(diffText);
  const { lines, hadTrailingNewline } = splitLines(original);

  // Running offset between the hunk's declared old line numbers and the current
  // (already-patched) array. Hunks are applied left-to-right.
  let offset = 0;
  for (let h = 0; h < hunks.length; h++) {
    const hunk = hunks[h];
    const block = hunk.oldLines;

    let at;
    if (block.length === 0) {
      // Pure insertion with no context. Insert at the declared position.
      at = Math.max(0, Math.min(lines.length, hunk.oldStart - 1 + offset + (hunk.oldStart === 0 ? 1 : 0)));
    } else {
      const expected = hunk.oldStart - 1 + offset;
      if (blockMatchesAt(lines, block, expected)) {
        at = expected;
      } else {
        // Full scan for an exact content match; prefer the one closest to the
        // diff's declared position (handles duplicate blocks + line drift).
        at = -1;
        let bestDist = Infinity;
        for (let i = 0; i + block.length <= lines.length; i++) {
          if (blockMatchesAt(lines, block, i)) {
            const dist = Math.abs(i - expected);
            if (dist < bestDist) { bestDist = dist; at = i; }
          }
        }
        if (at === -1) {
          throw new Error(
            `hunk #${h + 1} (@@ -${hunk.oldStart},${hunk.oldLen} +${hunk.newStart},${hunk.newLen} @@) ` +
            `did not match the current file content — the file may have changed since the diff was generated, ` +
            `or the context lines are wrong. Re-read the file and regenerate the diff.`
          );
        }
      }
    }

    lines.splice(at, block.length, ...hunk.newLines);
    offset += hunk.newLines.length - block.length;
  }

  let out = lines.join('\n');
  if (hadTrailingNewline && out.length > 0) out += '\n';
  return out;
}
