// Tiny JSON-file store. One writer (this process), atomic replace on every save.
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'fs';
import { join } from 'path';

const empty = () => ({ passes: [], device: null });

export function openStore(dataDir) {
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const file = join(dataDir, 'state.json');
  let state = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : empty();
  state.passes ||= [];
  return {
    get state() { return state; },
    save() {
      const tmp = `${file}.tmp`;
      writeFileSync(tmp, JSON.stringify(state, null, 2), { mode: 0o600 });
      renameSync(tmp, file);
    },
  };
}
