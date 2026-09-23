import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Reported on a real instance: every message sent with the element picker
// failed with
//     error: unknown option '--- Pointed element ---
// The prompt followed `-p` as an ordinary argument, so the CLI's parser read a
// leading dash as a flag. Reproduced against the CLI in the studio image, which
// also showed that after `--` even a prompt of `--version` is taken as text.
// The same hole let a message such as `--mcp-config x` become a real option.
process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-promptopt-'));
process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.LOG_LEVEL = 'error';
const { runAgentExec } = await import('../server/services/llm/runAgent.js');

const PICKER = '--- Pointed element ---\nSelector: div#root > span\nTag: <span>\nchange it to gold';

for (const prompt of [PICKER, '--mcp-config /tmp/evil.json', '-v', 'an ordinary message']) {
  test(`the prompt reaches claude as text, after --: ${JSON.stringify(prompt.slice(0, 24))}`, () => {
    const jail = mkdtempSync(join(tmpdir(), 'crane-promptopt-jail-'));
    const argvLog = join(jail, 'argv');
    writeFileSync(join(jail, 'claude'), `#!/bin/sh
{ for a in "$@"; do printf '%s\\037' "$a"; done; } > "${argvLog}"
`, { mode: 0o755 });
    const cmd = runAgentExec({ containerId: 'c0', prompt, model: 'sonnet', apiKey: 'k', workdir: jail, homeDir: jail })
      .getDockerArgs().pop();
    execFileSync('/bin/sh', ['-c', cmd], { env: { PATH: `${jail}:${process.env.PATH}`, HOME: jail }, stdio: 'pipe' });

    const argv = readFileSync(argvLog, 'utf8').split('\x1f').slice(0, -1);
    assert.equal(argv[argv.length - 1], prompt, 'the prompt is not the final argument, intact');
    assert.equal(argv[argv.length - 2], '--', 'the prompt is not behind `--`, so a leading dash is parsed as a flag');
    assert.equal(argv.indexOf('--'), argv.length - 2, 'something else follows the end-of-options marker');
  });
}
