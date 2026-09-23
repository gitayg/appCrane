import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Measured on a real instance, first message to a coder:
//   AppStudio context BUILD for tiny-barons @ undefined
//   Builder: ensureCodebaseContext failed for tiny-barons: Agent exited with code 1
// Three separate faults:
//   1. host git refused the container-owned workspace ("dubious ownership"),
//      so the summary had no commit (never cached) and an empty file tree;
//   2. it ran on the platform key although the user runs on their own token;
//   3. the CLI printed why it failed on stdout, and the error dropped it.
const ROOT = mkdtempSync(join(tmpdir(), 'crane-ctxreal-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.LOG_LEVEL = 'error';
process.env.ANTHROPIC_API_KEY = 'sk-ant-platform-key-for-test';
// git's own switch for "this repository belongs to someone else".
process.env.GIT_TEST_ASSUME_DIFFERENT_OWNER = '1';

const BIN = join(ROOT, 'bin');
const ARGV = join(ROOT, 'docker-argv');
mkdirSync(BIN, { recursive: true });
writeFileSync(join(BIN, 'docker'), `#!/bin/sh
case "$1" in
  image) echo 4 ; exit 0 ;;
  run)
    { for a in "$@"; do printf '%s\\037' "$a"; done; } > "${ARGV}"
    printf '%s\\n' '{"type":"assistant","message":{"content":[{"type":"text","text":"Your credit balance is too low to access the Anthropic API."}]}}'
    printf '%s\\n' '{"type":"result","is_error":true,"usage":{}}'
    exit 1 ;;
esac
exit 0
`, { mode: 0o755 });
process.env.PATH = `${BIN}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const { setUserClaudeToken } = await import('../server/services/userClaudeToken.js');
const { ensureCodebaseContext } = await import('../server/services/appstudio/contextBuilder.js');

const userId = db.prepare("INSERT INTO users (name,email,role,api_key_hash,active,kind) VALUES ('u','u@x','platform_admin','h',1,'human')")
  .run().lastInsertRowid;
const USER_TOKEN = 'sk-ant-oat01-' + 'x'.repeat(95);
setUserClaudeToken(userId, USER_TOKEN);

const repo = mkdtempSync(join(ROOT, 'ws-'));
const git = (...a) => execFileSync('git', ['-c', `safe.directory=${repo}`, '-C', repo, ...a], { stdio: 'pipe' });
git('init', '-q');
writeFileSync(join(repo, 'server.js'), 'console.log(1)\n');
git('add', '.');
git('-c', 'user.email=a@b', '-c', 'user.name=a', 'commit', '-q', '-m', 'seed');

test('the codebase summary reads a container-owned workspace, runs as the user, and says why it failed', async () => {
  assert.throws(() => execFileSync('git', ['-C', repo, 'rev-parse', 'HEAD'], { stdio: 'pipe' }), /dubious ownership/,
    'the fixture does not reproduce the ownership refusal, so this test would prove nothing');

  const err = await ensureCodebaseContext('ctxapp', repo, { actingUserId: userId }).then(() => null, (e) => e);
  assert.ok(err, 'the failing agent was reported as success');
  assert.match(err.message, /credit balance is too low/, `the agent's own explanation was dropped: ${err.message}`);

  const argv = readFileSync(ARGV, 'utf8').split('\x1f');
  const envs = argv.filter((a, i) => argv[i - 1] === '-e').map((e) => e.split('=')[0]);
  assert.ok(envs.includes('CLAUDE_CODE_OAUTH_TOKEN'), `built on another credential: ${envs.join(', ')}`);
  assert.ok(!envs.includes('ANTHROPIC_API_KEY'), 'the platform key was used for a user on their own token');
  assert.match(argv.join(' '), /server\.js/, 'the summary was built from an empty file tree');
});
