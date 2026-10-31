import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { spawnSync } from 'child_process';

// A Crew app coder turn's container, run for real against Docker with the
// exact options the runner uses (crewTurnContainerOptions) and a command that
// searches the whole filesystem for canary files planted in the app's shared
// transcript directory and in another task's Claude home. None may be visible.
// Positive control: the same search with the app container's transcript mount
// added finds the canary, so a pass is not a search that cannot see anything.
// Skipped only when docker or the studio image is unavailable.

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-crew-isolation-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const IMAGE = process.env.APPSTUDIO_IMAGE || 'appcrane-studio:latest';
const dockerOk = spawnSync('docker', ['image', 'inspect', IMAGE], { stdio: 'pipe', timeout: 15000 }).status === 0;
const skip = dockerOk ? false : `docker or the ${IMAGE} image is unavailable`;

const { initDb } = await import('../server/db.js');
initDb();
const { runAgentNewArgs } = await import('../server/services/llm/runAgent.js');
const { crewTurnContainerOptions } = await import('../server/services/crewAppCoderRunner.js');
const { prepareCrewTaskHome } = await import('../server/services/crewCoderHome.js');
const { transcriptDirFor, CONTAINER_CLAUDE_PROJECTS_DIR } = await import('../server/services/builder/appContainer.js');

const SLUG = 'isoapp';
const APP_CANARY = 'canary-app-transcript-7f3a';
const TASK_CANARY = 'canary-other-task-9c1e';
const SEARCH = `find / \\( -path /proc -o -path /sys \\) -prune -o \\( -name '${APP_CANARY}*' -o -name '${TASK_CANARY}*' \\) -print 2>/dev/null; `
  + `grep -rl 'CANARY-CONTENT' /home /workspace /tmp /root /mnt /srv /data 2>/dev/null; echo SEARCH-DONE`;

function setup() {
  const ws = join(process.env.DATA_DIR, 'app-containers', SLUG, 'workspace');
  mkdirSync(ws, { recursive: true });
  const transcripts = join(transcriptDirFor(SLUG), '-workspace');
  mkdirSync(transcripts, { recursive: true });
  writeFileSync(join(transcripts, `${APP_CANARY}.jsonl`), 'CANARY-CONTENT owner conversation');
  const other = prepareCrewTaskHome('otherTask1', { slug: SLUG });
  mkdirSync(join(other, 'projects', '-workspace'), { recursive: true });
  writeFileSync(join(other, 'projects', '-workspace', `${TASK_CANARY}.jsonl`), 'CANARY-CONTENT other task');
  const mine = prepareCrewTaskHome('thisTask1', { slug: SLUG });
  return { ws, mine };
}

function run(extraMounts = []) {
  const { ws, mine } = setup();
  const name = `appcrane-crewtest-iso-${process.pid}-${extraMounts.length}`;
  const opts = crewTurnContainerOptions({ slug: SLUG, taskId: 'thisTask1', workspaceDir: ws, claudeHomeDir: mine, containerName: name });
  const argv = runAgentNewArgs({
    ...opts,
    labels: { 'appcrane.test': 'crew-isolation' },
    prompt: 'unused', model: 'sonnet', apiKey: 'unused', actingUserId: null,
    extraMounts: [...(opts.extraMounts || []), ...extraMounts],
    cmd: ['sh', '-c', SEARCH],
  });
  const r = spawnSync('docker', argv, { encoding: 'utf8', timeout: 120000 });
  spawnSync('docker', ['rm', '-f', name], { stdio: 'pipe' });
  assert.equal(r.status, 0, `docker run failed: ${r.stderr}`);
  assert.match(r.stdout, /SEARCH-DONE/);
  return { out: r.stdout, argv };
}

test('a Crew turn container sees neither the app transcripts nor another task home', { skip }, () => {
  const { out, argv } = run();
  assert.ok(argv.includes('--read-only'));
  assert.ok(!out.includes(APP_CANARY), `app transcript visible:\n${out}`);
  assert.ok(!out.includes(TASK_CANARY), `another task's home visible:\n${out}`);
  assert.ok(!out.includes('CANARY-CONTENT') && !/\.jsonl/.test(out.replace('SEARCH-DONE', '')), `canary content visible:\n${out}`);
});

test('positive control: with the app container transcript mount the canary is found', { skip }, () => {
  const { out } = run([{ host: transcriptDirFor(SLUG), container: CONTAINER_CLAUDE_PROJECTS_DIR }]);
  assert.ok(out.includes(APP_CANARY), `the search should have found the canary:\n${out}`);
});
