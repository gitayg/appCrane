import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, chmodSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// The coder workspace is handed to the uid the agent runs as (the studio
// image's `studio`, 100:101 — STUDIO_UID/STUDIO_GID), not to 1000. The studio
// image names uid 1000 `node`, so a workspace chowned to it showed the agent
// its whole .git/ as `node`'s and the agent told the user `.git/refs/heads/` was
// "owned by node and not writable by me". And the hand-over must come after
// `checkout -B builder/<slug>`, or the branch's ref directory is created after
// it, owned by AppCrane (v2.107.6).
//
// chown is a PATH shim recording its argv and whether the session branch's ref
// already existed at that moment; git is real; docker is a shim.

const ROOT = mkdtempSync(join(tmpdir(), 'crane-wsowner-'));
process.env.DATA_DIR = ROOT;
process.env.ENCRYPTION_KEY = 'w'.repeat(64);
process.env.LOG_LEVEL = 'error';

const BIN = join(ROOT, 'bin');
const CHOWN_LOG = join(ROOT, 'chown.log');
mkdirSync(BIN, { recursive: true });
writeFileSync(CHOWN_LOG, '');
writeFileSync(join(BIN, 'docker'), `#!/bin/sh
case "$1" in
  run)     echo c0ffee000000c0ffee000000c0ffee000000c0ffee000000c0ffee000000c0ff ;;
  image)   echo 5 ;;
  inspect) echo true ;;
esac
exit 0
`);
writeFileSync(join(BIN, 'chown'), `#!/bin/sh
last=""; for a in "$@"; do last="$a"; done
if [ -f "$last/.git/refs/heads/builder/wsowner" ]; then ref=ref-present; else ref=ref-absent; fi
printf '%s %s\\n' "$*" "$ref" >> ${JSON.stringify(CHOWN_LOG)}
exit 0
`);
chmodSync(join(BIN, 'docker'), 0o755);
chmodSync(join(BIN, 'chown'), 0o755);
process.env.PATH = `${BIN}:${process.env.PATH}`;

const { initDb, getDb } = await import('../server/db.js');
initDb();
const db = getDb();
const lg = await import('../server/services/localGit.js');
const appContainer = await import('../server/services/builder/appContainer.js');

after(async () => {
  try { (await import('../server/services/healthChecker.js')).stopHealthChecker(); } catch (_) {}
  rmSync(ROOT, { recursive: true, force: true });
});

test('the workspace is chowned to the agent\'s uid, after the session branch exists', async () => {
  await lg.createAppRepo('wsowner');
  await lg.pushFilesToManagedRepo('wsowner', [{ path: 'README.md', content: '# seed\n' }], { message: 'seed' });
  db.prepare("INSERT INTO apps (name,slot,slug,source_type,repo_backend,branch) VALUES ('wsowner',941,'wsowner','managed','local','main')").run();
  const app = db.prepare("SELECT * FROM apps WHERE slug = 'wsowner'").get();

  const c = await appContainer.getOrCreate(app);
  const forWorkspace = readFileSync(CHOWN_LOG, 'utf8').split('\n').filter((l) => l.includes(` ${c.workspaceDir} `));
  assert.equal(forWorkspace.length, 1, `expected one chown of the workspace, got:\n${readFileSync(CHOWN_LOG, 'utf8')}`);
  assert.equal(forWorkspace[0], `-R ${appContainer.STUDIO_UID}:${appContainer.STUDIO_GID} ${c.workspaceDir} ref-present`);
  assert.equal(`${appContainer.STUDIO_UID}:${appContainer.STUDIO_GID}`, '100:101', 'STUDIO_UID/GID drifted from infra/studio.Dockerfile');
  appContainer.evict('wsowner', 'test');
});
