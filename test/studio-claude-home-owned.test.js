import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';

// Reported on a real instance: the coder said "Bash is blocked by an
// environment permission issue". Measured inside its container:
//   uid=100(studio)
//   drwxr-sr-x root studio  /home/studio/.claude
//   mkdir ~/.claude/shell-snapshots: Permission denied
//   -rw------- node node    .../projects/-workspace/<id>.jsonl   (unreadable)
// Two causes. The image never created ~/.claude, so Docker created it as root
// when it mounted the transcripts under it. And every container start ran
// `chown -R 1000:1000` over the transcripts, a uid the agent does not run as,
// so its own 0600 conversation became unreadable to it.
// Reproduced with the v4 image and fixed with v5 before this test was written.
const dockerfile = readFileSync(new URL('../infra/studio.Dockerfile', import.meta.url), 'utf8');
const generator  = readFileSync(new URL('../server/services/appstudio/generator.js', import.meta.url), 'utf8');
const container  = readFileSync(new URL('../server/services/builder/appContainer.js', import.meta.url), 'utf8');

test('the image creates ~/.claude owned by studio, in both recipes', () => {
  for (const [name, src] of [['infra/studio.Dockerfile', dockerfile], ['generator.js inline recipe', generator]]) {
    assert.match(src, /mkdir -p \/home\/studio\/\.claude /, `${name}: ~/.claude is left for Docker to create as root`);
    assert.match(src, /chown -R studio:studio \/home\/studio/, `${name}: ~/.claude is not handed to studio`);
  }
});

test('the transcripts are chowned to the uid the image runs as, not another one', () => {
  const uid = /STUDIO_UID = (\d+)/.exec(container)?.[1];
  const gid = /STUDIO_GID = (\d+)/.exec(container)?.[1];
  assert.ok(uid && gid, 'STUDIO_UID / STUDIO_GID not found');
  for (const [name, src] of [['infra/studio.Dockerfile', dockerfile], ['generator.js inline recipe', generator]]) {
    assert.match(src, new RegExp(`addgroup -S -g ${gid} studio && adduser -S -u ${uid} -G studio studio`),
      `${name} does not pin studio to ${uid}:${gid}, so the chown can drift from the user again`);
  }
  assert.match(container, /chown', \['-R', `\$\{STUDIO_UID\}:\$\{STUDIO_GID\}`, dir\]/);
  assert.doesNotMatch(container, /chown', \['-R', '1000:1000', dir\]/, 'back to a uid the agent does not run as');
});

test('the image version was bumped so existing hosts rebuild', () => {
  const constant = /STUDIO_IMAGE_VERSION = '(\d+)'/.exec(generator)?.[1];
  assert.ok(Number(constant) >= 5, `STUDIO_IMAGE_VERSION is ${constant}; hosts keep the image without ~/.claude`);
  assert.equal(/ARG STUDIO_IMAGE_VERSION=(\d+)/.exec(dockerfile)?.[1], constant);
});
