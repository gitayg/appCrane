import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, symlinkSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// CVE-2026-76845 / GHSA-vwc7-r8mq-g2x9 (CWE-59) — adm-zip follows a symlink
// that already exists at the extraction destination.
//
// There is no fixed adm-zip: the advisory's first_patched_version is null and
// 0.6.0 is the latest published version. So the defence lives in AppCrane, in
// safeExtractZip, and needs a test of its own or it will be refactored away by
// someone who reads it as redundant with the entry-name scan above it.
//
// It is NOT redundant. The archive here is completely well-formed: one entry
// named `config.js`, no '..', no leading slash, nothing that resolves outside
// the destination. Every check safeExtractZip performed before this fix passes.
// The write escapes anyway, through a symlink sitting at the destination,
// because adm-zip's writeFileTo opens with fs.openSync(path, 'w') — no
// O_NOFOLLOW, no lstat.

const { safeExtractZip } = await import('../server/utils/safeExtract.js');
const AdmZip = (await import('adm-zip')).default;

function scenario() {
  const root = mkdtempSync(join(tmpdir(), 'admzip-cve-'));
  const dest = join(root, 'dest');
  const outside = join(root, 'outside');
  mkdirSync(dest);
  mkdirSync(outside);

  const victim = join(outside, 'secret.txt');
  writeFileSync(victim, 'ORIGINAL');

  // The attacker's foothold: a symlink in the destination, planted before
  // extraction. adm-zip cannot create this from an archive entry (it never
  // calls symlinkSync), which is why the advisory's precondition is separate
  // write access to a shared or predictable extraction directory.
  symlinkSync(victim, join(dest, 'config.js'));

  const zip = new AdmZip();
  zip.addFile('config.js', Buffer.from('PWNED'));
  const archive = join(root, 'payload.zip');
  zip.writeZip(archive);

  return { dest, victim, archive };
}

test('a symlink at the destination cannot be written through', async () => {
  const { dest, victim, archive } = scenario();

  await assert.rejects(
    () => safeExtractZip(archive, dest),
    /symlink/i,
    'extraction into a destination containing a symlink must be refused',
  );

  assert.equal(
    readFileSync(victim, 'utf8'), 'ORIGINAL',
    'the file outside the extraction root was overwritten through the symlink — '
    + 'this is CVE-2026-76845 landing in AppCrane',
  );
});

test('an ordinary archive still extracts', async () => {
  const root = mkdtempSync(join(tmpdir(), 'admzip-ok-'));
  const dest = join(root, 'dest');
  mkdirSync(dest);

  const zip = new AdmZip();
  zip.addFile('package.json', Buffer.from('{"name":"x"}'));
  zip.addFile('src/index.js', Buffer.from('console.log(1)\n'));
  const archive = join(root, 'app.zip');
  zip.writeZip(archive);

  await safeExtractZip(archive, dest);

  assert.ok(existsSync(join(dest, 'package.json')), 'the guard broke normal extraction');
  assert.equal(readFileSync(join(dest, 'src', 'index.js'), 'utf8'), 'console.log(1)\n');
});
