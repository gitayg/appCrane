import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Configured vs APPLIED cpu/memory (v2.48.0).
//
// `--memory` and `--cpus` are `docker run` arguments. Changing max_ram_mb on a
// running app rewrites the row and nothing else — the container keeps the
// command line it was created with until it is RECREATED. Every AppCrane
// surface reported the configured number, so a container running with NO
// memory limit looked exactly like one running at 512 MB.
//
// The August 2026 incident review is why this exists. It recorded clamd
// OOM-killed at 992 MB anonymous RSS on an app configured max_ram_mb=512 —
// and the question "was the limit actually in force?" could not be answered
// from any AppCrane surface. It took an ssh and a docker inspect. (It turned
// out the limit WAS applied and the real story was --memory-swap=1g against a
// host with zero swap; the point stands that nothing could tell you either way.)

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'crane-resdrift-'));
process.env.ENCRYPTION_KEY = 'e'.repeat(64);
process.env.LOG_LEVEL = 'error';

const { resourceDrift } = await import('../server/services/resourceDrift.js');

const app = { max_ram_mb: 512, max_cpu_percent: 50 };
const MB = 1024 * 1024;
const applied = { memoryBytes: 512 * MB, nanoCpus: 0.5e9, running: true };

test('a container carrying its configured limits reads as applied', () => {
  const d = resourceDrift(app, applied);
  assert.equal(d.applied, true);
  assert.deepEqual(d.findings, []);
});

test('THE CASE: memory limit absent entirely is not_applied, not merely different', () => {
  // Docker encodes "no limit" as 0. This is categorically worse than a wrong
  // number: the container can take the whole host.
  const d = resourceDrift(app, { ...applied, memoryBytes: 0 });
  assert.equal(d.applied, false);
  const mem = d.findings.find(f => f.resource === 'memory');
  assert.equal(mem.state, 'not_applied');
  assert.match(mem.message, /NO memory limit/);
  assert.match(mem.message, /entire host/);
  assert.match(mem.message, /RECREATED/, 'the remedy must travel with the finding');
  assert.match(mem.message, /docker restart.*reuses/is,
    'a plain restart does not apply a limit, and that is the trap this exists to close');
});

test('a container limited to the WRONG value is stale, and both numbers are named', () => {
  const d = resourceDrift(app, { ...applied, memoryBytes: 256 * MB });
  const mem = d.findings.find(f => f.resource === 'memory');
  assert.equal(mem.state, 'stale');
  assert.equal(mem.expected_mb, 512);
  assert.equal(mem.actual_mb, 256);
  assert.match(mem.message, /256 MB/);
  assert.match(mem.message, /512 MB/);
});

test('an absent CPU limit is reported, and says --cpus is a HARD cap', () => {
  // The incident review claimed --cpus was a soft limit. It is a CFS quota.
  // Stating it in the finding stops that error being made twice.
  const d = resourceDrift(app, { ...applied, nanoCpus: 0 });
  const cpu = d.findings.find(f => f.resource === 'cpu');
  assert.equal(cpu.state, 'not_applied');
  assert.match(cpu.message, /HARD ceiling/);
  assert.match(cpu.message, /not a share/);
});

test('a wrong CPU cap is stale and reports both percentages', () => {
  const d = resourceDrift(app, { ...applied, nanoCpus: 1e9 });   // 100% vs configured 50%
  const cpu = d.findings.find(f => f.resource === 'cpu');
  assert.equal(cpu.state, 'stale');
  assert.equal(cpu.actual_percent, 100);
  assert.equal(cpu.expected_percent, 50);
});

test('float dust in NanoCpus is not reported as drift', () => {
  // 0.5 CPU does not always round-trip to exactly 5e8.
  const d = resourceDrift(app, { ...applied, nanoCpus: 0.5e9 + 500 });
  assert.equal(d.applied, true, 'a rounding artefact was reported as a real mismatch');
});

test('both resources missing yields two findings, not one', () => {
  const d = resourceDrift(app, { memoryBytes: 0, nanoCpus: 0, running: true });
  assert.equal(d.findings.length, 2);
  assert.deepEqual(d.findings.map(f => f.resource).sort(), ['cpu', 'memory']);
});

test('an unreadable container is UNKNOWN — never reported as unlimited', () => {
  const d = resourceDrift(app, null);
  assert.equal(d.applied, null,
    'false here would tell an operator a container has no limit because we failed to look — ' +
    'the same wrong answer, one resource over');
  assert.deepEqual(d.findings, []);
});

test('an app with no explicit limits is judged against the platform defaults', () => {
  // 512 MB / 50% are what routes/apps.js and deploy.js fall back to, so a row
  // that never set them must be compared against the same numbers the deploy
  // path would have applied — otherwise every default app reads as drifted.
  const d = resourceDrift({}, applied);
  assert.equal(d.applied, true);
  assert.equal(d.expected.memory_mb, 512);
  assert.equal(d.expected.cpu_percent, 50);
});
