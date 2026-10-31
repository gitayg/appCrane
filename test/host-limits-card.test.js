import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// The Host limits card on Settings > Job Health applies scripts/host-hardening.sh
// through /api/settings/host-hardening/apply. These pin the contract with that
// route: the path, the second factor in the body, the manual-mode command, and
// that the refusals an admin can hit are put into words on the card.

const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');
const card = read('studio-web/src/components/HostLimitsCard.tsx');
const page = read('studio-web/src/pages/JobHealth.tsx');

test('the card is rendered on the Job Health page', () => {
  assert.match(page, /import \{ HostLimitsCard \} from '\.\.\/components\/HostLimitsCard'/);
  assert.match(page, /<HostLimitsCard \/>/);
});

test('apply POSTs to the frozen path and reads the status path', () => {
  assert.match(card, /const APPLY_PATH = '\/api\/settings\/host-hardening\/apply'/);
  assert.match(card, /const STATUS_PATH = '\/api\/settings\/host-hardening'/);
  assert.match(card, /adminApi\.post<ApplyResult>\(APPLY_PATH, body\)/);
});

test('the second-factor code goes in the body as mfa_code when the server asks for it', () => {
  assert.match(card, /const body = status\.mfa_required \? \{ mfa_code: code\.trim\(\) \} : \{\}/);
  assert.match(card, /\{status\.mfa_required && \(/, 'the code input is shown only when mfa_required');
});

test('manual mode shows the command to run in a copyable block and no Apply button', () => {
  assert.match(card, /status\.run\.mode === 'manual'/);
  assert.match(card, /AppCrane can't run this itself \(it runs without root and no sudo rule is installed\)\. Run on the server:/);
  assert.match(card, /\{status\.run\.command && <CommandBlock command=\{status\.run\.command\} \/>\}/);
  assert.match(card, /navigator\.clipboard\.writeText\(command\)/);
  assert.match(card, /const canRun = status\?\.run\.mode === 'root' \|\| status\?\.run\.mode === 'sudo'/);
});

test('RUNNING (409) and MANUAL_ONLY refusals are shown in plain words', () => {
  assert.match(card, /case 'RUNNING': return '[^']+'/);
  assert.match(card, /case 'MANUAL_ONLY': return '[^']+'/);
  assert.match(card, /case 'MFA_INVALID': return '[^']+'/);
  assert.match(card, /e\.status === 429/);
  assert.match(card, /setApplyError\(applyErrorText\(e\)\)/);
  assert.match(card, /\{applyError && <p[^>]*>\{applyError\}<\/p>\}/);
  assert.match(card, /e\.code === 'MANUAL_ONLY' && typeof e\.details\.command === 'string'/, 'MANUAL_ONLY carries the command');
});

test('a run in progress on load is polled every 5 seconds', () => {
  assert.match(card, /const POLL_MS = 5_000/);
  assert.match(card, /setInterval\(load, POLL_MS\)/);
});

test('the stale-copy warning shows the refresh command, not the Apply command', () => {
  const block = card.slice(card.indexOf('installed_copy_stale && ('), card.indexOf("run.mode === 'manual'"))
  assert.match(block, /<CommandBlock command=\{status\.run\.setup_command\} \/>/)
  assert.doesNotMatch(block, /command=\{status\.run\.command\}/)
})

test('the summary does not count items that do not apply', () => {
  assert.match(card, /filter\(i => i\.state !== 'not-applicable'\)/)
  assert.match(card, /\{applied\} of \{counted\.length\} applied/)
})
