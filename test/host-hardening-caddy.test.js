import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// The caddy parts of scripts/host-hardening.sh: its log dir and the restart
// policy drop-in, so one restart storm can no longer trip systemd's start limit.

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const src = readFileSync(join(ROOT, 'scripts', 'host-hardening.sh'), 'utf8');
const { skipFor, run } = await import('./host-hardening-harness.js');
const R = '24.04';

test('caddy log dir: created owned by caddy, mode 0750; a root-owned one is fixed; a second run changes nothing', { skip: skipFor(R) }, () => {
  const fresh = run(R, '', { runs: 2, env: { APPCRANE_RESERVE_MIN_FREE_GB: '100000' } });
  assert.equal(fresh.runs[0].exit, 0, fresh.runs[0].log);
  assert.equal(fresh.runs[0].caddyDir, 'caddy:caddy 750');
  assert.equal(fresh.runs[1].caddyDir, 'caddy:caddy 750');
  assert.match(fresh.runs[1].log, /already caddy:caddy 0750/);

  const rootOwned = run(R, 'mkdir -p /var/log/caddy && chown root:root /var/log/caddy && chmod 755 /var/log/caddy',
    { env: { APPCRANE_RESERVE_MIN_FREE_GB: '100000' } });
  assert.equal(rootOwned.runs[0].caddyDir, 'caddy:caddy 750');
  assert.match(rootOwned.runs[0].log, /was: root:root 755/);
});

test('caddy log dir: skipped with a warning when the caddy user does not exist', { skip: skipFor(R) }, () => {
  const r = run(R, 'userdel caddy', { env: { APPCRANE_RESERVE_MIN_FREE_GB: '100000' } });
  assert.equal(r.runs[0].exit, 0, r.runs[0].log);
  assert.equal(r.runs[0].caddyDir, 'missing');
  assert.match(r.runs[0].log, /user 'caddy' does not exist/);
});

// ---- Caddy restart policy drop-in ----
// systemctl show caddy on a production box: Restart=no, StartLimitIntervalUSec=10s,
// StartLimitBurst=5. One restart burst hit the limit and every site stayed down.

const CADDY_DROPIN = '# Written by AppCrane scripts/host-hardening.sh\n[Unit]\nStartLimitIntervalSec=0\n\n[Service]\nRestart=on-failure\nRestartSec=2\n';

test('caddy restart policy: drop-in written exactly; a second run changes nothing and backs nothing up', { skip: skipFor(R) }, () => {
  const r = run(R, '', { runs: 2, env: { APPCRANE_RESERVE_MIN_FREE_GB: '100000' } });
  const [a, b] = r.runs;
  assert.equal(a.exit, 0, a.log);
  assert.equal(a.caddyDropin, CADDY_DROPIN);
  assert.match(a.log, /caddy restart policy: \/etc\/systemd\/system\/caddy\.service\.d\/appcrane\.conf changed/);
  assert.equal(b.exit, 0, b.log);
  assert.equal(b.caddyDropin, CADDY_DROPIN);
  assert.match(b.log, /caddy restart policy: \/etc\/systemd\/system\/caddy\.service\.d\/appcrane\.conf unchanged/);
  assert.equal(b.caddyBackups, 0);
  assert.match(a.log, /caddy restart policy: no running systemd/, 'the no-systemd path must say so, not fail');
});

test('caddy restart policy: a different file there is backed up once, then replaced', { skip: skipFor(R) }, () => {
  const r = run(R, 'mkdir -p /etc/systemd/system/caddy.service.d && printf "[Service]\\nRestart=no\\n" > /etc/systemd/system/caddy.service.d/appcrane.conf',
    { runs: 2, env: { APPCRANE_RESERVE_MIN_FREE_GB: '100000' } });
  assert.equal(r.runs[0].caddyDropin, CADDY_DROPIN);
  assert.equal(r.runs[0].caddyBackups, 1, r.runs[0].log);
  assert.equal(r.runs[1].caddyBackups, 1, 'an unchanged file was backed up again');
});

test('caddy restart policy: the script never restarts or stops Caddy, and starts it only when it is failed', () => {
  assert.doesNotMatch(src, /systemctl\s+(?:restart|stop|try-restart|reload-or-restart)\s+caddy/);
  const starts = src.match(/systemctl start caddy/g) || [];
  assert.equal(starts.length, 1);
  const at = src.indexOf('systemctl start caddy');
  assert.match(src.slice(Math.max(0, at - 300), at), /is-active caddy[^\n]*" == failed/);
});

// ---- Apply from Settings > Job Health > Host limits on a non-root AppCrane ----
