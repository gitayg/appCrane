import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// Opening an app's env vars used to fetch ?reveal=true, decrypting every value
// and mailing the owners on a page load. These pin the client to the masked
// list plus the per-key reveal route; tsc cannot see a query string.

const web = (p) => readFileSync(new URL(`../studio-web/src/${p}`, import.meta.url), 'utf8');
const srv = (p) => readFileSync(new URL(`../server/${p}`, import.meta.url), 'utf8');

const appManager = web('pages/AppManager.tsx');
const api = web('components/env/envVarsApi.ts');
const panel = web('components/env/EnvVarsPanel.tsx');
const row = web('components/env/EnvVarRow.tsx');
const route = srv('routes/envVars.js');

const envCard = appManager.slice(appManager.indexOf('function EnvVarsCard('), appManager.indexOf('interface DeployHistoryCardProps'));

test('AppManager\'s env card no longer requests ?reveal=true on load', () => {
  assert.ok(envCard.length > 0, 'EnvVarsCard was not found in AppManager.tsx');
  assert.doesNotMatch(appManager, /reveal=true/, 'AppManager.tsx still requests ?reveal=true');
  assert.match(envCard, /<EnvVarsPanel\b/, 'the env card does not render the shared panel');
});

test('the shared panel loads the masked list and reveals through the per-key POST route', () => {
  assert.doesNotMatch(api + panel + row, /reveal=true/, 'the shared env panel requests ?reveal=true');
  assert.match(api, /loadMaskedEnv = \(slug: string, env: EnvName\) =>\s*adminApi\.get<MaskedEnvList>\(base\(slug, env\)\)/);
  assert.match(api, /adminApi\.post<RevealedEnvVar>\(`\$\{base\(slug, env\)\}\/\$\{encodeURIComponent\(key\)\}\/reveal`\)/);
  assert.match(route, /router\.post\('\/:slug\/env\/:env\/:key\/reveal', requireAppUser,/,
    'the server route the panel calls is gone');
  assert.match(panel, /loadMaskedEnv\(slug, env\)/, 'the panel does not load the masked list on mount');
});

test('editing opens an empty field and saves without revealing the old value', () => {
  assert.match(row, /placeholder="Enter a new value"/);
  assert.match(row, /const \[draft, setDraft\] = useState\(''\)/, 'the edit field is not empty when opened');
  const saveFn = panel.slice(panel.indexOf('async function save('), panel.indexOf('async function remove('));
  assert.ok(saveFn.length > 0);
  assert.doesNotMatch(saveFn, /revealEnvVar/, 'saving an edit reveals the old value first');
  assert.match(saveFn, /setEnvVar\(slug, env, key, value\)/);
});

test('Copy exists only once the value has been revealed', () => {
  const copyBranch = row.slice(row.indexOf('{revealed !== undefined ? ('), row.indexOf('>Reveal</button>'));
  assert.match(copyBranch, /Copy/, 'Copy is not inside the revealed branch');
  assert.equal((row.match(/'Copy'/g) || []).length, 1, 'Copy is rendered outside the revealed branch');
});

test('the Applications env panel uses the masked panel and never bulk-reveals', () => {
  const apps = readFileSync(new URL('../studio-web/src/pages/Applications.tsx', import.meta.url), 'utf8');
  assert.doesNotMatch(apps, /reveal=true/, 'Applications.tsx still bulk-reveals env vars');
  assert.match(apps, /<EnvVarsPanel /);
});
