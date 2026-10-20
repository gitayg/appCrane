import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Stored secrets render masked behind an eye that fetches the value only when
// pressed (that server call is what audits and alerts); typed secrets get an
// eye that only toggles the field locally. tsc cannot check either rule.

const SRC = fileURLToPath(new URL('../studio-web/src/', import.meta.url));
const web = (p) => readFileSync(join(SRC, p), 'utf8');

const secretValue = web('components/secret/SecretValue.tsx');
const passwordInput = web('components/secret/PasswordInput.tsx');
const row = web('components/env/EnvVarRow.tsx');
const panel = web('components/env/EnvVarsPanel.tsx');
const envFiles = web('components/StoredEnvFilesCard.tsx');

function walk(dir, out = []) {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.tsx?$/.test(n)) out.push(p);
  }
  return out;
}
const sources = walk(SRC).map((p) => ({ rel: p.slice(SRC.length), text: readFileSync(p, 'utf8') }));

test('SecretValue holds no value until the eye is pressed, and fetches only from that press', () => {
  assert.match(secretValue, /useState<string \| undefined>\(undefined\)/, 'the value state does not start empty');
  assert.doesNotMatch(secretValue, /useEffect/, 'SecretValue runs an effect, which could reveal on mount');
  const toggle = secretValue.slice(secretValue.indexOf('async function toggle()'), secretValue.indexOf('async function copy()'));
  assert.match(toggle, /await reveal\(\)/, 'the eye press does not call reveal()');
  const code = secretValue.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n');
  assert.equal((code.match(/reveal\(\)/g) || []).length, 1, 'reveal() is called outside the eye press');
  assert.match(toggle, /if \(shown\) \{ setValue\(undefined\)/, 'hiding does not drop the plaintext');
});

test('SecretValue\'s eye is an accessible toggle and Copy appears only after a reveal', () => {
  assert.match(secretValue, /aria-label=\{shown \? `Hide \$\{name\}` : `Show \$\{name\}`\}/);
  assert.match(secretValue, /aria-pressed=\{shown\}/);
  assert.match(secretValue, /<Icon\.EyeOff[^>]*\/> : <Icon\.Eye /);
  assert.match(secretValue, /\{shown && \(\s*<button[^>]*onClick=\{copy\}/, 'Copy is not gated on the value being shown');
  assert.equal((secretValue.match(/onClick=\{copy\}/g) || []).length, 1);
});

test('PasswordInput only toggles the field locally: no server call', () => {
  assert.doesNotMatch(passwordInput, /adminApi|fetch\(|reveal/i, 'PasswordInput talks to the server');
  assert.match(passwordInput, /type=\{visible \? 'text' : 'password'\}/);
  assert.match(passwordInput, /const \[visible, setVisible\] = useState\(false\)/, 'the field does not start masked');
  assert.match(passwordInput, /aria-pressed=\{visible\}/);
  assert.match(passwordInput, /aria-label=\{visible \? `Hide \$\{label\}` : `Show \$\{label\}`\}/);
});

test('env vars: the row shows SecretValue, editing and adding type into PasswordInput', () => {
  assert.match(row, /<SecretValue\b/);
  assert.match(row, /<PasswordInput\b[\s\S]*?placeholder="Enter a new value"/, 'the edit field has no eye');
  assert.match(panel, /<PasswordInput label="new value"/, 'the add-value field has no eye');
  assert.match(panel, /const reveal = async \(key: string\) => \(await revealEnvVar\(slug, env, key\)\)\.value/);
  const load = panel.slice(panel.indexOf('const load = useCallback'), panel.indexOf('const reveal ='));
  assert.ok(load.length > 0);
  assert.doesNotMatch(load, /revealEnvVar/, 'the panel reveals while loading');
  assert.match(panel, /key=\{`\$\{env\}\/\$\{v\.key\}\/\$\{generation\}`\}/, 'a reload or env switch can keep a revealed value on screen');
});

test('stored .env files: each row is a SecretValue whose reveal is the only content fetch', () => {
  assert.match(envFiles, /<SecretValue name=\{`stored \$\{f\.path\}`\} multiline reveal=\{\(\) => revealContent\(f\.path\)\} \/>/);
  assert.equal((envFiles.match(/env-files\/content/g) || []).length, 1, 'content is fetched from more than one place');
  const load = envFiles.slice(envFiles.indexOf('const load = useCallback'), envFiles.indexOf('useEffect('));
  assert.ok(load.length > 0);
  assert.doesNotMatch(load, /content|revealContent/, 'the list load fetches content');
});

test('no component reveals a secret from an effect or a list load', () => {
  for (const { rel, text } of sources) {
    for (const m of text.matchAll(/useEffect\(\(\) => \{?([\s\S]*?)\}, \[/g)) {
      assert.doesNotMatch(m[1], /revealEnvVar|revealContent|\/reveal\b|reveal=true|env-files\/content/, `${rel} reveals inside an effect`);
    }
  }
  const revealCallers = sources.filter(({ text }) => /revealEnvVar\(|\/reveal`/.test(text)).map((s) => s.rel).sort();
  assert.deepEqual(revealCallers, ['components/env/EnvVarsPanel.tsx', 'components/env/envVarsApi.ts']);
});

test('every password field in the dashboard has the eye', () => {
  const raw = sources.filter(({ rel, text }) => rel !== 'components/secret/PasswordInput.tsx' && /type=["'{]+password/.test(text)).map((s) => s.rel);
  assert.deepEqual(raw, [], 'a password field bypasses PasswordInput');
  const users = sources.filter(({ text }) => /<PasswordInput\b/.test(text)).map((s) => s.rel).sort();
  assert.deepEqual(users, [
    'components/ChangePasswordCard.tsx', 'components/ClaudeTokenCard.tsx', 'components/Login.tsx', 'components/SetUserPasswordModal.tsx',
    'components/env/EnvVarRow.tsx', 'components/env/EnvVarsPanel.tsx',
    'pages/Catalog.tsx', 'pages/Settings.tsx', 'pages/Users.tsx',
  ]);
  for (const { rel, text } of sources) {
    for (const m of text.matchAll(/<PasswordInput\b([\s\S]*?)\/>/g)) {
      assert.match(m[1], /\blabel=/, `${rel}: a PasswordInput has no accessible label`);
    }
  }
});
