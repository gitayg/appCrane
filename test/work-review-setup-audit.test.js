import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';

// The work-review setup audit (plugins/work-review/skills/work-review/scripts/audit-setup.mjs).
//
// The question it answers is not "how much did it cost" but "is this set up the
// way Claude Code's docs recommend, or in a more complicated way": a CLAUDE.md
// grown into a manual, subagents that are really playbooks, skills that never
// trigger, servers nobody calls, permissions that allow everything, and a
// multi-agent graph where one agent with skills might do. A clean setup must
// produce no findings, or the review cries wolf.

const SCRIPT = join(import.meta.dirname, '..', 'plugins', 'work-review', 'skills', 'work-review', 'scripts', 'audit-setup.mjs');

function run(project, userDir, usage) {
  const out = join(mkdtempSync(join(tmpdir(), 'audit-out-')), 'a.json');
  const argv = [SCRIPT, '--project', project, '--user-dir', userDir, '--json', out];
  if (usage) {
    const rep = join(project, '..', 'wr.json');
    writeFileSync(rep, JSON.stringify({ usage }));
    argv.push('--report', rep);
  }
  const md = execFileSync(process.execPath, argv, { encoding: 'utf8', env: { ...process.env, HOME: join(project, '..', 'home') } });
  return { md, ...JSON.parse(readFileSync(out, 'utf8')) };
}
const kinds = r => r.findings.map(f => f.kind);
const w = (p, t) => { mkdirSync(join(p, '..'), { recursive: true }); writeFileSync(p, t); };

test('an overcomplicated setup is caught, item by item', () => {
  const root = mkdtempSync(join(tmpdir(), 'audit-'));
  const proj = join(root, 'proj'), user = join(root, 'user');
  mkdirSync(join(root, 'home'), { recursive: true });

  // CLAUDE.md: 230 lines, a 10-step procedure, shouting, and a big import.
  const steps = Array.from({ length: 10 }, (_, i) => `${i + 1}. deploy step ${i + 1}`).join('\n');
  const shout = Array.from({ length: 8 }, () => 'You MUST NEVER do this. IMPORTANT.').join('\n');
  w(join(proj, 'CLAUDE.md'), `# Project\n@docs/handbook.md\n${steps}\n${shout}\n` + 'filler line\n'.repeat(210));
  w(join(proj, 'docs', 'handbook.md'), 'x'.repeat(20000));

  // Subagents: a thin description, a playbook with all tools, an opus searcher,
  // two near-duplicates, one never used.
  w(join(proj, '.claude', 'agents', 'helper.md'), '---\nname: helper\ndescription: helps\n---\nDo things.');
  w(join(proj, '.claude', 'agents', 'playbook.md'), '---\nname: playbook\ndescription: Runs the full release procedure for the billing service end to end\n---\n' + 'step\n'.repeat(40));
  w(join(proj, '.claude', 'agents', 'finder.md'), '---\nname: finder\ndescription: Searches the codebase for where a symbol is defined and used\ntools: Read, Grep, Glob\nmodel: opus\n---\nSearch.');
  w(join(proj, '.claude', 'agents', 'finder2.md'), '---\nname: finder2\ndescription: Searches the codebase for where a symbol is defined and referenced\ntools: Read, Grep\n---\nSearch.');

  // Skills: a deploy skill Claude may fire on its own, a missing description,
  // and an org-synced one that must NOT be judged.
  w(join(proj, '.claude', 'skills', 'ship', 'SKILL.md'), '---\nname: ship\ndescription: Deploy the app to production and publish the release notes when the user asks to ship\n---\nsteps');
  w(join(proj, '.claude', 'skills', 'mystery', 'SKILL.md'), 'no frontmatter at all');
  w(join(user, 'skills', 'synced', 'org', 'tool', 'SKILL.md'), '---\nname: orgtool\n---\n' + 'x\n'.repeat(900));

  // Settings: allow everything, a python wildcard, rm, bypass, an unmatched hook, a slow SessionStart.
  w(join(proj, '.claude', 'settings.json'), JSON.stringify({
    permissions: { allow: ['Bash(*)', 'Bash(python3 *)', 'Bash(rm -rf build)'], defaultMode: 'bypassPermissions' },
    hooks: {
      PostToolUse: [{ matcher: '', hooks: [{ type: 'command', command: 'npx prettier --write .' }] }],
      SessionStart: [{ hooks: [{ type: 'command', command: 'npm install && curl https://example.test/ping' }] }],
    },
  }));
  w(join(proj, '.mcp.json'), JSON.stringify({ mcpServers: { jira: {}, figma: {} } }));

  // What's being built: a LangGraph multi-agent graph.
  w(join(proj, 'src', 'graph.py'), 'from langgraph.graph import StateGraph\ng = StateGraph(dict)\n');

  const r = run(proj, user, { sessions: 12, agents: { helper: 3, playbook: 2, finder: 1 }, skills: {}, mcpServers: { jira: 9 }, commands: {} });
  const k = kinds(r);
  for (const want of ['claude-md-long', 'claude-md-procedure', 'claude-md-shouting', 'always-on-heavy',
    'agent-thin-description', 'agent-all-tools', 'agent-is-a-skill', 'agent-oversized-model', 'agent-overlap', 'agent-unused',
    'skill-side-effect-auto', 'skill-no-description', 'allow-all-bash', 'allow-interpreter', 'allow-destructive',
    'bypass-permissions', 'hook-every-tool', 'hook-slow-session-start', 'mcp-unused', 'multi-agent-framework']) {
    assert.ok(k.includes(want), `expected a ${want} finding; got ${k.join(', ')}`);
  }
  assert.ok(r.inventory.alwaysOnTokens > 5000, 'the @import is counted: imports do not reduce context cost');
  assert.equal(r.findings.find(f => f.kind === 'agent-unused').item, 'finder2', 'only the agent with no runs is unused');
  assert.equal(r.findings.find(f => f.kind === 'mcp-unused').item, 'figma');
  assert.ok(!r.findings.some(f => f.item === 'orgtool'), 'an org-synced skill is inventoried, not judged');
  assert.ok(r.inventory.skills.some(s => s.name === 'orgtool' && s.managed));
  assert.equal(r.findings[0].severity, 'high', 'most severe first');
});

test('a lean setup produces no findings, and "unused" needs enough history', () => {
  const root = mkdtempSync(join(tmpdir(), 'audit-'));
  const proj = join(root, 'proj'), user = join(root, 'user');
  mkdirSync(join(root, 'home'), { recursive: true });
  w(join(proj, 'CLAUDE.md'), '# Project\n\n- Test with `npm test`; it must pass before a commit.\n- Code lives in src/, tests in test/.\n');
  w(join(proj, '.claude', 'agents', 'reviewer.md'), '---\nname: reviewer\ndescription: Reviews a diff for correctness bugs and missing tests; use after a change is made\ntools: Read, Grep, Glob, Bash\nmodel: sonnet\n---\nReview the diff.');
  w(join(proj, '.claude', 'skills', 'release-notes', 'SKILL.md'), '---\nname: release-notes\ndescription: Drafts release notes from merged commits; use when the user asks for a changelog or release notes\n---\nsteps');
  w(join(proj, '.claude', 'settings.json'), JSON.stringify({ permissions: { allow: ['Bash(npm test)', 'Bash(git status)'] }, hooks: { PostToolUse: [{ matcher: 'Edit|Write', hooks: [{ type: 'command', command: 'npx prettier --write "$FILE"' }] }] } }));

  const r = run(proj, user, { sessions: 3, agents: {}, skills: {}, mcpServers: {}, commands: {} });
  assert.deepEqual(kinds(r), [], `expected no findings; got ${kinds(r).join(', ')}`);
  assert.match(r.md, /No findings/);
});

test('a skill installed as a symlink is inventoried', async () => {
  const { symlinkSync } = await import('fs');
  const root = mkdtempSync(join(tmpdir(), 'audit-'));
  const proj = join(root, 'proj'), user = join(root, 'user');
  mkdirSync(join(root, 'home'), { recursive: true });
  w(join(root, 'checkout', 'linked', 'SKILL.md'), '---\nname: linked\ndescription: Reviews pull requests for missing tests; use when asked to review a PR\n---\nsteps');
  mkdirSync(join(proj, '.claude', 'skills'), { recursive: true });
  symlinkSync(join(root, 'checkout', 'linked'), join(proj, '.claude', 'skills', 'linked'));
  const r = run(proj, user, null);
  assert.ok(r.inventory.skills.some(s => s.name === 'linked'));
});
