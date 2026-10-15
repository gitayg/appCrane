---
name: work-review
description: Analyze how the user actually works with Claude Code — mine local session transcripts for redundancy (re-reading unchanged files, re-running commands with nothing changed, retry loops, repeated instructions across sessions), friction (tool errors, permission denials, corrections, interrupts, compactions) and missed leverage, then turn the findings into concrete fixes (CLAUDE.md lines, skills/slash commands, permission allowlists, hooks). Use when the user asks to review, audit or retro their Claude usage, asks "where am I wasting tokens/time", "what should go in CLAUDE.md", "what should I automate", or wants a weekly/monthly work review.
---

# Work review

Find where working with Claude is redundant or rough, and propose specific changes that remove it. The analysis is quantitative first (a script over the transcripts), then qualitative (you read the flagged moments), then prescriptive (diffs the user can accept).

Everything stays local. Transcripts can contain secrets and private code: never send them, or excerpts of them, to any external service, and quote at most a sentence of any prompt in your report.

## 1. Measure

Run the analyzer (Node, no dependencies):

```bash
node <skill-dir>/scripts/analyze.mjs --since 30 --json /tmp/work-review.json
```

Options: `--project <substr>` limits to one project (transcript dirs are named after the cwd, e.g. `-home-user-appCrane`); `--session <id>`; `--since <days>` (default 30); `--include-subagents`; `--top <n>`; `--root <dir>` for a different transcript root. The default root is `$CLAUDE_CONFIG_DIR/projects` or `~/.claude/projects`. In AppCrane, an app's builder transcripts live on the host at `$DATA_DIR/apps/<slug>/claude-projects`.

By default, scope to the current project when the user is asking about "this repo", and to everything otherwise. If no transcripts are found, say so and stop. Don't fabricate a review.

## 2. Understand

The script prints a summary table and ranked lists. Read `/tmp/work-review.json` for the details: `cross.*` holds cross-session patterns, `worstSessions` the sessions with the most waste signals, and each session's `file` is the transcript path.

For the top 3–5 signals, open the actual transcript around the flagged event (`grep -n` for the file path, command or error text, then read about 40 lines around it) and decide what really happened. The heuristics over-flag. Discard or downgrade these:
- A re-read after an external change (a `git pull`, a formatter, the user editing the file).
- A test re-run while waiting on a server, or a deliberate flake check.
- Errors that were the point, such as probing whether a file exists.
- "Corrections" that are really a new requirement rather than Claude getting it wrong.

Signals and what they usually mean:

| Signal | Typical root cause | Typical fix |
|---|---|---|
| Same instruction in ≥2 sessions | Knowledge lives in the user's head, not the repo | Line in `CLAUDE.md`, or a skill/slash command if it's a multi-step procedure |
| Recurring correction | Claude defaults to the wrong convention | `CLAUDE.md` rule stated positively, with the reason |
| Redundant reads of the same file | Large file, or lost context after compaction | `CLAUDE.md` map of where things live; read with offset/limit; split the file |
| Command re-run with no edit | Polling, or a flaky or slow check | Background run plus wait; fix the flake; document the right check |
| Retry loop / edit misses | Stale view of the file, ambiguous `old_string` | Re-read before editing; smaller unique anchors |
| Permission denials on safe commands | Missing allowlist | `permissions.allow` entries in `.claude/settings.json` |
| Frequent identical shell commands | A routine step done by hand | Hook (e.g. format on edit) or script; allowlist it |
| Oversized outputs | `cat` of logs or builds, unbounded test output | `| tail -n 50`, `--quiet` flags; note in `CLAUDE.md` |
| Search bursts (≥8 Grep/Glob) | Codebase is hard to navigate | Architecture map in `CLAUDE.md`; Explore subagent |
| Compactions / very long sessions | One session doing several tasks | Split tasks, `/clear` between them, hand off notes in a file |
| Low parallel-call share | Independent reads done one by one | Usually a model habit; mention it, but it's rarely the user's fix |
| Low cache hit rate | Frequently changing system prompt or CLAUDE.md, long idle gaps | Keep CLAUDE.md stable; batch work |

Before proposing a `CLAUDE.md` line, read the existing `CLAUDE.md`, `.claude/settings.json` and `.claude/skills/`. Don't propose what's already there. If a rule exists and Claude still gets corrected on it, the fix is to rewrite that rule (clearer, with the reason, placed earlier), not to add a duplicate.

## 3. Prescribe

Write the review in this shape. Keep it short, because the user wants actions, not a dashboard:

1. **Headline**: 2–3 sentences, giving the biggest source of waste and what fixing it would save, in counts from the data (e.g. "you restated the test command in 6 of 9 sessions").
2. **Top fixes** (at most 5, ranked by occurrences × effort saved). Each one has:
   - the evidence: the count, the sessions, and one short quoted example;
   - the exact change: a ready-to-apply diff to `CLAUDE.md` or `.claude/settings.json`, a new `SKILL.md` skeleton, or a hook config;
   - confidence (high/medium/low), and why.
3. **Habits worth keeping**: one or two things that are working well, such as a high cache hit rate or few corrections. A review that only criticises gets ignored.
4. **Numbers**: the summary table from the script.

Then ask which fixes to apply. Apply only the ones the user approves. When you apply a fix:
- for a `CLAUDE.md` edit, keep the file's style and keep rules short and imperative, with the reason attached;
- for a permission allowlist, add only read-only or clearly safe commands, never broad patterns like `Bash(*)`, `rm`, `git push` or `curl` to arbitrary hosts;
- for a new skill, create `.claude/skills/<name>/SKILL.md` with a precise trigger `description`.

## 4. Track (optional)

If the user wants to see a trend, save the JSON with a date (`.claude/work-review/<YYYY-MM-DD>.json`, gitignored) and compare its `totals` with the previous run, reporting which signals went down after the fixes. Suggest re-running about two weeks after applying fixes.
