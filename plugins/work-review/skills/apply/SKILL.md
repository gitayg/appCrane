---
name: apply
description: Apply numbered fixes from the latest work review in this conversation, such as CLAUDE.md lines, permission allowlists, skills or subagent model settings, then save a baseline so the next review can tell whether they worked. Runs only when the user types /work-review:apply with the fix numbers or "all".
argument-hint: "<fix numbers, e.g. 1 3> | all"
disable-model-invocation: true
allowed-tools: Read, Edit, Write, Bash(node ${CLAUDE_PLUGIN_ROOT}/skills/work-review/scripts/analyze.mjs *)
---

# Apply work-review fixes

Fixes to apply: **$ARGUMENTS**

1. **Find the fixes.** Use the numbered fixes of the most recent work review in this conversation. If there is none, or a number given here isn't in it, say so and stop: run `/work-review` first. Never invent a fix that the review didn't propose.
2. **Apply exactly those numbers**, nothing more. Before each edit, read the file as it is now; if it changed since the review so the diff no longer fits, say so and skip that fix rather than force it.
   - **A `CLAUDE.md` edit:** keep the file's style, and keep rules short and imperative with the reason attached.
   - **A permission allowlist:** add only read-only or clearly safe commands, never broad patterns like `Bash(*)`, `rm`, `git push` or `curl` to arbitrary hosts.
   - **A new skill:** create `.claude/skills/<name>/SKILL.md` with a precise trigger `description`.
   - **A subagent model change:** set `model:` in that agent's frontmatter, as the review proposed.
3. **Save a baseline**, so the next review can say whether each fix worked:
   - run `node ${CLAUDE_PLUGIN_ROOT}/skills/work-review/scripts/analyze.mjs --json .claude/work-review/<today, YYYY-MM-DD>.json` with the same `--project` and `--since` the review used;
   - append one line per applied fix to `.claude/work-review/applied.md`: the date, the fix, and the signal it targets;
   - make sure `.claude/work-review/` is in `.gitignore`, since the reports quote prompts.
4. **Report** in a few lines: what was applied, what was skipped and why, and when to re-run `/work-review` to judge it (about two weeks).
