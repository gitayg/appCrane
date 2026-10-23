---
name: work-review
description: Analyze how the user actually works with Claude Code — mine local session transcripts for costly instructions (vague prompts that send Claude searching, prompts that end in a correction, missing done-criteria, overcomplicated setups), redundancy (re-reading unchanged files, re-running commands with nothing changed, retry loops, repeated instructions across sessions), friction (tool errors, permission denials, corrections, interrupts, compactions) and missed leverage, then turn the findings into concrete fixes (CLAUDE.md lines, skills/slash commands, permission allowlists, hooks). Use when the user asks to review, audit or retro their Claude usage, asks "where am I wasting tokens/time", "how can I prompt better", "what should go in CLAUDE.md", "what should I automate", or wants a weekly/monthly work review.
---

# Work review

Find where working with Claude is redundant or rough, and propose specific changes that remove it. The biggest lever is usually the instructions themselves. A vague or overcomplicated brief makes Claude spend tokens finding out what the user already knew, or doing the wrong thing first. So lead with instruction quality, then the mechanical waste. The analysis is quantitative first (a script over the transcripts), then qualitative (you read the flagged moments), then prescriptive (diffs the user can accept).

## Where this fits

Claude Code already ships tools that overlap with parts of this skill. Don't redo their work; point the user to them:
- `/insights` gives an LLM-written narrative of friction, and spends plan tokens to do it.
- `/fewer-permission-prompts` writes a permission allowlist from the transcripts. For permission friction, recommend running it rather than hand-writing an allowlist.
- `/doctor` covers config hygiene: unused MCP servers and skills, duplicated CLAUDE.md content, and conflicting rules (`/doctor prompt-audit`).

What this skill adds:
- deterministic counts with an estimated token cost, so you can rank fixes by what they save;
- evidence-backed diffs that go to the right destination (a CLAUDE.md rule, a skill, a hook, or a settings entry);
- before/after verification that a change actually reduced the waste.

See `references/market-analysis.md` for the full landscape.

Analysis is local. Transcripts can contain secrets and private code: never send them, or excerpts of them, to any external service, and quote at most a sentence of any prompt in your report. The one exception is the opt-in daily upload in §5. It sends a fixed, scrubbed summary to the Work Review hub on app.opswat.com, through `scripts/upload.mjs` only. Never send review data any other way.

## 1. Measure

Run the analyzer (Node, no dependencies):

```bash
node <skill-dir>/scripts/analyze.mjs --since 30 --json /tmp/work-review.json
```

Options: `--project <substr>` limits to one project (transcript dirs are named after the cwd, e.g. `-home-user-appCrane`); `--session <id>`; `--since <days>` (default 30); `--include-subagents`; `--top <n>`; `--root <dir>` for a different transcript root. The default root is `$CLAUDE_CONFIG_DIR/projects` or `~/.claude/projects`. In AppCrane, an app's builder transcripts live on the host at `$DATA_DIR/apps/<slug>/claude-projects`.

**Dollars.** The analyzer prices every message at Claude API list rates, per model. Cache writes are 1.25× or 2× input depending on TTL, cache reads are priced per model, and fast mode costs 2×. The prices table is in `analyze.mjs` and carries its as-of date. On a Team, Max or Enterprise seat, `/usage` mostly shows plan-limit bars, because "usage inside the seat allowance isn't metered in dollars" ([costs docs](https://code.claude.com/docs/en/costs.md)). So the analyzer's figure is the *API-equivalent value* of the work. Always call it that, never "your bill". The actual dollar spend on a Team plan (usage credits beyond the seat) is in the claude.ai admin spend report. If the organisation pays contract rates, pass `--prices <file.json>` with `{ "<model prefix>": { "in", "out", "read" } }` in $ per million tokens, so the figures match the `modelPricing` managed setting. Models not in the table are listed as unpriced, never guessed.

By default, scope to the current project when the user is asking about "this repo", and to everything otherwise. If no transcripts are found, say so and stop. Don't fabricate a review.

## 2. Understand

The script prints a summary table and ranked lists. Read `/tmp/work-review.json` for the details: `cross.*` holds cross-session patterns, `worstSessions` the sessions with the most waste signals, and each session's `file` is the transcript path.

For the top 3–5 signals, open the actual transcript around the flagged event (`grep -n` for the file path, command or error text, then read about 40 lines around it) and decide what really happened. The heuristics over-flag. Discard or downgrade these:
- A re-read after an external change (a `git pull`, a formatter, the user editing the file).
- A test re-run while waiting on a server, or a deliberate flake check.
- Errors that were the point, such as probing whether a file exists.
- "Corrections" that are really a new requirement rather than Claude getting it wrong.

### Instruction quality (lead with this)

The analyzer charges every token to the human prompt that triggered it: everything up to the next prompt, priced in fresh-input-token equivalents (output ×5, cache write ×1.25, cache read ×0.1). `instructionQuality` in the JSON compares groups of prompts by their median cost, the lookups Claude did before its first edit, and how often each led to rework:
- vague prompts against anchored ones (naming a file, code, an error or a URL);
- prompts with done-criteria against prompts without.

`reworkCost` is what prompts followed by a correction or interrupt cost.

For the 3 costliest entries in `costliestBadPrompts`, read the prompt and what Claude did next, and work out what was missing. Usually it is one of these:
- **where**: a file, function, or screen;
- **what done looks like**: a test that passes, or an output;
- **a constraint Claude violated**: "don't touch the API", "keep the old flag";
- **the actual error text**: as opposed to "it's broken".

Then show the user a rewrite of that prompt: the same request, one or two sentences longer, with the missing piece added. Show what that piece would have saved, e.g. "the 14 lookups before the first edit, ~40k tokens". This is the most useful part of the review, so make it concrete. Don't lecture about prompting in general.

If the same missing context shows up across sessions (the same "where", the same constraint), it doesn't belong in prompts. Put it in `CLAUDE.md` once.

Don't punish short prompts in general. "fix the failing test in `billing.test.js`" is short and anchored. A cheap vague prompt that worked is fine. Flag cost, not style.

### Overcomplication

`overcomplication` flags sessions where effort didn't turn into output:

| Flag | What it suggests | Simpler alternative |
|---|---|---|
| `heavy-for-output` (top 20% tokens, ≤2 edits/commits) | Exploring without a target, or a Q&A session. Check which | Anchor the prompt, or accept it: research sessions are fine |
| `long-brief-small-change` (prompt >3k chars, ≤2 edits) | Pasted logs or specs where one line would do | Paste the failing excerpt and say what done is |
| `subagent-fanout` (≥3 subagents, ≤3 edits) | Orchestration for a task that needed none | Ask directly; save subagents for broad independent searches |
| `ceremony` (todo/plan calls outnumber edits) | Process overhead on small work | Skip plan mode and todos for one-step tasks |
| `micromanaged` ("continue"/"yes" prompts, <3 tool calls per prompt) | Approving step by step | State the whole goal and done-criteria once; widen permissions for safe steps |
| `big-model-small-task` | Top-tier model on a trivial ask | A smaller or faster model, or lower effort |

`medianBaselineContextTokens` is the always-on context each session pays before any work: the system prompt, tools, MCP servers, skills and CLAUDE.md. If it is large (over about 40k), the fix is removal, not addition, so point to `/doctor`.

`returnsCurve` bins sessions by tokens and shows output (edits + commits) per bin, similar to Jellyfish's productivity-by-token curve. If output per token falls sharply in the top bins, the biggest sessions are the place to simplify. These are usually long sessions doing several tasks, so split them and `/clear` between tasks.

### Mechanical waste

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

1. **Headline**: 2–3 sentences, giving the biggest source of waste and what fixing it would save, in dollars at API list prices where priced, and in counts from the data (e.g. "prompts that ended in a correction took 31% of your spend", "you restated the test command in 6 of 9 sessions").
2. **Your costliest instructions**: up to 3 before/after prompt rewrites, each with what it would have saved.
3. **Top fixes** (at most 5, ranked by occurrences × cost: use `totals.wastedTokensEstimate`, which is a floor because the output then stays in context for the rest of the session). Each one has:
   - the evidence: the count, the sessions, and one short quoted example;
   - the exact change: a ready-to-apply diff to `CLAUDE.md` or `.claude/settings.json`, a new `SKILL.md` skeleton, or a hook config;
   - confidence (high/medium/low), and why.
4. **Habits worth keeping**: one or two things that are working well, such as a high cache hit rate or few corrections. A review that only criticises gets ignored.
5. **Numbers**: the summary table from the script.

Don't overcomplicate the fixes either. Prefer removing to adding: deleting a stale CLAUDE.md rule, an unused MCP server or a needless step beats adding a new skill. Propose a skill or hook only when a procedure really repeats.

Then ask which fixes to apply. Apply only the ones the user approves. When you apply a fix:
- for a `CLAUDE.md` edit, keep the file's style and keep rules short and imperative, with the reason attached;
- for a permission allowlist, add only read-only or clearly safe commands, never broad patterns like `Bash(*)`, `rm`, `git push` or `curl` to arbitrary hosts;
- for a new skill, create `.claude/skills/<name>/SKILL.md` with a precise trigger `description`.

## 4. Verify

A fix only counts if the waste it targeted goes down. When you apply fixes, save the report as a baseline: `--json .claude/work-review/<YYYY-MM-DD>.json`. Make sure `.claude/work-review/` is gitignored, since the reports quote prompts. Also append one line per applied fix to `.claude/work-review/applied.md` with the date, the fix, and the signal it targets (e.g. `recurringCorrections: "don't mock the db"`).

On a later run, if a baseline exists:
- run with `--since <days since that baseline>` so only sessions after the fix are counted;
- for each line in `applied.md`, compare the targeted signal, normalised per session;
- say plainly which fixes worked, which didn't, and which have too few sessions to tell (fewer than about 5).

A CLAUDE.md rule that didn't reduce its signal is just context overhead. Propose rewriting it or removing it.

Suggest re-running about two weeks after applying fixes.

## 5. Share (daily upload to the Work Review hub)

`scripts/upload.mjs` sends a rolling 7-day summary, at most once a day, to the Work Review hub. The hub is an AppCrane app on app.opswat.com; its source is in `examples/work-review-hub/` in the appCrane repo. There each developer sees their own trend, and app admins see team numbers.

**What leaves the machine:** numeric totals, flags, the returns curve, recurring-correction counts, and up to 5 prompt excerpts.
- Excerpts are at most 160 characters. Secrets, emails, URLs, IPs, paths and long tokens are scrubbed out.
- The hub shows excerpts to their author only, never to admins.

**What never leaves:** transcripts, file contents, file paths, shell commands, error text, project names, session IDs.

**Security:**
- Uploads go over HTTPS only, and only to `app.opswat.com` or its subdomains. The host is pinned in code.
- Redirects are refused.
- Auth uses an **app sign-in key** (`dhk_uak_*`) that the developer issues for the hub app only. The key signs in to that one app, is refused by the rest of AppCrane, and the hub accepts it only for uploads. It cannot read or delete reports. The uploader refuses a full `dhk_user_*` key.
- The key is read from stdin at setup and stored in `~/.config/work-review/key` with owner-only permissions (0600); the uploader refuses a key file others can read.
- AppCrane's proxy checks the key and passes the verified identity to the hub, which re-validates every field.
- Each payload sent is kept in `~/.config/work-review/sent/` for audit.

When the user asks to set it up, walk them through these steps. Don't do any of them for them:
1. In AppCrane, open the MCP page, go to **App sign-in keys**, and issue a key for the Work Review hub app (it expires after 180 days by default). Then run:
   `node <skill-dir>/scripts/upload.mjs --setup --url https://<hub-app-host>`, pasting the key at the prompt (it is read from stdin).
2. Preview the payload: `node <skill-dir>/scripts/upload.mjs --dry-run`.
3. Send one now: `node <skill-dir>/scripts/upload.mjs --force`.
4. Make it daily by adding this to their own `~/.claude/settings.json`. The hook returns at once and uploads in the background only if the last upload is more than 24h old:
   ```json
   { "hooks": { "SessionStart": [ { "hooks": [ { "type": "command", "command": "node ~/.claude/skills/work-review/scripts/upload.mjs --hook" } ] } ] } }
   ```
   This assumes a personal install at `~/.claude/skills/work-review`. Adjust the path otherwise.

To stop: `upload.mjs --disable`, or remove the hook. To erase what was uploaded, use "Delete all my data" on the hub. Errors go to `~/.config/work-review/upload.log` and never interrupt a session.
