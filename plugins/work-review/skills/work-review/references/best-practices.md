# Claude Code setup: what the docs recommend

The yardstick for `scripts/audit-setup.mjs` and for your judgement when you read a flagged file. Rules come from the Claude Code docs as read on 2026-10-25, with short verbatim quotes. Re-read the linked page before quoting a rule to the user, since docs change. Where the docs say nothing, this file says so. Never present this skill's own heuristics as Anthropic guidance.

Sources:
- [best-practices](https://code.claude.com/docs/en/best-practices.md)
- [memory](https://code.claude.com/docs/en/memory.md)
- [sub-agents](https://code.claude.com/docs/en/sub-agents.md)
- [skills](https://code.claude.com/docs/en/skills.md)
- [mcp](https://code.claude.com/docs/en/mcp.md)
- [hooks](https://code.claude.com/docs/en/hooks.md)
- [permissions](https://code.claude.com/docs/en/permissions.md)
- [permission-modes](https://code.claude.com/docs/en/permission-modes.md)
- [costs](https://code.claude.com/docs/en/costs.md)

## The one-line test

**"Would removing this cause Claude to make mistakes? If not, cut it."** (best-practices). It applies to every CLAUDE.md line, agent, skill, server and hook. The usual fix for an overcomplicated setup is deletion.

## CLAUDE.md

- **Keep each file under 200 lines.** "target under 200 lines per CLAUDE.md file. Longer files consume more context and reduce adherence." (memory)
- **Leave out what the code already shows:** "Anything Claude can figure out by reading code", and "File-by-file descriptions of the codebase" (best-practices).
- **A procedure is a skill.** Move "a section of CLAUDE.md [that] has grown into a procedure rather than a fact" into a skill (skills).
- **Imports organise, they don't save:** "Imports help you organize a long file but don't reduce its context cost" (memory). The audit counts imported text as always-on.
- **Area-specific rules go where they apply.** Nested CLAUDE.md files "load on demand", and `.claude/rules/*.md` with `paths:` load only when matching files are touched (memory).
- **Emphasis is for one stubborn rule:** "If Claude keeps skipping one instruction, add emphasis such as 'IMPORTANT' to that line alone" (best-practices). A file full of MUST and NEVER is dated prompting; this threshold is ours.

## Subagents (`.claude/agents/*.md`)

- **Use one for isolation:** when "a side task would flood your main conversation with search results, logs, or file contents you won't reference again" (sub-agents).
- **Stay in the main thread** when "multiple phases share significant context, such as planning, implementation, and testing" (sub-agents).
- **Only `name` and `description` are required.** Claude "uses each subagent's description to decide when to delegate". Unknown frontmatter fields are ignored silently (sub-agents).
- **Restrict tools.** Omitting `tools` inherits every tool. The docs' example allows only Read, Grep, Glob and Bash (sub-agents).
- **Subagents count against the same usage limits** as the main conversation. Route simple work to a cheaper model, e.g. `model: haiku` (sub-agents, costs).
- **Not documented:** a recommended number of agents, or a head-to-head comparison of a single agent with skills against a multi-agent setup. The "single agent + skills often wins" claim circulating publicly is not on these pages, so present it as a rule of thumb, not as Anthropic guidance. Agent teams are documented as costly: "Keep teams small", and roughly 7× more tokens when teammates run in plan mode (costs).

## Skills (`.claude/skills/<name>/SKILL.md`)

- **Progressive disclosure:** "Unlike CLAUDE.md content, a skill's body loads only when it's used". Only descriptions load up front (skills).
- **Commands are merged into skills:** "Prefer a skill for new work, since skills also support supporting files" (skills).
- **Description:** put the key use case first. Description and `when_to_use` are "truncated at 1,536 characters" in the listing (skills).
- **Side effects:** use `disable-model-invocation: true`, because "You don't want Claude deciding to deploy because your code looks ready" (skills).
- **One copy per skill (ours):** the docs do not cover a skill installed twice. Plugin skills are namespaced, so a personal copy beside a plugin's does not replace it: both load and compete for the same requests, and a plugin update moves only one. `skill-installed-twice` flags it; a symlink to the same file is one install.
- **Size:** "Keep `SKILL.md` under 500 lines. Move detailed reference material to separate files." (skills)
- **Scripts are "executed, not loaded".** Reference them via `${CLAUDE_SKILL_DIR}` (skills).

## MCP servers

- **Tool search is on by default:** "MCP tools are deferred and discovered on demand", and "Only tool names and server instructions load at session start" (mcp). So the number of servers matters less than it used to. There is no documented per-server cap or recommended count.
- **Disable unused servers** (`/mcp`). Prefer CLI tools (`gh`, `aws`, `gcloud`), which "don't add any per-tool listing" (costs, best-practices).

## Hooks

- **Use hooks for what must always happen:** "Unlike CLAUDE.md instructions which are advisory, hooks are deterministic and guarantee the action happens" (best-practices).
- **Hard allow/deny belongs in permissions:** "use the permission system rather than a hook to enforce a hard allow or deny" (hooks). For static facts, "prefer CLAUDE.md" (hooks).
- **Keep SessionStart fast:** "SessionStart runs on every session, so keep these hooks fast". Use matchers or `if` to avoid running a hook on every tool (hooks).

## Permissions

- **Order is deny, then ask, then allow; the first match wins.** "An allow rule can't carve an exception out of a deny rule" (permissions).
- **Prefer narrow rules** such as `Bash(npm test)`. "`Bash(*)` is equivalent to `Bash` and matches all Bash commands" (permissions).
- **Auto mode drops broad allows when it starts:** blanket `Bash(*)`, wildcarded interpreters such as `Bash(python*)`, package-manager run commands, and `Agent` allows (permission-modes).
- **Deny rules hold everywhere:** "Deny rules block in every mode, including `bypassPermissions`" (permission-modes).

## Keep it simple

- **Keep it concise:** "Bloated CLAUDE.md files cause Claude to ignore your actual instructions!" Start with `/init`, then refine (best-practices).
- **Skip the plan when the change is small:** "If you could describe the diff in one sentence, skip the plan" (best-practices).
- **Give Claude a check it can run:** tests, a build, or a screenshot to compare (best-practices).
- **`/clear` between unrelated tasks;** after two failed corrections, clear and restart (best-practices).
