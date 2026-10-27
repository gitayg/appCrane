# work-review (Claude Code plugin)

Reviews how you work with Claude Code: what each prompt cost and why,
redundancy and friction in your sessions, and whether your setup (CLAUDE.md,
subagents, skills, MCP servers, hooks, permissions) is simpler or more
complicated than the docs recommend. Every finding comes with a concrete
fix. Optionally, it uploads a redacted daily summary to a Work Review hub
(`examples/work-review-hub/` in this repository).

## Install

```
/plugin marketplace add gitayg/appCrane
/plugin install work-review@appcrane
```

Then ask Claude to "review how I work with Claude", or run `/work-review:work-review`.

## Roll it out to a team

In managed settings (or a repository's `.claude/settings.json`):

```json
{
  "extraKnownMarketplaces": {
    "appcrane": { "source": { "source": "github", "repo": "gitayg/appCrane" }, "autoUpdate": true }
  },
  "enabledPlugins": { "work-review@appcrane": true }
}
```

Auto-update is off by default for third-party marketplaces, so `autoUpdate`
is set explicitly. `version` in `.claude-plugin/plugin.json` pins what users
get: bump it on every change that should reach them.

## What runs where

- **Analysis is local.** It reads `~/.claude/projects` transcripts and the
  project's setup files, and nothing is sent.
- **The start-up hook does nothing until a developer runs the uploader's
  `--setup`.** Setup requires an app sign-in key (`dhk_uak_*`) and at least
  one `--allow-remote` repository pattern. See the skill's step 5.

## Check

```
claude plugin validate ./plugins/work-review --strict
claude plugin validate . --strict
```
