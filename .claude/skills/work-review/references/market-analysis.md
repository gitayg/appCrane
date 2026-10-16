# Market analysis: analyzing how people work with AI coding agents

Researched 2026-10-15. Sources are linked inline. Vendor claims (accuracy, ROI, "causal" impact) are not independently verified, and pricing is omitted where no vendor publishes it.

## The landscape in one table

| Segment | Examples | Data source | Finds *why* work was wasteful? | Emits fixes? |
|---|---|---|---|---|
| Anthropic first-party | `/insights`, `/doctor`, `/fewer-permission-prompts`, `/context`, `/usage`, OTel, Analytics dashboard | Local transcripts / telemetry | `/insights` does (an LLM narrative, per machine, up to 200 new sessions) | Allowlist diff (`/fewer-permission-prompts`), CLAUDE.md moves (`/doctor`) |
| Local transcript analyzers | ccusage, Claude-Code-Usage-Monitor, claude-code-log, sniffly, opcode, vibe-log, ccwhy/cclint, claude-token-report, Rudel | `~/.claude/projects/*.jsonl` | Mostly no: about 90% measure tokens and cost. ccwhy and claude-token-report flag re-reads and oversized output | Text tips only |
| Runtime guards | read-once hook, Smart Read Cache, Semantic Cache MCP | Hooks / MCP | They *prevent* re-reads rather than analyze | n/a |
| Enterprise SEI / AI-impact | Copilot metrics API, Cursor Analytics + Conversation Insights, Codex dashboard, DX, Jellyfish, LinearB, Swarmia, Faros, Span, Waydev | Telemetry + git + Jira | No. Outcomes and adoption (PRs, cycle time, spend). Faros claims "wasteful tokens" without publishing its method | No |
| LLM observability | LangSmith Insights, Braintrust Patterns/Topics, Arize Alyx/Phoenix, Langfuse, W&B Weave, Helicone | Traces shipped to a vendor | Yes, by clustering, but tuned for teams debugging *their own* agent product | Braintrust "copy pattern as prompt" comes closest |
| Self-improvement loops | claude-reflect, zolat retros, cursor Reflect, Continuous Learning skill, Spective | Hooks on correction phrases | Per-user, triggered by phrasing | CLAUDE.md / skill text, unverified |

## Key facts per segment

**Anthropic** ([commands](https://code.claude.com/docs/en/commands), [costs](https://code.claude.com/docs/en/costs#analyze-your-usage-patterns), [monitoring](https://code.claude.com/docs/en/monitoring-usage), [analytics](https://code.claude.com/docs/en/analytics))
- `/insights` writes `~/.claude/usage-data/report.html` covering what you work on, friction, and suggestions. It spends plan tokens, covers this machine only, and is not available in cloud sessions. Third-party write-ups (unverified) describe per-session "facets" and a "CLAUDE.md additions" section.
- `/doctor` flags unused skills, MCP servers and plugins by their context cost, as well as CLAUDE.md content that is duplicated or derivable. `/doctor prompt-audit` checks for stale or conflicting rules.
- OTel exports cost, tokens, LOC, commits, PRs and tool decisions. Prompt and tool content is redacted by default.
- The Teams/Enterprise dashboard shows lines accepted, DAU and PRs with Claude Code, matched by a 21-day attribution window. It is not available under ZDR.

**Local analyzers**
- [ccusage](https://npmjs.com/package/ccusage): cost per day, session and 5-hour block.
- [Usage Monitor](https://gittrend.io/repo/Maciek-roboblog/Claude-Code-Usage-Monitor): burn rate and limit prediction.
- [sniffly](https://osrepos.com/repo-chiphuyen-sniffly): error breakdown; may be unmaintained.
- [vibe-log](https://github.com/vibe-log/vibe-log-cli): prompt-quality score.
- [ccwhy](https://github.com/SingggggYee/claude-usage-analyzer): token sinks and anomaly sessions.
- [Rudel](https://feedbagel.com/post/rudel-open-source-analytics-dashboard-for-claude-code-and-codex-development-team): team dashboard, but it uploads full transcripts.

**Enterprise**
- [Cursor Conversation Insights](https://cursor.com/docs/account/teams/analytics) classifies sessions on-device: category, work type, and prompt specificity. It is the only privacy-preserving deep classifier.
- [Jellyfish](https://jellyfish.co/platform/claude-code-dashboard/), [LinearB](https://linearb.helpdocs.io/article/692cmb6vu7-configuring-claude-code-in-linear-b), [Swarmia](https://www.swarmia.com/changelog/2026-03-13-claude-code-otel), [DX](https://docs.getdx.com/connectors/claude-code-otel/) and [Faros](https://www.faros.ai/blog/claude-code-token-usage) all added Claude Code connectors in 2025–26.
- Span raised $25M in Nov 2025 for AI-code detection ([BusinessWire](https://www.businesswire.com/news/home/20251105703479/en/)).

**Observability**
- [LangSmith Insights](https://docs.langchain.com/langsmith/insights) clusters "poor interactions" by root cause.
- [Braintrust Patterns](https://www.braintrust.dev/docs/observe/patterns) finds recurring issues on a schedule and suggests a fix.
- [Arize Phoenix](https://arize.com/docs/phoenix/integrations/coding-agents/claude-code) and [Langfuse](https://langfuse.com/integrations/other/claude-code) both have Claude Code integrations.
- The [W&B Weave](https://docs.wandb.ai/weave/guides/integrations/claude_code.md) plugin does not scrub PII.

**Self-improvement**
- [claude-reflect](https://smithery.ai/skills/BayramAnnakov/claude-reflect) queues correction phrases and applies them to CLAUDE.md with `/reflect`, with `--scan-history` and `--dedupe` options.
- [zolat retros](https://claudepluginhub.com/plugins/zolat-retros-retros) uses Stop-hook retros and `/retro`.

## Demand signals
- Claude Code passed a $2.5B run-rate by Feb 2026; higher later figures are secondary estimates.
- Every major SEI vendor now integrates Claude Code, and the category is consolidating around "AI impact".
- Productivity evidence is contested. METR's 2025 RCT found experienced developers were 19% slower while believing they were faster ([eWeek](https://eweek.com/news/news-ai-tools-slow-developer-productivity-study)). In the Stack Overflow 2025 survey, 66% cite "almost right" AI output ([VentureBeat](https://venturebeat.com/ai/stack-overflow-data-reveals-the-hidden-productivity-tax-of-almost-right-ai-code)). Measurement is in demand because nobody is sure about the gains.
- No credible market size exists for this niche. AI coding tools overall are put at about $8.5B for 2026 by a secondary source, which is directional only.

## Jellyfish AI Engineering Trends (Sept 2026)

Source: [jellyfish.co/ai-engineering-trends](https://jellyfish.co/ai-engineering-trends/). The dataset is 294K engineers, 105M PRs and 1,300+ companies. Jellyfish says all comparisons are "correlational rather than causal". Most chart values are rendered interactively and could not be read as text.

The report has three sections: **AIDLC → ROI → Adoption**.
- **AIDLC**
  - Autonomous agent PR share.
  - Agentic-merged PRs: merged with AI-only review. The median company is at 0.6% and leaders are at 9%+.
  - Model usage per tool. In Claude Code, Opus 5 gained +10.4pp month over month in Jul→Aug.
  - Open-weight models: 0.7% of weekly engineers, up from about 0.2% in March.
  - Agent-skill categories: Cursor skill invocations, sorted into categories by an LLM.
- **ROI**
  - AI spend per developer-week. It is heavily concentrated: top users spend an order of magnitude more than the median, and the headline figure is "$949/month" for top users.
  - Token consumption.
  - **Productivity by token consumption**: developer-weeks are put in 50 bins by tokens and compared on merged PRs. Throughput rises with tokens, but sub-linearly, and **tapers at the high end**.
- **Adoption**: Access %, WAU %, and AI Code % (AI-assisted merged additions divided by all merged additions).

What `work-review` borrows:
- **Returns curve**: `overcomplication.returnsCurve` bins one user's sessions by tokens and shows edits+commits per bin. This is Jellyfish's diminishing-returns view at the level of one person. Org dashboards show *that* spend tapers off. The transcript shows *which* sessions and *which prompts* did it.
- **Spend concentration**: the per-prompt cost attribution in `instructionQuality` explains the top-user tail at the level of individual instructions. Jellyfish can only see the totals.
- **Model right-sizing**: per-tool model mix becomes the `big-model-small-task` flag.
- **Skill usage**: `overcomplication.skillsInvoked` counts the skills actually used, so unused ones can be removed.
- **Roadmap for AppCrane team mode**:
  - spend distribution across apps and users;
  - share of commits made autonomously by the builder;
  - an agentic-merge rate, meaning changes deployed with no human look. This is Jellyfish's 9% metric, on AppCrane's own deploy log.

## Gaps nobody fills well
0. **Instruction quality, priced.** Org tools see spend, and Cursor scores "prompt specificity" without attaching a cost. Nobody charges each prompt for the work it triggered and shows a cheaper rewrite.
1. **Semantic redundancy across sessions**, e.g. re-explaining the same context, rediscovering the build command, redoing the same fix. Today's detection is lexical: the same file read twice.
2. **Pricing per pattern.** Cost tools don't know why tokens were spent, and friction tools don't put a price on the friction.
3. **Routing findings into the right artifact**, with a diff: CLAUDE.md rule, skill, hook, allowlist, or removing an MCP server.
4. **Before/after verification** that a change reduced the friction.
5. **Team-level pattern mining that stays private**: extract abstract findings locally, aggregate them across teammates, and propose checked-in skills.
6. **Cross-agent coverage**: Claude Code, Codex and Cursor in one review.
7. **Linking session patterns to outcomes**: thrash leading to reverts or rework.

## How `work-review` positions against this
- **Built:** a cost for every prompt, comparing vague and anchored prompts and prompts with and without done-criteria, plus the rework cost and prompt rewrites (gap 0); overcomplication flags and a returns curve; deterministic detectors with token estimates (gaps 2 and 3, partly), destination routing with diffs (gap 3), a baseline plus `applied.md` verification loop (gap 4), and deferring to `/fewer-permission-prompts`, `/doctor` and `/insights` instead of duplicating them.
- **Cross-session repetition:** detected by lexical shingle similarity, followed by a manual read of the transcripts (gap 1, partly).
- **Roadmap:**
  - embedding or LLM clustering of re-explanations (gap 1);
  - a redacted findings export for team aggregation, which fits AppCrane well because it already holds every app's builder transcripts under `DATA_DIR/apps/<slug>/claude-projects` (gap 5);
  - Codex and Cursor transcript parsers (gap 6);
  - joining sessions to git reverts (gap 7).
