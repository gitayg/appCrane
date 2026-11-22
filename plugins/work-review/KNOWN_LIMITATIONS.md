# Known limitations

What work-review's numbers can and cannot tell you. Each item names the heuristic, where it is wrong, and which way the error leans. Add to this list when you find a case; don't remove an entry because it is unflattering.

## Dollars

- **List price, not a bill.** Usage is priced at Claude API list rates (`scripts/prices.mjs`). On a Team, Max or Enterprise seat this is the API-equivalent value of the work, not what was charged. Contract rates need `--prices`.
- **The table ages.** Rates are as of `PRICES_AS_OF`. A model released later is listed as unpriced and left out of the total, never guessed.
- **Not priced:** Batch API discounts, data-residency multipliers other than US-only, tool fees such as web search, and Bedrock or Vertex rates.

## Instruction quality

- **These are text tests, and they are measured.** The patterns in `scripts/classify.mjs` are scored against prompts a person labelled by meaning (`test/fixtures/work-review-labelled-prompts.json`). On 29 held-out prompts the patterns were not tuned on (labelled 2026-11-22):

  | Test | Precision | Recall | Typical miss |
  |---|---|---|---|
  | vague | 78% | 100% | "sounds good", "approved": a go-ahead it doesn't recognise is counted as vague |
  | done-criteria | 67% | 50% | "confirm it still builds", "only stop when every warning is gone" |
  | correction | 60% | 50% | "put that back", "I didn't ask you to change the CSS"; "Don't use new dependencies" is wrongly counted |
  | nudge | 100% | 20% | only a fixed list of words counts as a go-ahead |

  29 prompts is a small sample, so read these as a direction, not exact rates. They lean one way: vague prompts and their cost are overstated, and rework is understated, because half of real corrections are missed.
- **"Vague" ignores context.** A prompt counts as vague if it is short and names no file, code, error, route or URL. "Fix it like yesterday" in a session full of context is flagged although it was clear enough.
- **Rework is "followed by a correction or interrupt".** A correction about something else, or an interrupt to add information, is still counted.
- **Cost is charged to the prompt that started the turn.** The cost of work Claude chose to do on its own lands on that prompt.

## Outcomes

- **Commits are found in the session's own `git commit` output** (the printed SHA, or the `-m` subject). A commit made outside Claude Code, or one whose output was hidden, isn't counted. That raises cost per commit.
- **Commits are not quality.** Cost per commit rewards small commits. Read it next to rework share, never alone.

## Mechanical waste

- **Floors, not totals.** Re-reads, idle re-runs and error output are priced once at 1.25× input. They are then re-read on every later turn, so the real cost is higher.
- **"Unchanged" means "no edit by Claude in between".** A file changed by the user or another process between two reads still counts as a redundant read.

## Model fit

- **An upper bound.** It assumes the cheaper model needs the same tokens and turns, and a model switch loses the prompt cache at first. Judge a switch with `--baseline`, by cost per commit next to rework.
- **"Small or read-only" is about the work, not its difficulty.** A subagent that edited nothing may still have needed careful reasoning.

## MCP tool results

- **Tokens are characters ÷ 4,** priced once at 1.25× input: a floor, since each result is re-read on later turns.
- **Only MCP tools are ranked.** Built-in tools with large output appear under oversized outputs instead.

## Setup audit

- **"Unused" needs history.** It is reported only with at least 10 sessions, and only for this machine's transcripts. A skill used on another machine reads as unused here.
- **Overlap is word overlap.** Two skills with similar wording but distinct jobs can be flagged; two that do the same thing in different words can be missed.

## The read-only review

- **`disallowed-tools` removes Write, Edit and NotebookEdit while the review runs,** so it cannot edit files that way.
- **Bash is not removed.** The review needs it for the analyzer. A shell command could still change files, so the read-only promise rests on the review's instructions for Bash, not on a permission.
