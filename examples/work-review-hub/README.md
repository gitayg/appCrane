# Work Review hub

Receives the daily redacted snapshots uploaded by the `work-review` Claude Code
skill (`.claude/skills/work-review/scripts/upload.mjs`) and shows each developer
their trends: spend, rework share, vague vs anchored prompts, overcomplication
flags and their costliest prompts. App admins get a Team tab of team-wide totals, without names.

No dependencies; Node 22+. Storage is JSON files under `DATA_DIR/reports/`, one
snapshot per user per day, pruned after `RETENTION_DAYS` (default 180).

## Deploy on AppCrane (app.opswat.com)

1. Put this folder in its own git repo (AppCrane builds an app from a repo root).
2. Create the app in AppCrane. Keep the default auth mode, which runs it behind
   `forward_auth` and SSO. **Never `headless`:** the app has no login of its own
   and refuses any request without AppCrane identity headers.
3. Give developers the `user` role on the app, and team leads `admin`.
4. Deploy. The health check is `/api/health`.
5. Each developer runs the skill's `upload.mjs --setup --url https://<app host>`
   with an **app sign-in key** (`dhk_uak_*`) they issue for this app in
   AppCrane (MCP page → App sign-in keys). That key signs in to this app only,
   and is refused by the rest of AppCrane.

## Trust model

- **Who is calling:** read only from `X-AppCrane-User-Email` and
  `X-AppCrane-App-Role`. AppCrane's proxy sets these after verifying the SSO
  session or the app sign-in key, and strips any copy a client sends.
- **What an app key can do:** AppCrane adds `X-AppCrane-Auth-Via: app-key` when
  the caller used one. The hub then allows `POST /api/reports` only, so a key
  copied off a laptop cannot read or delete that person's reports.
- **Storage:** each person's data sits under a hash of their email. Excerpts are
  returned only to their author.
- **Team view:** `/api/team` (admins) returns aggregates only: medians, totals,
  and how many people have each finding. It never returns a row per person or
  any name. It shows only a count until at least `TEAM_MIN_PEOPLE` people (default
  5, never below 3) have uploaded in the last 14 days.
- **Uploads:** must send `application/json` and `X-Work-Review-Client`, which
  blocks cross-site form posts (CSRF). Bodies are capped at 64 KB. Every field
  is re-validated and unknown fields are dropped. Excerpts over 200 characters,
  or that look like a secret, are refused.
- **Dashboard:** renders stored text with `textContent` only, and is served with
  a strict CSP.
- **Your data:** users can delete everything they uploaded from the dashboard.

## Policy: not for performance reviews

The hub exists so each developer can see how they work with Claude and improve
it. Admins see team-wide patterns, such as "4 of 9 people have subagents they
never use", in order to fix shared setup and training. They never see a
ranking or one person's numbers. Keep it that way: when people expect to be
judged on the numbers, the numbers stop being honest.
