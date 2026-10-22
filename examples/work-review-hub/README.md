# Work Review hub

Receives the daily redacted snapshots uploaded by the `work-review` Claude Code
skill (`.claude/skills/work-review/scripts/upload.mjs`) and shows each developer
their trends: spend, rework share, vague vs anchored prompts, overcomplication
flags and their costliest prompts. App admins also get a Team tab with numbers
only.

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
   with their personal `dhk_*` key.

## Trust model

- **Who is calling:** read only from `X-AppCrane-User-Email` and
  `X-AppCrane-App-Role`. AppCrane's proxy sets these after verifying the SSO
  session or the `dhk_*` key, and strips any copy a client sends.
- **Storage:** each person's data sits under a hash of their email. Excerpts are
  returned only to their author. `/api/team` (admins) returns numbers only.
- **Uploads:** must send `application/json` and `X-Work-Review-Client`, which
  blocks cross-site form posts (CSRF). Bodies are capped at 64 KB. Every field
  is re-validated and unknown fields are dropped. Excerpts over 200 characters,
  or that look like a secret, are refused.
- **Dashboard:** renders stored text with `textContent` only, and is served with
  a strict CSP.
- **Your data:** users can delete everything they uploaded from the dashboard.
