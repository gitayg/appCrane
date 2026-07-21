# AppCrane — Claude Code Notes

## Distribution & updating
AppCrane is **not** published to npm (`package.json` is `private`). It's a self-hosted
app distributed from its GitHub repo — see `repository` in `package.json`
(github.com/gitayg/appCrane). Fresh install: the `install.sh` / `git clone` steps in
README.md. An existing deployment **self-updates from its own git `origin`**: a platform
admin POSTs `/api/self-update`, which runs `git fetch origin` + `git reset --hard
origin/main`, `npm install`, rebuilds the admin SPA, and restarts. So the source of truth
for any deployed box is its `git remote -v` — you don't pull from a separate distribution
channel.

## Data Persistence
If settings or configuration appear wiped, always check `/data` first.
AppCrane stores all persistent state (database, env vars, app configs) under the `DATA_DIR` path (default: `./data`).
Settings that "disappear" are usually still on disk — the process may have restarted pointing at a different working directory or `DATA_DIR` env var.
