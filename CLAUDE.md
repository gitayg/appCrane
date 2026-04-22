# AppCrane — Claude Code Notes

## Data Persistence
If settings or configuration appear wiped, always check `/data` first.
AppCrane stores all persistent state (database, env vars, app configs) under the `DATA_DIR` path (default: `./data`).
Settings that "disappear" are usually still on disk — the process may have restarted pointing at a different working directory or `DATA_DIR` env var.
