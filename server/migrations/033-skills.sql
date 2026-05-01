-- Skills: Anthropic-style skill bundles uploadable via the Studio Settings.
-- Each skill is a directory under DATA_DIR/skills/<slug>/ with at minimum a
-- SKILL.md. Enabled skills are symlinked into a per-dispatch runtime dir
-- that gets bind-mounted into each container as ~/.claude/skills/, where
-- the Claude Code CLI's native loader picks them up.
CREATE TABLE IF NOT EXISTS skills (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  slug        TEXT UNIQUE NOT NULL,
  name        TEXT NOT NULL,
  description TEXT,
  enabled     INTEGER NOT NULL DEFAULT 1,
  uploaded_by INTEGER,
  uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (uploaded_by) REFERENCES users(id)
);
